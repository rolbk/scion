// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package daemon

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/scionproto/scion/pkg/private/serrors"
)

// AutoConnectorOption is a functional option for NewAutoConnector and
// overrides the default priorities.
type AutoConnectorOption func(*suppliedOptions)

type suppliedOptions struct {
	sciond    string
	configDir string
}

// WithDaemon sets the daemon address for a gRPC connector.
// When set, the connector will connect to the specified daemon via gRPC.
// Mutually exclusive with WithConfigDir.
func WithDaemon(addr string) AutoConnectorOption {
	return func(o *suppliedOptions) {
		o.sciond = addr
	}
}

// WithConfigDir sets the configuration directory for standalone mode.
// The directory should contain topology.json and a certs/ subdirectory.
// Mutually exclusive with WithDaemon.
func WithConfigDir(dir string) AutoConnectorOption {
	return func(o *suppliedOptions) {
		o.configDir = dir
	}
}

// NewAutoConnector creates a new Connector based on supplied and default options.
//
// Priority order:
//  1. If WithDaemon was called, return a gRPC connector to the specified daemon.
//  2. If WithConfigDir was called, use standalone mode with the specified directory.
//  3. If topology file exists at default location, use standalone mode.
//  4. If daemon is reachable at default address, connect via gRPC.
//  5. Return error if none of the above are successful.
//
// TODO(emairoll): Include bootstrapping functionality
func NewAutoConnector(ctx context.Context, opts ...AutoConnectorOption) (Connector, error) {
	options := &suppliedOptions{}
	for _, opt := range opts {
		opt(options)
	}

	// Check mutual exclusivity
	if options.sciond != "" && options.configDir != "" {
		return nil, serrors.New("WithDaemon and WithConfigDir are mutually exclusive")
	}

	// Priority 1: Use provided daemon address
	if options.sciond != "" {
		ctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		return NewService(options.sciond).Connect(ctx)
	}

	// Priority 2: Use provided config directory for standalone mode
	if options.configDir != "" {
		topoFile := filepath.Join(options.configDir, "topology.json")
		certsDir := filepath.Join(options.configDir, "certs")
		localASInfo, err := LoadASInfoFromFile(topoFile)
		if err != nil {
			return nil, serrors.Wrap("loading topology from file", err,
				"topology_file", topoFile)
		}
		return NewStandaloneConnector(ctx, localASInfo, WithCertsDir(certsDir))
	}

	// Priority 3: Create from topology file at default location if it exists
	if _, err := os.Stat(DefaultTopologyFile); err == nil {
		localASInfo, err := LoadASInfoFromFile(DefaultTopologyFile)
		if err != nil {
			return nil, serrors.Wrap("loading topology from file", err)
		}
		return NewStandaloneConnector(ctx, localASInfo, WithCertsDir(DefaultCertsDir))
	}

	// Priority 4: Connect to daemon via gRPC if reachable
	if isReachable(DefaultAPIAddress, 500*time.Millisecond) {
		ctx, cancel := context.WithTimeout(ctx, time.Second)
		defer cancel()
		return NewService(DefaultAPIAddress).Connect(ctx)
	}

	// TODO: Better error message
	return nil, serrors.New(
		"no suitable daemon connection method found",
		"tried_supplied_api_address", options.sciond,
		"tried_supplied_config_dir", options.configDir,
		"tried_default_topology_file", DefaultTopologyFile,
		"tried_default_api_address", DefaultAPIAddress,
	)
}

func isReachable(addr string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
