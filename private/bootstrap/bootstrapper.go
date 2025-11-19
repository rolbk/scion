// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bootstrap

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/topology"
)

const (
	// TopologyEndpoint is the default endpoint for fetching topology information.
	TopologyEndpoint = "topology"
	// DefaultPort is the default port for bootstrap servers.
	DefaultPort = 8041
	// HTTPRequestTimeout is the timeout for HTTP requests.
	HTTPRequestTimeout = 2 * time.Second
)

// Bootstrapper tries to find the address of the control server and fetch topology information.
//
// It currently supports:
// - DNS lookup NAPTR with A/AAAA and TXT for port information
// - Direct connection to a bootstrap server IP
// - Loading from a topology file
type Bootstrapper struct {
	topologyResource string
	localTopology    *topology.RWTopology
}

// NewViaDNS creates a Bootstrapper that uses DNS to discover the bootstrap server.
// It performs NAPTR DNS lookup to find the bootstrap server address.
func NewViaDNS(ctx context.Context, host string) (*Bootstrapper, error) {
	addr, err := bootstrapViaDNS(ctx, host)
	if err != nil {
		return nil, serrors.Wrap("bootstrapping via DNS", err, "host", host)
	}
	return newViaBootstrapServerIP(ctx, addr)
}

// NewViaBootstrapServerIP creates a Bootstrapper using a direct bootstrap server address.
// The address should be in the format "host:port" or just "host" (default port will be used).
func NewViaBootstrapServerIP(ctx context.Context, hostAndPort string) (*Bootstrapper, error) {
	return newViaBootstrapServerIP(ctx, hostAndPort)
}

// NewViaTopoFile creates a Bootstrapper that loads topology from a file.
func NewViaTopoFile(ctx context.Context, file string) (*Bootstrapper, error) {
	topo, err := loadTopologyFromFile(file)
	if err != nil {
		return nil, serrors.Wrap("loading topology from file", err, "file", file)
	}
	return &Bootstrapper{
		topologyResource: file,
		localTopology:    topo,
	}, nil
}

// GetLocalTopology returns the local AS topology information.
func (b *Bootstrapper) GetLocalTopology() *topology.RWTopology {
	return b.localTopology
}

// FetchResource fetches a resource from the bootstrap server via HTTP.
func (b *Bootstrapper) FetchResource(ctx context.Context, resource string) (string, error) {
	if b.topologyResource == "" {
		return "", serrors.New("no topology resource configured")
	}

	log.Debug("Fetching resource from bootstrap server",
		"server", b.topologyResource, "resource", resource)

	url := fmt.Sprintf("http://%s/%s", b.topologyResource, resource)
	return fetchHTTP(ctx, url)
}

// RefreshTopology refreshes the topology information from the bootstrap server.
func (b *Bootstrapper) RefreshTopology(ctx context.Context) error {
	if b.topologyResource == "" {
		return serrors.New("cannot refresh topology: no bootstrap server configured")
	}

	content, err := b.FetchResource(ctx, TopologyEndpoint)
	if err != nil {
		return serrors.Wrap("fetching topology", err)
	}

	topo, err := topology.RWTopologyFromJSONBytes([]byte(content))
	if err != nil {
		return serrors.Wrap("parsing topology", err)
	}

	b.localTopology = topo
	return nil
}

// newViaBootstrapServerIP is the internal constructor for bootstrap server IP.
func newViaBootstrapServerIP(ctx context.Context, hostAndPort string) (*Bootstrapper, error) {
	addr := ensurePortOrDefault(hostAndPort, DefaultPort)

	b := &Bootstrapper{
		topologyResource: addr,
	}

	// Fetch the initial topology
	if err := b.RefreshTopology(ctx); err != nil {
		return nil, serrors.Wrap("fetching initial topology", err)
	}

	return b, nil
}

// ensurePortOrDefault ensures the address has a port, or adds the default port.
func ensurePortOrDefault(address string, defaultPort int) string {
	// Check if port is already specified
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// No port specified, add default
		return net.JoinHostPort(address, strconv.Itoa(defaultPort))
	}
	// Port already specified
	return net.JoinHostPort(host, port)
}

// loadTopologyFromFile loads topology from a file path.
func loadTopologyFromFile(filePath string) (*topology.RWTopology, error) {
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		// Try to find in working directory or as relative path
		absPath, err := filepath.Abs(filePath)
		if err != nil {
			return nil, serrors.Wrap("resolving file path", err, "path", filePath)
		}
		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			return nil, serrors.New("topology file not found", "path", filePath)
		}
		filePath = absPath
	}

	// Read and parse the topology file
	topo, err := topology.RWTopologyFromJSONFile(filePath)
	if err != nil {
		return nil, serrors.Wrap("reading topology file", err, "path", filePath)
	}

	// Validate that there are control services
	if len(topo.CS) == 0 {
		return nil, serrors.New("no control service found in topology file", "path", filePath)
	}

	return topo, nil
}

// fetchHTTP fetches content from a URL via HTTP GET.
func fetchHTTP(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", serrors.Wrap("creating HTTP request", err, "url", url)
	}

	client := &http.Client{
		Timeout: HTTPRequestTimeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", serrors.Wrap("executing HTTP request", err, "url", url)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", serrors.New("HTTP request failed",
			"url", url, "status_code", resp.StatusCode, "status", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", serrors.Wrap("reading HTTP response", err, "url", url)
	}

	return string(body), nil
}

// bootstrapViaDNS performs DNS NAPTR lookup to discover the bootstrap server address.
func bootstrapViaDNS(ctx context.Context, hostName string) (string, error) {
	addr, err := GetScionDiscoveryAddress(hostName)
	if err != nil {
		return "", serrors.Wrap("DNS lookup failed", err, "host", hostName)
	}
	if addr == "" {
		return "", serrors.New("no valid DNS NAPTR entry found", "host", hostName)
	}
	return addr, nil
}
