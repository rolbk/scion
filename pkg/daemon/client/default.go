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

package client

import (
	"context"
	"os"

	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/private/bootstrap"
)

// ConnectorOptions specifies options for creating a daemon connector.
type ConnectorOptions struct {
	// TopoFile specifies a topology file to use for bootstrapping
	TopoFile string
	// BootstrapHost specifies a bootstrap server address (IP:port)
	BootstrapHost string
	// BootstrapNAPTRName specifies a DNS name for NAPTR-based discovery
	BootstrapNAPTRName string
	// DaemonAddr specifies the daemon address to connect to
	DaemonAddr string
	// DNSSearchDomains specifies DNS search domains for discovery
	DNSSearchDomains string
	// UseOSSearchDomains enables using OS-configured DNS search domains
	UseOSSearchDomains bool
}

// ConnectorWithOptions returns a daemon connector with the specified options.
// For typical application use, obtain options from flag.SCIONEnvironment which
// handles the precedence: command line flag > environment variable > config file > default.
//
// It tries multiple bootstrap methods in order based on which options are set:
//  1. Bootstrap via topology file (if TopoFile is set)
//  2. Bootstrap via server IP (if BootstrapHost is set)
//  3. Bootstrap via DNS NAPTR (if BootstrapNAPTRName is set)
//  4. Daemon connection (if DaemonAddr is set or as fallback)
//  5. DNS search for discovery service (if UseOSSearchDomains/DNSSearchDomains is set)
func ConnectorWithOptions(ctx context.Context, opts ConnectorOptions) (daemon.Connector, error) {
	// Try bootstrap via topology file
	if opts.TopoFile != "" {
		log.Info("Attempting bootstrap via topology file", "file", opts.TopoFile)
		_, err := bootstrap.NewViaTopoFile(ctx, opts.TopoFile)
		if err != nil {
			log.Info("Failed to bootstrap via topology file", "err", err)
		} else {
			conn, err := NewLocalDaemon(ctx, opts.TopoFile)
			if err != nil {
				log.Info("Failed to create local daemon", "err", err)
			} else {
				return conn, nil
			}
		}
	}

	// Try bootstrap via server IP
	if opts.BootstrapHost != "" {
		log.Info("Attempting bootstrap via server IP", "server", opts.BootstrapHost)
		b, err := bootstrap.NewViaBootstrapServerIP(ctx, opts.BootstrapHost)
		if err != nil {
			log.Info("Failed to bootstrap via server IP", "err", err)
		} else {
			conn, _, err := createConnectorFromBootstrapper(ctx, b)
			if err != nil {
				log.Info("Failed to create local daemon from bootstrapper", "err", err)
			} else {
				return conn, nil
			}
		}
	}

	// Try bootstrap via DNS NAPTR
	if opts.BootstrapNAPTRName != "" {
		log.Info("Attempting bootstrap via DNS NAPTR", "name", opts.BootstrapNAPTRName)
		b, err := bootstrap.NewViaDNS(ctx, opts.BootstrapNAPTRName)
		if err != nil {
			log.Info("Failed to bootstrap via DNS NAPTR", "err", err)
		} else {
			conn, _, err := createConnectorFromBootstrapper(ctx, b)
			if err != nil {
				log.Info("Failed to create local daemon from bootstrapper", "err", err)
			} else {
				return conn, nil
			}
		}
	}

	// Try daemon connection
	daemonAddr := opts.DaemonAddr
	if daemonAddr == "" {
		daemonAddr = daemon.DefaultAPIAddress
	}

	log.Info("Attempting daemon connection", "address", daemonAddr)
	service := daemon.Service{Address: daemonAddr}
	conn, err := service.Connect(ctx)
	if err != nil {
		// Only fail if the user explicitly set the daemon address
		if opts.DaemonAddr != "" {
			return nil, serrors.Wrap("connecting to daemon", err, "address", daemonAddr)
		}
		log.Info("Failed to connect to daemon", "err", err)
	} else {
		return conn, nil
	}

	// Try DNS search for discovery service
	if opts.UseOSSearchDomains || opts.DNSSearchDomains != "" {
		log.Info("Attempting DNS search for discovery service")
		addr, err := searchForDiscoveryServiceWithDomains(opts.DNSSearchDomains)
		if err == nil && addr != "" {
			log.Info("Found discovery service via DNS search", "address", addr)
			b, err := bootstrap.NewViaBootstrapServerIP(ctx, addr)
			if err != nil {
				log.Info("Failed to bootstrap via discovered server", "err", err)
			} else {
				conn, _, err := createConnectorFromBootstrapper(ctx, b)
				if err != nil {
					log.Info("Failed to create local daemon from bootstrapper", "err", err)
				} else {
					return conn, nil
				}
			}
		}
		log.Info("No DNS record found for bootstrap server")
		return nil, serrors.New("no DNS record found for bootstrap server")
	}

	return nil, serrors.New("could not connect to daemon, DNS, or bootstrap resource")
}

// searchForDiscoveryServiceWithDomains searches for a SCION discovery service using DNS
// with the provided search domains string.
func searchForDiscoveryServiceWithDomains(searchDomains string) (string, error) {
	if searchDomains == "" {
		return "", serrors.New("no search domains configured")
	}

	// Try each search domain separated by semicolons
	domains := splitSearchDomains(searchDomains)
	for _, domain := range domains {
		log.Debug("Checking discovery service domain", "domain", domain)
		addr, err := bootstrap.GetScionDiscoveryAddress(domain)
		if err == nil && addr != "" {
			return addr, nil
		}
	}

	return "", serrors.New("no discovery service found in search domains")
}

// splitSearchDomains splits a semicolon-separated list of search domains.
func splitSearchDomains(searchDomains string) []string {
	var domains []string
	current := ""
	for _, ch := range searchDomains {
		if ch == ';' {
			if current != "" {
				domains = append(domains, current)
				current = ""
			}
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		domains = append(domains, current)
	}
	return domains
}

// createConnectorFromBootstrapper creates a local daemon connector from a bootstrapper
// by saving the topology to a temporary file.
func createConnectorFromBootstrapper(ctx context.Context, b *bootstrap.Bootstrapper) (daemon.Connector, func() error, error) {
	if b.GetLocalTopology() == nil {
		return nil, nil, serrors.New("bootstrapper has no topology")
	}

	// Fetch the topology JSON content from the bootstrap server
	topoJSON, err := b.FetchResource(ctx, bootstrap.TopologyEndpoint)
	if err != nil {
		return nil, nil, serrors.Wrap("fetching topology from bootstrap server", err)
	}

	// Create a temporary file for the topology
	tmpDir := os.TempDir()
	f, err := os.CreateTemp(tmpDir, "scion-bootstrap-topo-*.json")
	if err != nil {
		return nil, nil, serrors.Wrap("creating temporary topology file", err)
	}
	tmpFilePath := f.Name()

	// Write the topology JSON to the file
	if _, err := f.Write([]byte(topoJSON)); err != nil {
		f.Close()
		os.Remove(tmpFilePath)
		return nil, nil, serrors.Wrap("writing topology to file", err)
	}

	if err := f.Close(); err != nil {
		os.Remove(tmpFilePath)
		return nil, nil, serrors.Wrap("closing topology file", err)
	}

	// Create the local daemon from the temporary file
	conn, err := NewLocalDaemon(ctx, tmpFilePath)
	if err != nil {
		os.Remove(tmpFilePath)
		return nil, nil, serrors.Wrap("creating local daemon", err)
	}

	// Return a cleanup function that removes the temporary file
	cleanupFunc := func() error {
		return os.Remove(tmpFilePath)
	}

	return conn, cleanupFunc, nil
}
