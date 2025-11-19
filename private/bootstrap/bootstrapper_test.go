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
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testTopologyJSON = `{
  "timestamp": 1234567890,
  "isd_as": "1-ff00:0:110",
  "mtu": 1472,
  "attributes": ["core"],
  "border_routers": {
    "br1": {
      "internal_addr": "127.0.0.1:31000",
      "interfaces": {
        "1": {
          "isd_as": "1-ff00:0:111",
          "link_to": "core",
          "mtu": 1472
        }
      }
    }
  },
  "control_service": {
    "cs1": {
      "addr": "127.0.0.1:30252"
    }
  }
}`

func TestEnsurePortOrDefault(t *testing.T) {
	tests := []struct {
		name        string
		address     string
		defaultPort int
		expected    string
	}{
		{
			name:        "address without port",
			address:     "192.0.2.1",
			defaultPort: 8041,
			expected:    "192.0.2.1:8041",
		},
		{
			name:        "address with port",
			address:     "192.0.2.1:9000",
			defaultPort: 8041,
			expected:    "192.0.2.1:9000",
		},
		{
			name:        "hostname without port",
			address:     "example.com",
			defaultPort: 8041,
			expected:    "example.com:8041",
		},
		{
			name:        "hostname with port",
			address:     "example.com:9000",
			defaultPort: 8041,
			expected:    "example.com:9000",
		},
		{
			name:        "IPv6 without port",
			address:     "2001:db8::1",
			defaultPort: 8041,
			expected:    "[2001:db8::1]:8041",
		},
		{
			name:        "IPv6 with port",
			address:     "[2001:db8::1]:9000",
			defaultPort: 8041,
			expected:    "[2001:db8::1]:9000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ensurePortOrDefault(tt.address, tt.defaultPort)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewViaTopoFile(t *testing.T) {
	ctx := context.Background()

	t.Run("valid topology file", func(t *testing.T) {
		// Create a temporary file with test topology
		tmpDir := t.TempDir()
		topoFile := filepath.Join(tmpDir, "topology.json")
		err := os.WriteFile(topoFile, []byte(testTopologyJSON), 0644)
		require.NoError(t, err)

		// Create bootstrapper
		b, err := NewViaTopoFile(ctx, topoFile)
		require.NoError(t, err)
		require.NotNil(t, b)

		// Verify topology was loaded
		topo := b.GetLocalTopology()
		require.NotNil(t, topo)
		assert.Equal(t, "1-ff00:0:110", topo.IA.String())
		assert.Equal(t, 1472, topo.MTU)
		assert.True(t, topo.IsCore)
		assert.Len(t, topo.CS, 1)
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, err := NewViaTopoFile(ctx, "/non/existent/file.json")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "topology file not found")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		tmpDir := t.TempDir()
		topoFile := filepath.Join(tmpDir, "invalid.json")
		err := os.WriteFile(topoFile, []byte("invalid json"), 0644)
		require.NoError(t, err)

		_, err = NewViaTopoFile(ctx, topoFile)
		require.Error(t, err)
	})

	t.Run("topology without control service", func(t *testing.T) {
		invalidTopo := `{
  "timestamp": 1234567890,
  "isd_as": "1-ff00:0:110",
  "mtu": 1472
}`
		tmpDir := t.TempDir()
		topoFile := filepath.Join(tmpDir, "no_cs.json")
		err := os.WriteFile(topoFile, []byte(invalidTopo), 0644)
		require.NoError(t, err)

		_, err = NewViaTopoFile(ctx, topoFile)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no control service found")
	})
}

func TestNewViaBootstrapServerIP(t *testing.T) {
	ctx := context.Background()

	t.Run("successful bootstrap", func(t *testing.T) {
		// Create a test HTTP server
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/topology" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(testTopologyJSON))
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		// Extract host and port from test server
		serverAddr := server.Listener.Addr().String()

		// Create bootstrapper
		b, err := NewViaBootstrapServerIP(ctx, serverAddr)
		require.NoError(t, err)
		require.NotNil(t, b)

		// Verify topology was fetched
		topo := b.GetLocalTopology()
		require.NotNil(t, topo)
		assert.Equal(t, "1-ff00:0:110", topo.IA.String())
	})

	t.Run("server not reachable", func(t *testing.T) {
		_, err := NewViaBootstrapServerIP(ctx, "192.0.2.1:8041")
		require.Error(t, err)
	})

	t.Run("server returns error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		serverAddr := server.Listener.Addr().String()
		_, err := NewViaBootstrapServerIP(ctx, serverAddr)
		require.Error(t, err)
	})
}

func TestFetchResource(t *testing.T) {
	ctx := context.Background()

	t.Run("successful fetch", func(t *testing.T) {
		expectedContent := "test resource content"
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/test-resource" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(expectedContent))
			} else {
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		serverAddr := server.Listener.Addr().String()
		b := &Bootstrapper{
			topologyResource: serverAddr,
		}

		content, err := b.FetchResource(ctx, "test-resource")
		require.NoError(t, err)
		assert.Equal(t, expectedContent, content)
	})

	t.Run("no topology resource configured", func(t *testing.T) {
		b := &Bootstrapper{}
		_, err := b.FetchResource(ctx, "test-resource")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no topology resource configured")
	})
}

func TestRefreshTopology(t *testing.T) {
	ctx := context.Background()

	t.Run("successful refresh", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/topology" {
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(testTopologyJSON))
			}
		}))
		defer server.Close()

		serverAddr := server.Listener.Addr().String()
		b := &Bootstrapper{
			topologyResource: serverAddr,
		}

		err := b.RefreshTopology(ctx)
		require.NoError(t, err)

		topo := b.GetLocalTopology()
		require.NotNil(t, topo)
		assert.Equal(t, "1-ff00:0:110", topo.IA.String())
	})

	t.Run("no bootstrap server configured", func(t *testing.T) {
		b := &Bootstrapper{}
		err := b.RefreshTopology(ctx)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no bootstrap server configured")
	})
}

func TestFetchHTTP(t *testing.T) {
	ctx := context.Background()

	t.Run("successful request", func(t *testing.T) {
		expectedContent := "test content"
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(expectedContent))
		}))
		defer server.Close()

		content, err := fetchHTTP(ctx, server.URL)
		require.NoError(t, err)
		assert.Equal(t, expectedContent, content)
	})

	t.Run("HTTP error status", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		_, err := fetchHTTP(ctx, server.URL)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP request failed")
	})

	t.Run("invalid URL", func(t *testing.T) {
		_, err := fetchHTTP(ctx, "http://192.0.2.999:99999/invalid")
		require.Error(t, err)
	})

	t.Run("context cancellation", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Simulate slow response
			select {
			case <-r.Context().Done():
				return
			case <-time.After(10 * time.Second):
				w.WriteHeader(http.StatusOK)
			}
		}))
		defer server.Close()

		ctx, cancel := context.WithCancel(ctx)
		cancel() // Cancel immediately

		_, err := fetchHTTP(ctx, server.URL)
		require.Error(t, err)
	})
}

// TODO: Is there any static SCION server to test against?

// TestGetScionDiscoveryAddress tests DNS NAPTR lookup functionality.
// Note: This test requires a properly configured DNS server with NAPTR records,
// so it's marked as a placeholder for integration testing.
func TestGetScionDiscoveryAddress(t *testing.T) {
	t.Skip("DNS NAPTR lookup requires integration test setup")

	t.Run("valid NAPTR record", func(t *testing.T) {
		// This would require a real DNS setup or a mock DNS resolver
		addr, err := GetScionDiscoveryAddress("test.scion")
		require.NoError(t, err)
		assert.NotEmpty(t, addr)
	})
}

func ExampleNewViaTopoFile() {
	ctx := context.Background()
	b, err := NewViaTopoFile(ctx, "/path/to/topology.json")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	topo := b.GetLocalTopology()
	fmt.Printf("Loaded topology for AS: %s\n", topo.IA)
}

func ExampleNewViaBootstrapServerIP() {
	ctx := context.Background()
	b, err := NewViaBootstrapServerIP(ctx, "192.0.2.1:8041")
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	topo := b.GetLocalTopology()
	fmt.Printf("Fetched topology for AS: %s\n", topo.IA)
}
