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

package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/scionproto/scion/pkg/daemon/client"
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

func TestConnectorViaTopoFile(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	topoFile := filepath.Join(tmpDir, "topology.json")
	err := os.WriteFile(topoFile, []byte(testTopologyJSON), 0644)
	require.NoError(t, err)

	// Create connector with topology file
	opts := client.ConnectorOptions{
		TopoFile: topoFile,
	}
	conn, err := client.ConnectorWithOptions(ctx, opts)
	require.NoError(t, err)
	require.NotNil(t, conn)

	// Verify it works
	ia, err := conn.LocalIA(ctx)
	require.NoError(t, err)
	assert.Equal(t, "1-ff00:0:110", ia.String())
}

func TestConnectorViaBootstrapServer(t *testing.T) {
	ctx := context.Background()

	// Create test HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/topology" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(testTopologyJSON))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	serverAddr := server.Listener.Addr().String()

	// Create connector with bootstrap server
	opts := client.ConnectorOptions{
		BootstrapHost: serverAddr,
	}
	conn, err := client.ConnectorWithOptions(ctx, opts)
	require.NoError(t, err)
	require.NotNil(t, conn)

	// Verify it works
	ia, err := conn.LocalIA(ctx)
	require.NoError(t, err)
	assert.Equal(t, "1-ff00:0:110", ia.String())
}

func ExampleConnectorWithOptions() {
	ctx := context.Background()

	// Create a connector with explicit options
	opts := client.ConnectorOptions{
		TopoFile: "/path/to/topology.json",
		// Or use daemon address:
		// DaemonAddr: "localhost:30255",
	}

	conn, err := client.ConnectorWithOptions(ctx, opts)
	if err != nil {
		// Handle error
		return
	}

	// Use the connector
	ia, err := conn.LocalIA(ctx)
	if err != nil {
		// Handle error
		return
	}
	_ = ia
}
