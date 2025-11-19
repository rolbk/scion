# Default Service Documentation

The `default.go` module provides a singleton default service implementation for SCION daemon connectivity.
## Overview

The default service tries multiple bootstrap methods in order until one succeeds:

1. **Bootstrap via Topology File** (`SCION_BOOTSTRAP_TOPO_FILE`)
2. **Bootstrap via Server IP** (`SCION_BOOTSTRAP_HOST`)
3. **Bootstrap via DNS NAPTR** (`SCION_BOOTSTRAP_NAPTR_NAME`)
4. **Daemon Connection** (`SCION_DAEMON_ADDRESS` or default `127.0.0.1:30255`)
5. **DNS Search for Discovery Service** (if `SCION_USE_OS_SEARCH_DOMAINS` or `SCION_DNS_SEARCH_DOMAINS` is set)

## API

### Main Functions

#### `DefaultServiceConnector(ctx context.Context) (Connector, error)`
Returns the default daemon connector. Creates and caches a singleton instance.

```go
ctx := context.Background()
conn, err := daemon.DefaultServiceConnector(ctx)
if err != nil {
    log.Fatal(err)
}
defer daemon.CloseDefaultService()

// Use the connector
ia, err := conn.LocalIA(ctx)
```

#### `GetDefaultService(ctx context.Context) (*DefaultService, error)`
Returns the full default service, including both connector and bootstrapper (if available).

```go
ctx := context.Background()
service, err := daemon.GetDefaultService(ctx)
if err != nil {
    log.Fatal(err)
}
defer daemon.CloseDefaultService()

// Access bootstrapper if available
if bootstrapper := service.Bootstrapper(); bootstrapper != nil {
    topo := bootstrapper.GetLocalTopology()
}
```

#### `CloseDefaultService()`
Closes and clears the default service singleton.

```go
daemon.CloseDefaultService()
```

### DefaultService Type

```go
type DefaultService struct {
    // Methods
    Connector() Connector                   // Get daemon connector
    Bootstrapper() *bootstrap.Bootstrapper  // Get bootstrapper (may be nil)
    Mode() string                           // Get bootstrap mode used
}
```

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `SCION_BOOTSTRAP_TOPO_FILE` | Path to topology JSON file | `/etc/scion/topology.json` |
| `SCION_BOOTSTRAP_HOST` | Bootstrap server address | `192.0.2.1:8041` |
| `SCION_BOOTSTRAP_NAPTR_NAME` | DNS name for NAPTR lookup | `example.scion` |
| `SCION_DAEMON_ADDRESS` | Daemon server address | `127.0.0.1:30255` |
| `SCION_DNS_SEARCH_DOMAINS` | Semicolon-separated search domains | `scion.example.com;example.com` |
| `SCION_USE_OS_SEARCH_DOMAINS` | Enable OS DNS search domains | `true` |

## Bootstrap Modes

The service tracks which bootstrap method succeeded via the `Mode()` method:

- `"bootstrap_topo_file"` - Loaded from topology file
- `"bootstrap_server_ip"` - Connected to bootstrap server
- `"bootstrap_via_dns"` - Discovered via DNS NAPTR
- `"daemon"` - Connected to SCION daemon
- `"dns_search"` - Discovered via DNS search domains

## Usage Examples

### Simple Usage

```go
package main

import (
    "context"
    "log"

    "github.com/scionproto/scion/pkg/daemon"
)

func main() {
    ctx := context.Background()

    // Get default connector (tries all bootstrap methods)
    conn, err := daemon.DefaultServiceConnector(ctx)
    if err != nil {
        log.Fatal(err)
    }
    defer daemon.CloseDefaultService()

    // Use the connector
    ia, err := conn.LocalIA(ctx)
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Local IA: %s", ia)
}
```

### With Bootstrap Server

```go
package main

import (
    "context"
    "log"
    "os"

    "github.com/scionproto/scion/pkg/daemon"
)

func main() {
    // Configure bootstrap server
    os.Setenv("SCION_BOOTSTRAP_HOST", "192.0.2.1:8041")

    ctx := context.Background()
    service, err := daemon.GetDefaultService(ctx)
    if err != nil {
        log.Fatal(err)
    }
    defer daemon.CloseDefaultService()

    log.Printf("Bootstrap mode: %s", service.Mode())

    // Access topology if available
    if bootstrapper := service.Bootstrapper(); bootstrapper != nil {
        topo := bootstrapper.GetLocalTopology()
        log.Printf("Local AS: %s", topo.IA)
    }
}
```

### With Topology File

```go
package main

import (
    "context"
    "log"
    "os"

    "github.com/scionproto/scion/pkg/daemon"
)

func main() {
    // Configure topology file
    os.Setenv("SCION_BOOTSTRAP_TOPO_FILE", "/etc/scion/topology.json")

    ctx := context.Background()
    service, err := daemon.GetDefaultService(ctx)
    if err != nil {
        log.Fatal(err)
    }
    defer daemon.CloseDefaultService()

    // Access topology directly
    bootstrapper := service.Bootstrapper()
    topo := bootstrapper.GetLocalTopology()

    log.Printf("Local AS: %s", topo.IA)
    log.Printf("MTU: %d", topo.MTU)
    log.Printf("Is Core: %v", topo.IsCore)
}
```
