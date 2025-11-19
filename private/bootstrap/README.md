# Bootstrap Package

The `bootstrap` package provides functionality for discovering and connecting to SCION control servers through multiple bootstrap mechanisms.

## Features

The Bootstrapper supports four different methods for obtaining topology information:

1. **DNS Discovery** - Uses NAPTR DNS records to discover bootstrap servers
2. **Direct Bootstrap Server** - Connects to a known bootstrap server IP/hostname
3. **Topology File** - Loads topology from a local JSON file
4. **Daemon Connection** - Uses an existing daemon service connection

## Usage

### DNS-based Discovery

Bootstrap using DNS NAPTR records:

```go
ctx := context.Background()
bootstrapper, err := bootstrap.NewViaDNS(ctx, "example.scion")
if err != nil {
    log.Fatal(err)
}

topo := bootstrapper.GetLocalTopology()
fmt.Printf("Local AS: %s\n", topo.IA)
```

The DNS discovery looks for:
- NAPTR records with service `x-sciondiscovery:tcp`
- TXT records with format `x-sciondiscovery=<port>` for port information
- A or AAAA records for the bootstrap server address

### Direct Bootstrap Server

Connect directly to a known bootstrap server:

```go
ctx := context.Background()
bootstrapper, err := bootstrap.NewViaBootstrapServerIP(ctx, "192.0.2.1:8041")
if err != nil {
    log.Fatal(err)
}

topo := bootstrapper.GetLocalTopology()
```

The address can be:
- `host:port` - explicit host and port
- `host` - host with default port (8041)
- `[IPv6]:port` - IPv6 address with port
- `IPv6` - IPv6 address with default port

### Topology File

Load topology from a local JSON file:

```go
ctx := context.Background()
bootstrapper, err := bootstrap.NewViaTopoFile(ctx, "/path/to/topology.json")
if err != nil {
    log.Fatal(err)
}

topo := bootstrapper.GetLocalTopology()
```

### Daemon Connection

Use an existing daemon service connection:

```go
ctx := context.Background()
daemonConn := // ... obtain daemon connection
bootstrapper, err := bootstrap.NewViaDaemon(ctx, daemonConn)
if err != nil {
    log.Fatal(err)
}

conn := bootstrapper.GetDaemonConnector()
```

## API Reference

### Types

#### `Bootstrapper`

Main type that handles bootstrap operations.

**Methods:**
- `GetLocalTopology() *topology.RWTopology` - Returns the local AS topology
- `GetDaemonConnector() daemon.Connector` - Returns the daemon connector (if available)
- `FetchResource(ctx context.Context, resource string) (string, error)` - Fetches a resource from the bootstrap server
- `RefreshTopology(ctx context.Context) error` - Refreshes topology from the bootstrap server

### Constructor Functions

- `NewViaDNS(ctx context.Context, host string) (*Bootstrapper, error)`
- `NewViaBootstrapServerIP(ctx context.Context, hostAndPort string) (*Bootstrapper, error)`
- `NewViaTopoFile(ctx context.Context, file string) (*Bootstrapper, error)`
- `NewViaDaemon(ctx context.Context, conn daemon.Connector) (*Bootstrapper, error)`

## DNS Configuration

For DNS-based discovery to work, your DNS server must be configured with:

1. **NAPTR Record:**
   ```
   example.scion. IN NAPTR 10 10 "A" "x-sciondiscovery:tcp" "" bootstrap.example.scion.
   ```

2. **TXT Record:**
   ```
   example.scion. IN TXT "x-sciondiscovery=8041"
   ```

3. **A/AAAA Record:**
   ```
   bootstrap.example.scion. IN A 192.0.2.1
   ```

## Constants

- `TopologyEndpoint = "topology"` - Default endpoint for fetching topology
- `DefaultPort = 8041` - Default port for bootstrap servers
- `HTTPRequestTimeout = 2 * time.Second` - Timeout for HTTP requests

## Error Handling

All functions return errors that can be checked using standard Go error handling:

```go
bootstrapper, err := bootstrap.NewViaDNS(ctx, "example.scion")
if err != nil {
    // Handle error
    log.Printf("Bootstrap failed: %v", err)
    return
}
```

Errors are wrapped using `pkg/private/serrors` for better error context.

## Dependencies

- `github.com/miekg/dns` - For NAPTR DNS lookups
- `github.com/scionproto/scion/pkg/daemon` - For daemon connectivity
- `github.com/scionproto/scion/private/topology` - For topology parsing

## Testing

Run tests with:

```bash
go test github.com/scionproto/scion/private/bootstrap
```

Note: DNS NAPTR tests are skipped by default and require integration test setup.

## Implementation Notes

This implementation mirrors the Java bootstrap implementation from the SCION-Java project (`org.scion.jpan.internal.ScionBootstrapper`), providing equivalent functionality in Go.

The DNS helper functions follow the same patterns as the Java `DNSHelper` class:
- NAPTR lookup for service discovery
- TXT record parsing for port configuration
- A/AAAA record resolution for IP addresses
