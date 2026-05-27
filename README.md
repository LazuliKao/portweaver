# PortWeaver

[English](README.md) | [中文](README_zh.md)

High-performance port forwarding engine for OpenWrt, written in Zig. Combines kernel-level NAT forwarding with optional userspace forwarding (libuv-based), FRP tunneling, and dynamic DNS -- all statically linked into a single binary.

## Features

- **TCP/UDP Port Forwarding** — Kernel-level NAT via iptables/nftables
- **App-Layer Forwarding** — Userspace TCP/UDP forwarding via libuv with separate per-connection threads
- **Port Range Mapping** — Map port ranges (e.g. `8080-8090` to `9080-9090`) with automatic expansion
- **FRP Client (frpc)** — Statically linked Go library, reverse proxy tunneling (`-Dfrpc=true`)
- **FRP Server (frps)** — Statically linked Go library, act as an FRP server (`-Dfrps=true`)
- **DDNS** — 25 DNS providers (`-Dddns=true`)
- **UCI Config** — Native OpenWrt UCI configuration from `/etc/config/portweaver` (`-Duci=true`)
- **UCI Firewall** — Auto-manage ACCEPT and DNAT/redirect rules via UCI
- **Traffic Statistics** — Per-project byte counters when `enable_stats=true`
- **Source IP Preservation** — `preserve_source_ip` option for transparent proxying
- **IPv4/IPv6/Both** — Support IPv6 listen forwarding to IPv4 target (app-layer forwarding)

## Quick Start

### Minimal JSON Configuration

Create a `config.json` file:

```json
{
  "$schema": "./docs/portweaver-config.schema.json",
  "projects": [
    {
      "remark": "Forward HTTP",
      "listen_port": 8080,
      "target_address": "127.0.0.1",
      "target_port": 80,
      "protocol": "tcp",
      "family": "any",
      "enable_app_forward": true,
      "open_firewall_port": false,
      "add_firewall_forward": false
    }
  ]
}
```

Run with:

```bash
portweaver -c config.json
```

### UCI Configuration (OpenWrt)

Create `/etc/config/portweaver`:

```uci
config project 'rdp'
    option remark 'Windows RDP'
    option family 'ipv4'
    option protocol 'tcp'
    option listen_port '3389'
    option target_address '192.168.1.100'
    option target_port '3389'
    option open_firewall_port '1'
    option add_firewall_forward '1'
```

Build with UCI support:

```bash
zig build -Duci=true
```

For a complete configuration example, see [docs/example_config.json](docs/example_config.json).

## Building

### Standard Build

```bash
zig build                              # Default build
zig build -Doptimize=Debug            # Debug build
zig build -Doptimize=ReleaseSmall     # Optimized for embedded (LTO, stripped)
```

### Feature Flags

| Flag | Description |
|------|-------------|
| `-Duci=true` | Enable UCI config support (reads `/etc/config/portweaver`) |
| `-Dubus=true` | Enable UBUS RPC server |
| `-Dfrpc=true` | Enable FRP client (statically linked Go library) |
| `-Dfrps=true` | Enable FRP server (statically linked Go library) |
| `-Dddns=true` | Enable DDNS support (25 providers, statically linked Go library) |

All Go-based features (FRPC, FRPS, DDNS) are compiled together into a single `libgolibs.a` and statically linked into the final binary.

```bash
# Example: all features enabled
zig build -Duci=true -Dubus=true -Dfrpc=true -Dfrps=true -Dddns=true

# Example: embedded deployment with FRP client
zig build -Doptimize=ReleaseSmall -Duci=true -Dubus=true -Dfrpc=true
```

### Testing and Formatting

```bash
zig build test                        # Run all tests
zig fmt src/                          # Format all source files
```

### Remote Development

```bash
zig build dev-remote                  # Watch, build, and auto-upload to remote OpenWrt device
```

## CLI Usage

```
portweaver [options]

Options:
  -c <path>    Path to JSON configuration file (default: config.json)
               Only used in non-UCI builds.
```

In UCI builds (`-Duci=true`), the configuration is always loaded from `/etc/config/portweaver` and the `-c` flag is ignored.

## Architecture

```
                    +-------------------------------------+
                    |         PortWeaver Backend           |
                    |        (Zig + Statically Linked      |
                    |         Go Libraries)                 |
                    +------------------+------------------+
                                       |
         +-----------------------------+-----------------------------+
         |                             |                             |
    +----v----+                 +------+-------+             +------+-------+
    |  Config  |                 |   Core Loop  |             |   UBUS RPC  |
    |  System  |                 |  (100ms poll)|             |   Server    |
    | UCI/JSON |                 |              |             |  (optional) |
    +----+----+                 +------+-------+             +--------------+
         |                             |
    +----v----+                 +------+-------+
    | Firewall |                 |   Projects   |
    |  Rules   |                 |  (handles)   |
    | (UCI)   |                 +------+-------+
    +---------+                          |
                         +---------------+---------------+
                         |               |               |
                   +-----v-----+  +-----v-----+  +-----v-----+
                   | Kernel NAT |  | App-Layer |  |    FRP    |
                   | Forwarding |  | Forwarding|  | (clt/srv) |
                   | (iptables) |  |  (libuv)  |  |(libgolibs)|
                   +-----------+  +-----------+  +-----------+
                                                       |
                                                 +-----v-----+
                                                 |    DDNS   |
                                                 |(libgolibs)|
                                                 +-----------+
```

### Startup Sequence

1. **`ensureSingleInstance()`** -- Acquire PID file lock (Unix) or named mutex (Windows); graceful takeover with 5s delay
2. **`event_log.initGlobal()`** -- Initialize thread-safe event ring buffer (20 capacity)
3. **`loadConfig()`** -- Parse JSON file or load UCI config based on compile flag
4. **`file_log.initGlobalFileLogger()`** -- Start optional rotating file logger
5. **`setupProject()`** -- Create `ProjectHandle` for each enabled project
6. **`applyConfig()`** -- Apply UCI firewall rules, start DDNS instances, start FRPS servers
7. **`startForwardingThreads()`** -- Spawn per-port TCP/UDP forwarding threads for each project
8. **Main loop** -- Poll `shouldExitForTakeover()` with 100ms sleep intervals; exit cleanly on takeover signal

## Configuration

### Project Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `remark` | string | `""` | Project name/description |
| `enabled` | bool | `true` | Enable or disable this project |
| `family` | string | `"any"` | Address family: `any`, `ipv4`, `ipv6` |
| `protocol` | string | `"tcp"` | Protocol: `tcp`, `udp`, `both` |
| `listen_port` | number | -- | Listen port (single-port mode, mutually exclusive with `port_mappings`) |
| `target_address` | string | -- | Target IP or hostname |
| `target_port` | number | -- | Target port (single-port mode) |
| `port_mappings` | array | `[]` | Port range mappings (multi-port mode, mutually exclusive with `listen_port`/`target_port`) |
| `enable_app_forward` | bool | `false` | Enable userspace forwarding via libuv |
| `open_firewall_port` | bool | `true` | Open firewall for listen port |
| `add_firewall_forward` | bool | `true` | Add DNAT/redirect firewall rule |
| `preserve_source_ip` | bool | `false` | Use redirect rules to preserve source IP |
| `enable_stats` | bool | `false` | Enable per-project traffic byte counters |
| `reuseaddr` | bool | `true` | Enable SO_REUSEADDR on listen socket |
| `src_zones` | array | `["wan"]` | Firewall source zones for DNAT/redirect |
| `dest_zones` | array | `["lan"]` | Firewall destination zones for DNAT/redirect |

### Port Mappings

Each project can use either single-port mode (`listen_port`/`target_port`) or multi-port mode (`port_mappings`). They are mutually exclusive.

```json
{
  "remark": "Port range forwarding",
  "target_address": "192.168.1.100",
  "enable_app_forward": true,
  "port_mappings": [
    {
      "listen_port": "8080-8090",
      "target_port": "80-90",
      "protocol": "tcp"
    }
  ]
}
```

See [docs/PORT_MAPPINGS.md](docs/PORT_MAPPINGS.md) for detailed port mapping documentation.

See [docs/APP_FORWARD.md](docs/APP_FORWARD.md) for app-layer forwarding documentation.

### Full Configuration Schema

The JSON configuration schema is documented at [docs/portweaver-config.schema.json](docs/portweaver-config.schema.json).

### DDNS Providers

25 DNS providers are supported: `alidns`, `aliesa`, `tencentcloud`, `trafficroute`, `dnspod`, `dnsla`, `cloudflare`, `huaweicloud`, `callback`, `baiducloud`, `porkbun`, `godaddy`, `namecheap`, `namesilo`, `vercel`, `dynadot`, `dynv6`, `spaceship`, `nowcn`, `eranet`, `gcore`, `edgeone`, `nsone`, `name_com`.

## UBUS RPC API

Available when compiled with `-Dubus=true`. The RPC object is named `portweaver`.

### Common Methods

| Method | Parameters | Description |
|--------|-----------|-------------|
| `get_status` | -- | Overall engine status (projects, ports, traffic, uptime) |
| `get_full_status` | -- | Detailed status with all subsystem info |
| `list_projects` | -- | List all configured projects |
| `set_enabled` | `(id: int, enabled: bool)` | Enable or disable a project by ID |
| `get_events` | -- | Get recent event log entries |

### FRP Methods

Available when compiled with `-Dfrpc=true` or `-Dfrps=true`.

| Method | Parameters | Description |
|--------|-----------|-------------|
| `get_frp_status` | -- | Combined FRP client + server status |

#### FRP Client Methods (`-Dfrpc=true`)

| Method | Parameters | Description |
|--------|-----------|-------------|
| `get_frpc_info` | `(id: string)` | FRP client project info |
| `get_frpc_proxy_stats` | `(id: string)` | FRP client proxy statistics |
| `clear_frpc_logs` | `(id: string)` | Clear FRP client logs |

#### FRP Server Methods (`-Dfrps=true`)

| Method | Parameters | Description |
|--------|-----------|-------------|
| `get_frps_info` | `(id: string)` | FRP server project info |
| `get_frps_proxy_stats` | `(id: string)` | FRP server proxy statistics |
| `clear_frps_logs` | `(id: string)` | Clear FRP server logs |

### DDNS Methods (`-Dddns=true`)

| Method | Parameters | Description |
|--------|-----------|-------------|
| `get_ddns_global_status` | -- | All DDNS instances status |
| `get_ddns_status` | -- | DDNS status summary |
| `get_ddns_info` | `(name: string)` | Specific DDNS config info |
| `clear_ddns_logs` | `(name: string)` | Clear specific DDNS logs |

## Project Structure

```
src/
  main.zig                     # Entry point, main loop, startup sequence
  event_log.zig                # Thread-safe in-memory event ring buffer
  file_log.zig                 # Rotating file logger
  process_lock.zig             # Single-instance PID/mutex lock with graceful takeover
  compat.zig                   # Cross-platform compatibility layer
  config/
    types.zig                  # Configuration data structures
    mod.zig                    # Config module exports
    provider.zig               # Config provider abstraction
    uci_loader.zig             # UCI config loading
    json_loader.zig            # JSON config loading
  impl/
    app_forward.zig            # Application-layer forwarding orchestration
    app_forward/
      common.zig               # Shared forwarding utilities
      uv.zig                   # libuv integration
      tcp_forwarder_uv.zig     # TCP forwarder (libuv-based)
      udp_forwarder_uv.zig     # UDP forwarder (libuv-based)
    uci_firewall.zig           # UCI firewall rule management
    frpc_forward.zig           # FRP client forwarding logic
    frps_forward.zig           # FRP server forwarding logic
    frp_status.zig             # FRP status monitoring
    ddns_manager.zig           # DDNS lifecycle management
    project_status.zig         # Project handle and runtime state
    frpc/libfrpc.zig           # FRP client C API bindings
    frps/libfrps.zig           # FRP server C API bindings
    ddns/libddns.zig           # DDNS C API bindings
    golibs/                    # Go library sources (FRPC + FRPS + DDNS)
  uci/
    mod.zig                    # UCI module exports
    types.zig                  # UCI data types
    libuci.zig                 # libuci C bindings
  ubus/
    server.zig                 # UBUS RPC server implementation
    libubus.zig                # libubus C bindings
    libblobmsg_json.zig        # blobmsg JSON utilities
    ubox.zig                   # ubox utilities
  loader/
    dynamic_lib.zig            # Dynamic library loading
deps/                          # External C libraries (libuv, uci, ubus)
```

## License

GPL-3.0. See [LICENSE](LICENSE) for details.
