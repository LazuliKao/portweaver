# AGENTS.md - PortWeaver Backend (Zig)

## Overview

PortWeaver is a high-performance port forwarding engine for OpenWrt, written in Zig. It supports multiple forwarding modes (firewall rules, application-layer forwarding, FRP proxying, and DDNS) with UCI configuration integration.

---

## 1. Build & Test Commands

### Standard Build
```bash
zig build                    # Build with default settings
zig build -Doptimize=Debug  # Debug build
zig build -Doptimize=ReleaseSmall  # Optimized for embedded
```

### Feature Flags (Conditional Compilation)
```bash
zig build -Dfrpc=true       # Enable FRP client support (links libfrp.a)
zig build -Dddns=true       # Enable DDNS support (links libddns.a)
zig build -Djson=true       # Enable JSON config file support
zig build -Duci=true        # Enable UCI config support (default)
zig build -Dubus=true       # Enable UBUS integration (default)

# Combined example:
zig build -Dfrpc=true -Dddns=true -Doptimize=ReleaseSmall
```

### Testing
```bash
zig build test              # Run all tests (module + executable)
zig test src/path/to/file.zig  # Run tests in specific file only
```

### Code Formatting
```bash
zig fmt src/                # Format all source files (strictly enforced)
zig fmt src/path/to/file.zig  # Format specific file
```

### Running
```bash
zig build run               # Build and run locally
zig build run -- [args]     # Pass arguments to executable
zig build dev-remote        # Watch, build, and auto-upload to remote (requires dotnet fsi)
```

---

## 2. Project Structure

```
src/
├── main.zig                 # Application entry point, main loop
├── config/
│   ├── types.zig           # Configuration data structures
│   ├── mod.zig             # Config module exports
│   ├── provider.zig        # Config provider abstraction
│   ├── uci_loader.zig      # UCI config loading
│   ├── json_loader.zig     # JSON config loading (optional)
│   ├── file_loader.zig     # File I/O utilities
│   └── helper.zig          # Config parsing helpers
├── impl/
│   ├── app_forward.zig     # Application-layer forwarding (TCP/UDP)
│   ├── app_forward/
│   │   ├── common.zig      # Shared forwarding utilities
│   │   ├── uv.zig          # libuv integration
│   │   ├── tcp_forwarder_uv.zig  # TCP forwarder implementation
│   │   └── udp_forwarder_uv.zig  # UDP forwarder implementation
│   ├── uci_firewall.zig    # Firewall rule management
│   ├── frp_forward.zig     # FRP forwarding logic
│   ├── frp_status.zig      # FRP status monitoring
│   ├── frpc/
│   │   ├── libfrp.zig      # FRP C API bindings
│   │   └── example.zig     # FRP usage example
│   ├── ddns_manager.zig    # DDNS management
│   ├── ddns/
│   │   ├── libddns.zig     # DDNS C API bindings
│   │   └── example.zig     # DDNS usage example
│   └── project_status.zig  # Project status tracking
├── uci/
│   ├── mod.zig             # UCI module exports
│   ├── types.zig           # UCI data types
│   ├── libuci.zig          # libuci C bindings
│   └── [platform-specific files]
├── ubus/
│   ├── server.zig          # UBUS RPC server
│   ├── libubus.zig         # libubus C bindings
│   ├── ubox.zig            # ubox utilities
│   └── [platform-specific files]
├── loader/
│   └── dynamic_lib.zig     # Dynamic library loading
└── event_log.zig           # Event logging system
```

---

## 3. Code Style & Conventions

### Naming Conventions
- **Functions**: `snake_case` (e.g., `load_config`, `forward_packet`)
- **Types**: `CamelCase` (e.g., `ConfigProject`, `ForwarderState`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `MAX_BUFFER_SIZE`)
- **Private symbols**: Prefix with `_` or use file-local scope

### Memory Management (CRITICAL)
- **NEVER** use `std.heap.page_allocator` directly
- **ALWAYS** accept an `allocator: std.mem.Allocator` parameter in init functions
- **ALWAYS** use `defer` immediately after allocation for cleanup
- **ALWAYS** document allocator ownership (who frees what)

**Example:**
```zig
pub fn init(allocator: std.mem.Allocator) !Self {
    const config = try allocator.alloc(u8, 1024);
    defer allocator.free(config);  // ✅ Cleanup guaranteed
    // ... use config
}
```

### Error Handling
- **Use `try`** to propagate errors up the call stack
- **Use `catch`** only for specific error handling with logging
- **NEVER** use empty catch blocks: `catch |err| {}`
- **ALWAYS** log errors before returning or handling them

**Example:**
```zig
const file = try std.fs.cwd().openFile("config.json", .{});  // ✅ Propagate
defer file.close();

const data = file.readAllAlloc(allocator, 1024 * 1024) catch |err| {
    std.debug.print("Failed to read config: {}\n", .{err});  // ✅ Log first
    return err;
};
```

### Concurrency
- Threads are managed in `src/main.zig`
- Use `std.Thread.spawn()` for detached workers
- Use `std.Thread.join()` for synchronous waits
- Protect shared state with mutexes (`std.Thread.Mutex`)
- Document thread safety assumptions in comments

### Type Safety
- **NEVER** use `as any` or equivalent type coercions
- **NEVER** use `@as(T, undefined)` for uninitialized values
- Use explicit error unions (`!T`) instead of null checks
- Use `orelse` and `catch` for optional/error handling

### Comments & Documentation
- Document public functions with doc comments (`///`)
- Explain non-obvious logic with inline comments
- Document allocator ownership and lifetime
- Document thread safety requirements

---

## 4. Important Context: Feature Modules

### FRP Integration (Statically Linked)

**FRP is NOT an external program** — it is a statically linked library (`libfrp.a`) compiled from Go and linked into the portweaver binary at build time.

- **Enable**: Use build flag `-Dfrpc=true`
- **Check if enabled**: Use `build_options.frpc_mode` (compile-time constant)
- **Get version**: Import `src/impl/frpc/libfrp.zig` and call `libfrp.getVersion(allocator)`
- **DO NOT**: Try to detect FRP by running external commands (`pidof frpc`, `frpc --version`)
- **DO**: Check `build_options.frpc_mode` and use libfrp C API through Zig bindings

**Build Integration** (in `build.zig`):
- FRP library built from `src/impl/frpc/libfrpc-go/libfrp.go`
- Output: `src/impl/frpc/libfrpc-go/libfrp.a`
- Linked only when `-Dfrpc=true` is set

### DDNS Integration (Statically Linked)

**DDNS is a statically linked library** (`libddns.a`) compiled from Go and linked into the portweaver binary at build time.

- **Enable**: Use build flag `-Dddns=true`
- **Check if enabled**: Use `build_options.ddns_mode` (compile-time constant)
- **Get version**: Import `src/impl/ddns/libddns.zig` and call `libddns.getVersion(allocator)`
- **DO NOT**: Try to detect DDNS by running external commands
- **DO**: Check `build_options.ddns_mode` and use libddns C API through Zig bindings

**Build Integration** (in `build.zig`):
- DDNS library built from `src/impl/ddns/libddns-go/libddns.go`
- Output: `src/impl/ddns/libddns-go/libddns.a`
- Linked only when `-Dddns=true` is set

**Configuration** (UCI):
```uci
config project 'ddns_example'
    option remark 'DDNS Service'
    option enable_ddns '1'
    option ddns_provider 'cloudflare'
    option ddns_domain 'example.com'
    option ddns_token 'your-token'
```

### Application-Layer Forwarding

Pure Zig implementation using libuv for TCP/UDP forwarding (no system firewall required).

- **Enable**: Set `enable_app_forward: true` in project config
- **Protocols**: TCP and UDP supported
- **Implementation**: `src/impl/app_forward/` (libuv-based)
- **Concurrency**: Multi-threaded, handles multiple connections
- **Logging**: Detailed event logging via `src/event_log.zig`

---

## 5. Anti-Patterns (DO NOT DO)

### Memory & Allocation
- ❌ Using `std.heap.page_allocator` directly
- ❌ Forgetting `defer` after allocation
- ❌ Not documenting allocator ownership
- ❌ Mixing allocators without clear ownership

### Error Handling
- ❌ Empty catch blocks: `catch |err| {}`
- ❌ Ignoring errors silently
- ❌ Using `try` without understanding propagation
- ❌ Catching errors without logging

### Concurrency
- ❌ Accessing shared state without synchronization
- ❌ Spawning threads without tracking them
- ❌ Blocking operations in the main event loop
- ❌ Not documenting thread safety

### Type Safety
- ❌ Type coercions with `as any` or `@as(T, undefined)`
- ❌ Null checks instead of error unions
- ❌ Ignoring compiler warnings

---

## 6. Configuration System

### UCI Configuration (Primary)
- **File**: `/etc/config/portweaver`
- **Format**: UCI key-value pairs
- **Supported fields**: See `src/config/types.zig` for complete list
- **Loader**: `src/config/uci_loader.zig`

### JSON Configuration (Optional)
- **Enable**: Build with `-Djson=true`
- **File**: User-specified JSON file
- **Format**: Array of project objects or `{ "projects": [...] }`
- **Loader**: `src/config/json_loader.zig`

### Configuration Fields
```
remark              # Project description
family              # IPv4, IPv6, or both
protocol            # TCP, UDP, or TCP+UDP
listen_port         # Local listening port
target_address      # Destination IP
target_port         # Destination port
reuseaddr           # Reuse local address
open_firewall_port  # Open firewall port
add_firewall_forward # Add firewall forward rule
enable_app_forward  # Use app-layer forwarding
enable_frp          # Use FRP forwarding
enable_ddns         # Use DDNS service
```

---

## 7. Agent Operational Guidelines

### Before Starting Work
1. Check `build.zig` for feature flags and build logic
2. Review `src/config/types.zig` for data structures
3. Understand allocator ownership in the module you're editing
4. Check if feature is compile-time gated (e.g., `build_options.frpc_mode`)

### During Implementation
- Run `zig fmt src/` after code changes
- Use `zig build` to verify compilation
- Run `zig build test` to verify tests pass
- Check `lsp_diagnostics` on modified files

### After Completion
- Verify no type errors or warnings
- Ensure all `defer` statements are present
- Document allocator ownership
- Test with relevant feature flags enabled/disabled

---

## 8. Where to Look

| Task | File(s) |
|------|---------|
| Add new config field | `src/config/types.zig`, `src/config/uci_loader.zig` |
| Add new forwarding mode | `src/impl/`, create new module |
| Modify main loop | `src/main.zig` |
| Add UBUS RPC method | `src/ubus/server.zig` |
| Add UCI integration | `src/uci/libuci.zig` |
| Modify firewall rules | `src/impl/uci_firewall.zig` |
| Add FRP feature | `src/impl/frpc/libfrp.zig`, `src/impl/frp_*.zig` |
| Add DDNS feature | `src/impl/ddns/libddns.zig`, `src/impl/ddns_manager.zig` |
| Add app-layer forwarding | `src/impl/app_forward/` |
| Event logging | `src/event_log.zig` |

---

## 9. Testing Strategy

- **Unit tests**: Inline `test` blocks in source files
- **Integration tests**: Separate test files in `src/`
- **Run all**: `zig build test`
- **Run specific**: `zig test src/config/types.zig`
- **Debug tests**: Add `std.debug.print()` statements

---

## 10. Build System Details

The `build.zig` file orchestrates:
- **libuv compilation** from `deps/libuv/` (C library)
- **FRP library compilation** from Go (when `-Dfrpc=true`)
- **DDNS library compilation** from Go (when `-Dddns=true`)
- **Zig executable compilation** with conditional imports
- **Cross-compilation support** via Zig's target system

Key functions:
- `addLibuv()` — Builds libuv static library
- `addGoLibrary()` — Generic Go library builder (used for FRP and DDNS)
- `addLibFrp()` — Builds FRP library
- `addLibDdns()` — Builds DDNS library
- `build()` — Main build orchestration
