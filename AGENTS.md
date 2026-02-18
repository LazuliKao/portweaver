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
zig build -Dfrpc=true       # Enable FRP client support
zig build -Dfrps=true       # Enable FRP server support
zig build -Dddns=true       # Enable DDNS support
zig build -Djson=true       # Enable JSON config file support
zig build -Duci=true        # Enable UCI config support
zig build -Dubus=true       # Enable UBUS integration

# Combined example (all Go features compiled into single libgolibs.a):
zig build -Dfrpc=true -Dddns=true -Dfrps=true -Doptimize=ReleaseSmall
```

**Note:** FRP client, FRP server, and DDNS are compiled together into `libgolibs.a` from `src/impl/golibs/`.

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
├── all_tests.zig            # Test aggregator for `zig build test`
├── config/
│   ├── types.zig           # Configuration data structures
│   ├── mod.zig             # Config module exports
│   ├── provider.zig        # Config provider abstraction
│   ├── uci_loader.zig      # UCI config loading
│   ├── json_loader.zig     # JSON config loading (optional)
│   └── helper.zig          # Config parsing helpers
├── impl/
│   ├── app_forward.zig     # Application-layer forwarding (TCP/UDP)
│   ├── app_forward/
│   │   ├── common.zig      # Shared forwarding utilities
│   │   ├── uv.zig          # libuv integration
│   │   ├── tcp_forwarder_uv.zig  # TCP forwarder implementation
│   │   ├── udp_forwarder_uv.zig  # UDP forwarder implementation
│   │   └── forwarder/      # C forwarder implementation
│   ├── uci_firewall.zig    # Firewall rule management
│   ├── frpc_forward.zig    # FRP client forwarding logic
│   ├── frps_forward.zig    # FRP server forwarding logic
│   ├── frp_status.zig      # FRP status monitoring
│   ├── frpc/
│   │   └── libfrpc.zig     # FRP client C API bindings
│   ├── frps/
│   │   └── libfrps.zig     # FRP server C API bindings
│   ├── golibs/             # Go library sources (FRP client/server + DDNS)
│   ├── ddns_manager.zig    # DDNS management
│   ├── ddns/
│   │   └── libddns.zig     # DDNS C API bindings
│   └── project_status.zig  # Project status tracking
├── uci/
│   ├── mod.zig             # UCI module exports
│   ├── types.zig           # UCI data types
│   └── libuci.zig          # libuci C bindings
├── ubus/
│   ├── server.zig          # UBUS RPC server
│   ├── libubus.zig         # libubus C bindings
│   ├── libblobmsg_json.zig # blobmsg JSON utilities
│   └── ubox.zig            # ubox utilities
├── loader/
│   └── dynamic_lib.zig     # Dynamic library loading
└── event_log.zig           # Event logging system

deps/                        # External C libraries
├── libuv/                  # libuv event loop library
├── uci/                    # libuci headers
├── ubus/                   # libubus headers
└── openwrt-tools/          # OpenWrt utility headers

wrapper/                     # CGO cross-compile wrapper scripts
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

### FRP Client Integration (Statically Linked)

**FRP is NOT an external program** — it is a statically linked library compiled from Go and linked into the portweaver binary at build time.

- **Enable**: Use build flag `-Dfrpc=true`
- **Check if enabled**: Use `build_options.frpc_mode` (compile-time constant)
- **Get version**: Import `src/impl/frpc/libfrpc.zig` and call `libfrpc.getVersion(allocator)`
- **DO NOT**: Try to detect FRP by running external commands (`pidof frpc`, `frpc --version`)
- **DO**: Check `build_options.frpc_mode` and use libfrpc C API through Zig bindings

### FRP Server Integration (Statically Linked)

PortWeaver can act as an FRP server, allowing other clients to connect for reverse proxying.

- **Enable**: Use build flag `-Dfrps=true`
- **Check if enabled**: Use `build_options.frps_mode` (compile-time constant)
- **Get version**: Import `src/impl/frps/libfrps.zig` and call `libfrps.getVersion(allocator)`
- **DO NOT**: Try to detect FRPS by running external commands
- **DO**: Check `build_options.frps_mode` and use libfrps C API through Zig bindings

### DDNS Integration (Statically Linked)

**DDNS is a statically linked library** compiled from Go and linked into the portweaver binary at build time.

- **Enable**: Use build flag `-Dddns=true`
- **Check if enabled**: Use `build_options.ddns_mode` (compile-time constant)
- **Get version**: Import `src/impl/ddns/libddns.zig` and call `libddns.getVersion(allocator)`
- **DO NOT**: Try to detect DDNS by running external commands
- **DO**: Check `build_options.ddns_mode` and use libddns C API through Zig bindings

### Go Library Build Integration

FRP client, FRP server, and DDNS are compiled together into a single `libgolibs.a`:

- **Source**: `src/impl/golibs/`
- **Output**: `src/impl/golibs/dist/<target-triple>/libgolibs.a`
- **Build tags**: Automatically selected based on enabled features
- **Linked when**: Any of `-Dfrpc=true`, `-Dfrps=true`, or `-Dddns=true` is set

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
| Add FRP client feature | `src/impl/frpc/libfrpc.zig`, `src/impl/frpc_forward.zig` |
| Add FRP server feature | `src/impl/frps/libfrps.zig`, `src/impl/frps_forward.zig` |
| Add DDNS feature | `src/impl/ddns/libddns.zig`, `src/impl/ddns_manager.zig` |
| Add app-layer forwarding | `src/impl/app_forward/` |
| Event logging | `src/event_log.zig` |
| Go library source | `src/impl/golibs/` |

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
- **Go library compilation** from `src/impl/golibs/` (when any Go feature enabled)
- **Zig executable compilation** with conditional imports
- **Cross-compilation support** via Zig's target system

Key functions:
- `addLibuv()` — Builds libuv static library
- `addGoLibrary()` — Generic Go library builder (used for combined golibs)
- `addCombinedGoLib()` — Builds combined FRP+DDNS library (`libgolibs.a`)
- `createWrapperScript()` — Creates CGO cross-compile wrapper scripts
- `applyLinkOptimization()` — Applies LTO and section optimization
- `build()` — Main build orchestration
