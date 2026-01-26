# AGENTS.md - PortWeaver Backend (Zig)

## Overview

This is the core port forwarding engine written in Zig, designed for performance and low resource usage on OpenWrt devices.

## Structure

The `src/` directory is organized by functionality:
- `main.zig`: Application entry point.
- `config/`: Handles loading configuration from files or UCI.
- `impl/`: Contains platform-specific implementations (e.g., firewall rules).
- `ubus/` & `uci/`: OpenWrt integration modules.

## Where to Look

- **Build Logic**: `build.zig` (controls conditional compilation).
- **Business Logic**: `src/main.zig` (main loop), `src/app_forward.zig` (forwarding logic).
- **Configuration**: `src/config/types.zig` (data structures), `src/config/file_loader.zig`, `src/config/uci_loader.zig`.
- **Platform Integration**: `src/impl/uci_firewall.zig`, `src/ubus/ubus_server.zig`.

## Conventions

- **Memory Management**: Explicit allocator passing (`std.mem.Allocator`). Use `defer` for cleanup.
- **Error Handling**: Use `try` for propagation and `catch` for handling specific errors.
- **Concurrency**: Threads are managed in `src/main.zig`; use `std.Thread.spawn` for detached workers.

## Anti-Patterns

- **Global Allocators**: Do not use `std.heap.page_allocator` directly; always use the passed-in allocator.
- **Blocking I/O**: Avoid blocking operations in the main loop.
- **Ignoring Errors**: Do not use `catch |err| {}`; always handle or log errors.
