# Forwarder Runtime Boundary

## Purpose

This directory defines the C-side runtime boundary used by the Zig app-forwarding layer.

The goal of this boundary is:

- keep Zig from importing backend headers such as `uv.h`
- make runtime ownership explicit
- keep TCP/UDP forwarders focused on per-listener logic only
- leave room to swap the backend implementation later with minimal Zig-side churn

## Main Roles

### `forwarder_runtime_t`

`forwarder_runtime_t` is the **runtime host**.

It owns runtime-scoped resources such as:

- backend event/executor state
- wake/dispatch mechanism
- allocator bridge used by C allocations
- callback/user-data binding needed to wake and drain queued work

This object is the runtime/executor boundary between Zig and the C backend.

### `tcp_forwarder_t` / `udp_forwarder_t`

These are **listener forwarder instances**.

They should own only per-listener or per-session state, for example:

- listen port
- target address / target port
- listener handle state
- session tables
- traffic counters

They must **not** own the enclosing runtime.

## Lifecycle

## 1. Runtime lifecycle

The runtime comes first.

Typical sequence:

1. Zig creates a `LoopRuntime`
2. the runtime thread allocates `forwarder_runtime_t`
3. `forwarder_runtime_init(...)` initializes backend state and stores allocator/callback bindings
4. `forwarder_runtime_run(...)` drives the backend runtime
5. during shutdown, Zig asks forwarders to stop
6. C/Zig drain close callbacks and remaining runtime-owned handles
7. `forwarder_runtime_close(...)`
8. `forwarder_runtime_free(...)`

Rule: **the runtime must outlive every forwarder attached to it**.

Explicit teardown order:

1. request stop on attached forwarders
2. let close callbacks / teardown drain on the runtime thread
3. close runtime-owned wake mechanism and remaining owned handles
4. close the runtime itself
5. free the runtime container

## 2. Forwarder lifecycle

Forwarders are attached to an already-existing runtime.

Typical sequence:

1. on the runtime thread, call `*_create_on_runtime(runtime, ...)`
2. this allocates forwarder-owned state and prepares listener/backend handles
3. on the runtime thread, call `*_start(...)`
4. runtime continues running and drives traffic
5. from any thread, call `*_request_stop(...)` to request shutdown
6. runtime thread drains close callbacks and backend teardown
7. call `*_destroy(...)` to initiate cleanup (can be called before teardown completes)

Rule: **request_stop is a shutdown request; destroy initiates deferred cleanup**.

**Deferred destruction**: `*_destroy(...)` can be called at any time after `*_request_stop(...)`. It sets a flag and posts cleanup work to the runtime thread. The actual memory release happens only after all pending async operations have completed. This matches the libuv close-callback pattern where handles are closed asynchronously and the final free occurs when all close callbacks fire.

## Threading Rules

The contract is intentionally strict:

- `*_create_on_runtime(...)` must run on the owning runtime thread
- `*_start(...)` must run on the owning runtime thread
- `*_destroy(...)` must run on the owning runtime thread
- `*_request_stop(...)` is the cross-thread entry point

This keeps Zig-side orchestration simple and prevents ownership from being split across threads.

Allocator note:

- the allocator bridge stored in `forwarder_runtime_t` is treated as runtime-owned state
- backend code should assume allocations/frees happen under the runtime's lifecycle rules
- if the backend ever requires stronger allocator thread guarantees, that rule should be enforced inside the runtime boundary rather than leaked into Zig callers

## Ownership Rules

### Runtime owns

- backend runtime/executor state
- wake handle / dispatch mechanism
- allocator bridge storage

### Forwarder owns

- per-listener state
- per-session state
- stats state

### Caller owns

- the returned forwarder pointer lifetime
- the decision of when to call `*_destroy(...)` (can be called early; cleanup is deferred)

Important: `*_destroy(...)` must never tear down `forwarder_runtime_t`.

## Current ABI Status

`forwarder.h` is the **authoritative ABI contract**.

Both backends fully satisfy this contract:

- The libuv implementation (`impl_libuv/`) is the reference implementation.
- The Asio implementation (`impl_asio/`) implements the same contract using standalone Asio (not Boost).

Both backends are behind the same C ABI boundary — Zig only imports `forwarder.h`, never backend-specific headers.

## Backend Replaceability

This API is **backend neutral**:

- Zig does not import `uv.h` or any backend header
- runtime state is opaque (Zig only sees `forwarder_runtime_t *`)
- forwarders use semantic operations (`create`, `start`, `request_stop`, `destroy`, `get_stats`)

Design assumptions that are intentional, not limitations:

- exported names use a runtime/executor model — this reflects the architectural
  contract, not a specific backend
- the contract assumes a dedicated runtime thread and a wake mechanism — this
  keeps Zig-side orchestration simple and ownership clear

The ownership and lifecycle split is the core invariant:

- runtime owns execution
- forwarder owns listener state
- caller owns forwarder pointer lifetime

## Implementation Structure

| Directory | Backend | Status |
|-----------|---------|--------|
| `impl_libuv/` | libuv | Active implementation |
| `impl_asio/` | Asio (standalone C++) | Active implementation |

Both backends implement the same `forwarder.h` contract.
### Public ABI vs impl-internal helpers

The functions declared in `forwarder.h` are the public ABI. In addition,
each backend may expose its own impl-internal helpers that are NOT part of
the public contract:

- `forwarder_runtime_get_loop(forwarder_runtime_t *)` — libuv-only, returns
  `uv_loop_t *`. Used by TCP/UDP forwarders within `impl_libuv/` to access
  the backend event loop.
- `forwarder_runtime_get_allocator(forwarder_runtime_t *)` — returns the stored
  `forwarder_allocator_t`. Used by both backends to allocate through the
  runtime's allocator bridge.
- `forwarder_runtime_get_io_context(forwarder_runtime_t *)` — Asio-only, returns
  `asio::io_context &`. Used by TCP/UDP forwarders within `impl_asio/` to access
  the backend event loop.

These helpers are internal to `impl_libuv/` / `impl_asio/` and must not be
called from Zig or from any code outside the implementation directory.

## Stats Semantics

`*_get_stats(...)` should be treated as a read-only snapshot API.

- callers may read it without taking ownership of backend internals
- fields should be individually safe to observe
- multi-field reads are not guaranteed to represent one atomic transaction unless the backend explicitly provides that guarantee later

Currently `listen_port` remains part of `traffic_stats_t`, which makes the stats struct itself the query path for per-forwarder port identity.

## Build Matrix

The backend is selected at build time via `-Dforward_backend=<backend>`:

```bash
# Default (libuv)
zig build

# Asio backend (native)
zig build -Dforward_backend=asio

# Asio backend (Linux musl cross-compile)
zig build -Dforward_backend=asio -Dtarget=aarch64-linux-musl
zig build -Dforward_backend=asio -Dtarget=x86_64-linux-musl
```

| Target | libuv | Asio |
|--------|-------|------|
| native (Windows) | ✅ | ✅ |
| aarch64-linux-musl | ✅ | ✅ |
| x86_64-linux-musl | ✅ | ✅ |

## Backend-Dependent Utilities

`uv_get_version_string()` is retained as ABI compatibility but returns a backend-dependent value:

- **libuv backend**: returns the actual libuv version string (e.g., `"1.48.0"`)
- **Asio backend**: returns `"asio-standalone"` to indicate standalone Asio is in use

This allows code to detect which backend is active at runtime if needed, while maintaining ABI compatibility.
