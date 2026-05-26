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
7. only after teardown has fully drained, call `*_destroy(...)`

Rule: **request_stop is a shutdown request; destroy is final memory release**.

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
- the decision of when stop has fully drained and destroy is allowed

Important: `*_destroy(...)` must never tear down `forwarder_runtime_t`.

## Current ABI Status

`forwarder.h` is the **target ABI contract** for the refactor.

At the moment, the reverted legacy `forwarder.c` still implements an older self-owned-loop model. That means the header is intentionally ahead of the current C implementation.

So during this phase:

- `forwarder.h` describes the architecture we are moving to
- Zig is being aligned to that contract
- C implementation will later be rewritten to satisfy that contract

## Backend Replaceability

This API is already much better than exposing raw libuv types to Zig, but it is best viewed as:

- **backend hidden**
- not yet fully **backend neutral**

What helps replaceability today:

- Zig does not import `uv.h`
- runtime state is opaque
- forwarders use semantic operations (`create`, `start`, `request_stop`, `destroy`, `get_stats`)

What still reflects current backend assumptions:

- exported names still assume a runtime/executor model
- the contract assumes a dedicated runtime thread and a wake mechanism
- `uv_get_version_string()` is still a backend-specific utility leak

That is acceptable for now. The important part is to preserve the ownership and lifecycle split:

- runtime owns execution
- forwarder owns listener state
- caller owns forwarder pointer lifetime

## Stats Semantics

`*_get_stats(...)` should be treated as a read-only snapshot API.

- callers may read it without taking ownership of backend internals
- fields should be individually safe to observe
- multi-field reads are not guaranteed to represent one atomic transaction unless the backend explicitly provides that guarantee later

Currently `listen_port` remains part of `traffic_stats_t`, which makes the stats struct itself the query path for per-forwarder port identity.
