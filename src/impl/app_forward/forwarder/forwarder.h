#ifndef FORWARDER_H
#define FORWARDER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    // Address family types
    typedef enum
    {
        ADDR_FAMILY_IPV4 = 0,
        ADDR_FAMILY_IPV6 = 1,
        ADDR_FAMILY_ANY = 2,
    } addr_family_t;

    // Error codes for forwarder operations
    typedef enum
    {
        FORWARDER_OK = 0,
        FORWARDER_ERROR_MALLOC = -1,
        FORWARDER_ERROR_BIND = -2,
        FORWARDER_ERROR_ADDRESS_IN_USE = -3,
        FORWARDER_ERROR_PERMISSION_DENIED = -4,
        FORWARDER_ERROR_INVALID_ADDRESS = -5,
        FORWARDER_ERROR_UNKNOWN = -99,
    } forwarder_error_t;

    // Forward declarations for opaque handles
    typedef struct tcp_forwarder tcp_forwarder_t;
    typedef struct udp_forwarder udp_forwarder_t;
    typedef struct forwarder_runtime forwarder_runtime_t;

    // Traffic statistics structure shared across Zig/C boundary.
    typedef struct
    {
        uint64_t bytes_in;
        uint64_t bytes_out;
        unsigned int active_sessions; /* active client sessions */
        uint16_t listen_port;         /* the listening port for this forwarder */
    } traffic_stats_t;

    // Allocator interface
    typedef void *(*forwarder_malloc_cb)(void *ctx, size_t size);
    typedef void (*forwarder_free_cb)(void *ctx, void *ptr);

    typedef struct
    {
        void *ctx;
        forwarder_malloc_cb malloc_cb;
        forwarder_free_cb free_cb;
    } forwarder_allocator_t;

    /*
     * Forwarder runtime contract
     * --------------------------
     *
     * Naming note:
     * - This API uses runtime-oriented naming on purpose: callers should treat
     *   `forwarder_runtime_t` as a runtime/executor boundary, not as a promise
     *   about any specific backend implementation detail.
     *
     * Ownership:
     * 1. `forwarder_runtime_t` owns all runtime-scoped state needed to drive
     *    forwarders: backend loop/executor state, stored allocator bridge, and
     *    the wake/dispatch callback binding.
     * 2. `tcp_forwarder_t` / `udp_forwarder_t` own only per-listener and
     *    per-session state that lives inside the enclosing runtime context.
     * 3. Returned forwarder pointers are owned by the caller. C never
     *    self-frees them; the caller must eventually call `_destroy(...)`.
     * 4. Destroying a forwarder must never close, free, or otherwise tear down
     *    the enclosing `forwarder_runtime_t`.
     *
     * Thread / ordering rules:
     * 5. `_create_on_runtime(...)`, `*_start(...)`, and `*_destroy(...)`
     *    are runtime-thread operations and must run on the thread that owns the
     *    enclosing `forwarder_runtime_t`.
     * 6. `*_request_stop(...)` is the cross-thread stop entry point: it may be invoked
     *    from outside the runtime thread only if the implementation routes the
     *    stop onto the owning runtime safely.
     * 7. `*_destroy(...)` initiates deferred cleanup: it sets an internal flag
     *    and posts cleanup work to the runtime thread. The actual memory release
     *    happens only after all pending async operations complete. Callers may
     *    invoke destroy before teardown has fully drained; the implementation
     *    handles ordering internally.
     * 8. `*_get_stats(...)` should behave as a read-only snapshot API and be
     *    safe to call without extra caller locking.
     *
     * Architectural intent:
     * 9. Forwarders are passive objects hosted by a runtime; they must not run,
     *    own, or finalize the backend executor themselves.
     * 10. The runtime boundary should stay narrow enough that a future backend
     *     swap (for example, away from libuv) can keep the Zig-facing contract
     *     largely intact, even if the internal implementation changes.
     */

    // TCP Forwarder API
    // target_address must be a numeric IPv4/IPv6 literal (no DNS resolution).
    // The runtime/backend state + allocator come from `runtime`.
    // Must be called on `runtime`'s owning runtime thread.
    // Returns a caller-owned forwarder pointer on success, NULL on failure.
    // This only creates/binds listener state; it does not run the runtime.
    // Error code written to out_error if provided.

    tcp_forwarder_t *tcp_forwarder_create_on_runtime(
        forwarder_runtime_t *runtime,
        uint16_t listen_port,
        const char *target_address,
        uint16_t target_port,
        addr_family_t family,
        int enable_stats,
        int *out_error);

    // Must be called on the owning runtime thread.
    // Starts accepting traffic for an already-created listener but does not run
    // the enclosing runtime.
    int tcp_forwarder_start(tcp_forwarder_t *forwarder);
    // Cross-thread stop request entry point. Stop may be asynchronous: returning
    // from this function does not imply close callbacks have finished.
    void tcp_forwarder_request_stop(tcp_forwarder_t *forwarder);
    // Initiates deferred cleanup: sets an internal flag and posts cleanup work to the
    // runtime thread. Memory is released only when all pending async operations complete.
    // Do not call destroy concurrently with start/stop/get_stats on the same object.
    void tcp_forwarder_destroy(tcp_forwarder_t *forwarder);
    // Returns a read-only stats snapshot.
    traffic_stats_t tcp_forwarder_get_stats(tcp_forwarder_t *forwarder);

    // UDP Forwarder API
    // target_address must be a numeric IPv4/IPv6 literal (no DNS resolution).
    // The runtime/backend state + allocator come from `runtime`.
    // Must be called on `runtime`'s owning runtime thread.
    // Returns a caller-owned forwarder pointer on success, NULL on failure.
    // This only creates/binds listener state; it does not run the runtime.
    // Error code written to out_error if provided.

    udp_forwarder_t *udp_forwarder_create_on_runtime(
        forwarder_runtime_t *runtime,
        uint16_t listen_port,
        const char *target_address,
        uint16_t target_port,
        addr_family_t family,
        int enable_stats,
        int *out_error);

    // Must be called on the owning runtime thread.
    // Starts accepting traffic for an already-created listener but does not run
    // the enclosing runtime.
    int udp_forwarder_start(udp_forwarder_t *forwarder);
    // Cross-thread stop request entry point. Stop may be asynchronous: returning
    // from this function does not imply close callbacks have finished.
    void udp_forwarder_request_stop(udp_forwarder_t *forwarder);
    // Initiates deferred cleanup: sets an internal flag and posts cleanup work to the
    // runtime thread. Memory is released only when all pending async operations complete.
    // Do not call destroy concurrently with start/stop/get_stats on the same object.
    void udp_forwarder_destroy(udp_forwarder_t *forwarder);
    // Returns a read-only stats snapshot.
    traffic_stats_t udp_forwarder_get_stats(udp_forwarder_t *forwarder);

    // Utility functions
    const char *uv_get_version_string(void);

    // --- Runtime Wrapper API ---
    // Zig runtime-management code uses this surface instead of including backend
    // headers directly. Ordinary application code should not depend on these
    // details. The intent is a backend-replaceable runtime boundary.

    // Runtime wake callback type: called on the owning runtime thread when the
    // context dispatches queued work.
    typedef void (*forwarder_runtime_wake_cb_t)(void *user_data);

    // Allocate a runtime context container on the heap.
    // Returns NULL on allocation failure.
    forwarder_runtime_t *forwarder_runtime_alloc(void);

    // Initialize the runtime context: creates runtime-scoped backend state, stores the
    // allocator bridge, and binds the wake callback/user_data pair.
    // `wake_cb` runs on the owning runtime thread when async_send wakes the context.
    // Returns 0 on success, backend-specific error code on failure.
    int forwarder_runtime_init(forwarder_runtime_t *runtime, forwarder_runtime_wake_cb_t wake_cb, void *user_data, forwarder_allocator_t allocator);

    // Run the backend event/runtime executor until it naturally stops.
    // Intended for the dedicated runtime thread.
    int forwarder_runtime_run(forwarder_runtime_t *runtime);

    // Wake the owning runtime (thread-safe).
    int forwarder_runtime_wake(forwarder_runtime_t *runtime);

    // Check whether the runtime-scoped wake handle is closing.
    int forwarder_runtime_is_wake_closing(forwarder_runtime_t *runtime);

    // Request closure of the runtime-scoped wake handle.
    // Safe to call if already closing.
    void forwarder_runtime_close_wake(forwarder_runtime_t *runtime);

    // Walk all runtime-owned backend handles and close any that are not already
    // closing. Intended for final runtime teardown after user-facing forwarders
    // have been asked to stop.
    void forwarder_runtime_close_owned_handles(forwarder_runtime_t *runtime);

    // Close the backend runtime itself after all handles/state have been fully drained.
    int forwarder_runtime_close(forwarder_runtime_t *runtime);

    // Free the runtime context container.
    // This does NOT close handles or the runtime first; callers must do teardown
    // in the correct order before calling free.
    void forwarder_runtime_free(forwarder_runtime_t *runtime);


#ifdef __cplusplus
}
#endif

#endif // FORWARDER_H
