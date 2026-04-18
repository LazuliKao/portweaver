#include "forwarder.h"
#include "uv.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <unistd.h>
#endif

#define DATA_ALLOC(fwd, sz) ((fwd)->allocator.malloc_cb((fwd)->allocator.ctx, (sz)))
#define DATA_FREE(fwd, ptr)                                        \
    do                                                             \
    {                                                              \
        if (ptr)                                                   \
        {                                                          \
            (fwd)->allocator.free_cb((fwd)->allocator.ctx, (ptr)); \
        }                                                          \
    } while (0)

struct tcp_forwarder
{
    forwarder_allocator_t allocator;
    uv_loop_t *loop;
    uv_tcp_t server;
    uv_async_t stop_handle;
    char *target_address;
    uint16_t target_port;
    addr_family_t family;
    int running;
    int started;
    int loop_finalized;
    struct sockaddr_storage cached_dest_addr; // added: cache destination addr
    int enable_stats;
    unsigned long long bytes_in;
    unsigned long long bytes_out;
    unsigned int active_sessions; /* active TCP client sessions */
    uint16_t listen_port;
};
// Full UDP forwarder definition (kept here so C code can access members)
struct udp_forwarder
{
    forwarder_allocator_t allocator;
    uv_loop_t *loop;
    uv_udp_t server;
    uv_async_t stop_handle;
    char *target_address;
    uint16_t target_port;
    addr_family_t family;
    int running;
    int started;
    int loop_finalized;
    udp_client_session_t *sessions;
    udp_client_session_t *session_hash[UDP_SESSION_HASH_SIZE];
    struct sockaddr_storage cached_dest_addr;
    int enable_stats;
    unsigned long long bytes_in;
    unsigned long long bytes_out;
    unsigned int active_sessions; /* active UDP client sessions */
    unsigned int max_sessions;    /* runtime cap derived from fd limit */
    uint16_t listen_port;
};

// --- TCP Forwarder Implementation ---
typedef struct tcp_conn_ctx
{
    uv_tcp_t client;
    uv_tcp_t target;
    uv_connect_t connect_req;
    uv_shutdown_t shutdown_req_client; // changed: separate shutdown reqs
    uv_shutdown_t shutdown_req_target;
    struct tcp_forwarder *forwarder;
    int closed;
    int close_count;
    int active_counted;
} tcp_conn_ctx_t;

// Forward declarations for C callbacks
static void tcp_on_client_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf);
static void tcp_on_target_read(uv_stream_t *target, ssize_t nread, const uv_buf_t *buf);
static void tcp_on_client_write(uv_write_t *req, int status);
static void tcp_on_target_write(uv_write_t *req, int status);
static void tcp_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void udp_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void tcp_conn_close_cb(uv_handle_t *handle);
static void udp_session_close_cb(uv_handle_t *handle);
static int sockaddr_equal(const struct sockaddr *a, const struct sockaddr *b);
static void tcp_terminate_connection(tcp_conn_ctx_t *ctx);
static void close_handle_walk_cb(uv_handle_t *handle, void *arg);
static void tcp_close_walk_cb(uv_handle_t *handle, void *arg);
static void udp_close_walk_cb(uv_handle_t *handle, void *arg);
static void set_forwarder_error(int *out_error, int error_code);
static void allocator_free_raw(forwarder_allocator_t allocator, void *ptr);
static int map_libuv_init_error(int status);
static int map_bind_error(int status);
static void destroy_create_state(forwarder_allocator_t allocator, uv_loop_t *loop, int loop_initialized, char *target_address, void *forwarder);
static int cache_destination_addr(struct sockaddr_storage *dest, addr_family_t family, const char *target_address, uint16_t target_port);
static void build_listen_addr(struct sockaddr_storage *addr, addr_family_t family, uint16_t listen_port);
static int finalize_forwarder_loop(uv_loop_t *loop, uv_walk_cb walk_cb, void *arg);

/* Wrapper for write/send requests that carry a pointer back to the forwarder
 * so we can free memory with the right allocator in the completion callbacks.
 */
typedef struct fwd_write_req
{
    uv_write_t req;
    struct tcp_forwarder *fwd;
    tcp_conn_ctx_t *ctx;
} fwd_write_req_t;

typedef struct fwd_udp_send_req
{
    uv_udp_send_t req;
    struct udp_forwarder *fwd;
} fwd_udp_send_req_t;

static void tcp_on_client_write(uv_write_t *req, int status)
{
    fwd_write_req_t *fw = (fwd_write_req_t *)req;
    struct tcp_forwarder *fwd = fw->fwd;
    if (status != 0)
    {
        fprintf(stderr, "[tcp_on_client_write] write error: %s\n", uv_strerror(status));
        if (fw->ctx)
            tcp_terminate_connection(fw->ctx);
    }
    if (req->data)
        DATA_FREE(fwd, req->data);
    DATA_FREE(fwd, fw);
}

static void tcp_on_target_write(uv_write_t *req, int status)
{
    fwd_write_req_t *fw = (fwd_write_req_t *)req;
    struct tcp_forwarder *fwd = fw->fwd;
    if (status != 0)
    {
        fprintf(stderr, "[tcp_on_target_write] write error: %s\n", uv_strerror(status));
        if (fw->ctx)
            tcp_terminate_connection(fw->ctx);
    }
    if (req->data)
        DATA_FREE(fwd, req->data);
    DATA_FREE(fwd, fw);
}

static void tcp_on_client_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf)
{
    tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)client->data;
    if (nread > 0)
    {
        if (uv_is_closing((uv_handle_t *)&ctx->target))
        {
            DATA_FREE(ctx->forwarder, buf->base);
            return;
        }
        // Stats: count bytes received from client (bytes_in)
        if (ctx->forwarder->enable_stats)
        {
            __atomic_fetch_add(&ctx->forwarder->bytes_in, (uint64_t)nread, __ATOMIC_RELAXED);
        }
        fwd_write_req_t *fw = (fwd_write_req_t *)DATA_ALLOC(ctx->forwarder, sizeof(fwd_write_req_t));
        if (!fw)
        {
            DATA_FREE(ctx->forwarder, buf->base);
            tcp_terminate_connection(ctx);
            return;
        }
        fw->fwd = ctx->forwarder;
        fw->ctx = ctx;
        uv_buf_t wbuf = uv_buf_init(buf->base, nread);
        fw->req.data = buf->base;
        int r = uv_write(&fw->req, (uv_stream_t *)&ctx->target, &wbuf, 1, tcp_on_client_write);
        if (r != 0)
        {
            fprintf(stderr, "[tcp_on_client_read] uv_write failed: %s\n", uv_strerror(r));
            if (fw->req.data)
                DATA_FREE(fw->fwd, fw->req.data);
            DATA_FREE(fw->fwd, fw);
            tcp_terminate_connection(ctx);
        }
        return;
    }
    if (buf->base)
        DATA_FREE(ctx->forwarder, buf->base);
    if (nread < 0)
    {
        if (nread == UV_EOF)
        {
            // Avoid half-close leaks: terminate both ends on EOF.
            tcp_terminate_connection(ctx);
            return;
        }
        tcp_terminate_connection(ctx);
    }
}

static void tcp_on_target_read(uv_stream_t *target, ssize_t nread, const uv_buf_t *buf)
{
    tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)target->data;
    if (nread > 0)
    {
        if (uv_is_closing((uv_handle_t *)&ctx->client))
        {
            DATA_FREE(ctx->forwarder, buf->base);
            return;
        }
        // Stats: count bytes received from target (bytes_out)
        if (ctx->forwarder->enable_stats)
        {
            __atomic_fetch_add(&ctx->forwarder->bytes_out, (uint64_t)nread, __ATOMIC_RELAXED);
        }
        fwd_write_req_t *fw = (fwd_write_req_t *)DATA_ALLOC(ctx->forwarder, sizeof(fwd_write_req_t));
        if (!fw)
        {
            DATA_FREE(ctx->forwarder, buf->base);
            tcp_terminate_connection(ctx);
            return;
        }
        fw->fwd = ctx->forwarder;
        fw->ctx = ctx;
        uv_buf_t wbuf = uv_buf_init(buf->base, nread);
        fw->req.data = buf->base;
        int r = uv_write(&fw->req, (uv_stream_t *)&ctx->client, &wbuf, 1, tcp_on_target_write);
        if (r != 0)
        {
            fprintf(stderr, "[tcp_on_target_read] uv_write failed: %s\n", uv_strerror(r));
            if (fw->req.data)
                DATA_FREE(fw->fwd, fw->req.data);
            DATA_FREE(fw->fwd, fw);
            tcp_terminate_connection(ctx);
        }
        return;
    }
    if (buf->base)
        DATA_FREE(ctx->forwarder, buf->base);
    if (nread < 0)
    {
        if (nread == UV_EOF)
        {
            // Avoid half-close leaks: terminate both ends on EOF.
            tcp_terminate_connection(ctx);
            return;
        }
        tcp_terminate_connection(ctx);
    }
}

static void close_handle_walk_cb(uv_handle_t *handle, void *arg)
{
    (void)arg;
    if (!handle || uv_is_closing(handle))
        return;
    uv_close(handle, NULL);
}

static void set_forwarder_error(int *out_error, int error_code)
{
    if (out_error)
        *out_error = error_code;
}

static void allocator_free_raw(forwarder_allocator_t allocator, void *ptr)
{
    if (ptr)
        allocator.free_cb(allocator.ctx, ptr);
}

static int map_libuv_init_error(int status)
{
    if (status == UV_ENOMEM)
        return FORWARDER_ERROR_MALLOC;
    return FORWARDER_ERROR_UNKNOWN;
}

static int map_bind_error(int status)
{
    if (status == UV_EADDRINUSE)
        return FORWARDER_ERROR_ADDRESS_IN_USE;
    if (status == UV_EACCES)
        return FORWARDER_ERROR_PERMISSION_DENIED;
    return FORWARDER_ERROR_BIND;
}

static void destroy_create_state(forwarder_allocator_t allocator, uv_loop_t *loop, int loop_initialized, char *target_address, void *forwarder)
{
    if (loop)
    {
        if (loop_initialized)
        {
            uv_walk(loop, close_handle_walk_cb, NULL);
            uv_run(loop, UV_RUN_DEFAULT);
            (void)uv_loop_close(loop);
        }
        allocator_free_raw(allocator, loop);
    }

    allocator_free_raw(allocator, target_address);
    allocator_free_raw(allocator, forwarder);
}

static int cache_destination_addr(struct sockaddr_storage *dest, addr_family_t family, const char *target_address, uint16_t target_port)
{
    if (family == ADDR_FAMILY_IPV6)
    {
        struct sockaddr_in6 addr6;
        int rc = uv_ip6_addr(target_address, target_port, &addr6);
        if (rc != 0)
            return rc;
        memcpy(dest, &addr6, sizeof(addr6));
        return 0;
    }

    {
        struct sockaddr_in addr4;
        int rc = uv_ip4_addr(target_address, target_port, &addr4);
        if (rc != 0)
            return rc;
        memcpy(dest, &addr4, sizeof(addr4));
        return 0;
    }
}

static void build_listen_addr(struct sockaddr_storage *addr, addr_family_t family, uint16_t listen_port)
{
    if (family == ADDR_FAMILY_IPV4)
    {
        struct sockaddr_in addr4;
        uv_ip4_addr("0.0.0.0", listen_port, &addr4);
        memcpy(addr, &addr4, sizeof(addr4));
        return;
    }

    {
        struct sockaddr_in6 addr6;
        uv_ip6_addr("::", listen_port, &addr6);
        memcpy(addr, &addr6, sizeof(addr6));
    }
}

static int finalize_forwarder_loop(uv_loop_t *loop, uv_walk_cb walk_cb, void *arg)
{
    int lr = uv_loop_close(loop);
    while (lr == UV_EBUSY)
    {
        uv_walk(loop, walk_cb, arg);
        uv_run(loop, UV_RUN_NOWAIT);
        lr = uv_loop_close(loop);
    }
    return lr;
}

static void tcp_close_walk_cb(uv_handle_t *handle, void *arg)
{
    struct tcp_forwarder *fwd = (struct tcp_forwarder *)arg;
    if (!handle || uv_is_closing(handle) || !fwd)
        return;

    if (handle == (uv_handle_t *)&fwd->server || handle == (uv_handle_t *)&fwd->stop_handle)
    {
        uv_close(handle, NULL);
        return;
    }

    if (handle->type == UV_TCP)
    {
        uv_read_stop((uv_stream_t *)handle);
        uv_close(handle, tcp_conn_close_cb);
        return;
    }

    uv_close(handle, NULL);
}

static void udp_close_walk_cb(uv_handle_t *handle, void *arg)
{
    udp_forwarder_t *fwd = (udp_forwarder_t *)arg;
    if (!handle || uv_is_closing(handle) || !fwd)
        return;

    if (handle == (uv_handle_t *)&fwd->server || handle == (uv_handle_t *)&fwd->stop_handle)
    {
        uv_close(handle, NULL);
        return;
    }

    if ((handle->type == UV_UDP || handle->type == UV_TIMER) && handle->data)
    {
        uv_close(handle, udp_session_close_cb);
        return;
    }

    uv_close(handle, NULL);
}

static void tcp_terminate_connection(tcp_conn_ctx_t *ctx)
{
    if (!ctx)
        return;

    uv_read_stop((uv_stream_t *)&ctx->client);
    uv_read_stop((uv_stream_t *)&ctx->target);

    if (!uv_is_closing((uv_handle_t *)&ctx->client))
        uv_close((uv_handle_t *)&ctx->client, tcp_conn_close_cb);
    if (!uv_is_closing((uv_handle_t *)&ctx->target))
        uv_close((uv_handle_t *)&ctx->target, tcp_conn_close_cb);
}

static void tcp_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    if (handle && handle->data)
    {
        tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)handle->data;
        if (ctx && ctx->forwarder)
        {
            buf->base = (char *)DATA_ALLOC(ctx->forwarder, suggested_size);
            buf->len = (unsigned int)suggested_size;
            return;
        }
    }
    buf->base = NULL;
    buf->len = 0;
}

// UDP buffer allocation callback (optimized for typical UDP packet size)
// #define UDP_BUFFER_SIZE 65536 // Max UDP datagram size
static void udp_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    if (handle && handle->data)
    {
        struct udp_forwarder *fwd = (struct udp_forwarder *)handle->data;
        buf->base = (char *)DATA_ALLOC(fwd, suggested_size);
        buf->len = suggested_size;
        return;
    }
    buf->base = NULL;
    buf->len = 0;
}

// Compare two sockaddr structures for equality (supports IPv4 and IPv6)
static int sockaddr_equal(const struct sockaddr *a, const struct sockaddr *b)
{
    if (!a || !b)
        return 0;
    if (a->sa_family != b->sa_family)
        return 0;
    if (a->sa_family == AF_INET)
    {
        const struct sockaddr_in *ai = (const struct sockaddr_in *)a;
        const struct sockaddr_in *bi = (const struct sockaddr_in *)b;
        return ai->sin_port == bi->sin_port && ai->sin_addr.s_addr == bi->sin_addr.s_addr;
    }
    else if (a->sa_family == AF_INET6)
    {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
        const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
        if (a6->sin6_port != b6->sin6_port)
            return 0;
        if (a6->sin6_scope_id != b6->sin6_scope_id)
            return 0;
        return memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr)) == 0;
    }
    return 0;
}

static void tcp_on_connect(uv_connect_t *req, int status)
{
    tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)req->data;
    if (status == 0)
    {
        int r1 = uv_read_start((uv_stream_t *)&ctx->client, tcp_alloc_cb, tcp_on_client_read);
        int r2 = uv_read_start((uv_stream_t *)&ctx->target, tcp_alloc_cb, tcp_on_target_read);
        if (r1 != 0 || r2 != 0)
        {
            fprintf(stderr, "[tcp_on_connect] uv_read_start failed: client=%d target=%d\n", r1, r2);
            if (r1 == 0)
                uv_read_stop((uv_stream_t *)&ctx->client);
            if (r2 == 0)
                uv_read_stop((uv_stream_t *)&ctx->target);
            tcp_terminate_connection(ctx);
        }
    }
    else
    {
        uv_close((uv_handle_t *)&ctx->client, tcp_conn_close_cb);
        uv_close((uv_handle_t *)&ctx->target, tcp_conn_close_cb);
    }
}

// Stop callbacks for thread-safe loop termination
static void tcp_stop_cb(uv_async_t *handle)
{
    struct tcp_forwarder *fwd = (struct tcp_forwarder *)handle->data;
    if (!fwd)
        return;

    uv_walk(fwd->loop, tcp_close_walk_cb, fwd);
    uv_stop(fwd->loop);
}

static void udp_stop_cb(uv_async_t *handle)
{
    udp_forwarder_t *fwd = (udp_forwarder_t *)handle->data;
    if (!fwd)
        return;

    uv_walk(fwd->loop, udp_close_walk_cb, fwd);
    uv_stop(fwd->loop);
}

static void tcp_on_new_connection(uv_stream_t *server, int status)
{
    if (status < 0)
        return;
    struct tcp_forwarder *fwd = (struct tcp_forwarder *)server->data;
    if (!fwd)
    {
        fprintf(stderr, "[tcp_on_new_connection] fwd is NULL!\n");
        return;
    }
    // Allocate per-connection context using forwarder's data allocator
    tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)DATA_ALLOC(fwd, sizeof(tcp_conn_ctx_t));
    if (!ctx)
    {
        fprintf(stderr, "[tcp_on_new_connection] allocation for ctx failed\n");
        return;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->forwarder = fwd;
    ctx->closed = 0;
    ctx->close_count = 0;
    ctx->active_counted = 0;

    int init_rc = uv_tcp_init(fwd->loop, &ctx->client);
    if (init_rc != 0)
    {
        fprintf(stderr, "[tcp_on_new_connection] uv_tcp_init(client) failed: %s\n", uv_strerror(init_rc));
        DATA_FREE(fwd, ctx);
        return;
    }
    ctx->client.data = ctx;

    init_rc = uv_tcp_init(fwd->loop, &ctx->target);
    if (init_rc != 0)
    {
        fprintf(stderr, "[tcp_on_new_connection] uv_tcp_init(target) failed: %s\n", uv_strerror(init_rc));
        ctx->close_count = 1; // target not initialized, only client close callback will fire
        uv_close((uv_handle_t *)&ctx->client, tcp_conn_close_cb);
        return;
    }
    ctx->target.data = ctx;
    if (uv_accept(server, (uv_stream_t *)&ctx->client) == 0)
    {
        __atomic_fetch_add(&fwd->active_sessions, 1u, __ATOMIC_RELAXED);
        ctx->active_counted = 1;
        ctx->connect_req.data = ctx;
        // Use cached target address (avoid per-connection uv_ip*_addr)
        int connect_rc = uv_tcp_connect(&ctx->connect_req, &ctx->target, (const struct sockaddr *)&fwd->cached_dest_addr, tcp_on_connect);
        if (connect_rc != 0)
        {
            uv_close((uv_handle_t *)&ctx->client, tcp_conn_close_cb);
            uv_close((uv_handle_t *)&ctx->target, tcp_conn_close_cb);
        }
    }
    else
    {
        uv_close((uv_handle_t *)&ctx->client, tcp_conn_close_cb);
        uv_close((uv_handle_t *)&ctx->target, tcp_conn_close_cb);
    }
}

tcp_forwarder_t *tcp_forwarder_create(
    uint16_t listen_port,
    const char *target_address,
    uint16_t target_port,
    addr_family_t family,
    int enable_stats,
    forwarder_allocator_t allocator,
    int *out_error)
{
    struct tcp_forwarder *fwd = NULL;
    int loop_initialized = 0;
    fwd = (struct tcp_forwarder *)allocator.malloc_cb(allocator.ctx, sizeof(struct tcp_forwarder));
    if (!fwd)
    {
        set_forwarder_error(out_error, FORWARDER_ERROR_MALLOC);
        return NULL;
    }
    memset(fwd, 0, sizeof(*fwd));
    fwd->allocator = allocator;

    fwd->loop = (uv_loop_t *)DATA_ALLOC(fwd, sizeof(uv_loop_t));
    if (!fwd->loop)
    {
        set_forwarder_error(out_error, FORWARDER_ERROR_MALLOC);
        DATA_FREE(fwd, fwd);
        return NULL;
    }

    int rc = uv_loop_init(fwd->loop);
    if (rc != 0)
    {
        set_forwarder_error(out_error, map_libuv_init_error(rc));
        destroy_create_state(allocator, fwd->loop, loop_initialized, NULL, fwd);
        return NULL;
    }
    loop_initialized = 1;

    rc = uv_tcp_init(fwd->loop, &fwd->server);
    if (rc != 0)
    {
        set_forwarder_error(out_error, map_libuv_init_error(rc));
        destroy_create_state(allocator, fwd->loop, loop_initialized, NULL, fwd);
        return NULL;
    }
    fwd->server.data = fwd;

    rc = uv_async_init(fwd->loop, &fwd->stop_handle, tcp_stop_cb);
    if (rc != 0)
    {
        set_forwarder_error(out_error, map_libuv_init_error(rc));
        destroy_create_state(allocator, fwd->loop, loop_initialized, NULL, fwd);
        return NULL;
    }
    fwd->stop_handle.data = fwd;

    size_t target_len = strlen(target_address);
    fwd->target_address = (char *)DATA_ALLOC(fwd, target_len + 1);
    if (!fwd->target_address)
    {
        set_forwarder_error(out_error, FORWARDER_ERROR_MALLOC);
        destroy_create_state(allocator, fwd->loop, loop_initialized, NULL, fwd);
        return NULL;
    }
    memcpy(fwd->target_address, target_address, target_len + 1);
    fwd->target_port = target_port;
    fwd->family = family;
    fwd->listen_port = listen_port;
    fwd->running = 0;
    fwd->started = 0;
    fwd->loop_finalized = 0;
    fwd->enable_stats = enable_stats;
    // Initialize atomic counters
    __atomic_store_n(&fwd->bytes_in, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&fwd->bytes_out, 0, __ATOMIC_RELAXED);
    // cache parsed destination sockaddr to avoid repeated parsing
    rc = cache_destination_addr(&fwd->cached_dest_addr, family, fwd->target_address, fwd->target_port);
    if (rc != 0)
    {
        set_forwarder_error(out_error, FORWARDER_ERROR_INVALID_ADDRESS);
        destroy_create_state(allocator, fwd->loop, loop_initialized, fwd->target_address, fwd);
        return NULL;
    }

    struct sockaddr_storage addr;
    build_listen_addr(&addr, family, listen_port);
    int bind_result = uv_tcp_bind(&fwd->server, (const struct sockaddr *)&addr, 0);
    if (bind_result != 0)
    {
        set_forwarder_error(out_error, map_bind_error(bind_result));
        destroy_create_state(allocator, fwd->loop, loop_initialized, fwd->target_address, fwd);
        return NULL;
    }

    set_forwarder_error(out_error, FORWARDER_OK);
    return fwd;
}

int tcp_forwarder_start(tcp_forwarder_t *forwarder)
{
    int r = uv_listen((uv_stream_t *)&forwarder->server, 128, tcp_on_new_connection);
    if (r != 0)
        return r;
    forwarder->started = 1;
    forwarder->running = 1;
    // fprintf(stderr, "[tcp_forwarder_start]  loop up\n");
    int res = uv_run(forwarder->loop, UV_RUN_DEFAULT);
    forwarder->running = 0;
    // fprintf(stderr, "[tcp_forwarder_start]  loop down %d %s\n", res, uv_strerror(res));
    int lr = finalize_forwarder_loop(forwarder->loop, tcp_close_walk_cb, forwarder);
    if (lr == 0)
        forwarder->loop_finalized = 1;
    if (res != 0 && res != 1)
        return res;
    return lr;
}

void tcp_forwarder_stop(tcp_forwarder_t *forwarder)
{
    if (!forwarder)
        return;
    if (forwarder->running)
    {
        // Thread-safe: send async signal to stop the loop from its own thread
        uv_async_send(&forwarder->stop_handle);
    }
}
void tcp_forwarder_destroy(tcp_forwarder_t *forwarder)
{
    if (!forwarder)
        return;
    if (forwarder->loop)
    {
        if (!forwarder->started)
        {
            forwarder->loop_finalized = 1;
        }
        DATA_FREE(forwarder, forwarder->loop);
        forwarder->loop = NULL;
    }
    DATA_FREE(forwarder, forwarder->target_address);
    forwarder->target_address = NULL;
    DATA_FREE(forwarder, forwarder);
}

traffic_stats_t tcp_forwarder_get_stats(tcp_forwarder_t *forwarder)
{
    traffic_stats_t stats = {0};
    if (forwarder && forwarder->enable_stats)
    {
        stats.bytes_in = __atomic_load_n(&forwarder->bytes_in, __ATOMIC_RELAXED);
        stats.bytes_out = __atomic_load_n(&forwarder->bytes_out, __ATOMIC_RELAXED);
    }
    if (forwarder)
    {
        stats.active_sessions = __atomic_load_n(&forwarder->active_sessions, __ATOMIC_RELAXED);
        stats.listen_port = forwarder->listen_port;
    }
    return stats;
}

// --- UDP Forwarder Implementation ---

// [Moved up] client session struct must be declared before udp_forwarder_t uses it
typedef struct udp_client_session
{
    uv_udp_t sock; // ephemeral socket bound for this client to talk to target
    struct sockaddr_storage client_addr;
    int client_addr_len;
    struct udp_forwarder *fwd;
    struct udp_client_session *list_next;
    struct udp_client_session *hash_next;
    uv_timer_t timeout_timer; // timer for session timeout
    uint64_t last_activity;   // timestamp of last activity (milliseconds)
    int close_count;          // count of closed handles (timer + sock = 2)
    int expected_close_count; // number of handles expected to close before free
    int tracked_in_forwarder; // whether session has been added to list/hash + active_sessions
} udp_client_session_t;

#ifdef DEBUG
// 5s
#define UDP_SESSION_TIMEOUT_MS 5000
#else
// Session timeout in milliseconds (1 minutes of inactivity)
#define UDP_SESSION_TIMEOUT_MS 60000
#endif // DEBUG

// Hard cap to prevent complete FD exhaustion under UDP floods/scans.
#define UDP_MAX_SESSIONS 4000

// Keep some file descriptors available for listener sockets, logs, and other runtime needs.
#define UDP_SESSION_FD_RESERVE 128

static unsigned int udp_compute_session_limit(void)
{
    unsigned int max_sessions = UDP_MAX_SESSIONS;

#if !defined(_WIN32)
    long fd_limit = sysconf(_SC_OPEN_MAX);
    if (fd_limit > 0)
    {
        long derived = fd_limit - UDP_SESSION_FD_RESERVE;
        if (derived < 1)
            derived = fd_limit / 2;
        if (derived < 1)
            derived = 1;
        if (derived < (long)max_sessions)
            max_sessions = (unsigned int)derived;
    }
#endif

    return max_sessions;
}

static void udp_session_close_cb(uv_handle_t *handle);
static void udp_session_timeout_cb(uv_timer_t *timer);

// Hash function for sockaddr (for fast session lookup)
static inline uint32_t sockaddr_hash(const struct sockaddr *addr)
{
    uint32_t hash = 5381;
    if (addr->sa_family == AF_INET)
    {
        const struct sockaddr_in *a4 = (const struct sockaddr_in *)addr;
        hash = ((hash << 5) + hash) ^ a4->sin_addr.s_addr;
        hash = ((hash << 5) + hash) ^ a4->sin_port;
    }
    else if (addr->sa_family == AF_INET6)
    {
        const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)addr;
        const unsigned char *bytes = (const unsigned char *)&a6->sin6_addr;
        for (int i = 0; i < 16; i++)
            hash = ((hash << 5) + hash) ^ bytes[i];
        hash = ((hash << 5) + hash) ^ a6->sin6_port;
        hash = ((hash << 5) + hash) ^ a6->sin6_scope_id;
    }
    return hash % UDP_SESSION_HASH_SIZE;
}

static void udp_on_send(uv_udp_send_t *req, int status)
{
    fwd_udp_send_req_t *fw = (fwd_udp_send_req_t *)req;
    struct udp_forwarder *fwd = fw->fwd;
    if (status != 0)
    {
        fprintf(stderr, "[udp_on_send] send error: %s\n", uv_strerror(status));
    }
    if (req->data)
        DATA_FREE(fwd, req->data);
    DATA_FREE(fwd, fw);
}

// Remove session from forwarder's session list and hash table
static void udp_session_remove(udp_forwarder_t *fwd, udp_client_session_t *session)
{
    // Remove from linked list
    udp_client_session_t **pp = &fwd->sessions;
    while (*pp)
    {
        if (*pp == session)
        {
            *pp = session->list_next;
            break;
        }
        pp = &(*pp)->list_next;
    }

    // Remove from hash table
    uint32_t hash = sockaddr_hash((const struct sockaddr *)&session->client_addr);
    pp = &fwd->session_hash[hash];
    while (*pp)
    {
        if (*pp == session)
        {
            *pp = session->hash_next;
            return;
        }
        pp = &(*pp)->hash_next;
    }
}

// Close callback for UDP session (called after each handle closes)
static void udp_session_close_cb(uv_handle_t *handle)
{
    if (!handle || !handle->data)
        return;
    udp_client_session_t *session = (udp_client_session_t *)handle->data;

    // Increment close count
    session->close_count++;

    // Only free when all expected handles are closed
    if (session->close_count >= session->expected_close_count)
    {
        // Remove from session list/hash + active counter only for registered sessions
        if (session->tracked_in_forwarder)
        {
            udp_session_remove((udp_forwarder_t *)session->fwd, session);
            __atomic_fetch_sub(&session->fwd->active_sessions, 1u, __ATOMIC_RELAXED);
        }
        DATA_FREE(session->fwd, session);
    }
}

// Timer callback to check and cleanup inactive sessions
static void udp_session_timeout_cb(uv_timer_t *timer)
{
    udp_client_session_t *session = (udp_client_session_t *)timer->data;
    if (!session)
        return;

    uint64_t now = uv_now(timer->loop);
    uint64_t elapsed = now - session->last_activity;

    if (elapsed >= UDP_SESSION_TIMEOUT_MS)
    {
        // fprintf(stderr, "[udp_session_timeout] closing inactive session (elapsed=%llu ms)\n", (unsigned long long)elapsed);

        // Stop receiving on the socket
        uv_udp_recv_stop(&session->sock);

        // Close both handles with the same callback
        if (!uv_is_closing((uv_handle_t *)&session->timeout_timer))
            uv_close((uv_handle_t *)&session->timeout_timer, udp_session_close_cb);

        if (!uv_is_closing((uv_handle_t *)&session->sock))
            uv_close((uv_handle_t *)&session->sock, udp_session_close_cb);
    }
    else
    {
        // Reschedule timer for remaining time
        uint64_t remaining = UDP_SESSION_TIMEOUT_MS - elapsed;
        uv_timer_start(&session->timeout_timer, udp_session_timeout_cb, remaining, 0);
    }
}

// per-connection close callback: free ctx when both ends are closed
static void tcp_conn_close_cb(uv_handle_t *handle)
{
    if (!handle)
        return;
    tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)handle->data;
    if (!ctx)
        return;
    ctx->close_count++;
    if (ctx->close_count >= 2)
    {
        // free connection context using forwarder's allocator
        if (ctx->active_counted)
            __atomic_fetch_sub(&ctx->forwarder->active_sessions, 1u, __ATOMIC_RELAXED);
        DATA_FREE(ctx->forwarder, ctx);
    }
}

static void udp_session_on_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                                const struct sockaddr *addr, unsigned flags)
{
    udp_client_session_t *session = (udp_client_session_t *)handle->data;

    if ((flags & UV_UDP_PARTIAL) != 0)
    {
        fprintf(stderr, "[udp_session_on_recv] dropping partial UDP datagram\n");
        if (buf->base)
            DATA_FREE(session->fwd, buf->base);
        return;
    }

    if (nread > 0)
    {
        // Stats: count bytes received from target (bytes_out)
        if (session->fwd->enable_stats)
        {
            __atomic_fetch_add(&session->fwd->bytes_out, (uint64_t)nread, __ATOMIC_RELAXED);
        }
        // Update activity timestamp
        session->last_activity = uv_now(handle->loop);

        // forward to original client via the server socket
        fwd_udp_send_req_t *fw = (fwd_udp_send_req_t *)DATA_ALLOC(session->fwd, sizeof(fwd_udp_send_req_t));
        if (!fw)
        {
            DATA_FREE(session->fwd, buf->base);
            return;
        }
        fw->fwd = session->fwd;
        // Zero-copy optimization: pass ownership of buf->base to send request
        uv_buf_t wbuf = uv_buf_init(buf->base, nread);
        fw->req.data = buf->base;
        if (uv_is_closing((uv_handle_t *)&session->fwd->server))
        {
            DATA_FREE(fw->fwd, fw->req.data);
            DATA_FREE(fw->fwd, fw);
            return;
        }
        int r = uv_udp_send(&fw->req, &session->fwd->server, &wbuf, 1, (const struct sockaddr *)&session->client_addr, udp_on_send);
        if (r != 0)
        {
            fprintf(stderr, "[udp_session_on_recv] uv_udp_send failed: %s\n", uv_strerror(r));
            if (fw->req.data)
                DATA_FREE(fw->fwd, fw->req.data);
            DATA_FREE(fw->fwd, fw);
        }
        return; // buf->base will be freed in udp_on_send callback
    }
    if (buf->base)
        DATA_FREE(session->fwd, buf->base);
}

// create a session (ephemeral socket) for a client address
static udp_client_session_t *udp_session_create(udp_forwarder_t *fwd, const struct sockaddr *client_addr, int addr_len)
{
    unsigned int session_limit = fwd->max_sessions > 0 ? fwd->max_sessions : UDP_MAX_SESSIONS;
    unsigned int active_sessions = __atomic_load_n(&fwd->active_sessions, __ATOMIC_RELAXED);
    if (active_sessions >= session_limit)
    {
        fprintf(stderr, "[udp_session_create] session limit reached (%u), dropping packet\n", session_limit);
        return NULL;
    }

    udp_client_session_t *s = (udp_client_session_t *)DATA_ALLOC((struct udp_forwarder *)fwd, sizeof(udp_client_session_t));
    if (!s)
        return NULL;
    memset(s, 0, sizeof(*s));

    s->fwd = (struct udp_forwarder *)fwd;
    s->client_addr_len = addr_len;
    s->close_count = 0;
    s->expected_close_count = 0;
    s->tracked_in_forwarder = 0;
    memcpy(&s->client_addr, client_addr, addr_len);

    int r = uv_udp_init(fwd->loop, &s->sock);
    if (r < 0)
    {
        if (r == UV_EMFILE || r == UV_ENFILE)
        {
            fprintf(stderr,
                    "[udp_session_create] uv_udp_init failed: %s (active_sessions=%u, session_limit=%u)\n",
                    uv_strerror(r),
                    active_sessions,
                    session_limit);
        }
        else
        {
            fprintf(stderr, "[udp_session_create] uv_udp_init failed: %s\n", uv_strerror(r));
        }
        DATA_FREE((struct udp_forwarder *)fwd, s);
        return NULL;
    }
    s->expected_close_count = 1;
    s->sock.data = s;

    // Initialize timeout timer
    r = uv_timer_init(fwd->loop, &s->timeout_timer);
    if (r < 0)
    {
        fprintf(stderr, "[udp_session_create] uv_timer_init failed: %s\n", uv_strerror(r));
        if (!uv_is_closing((uv_handle_t *)&s->sock))
            uv_close((uv_handle_t *)&s->sock, udp_session_close_cb);
        return NULL;
    }
    s->expected_close_count = 2;
    s->timeout_timer.data = s;
    s->last_activity = uv_now(fwd->loop);

    // Start timeout timer
    r = uv_timer_start(&s->timeout_timer, udp_session_timeout_cb, UDP_SESSION_TIMEOUT_MS, 0);
    if (r < 0)
    {
        fprintf(stderr, "[udp_session_create] uv_timer_start failed: %s\n", uv_strerror(r));
        if (!uv_is_closing((uv_handle_t *)&s->timeout_timer))
            uv_close((uv_handle_t *)&s->timeout_timer, udp_session_close_cb);
        if (!uv_is_closing((uv_handle_t *)&s->sock))
            uv_close((uv_handle_t *)&s->sock, udp_session_close_cb);
        return NULL;
    }

    // bind ephemeral port (0)
    if (fwd->family == ADDR_FAMILY_IPV6)
    {
        struct sockaddr_in6 bind6;
        uv_ip6_addr("::", 0, &bind6);
        r = uv_udp_bind(&s->sock, (const struct sockaddr *)&bind6, 0);
    }
    else
    {
        struct sockaddr_in bind4;
        uv_ip4_addr("0.0.0.0", 0, &bind4);
        r = uv_udp_bind(&s->sock, (const struct sockaddr *)&bind4, 0);
    }
    if (r < 0)
    {
        if (r == UV_EMFILE || r == UV_ENFILE)
        {
            unsigned int current_sessions = __atomic_load_n(&fwd->active_sessions, __ATOMIC_RELAXED);
            fprintf(stderr,
                    "[udp_session_create] uv_udp_bind failed: %s (active_sessions=%u, session_limit=%u)\n",
                    uv_strerror(r),
                    current_sessions,
                    session_limit);
        }
        else
        {
            fprintf(stderr, "[udp_session_create] uv_udp_bind failed: %s\n", uv_strerror(r));
        }
        if (!uv_is_closing((uv_handle_t *)&s->timeout_timer))
            uv_close((uv_handle_t *)&s->timeout_timer, udp_session_close_cb);
        if (!uv_is_closing((uv_handle_t *)&s->sock))
            uv_close((uv_handle_t *)&s->sock, udp_session_close_cb);
        return NULL;
    }

    r = uv_udp_recv_start(&s->sock, udp_alloc_cb, udp_session_on_recv);
    if (r < 0)
    {
        fprintf(stderr, "[udp_session_create] uv_udp_recv_start failed: %s\n", uv_strerror(r));
        if (!uv_is_closing((uv_handle_t *)&s->timeout_timer))
            uv_close((uv_handle_t *)&s->timeout_timer, udp_session_close_cb);
        if (!uv_is_closing((uv_handle_t *)&s->sock))
            uv_close((uv_handle_t *)&s->sock, udp_session_close_cb);
        return NULL;
    }

    // prepend to session list
    s->list_next = fwd->sessions;
    fwd->sessions = s;

    // Add to hash table for fast lookup
    uint32_t hash = sockaddr_hash((const struct sockaddr *)&s->client_addr);
    s->hash_next = fwd->session_hash[hash];
    fwd->session_hash[hash] = s;
    __atomic_fetch_add(&fwd->active_sessions, 1u, __ATOMIC_RELAXED);
    s->tracked_in_forwarder = 1;

    return s;
}

// find session by client addr (O(1) hash lookup)
static udp_client_session_t *udp_find_session(udp_forwarder_t *fwd, const struct sockaddr *client_addr)
{
    uint32_t hash = sockaddr_hash(client_addr);
    udp_client_session_t *it = fwd->session_hash[hash];
    while (it)
    {
        if (sockaddr_equal((const struct sockaddr *)&it->client_addr, client_addr) &&
            !uv_is_closing((uv_handle_t *)&it->sock))
            return it;
        it = it->hash_next;
    }
    return NULL;
}

static void udp_on_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                        const struct sockaddr *addr, unsigned flags)
{
    udp_forwarder_t *fwd = (udp_forwarder_t *)handle->data;

    if ((flags & UV_UDP_PARTIAL) != 0)
    {
        fprintf(stderr, "[udp_on_recv] dropping partial UDP datagram\n");
        if (buf->base)
            DATA_FREE((struct udp_forwarder *)fwd, buf->base);
        return;
    }

    if (nread > 0 && addr)
    {
        // Stats: count bytes received from client (bytes_in)
        if (fwd->enable_stats)
        {
            __atomic_fetch_add(&fwd->bytes_in, (uint64_t)nread, __ATOMIC_RELAXED);
        }
        // create/find session for this client and send to cached target using per-client socket
        udp_client_session_t *session = udp_find_session(fwd, addr);
        if (!session)
        {
            session = udp_session_create(fwd, addr, (addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
            if (!session)
            {
                DATA_FREE((struct udp_forwarder *)fwd, buf->base);
                return;
            }
        }
        else
        {
            // Update activity timestamp for existing session
            session->last_activity = uv_now(fwd->loop);
        }

        fwd_udp_send_req_t *fw = (fwd_udp_send_req_t *)DATA_ALLOC((struct udp_forwarder *)fwd, sizeof(fwd_udp_send_req_t));
        if (!fw)
        {
            DATA_FREE((struct udp_forwarder *)fwd, buf->base);
            return;
        }
        fw->fwd = (struct udp_forwarder *)fwd;
        // Zero-copy optimization: pass ownership of buf->base to send request
        uv_buf_t wbuf = uv_buf_init(buf->base, nread);
        fw->req.data = buf->base;
        if (uv_is_closing((uv_handle_t *)&session->sock))
        {
            DATA_FREE(fw->fwd, fw->req.data);
            DATA_FREE(fw->fwd, fw);
            return;
        }
        // send from session socket to cached target addr
        int r = uv_udp_send(&fw->req, &session->sock, &wbuf, 1, (const struct sockaddr *)&fwd->cached_dest_addr, udp_on_send);
        if (r != 0)
        {
            fprintf(stderr, "[udp_on_recv] uv_udp_send failed: %s\n", uv_strerror(r));
            if (fw->req.data)
                DATA_FREE(fw->fwd, fw->req.data);
            DATA_FREE(fw->fwd, fw);
        }
        return; // buf->base will be freed in udp_on_send callback
    }
    if (buf->base)
        DATA_FREE((struct udp_forwarder *)fwd, buf->base);
}

// Expose an implementation alias used by the C file
udp_forwarder_t *udp_forwarder_create(
    uint16_t listen_port,
    const char *target_address,
    uint16_t target_port,
    addr_family_t family,
    int enable_stats,
    forwarder_allocator_t allocator,
    int *out_error)
{
    udp_forwarder_t *fwd = NULL;
    int loop_initialized = 0;

    fwd = (udp_forwarder_t *)allocator.malloc_cb(allocator.ctx, sizeof(udp_forwarder_t));
    if (!fwd)
    {
        set_forwarder_error(out_error, FORWARDER_ERROR_MALLOC);
        return NULL;
    }
    memset(fwd, 0, sizeof(*fwd));
    fwd->allocator = allocator;

    fwd->loop = (uv_loop_t *)DATA_ALLOC(fwd, sizeof(uv_loop_t));
    if (!fwd->loop)
    {
        set_forwarder_error(out_error, FORWARDER_ERROR_MALLOC);
        DATA_FREE(fwd, fwd);
        return NULL;
    }

    int rc = uv_loop_init(fwd->loop);
    if (rc != 0)
    {
        set_forwarder_error(out_error, map_libuv_init_error(rc));
        destroy_create_state(allocator, fwd->loop, loop_initialized, NULL, fwd);
        return NULL;
    }
    loop_initialized = 1;

    rc = uv_udp_init(fwd->loop, &fwd->server);
    if (rc != 0)
    {
        set_forwarder_error(out_error, map_libuv_init_error(rc));
        destroy_create_state(allocator, fwd->loop, loop_initialized, NULL, fwd);
        return NULL;
    }
    fwd->server.data = fwd;

    // Initialize async stop handle for thread-safe stopping
    rc = uv_async_init(fwd->loop, &fwd->stop_handle, udp_stop_cb);
    if (rc != 0)
    {
        set_forwarder_error(out_error, map_libuv_init_error(rc));
        destroy_create_state(allocator, fwd->loop, loop_initialized, NULL, fwd);
        return NULL;
    }
    fwd->stop_handle.data = fwd;

    size_t target_len = strlen(target_address);
    fwd->target_address = (char *)DATA_ALLOC(fwd, target_len + 1);
    if (!fwd->target_address)
    {
        set_forwarder_error(out_error, FORWARDER_ERROR_MALLOC);
        destroy_create_state(allocator, fwd->loop, loop_initialized, NULL, fwd);
        return NULL;
    }
    memcpy(fwd->target_address, target_address, target_len + 1);
    fwd->target_port = target_port;
    fwd->family = family;
    fwd->listen_port = listen_port;
    fwd->running = 0;
    fwd->started = 0;
    fwd->loop_finalized = 0;
    fwd->sessions = NULL;
    fwd->enable_stats = enable_stats;
    // Initialize atomic counters
    __atomic_store_n(&fwd->bytes_in, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&fwd->bytes_out, 0, __ATOMIC_RELAXED);
    fwd->max_sessions = udp_compute_session_limit();
    memset(fwd->session_hash, 0, sizeof(fwd->session_hash));
    // cache target addr
    rc = cache_destination_addr(&fwd->cached_dest_addr, family, fwd->target_address, fwd->target_port);
    if (rc != 0)
    {
        set_forwarder_error(out_error, FORWARDER_ERROR_INVALID_ADDRESS);
        destroy_create_state(allocator, fwd->loop, loop_initialized, fwd->target_address, fwd);
        return NULL;
    }

    struct sockaddr_storage addr;
    build_listen_addr(&addr, family, listen_port);
    int bind_result = uv_udp_bind(&fwd->server, (const struct sockaddr *)&addr, 0);
    if (bind_result != 0)
    {
        set_forwarder_error(out_error, map_bind_error(bind_result));
        destroy_create_state(allocator, fwd->loop, loop_initialized, fwd->target_address, fwd);
        return NULL;
    }

    set_forwarder_error(out_error, FORWARDER_OK);
    return (udp_forwarder_t *)fwd;
}

int udp_forwarder_start(udp_forwarder_t *forwarder)
{
    udp_forwarder_t *fwd = (udp_forwarder_t *)forwarder;
    if (!fwd)
        return UV_EINVAL;
    int r = uv_udp_recv_start(&fwd->server, udp_alloc_cb, udp_on_recv);
    if (r != 0)
        return r;
    fwd->started = 1;
    fwd->running = 1;
    int res = uv_run(fwd->loop, UV_RUN_DEFAULT);
    uv_udp_recv_stop(&fwd->server);
    fwd->running = 0;
    forwarder->running = 0;
    int lr = finalize_forwarder_loop(forwarder->loop, udp_close_walk_cb, forwarder);
    if (lr == 0)
        forwarder->loop_finalized = 1;
    if (res != 0 && res != 1)
        return res;
    return lr;
}

void udp_forwarder_stop(udp_forwarder_t *forwarder)
{
    if (!forwarder)
        return;
    if (forwarder->running)
    {
        // Thread-safe: send async signal to stop the loop from its own thread
        uv_async_send(&forwarder->stop_handle);
    }
}
void udp_forwarder_destroy(udp_forwarder_t *forwarder)
{
    if (!forwarder)
        return;
    if (forwarder->loop)
    {
        if (!forwarder->started)
        {
            forwarder->loop_finalized = 1;
        }
        DATA_FREE(forwarder, forwarder->loop);
        forwarder->loop = NULL;
    }
    DATA_FREE(forwarder, forwarder->target_address);
    forwarder->target_address = NULL;
    DATA_FREE(forwarder, forwarder);
}

traffic_stats_t udp_forwarder_get_stats(udp_forwarder_t *forwarder)
{
    traffic_stats_t stats = {0};
    udp_forwarder_t *fwd = (udp_forwarder_t *)forwarder;
    if (fwd && fwd->enable_stats)
    {
        stats.bytes_in = __atomic_load_n(&fwd->bytes_in, __ATOMIC_RELAXED);
        stats.bytes_out = __atomic_load_n(&fwd->bytes_out, __ATOMIC_RELAXED);
    }
    if (fwd)
    {
        stats.active_sessions = __atomic_load_n(&fwd->active_sessions, __ATOMIC_RELAXED);
        stats.listen_port = fwd->listen_port;
    }
    return stats;
}

// --- Utility ---
const char *uv_get_version_string(void)
{
    return uv_version_string();
}
