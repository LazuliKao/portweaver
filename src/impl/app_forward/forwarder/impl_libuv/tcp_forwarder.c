#include "forwarder.h"
#include "uv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <unistd.h>
#endif

extern uv_loop_t *forwarder_runtime_get_loop(forwarder_runtime_t *runtime);
extern forwarder_allocator_t forwarder_runtime_get_allocator(forwarder_runtime_t *runtime);

#define DATA_ALLOC(fwd, sz) (forwarder_runtime_get_allocator((fwd)->runtime).malloc_cb(forwarder_runtime_get_allocator((fwd)->runtime).ctx, (sz)))
#define DATA_FREE(fwd, ptr)                                                                                                      \
    do                                                                                                                           \
    {                                                                                                                            \
        if (ptr)                                                                                                                 \
        {                                                                                                                        \
            forwarder_runtime_get_allocator((fwd)->runtime).free_cb(forwarder_runtime_get_allocator((fwd)->runtime).ctx, (ptr)); \
        }                                                                                                                        \
    } while (0)

struct tcp_forwarder
{
    forwarder_runtime_t *runtime;
    uv_tcp_t server;
    uv_async_t stop_handle;
    char *target_address;
    uint16_t target_port;
    addr_family_t family;
    int started;
    int stop_requested;
    struct sockaddr_storage cached_dest_addr;
    int enable_stats;
    uint32_t connect_timeout_ms;
    unsigned long long bytes_in;
    unsigned long long bytes_out;
    unsigned int active_sessions;
    uint16_t listen_port;
    int destroy_requested;
    int closed_handles;
    int expected_closed_handles;
};

typedef struct tcp_conn_ctx
{
    uv_tcp_t client;
    uv_tcp_t target;
    uv_connect_t connect_req;
    uv_shutdown_t client_shutdown_req;
    uv_shutdown_t target_shutdown_req;
    struct tcp_forwarder *forwarder;
    int closed;
    int close_count;
    int expected_close_count;
    int active_counted;
    int client_eof;
    int target_eof;
    int client_shutdown_started;
    int target_shutdown_started;
    int client_shutdown_pending;
    int target_shutdown_pending;
    uv_timer_t connect_timer;
    int connect_timer_initialized;
} tcp_conn_ctx_t;

typedef struct fwd_write_req
{
    uv_write_t req;
    struct tcp_forwarder *fwd;
    tcp_conn_ctx_t *ctx;
} fwd_write_req_t;

static void tcp_terminate_connection(tcp_conn_ctx_t *ctx);
static void tcp_conn_close_cb(uv_handle_t *handle);
static void tcp_connect_timeout_cb(uv_timer_t *timer);
static void tcp_connect_timer_close_cb(uv_handle_t *handle);

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

static void tcp_maybe_finish_connection(tcp_conn_ctx_t *ctx)
{
    if (!ctx || ctx->closed)
        return;

    if (ctx->client_eof && ctx->target_eof &&
        !ctx->client_shutdown_pending && !ctx->target_shutdown_pending)
    {
        tcp_terminate_connection(ctx);
    }
}

static void tcp_on_shutdown(uv_shutdown_t *req, int status)
{
    tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)req->data;
    if (!ctx)
        return;

    if (req == &ctx->client_shutdown_req)
        ctx->client_shutdown_pending = 0;
    else if (req == &ctx->target_shutdown_req)
        ctx->target_shutdown_pending = 0;

    if (status != 0 && status != UV_ENOTCONN && status != UV_EPIPE && status != UV_ECANCELED)
    {
        fprintf(stderr, "[tcp_on_shutdown] shutdown error: %s\n", uv_strerror(status));
        tcp_terminate_connection(ctx);
        return;
    }

    tcp_maybe_finish_connection(ctx);
}

static void tcp_shutdown_peer_write(tcp_conn_ctx_t *ctx, uv_stream_t *stream, uv_shutdown_t *req, int *started, int *pending, const char *label)
{
    if (!ctx || !stream || !req || !started || !pending)
        return;

    if (*started || uv_is_closing((uv_handle_t *)stream))
    {
        tcp_maybe_finish_connection(ctx);
        return;
    }

    *started = 1;
    *pending = 1;
    req->data = ctx;

    int r = uv_shutdown(req, stream, tcp_on_shutdown);
    if (r != 0)
    {
        *pending = 0;
        if (r != UV_ENOTCONN && r != UV_EPIPE)
        {
            fprintf(stderr, "[%s] uv_shutdown failed: %s\n", label, uv_strerror(r));
            tcp_terminate_connection(ctx);
            return;
        }

        tcp_maybe_finish_connection(ctx);
    }
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
        uv_buf_t wbuf = uv_buf_init(buf->base, (unsigned int)nread);
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
            ctx->client_eof = 1;
            uv_read_stop(client);
            tcp_shutdown_peer_write(ctx,
                                    (uv_stream_t *)&ctx->target,
                                    &ctx->target_shutdown_req,
                                    &ctx->target_shutdown_started,
                                    &ctx->target_shutdown_pending,
                                    "tcp_on_client_read");
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
        uv_buf_t wbuf = uv_buf_init(buf->base, (unsigned int)nread);
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
            ctx->target_eof = 1;
            uv_read_stop(target);
            tcp_shutdown_peer_write(ctx,
                                    (uv_stream_t *)&ctx->client,
                                    &ctx->client_shutdown_req,
                                    &ctx->client_shutdown_started,
                                    &ctx->client_shutdown_pending,
                                    "tcp_on_target_read");
            return;
        }
        tcp_terminate_connection(ctx);
    }
}

static void tcp_conn_close_cb(uv_handle_t *handle)
{
    if (!handle)
        return;
    tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)handle->data;
    if (!ctx)
        return;
    ctx->close_count++;
    if (ctx->close_count >= ctx->expected_close_count)
    {
        if (ctx->active_counted)
            __atomic_fetch_sub(&ctx->forwarder->active_sessions, 1u, __ATOMIC_RELAXED);
        DATA_FREE(ctx->forwarder, ctx);
    }
}

static void tcp_terminate_connection(tcp_conn_ctx_t *ctx)
{
    if (!ctx || ctx->closed)
        return;

    ctx->closed = 1;

    int close_count = 0;
    uv_read_stop((uv_stream_t *)&ctx->client);
    uv_read_stop((uv_stream_t *)&ctx->target);

    if (ctx->connect_timer_initialized && !uv_is_closing((uv_handle_t *)&ctx->connect_timer))
    {
        uv_timer_stop(&ctx->connect_timer);
        uv_close((uv_handle_t *)&ctx->connect_timer, tcp_connect_timer_close_cb);
    }

    if (!uv_is_closing((uv_handle_t *)&ctx->client))
    {
        uv_close((uv_handle_t *)&ctx->client, tcp_conn_close_cb);
        close_count++;
    }
    if (!uv_is_closing((uv_handle_t *)&ctx->target))
    {
        uv_close((uv_handle_t *)&ctx->target, tcp_conn_close_cb);
        close_count++;
    }

    if (close_count > 0)
    {
        int expected_close_count = ctx->close_count + close_count;
        if (ctx->expected_close_count < expected_close_count)
            ctx->expected_close_count = expected_close_count;
    }
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

static void tcp_connect_timer_close_cb(uv_handle_t *handle)
{
    (void)handle;
}

static void tcp_connect_timeout_cb(uv_timer_t *timer)
{
    tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)timer->data;
    if (!ctx || ctx->closed)
        return;
    uv_cancel((uv_req_t *)&ctx->connect_req);
}


static void tcp_on_connect(uv_connect_t *req, int status)
{
    tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)req->data;
    if (ctx->connect_timer_initialized && !uv_is_closing((uv_handle_t *)&ctx->connect_timer))
    {
        uv_timer_stop(&ctx->connect_timer);
        uv_close((uv_handle_t *)&ctx->connect_timer, tcp_connect_timer_close_cb);
    }
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
        tcp_terminate_connection(ctx);
    }
}

static void tcp_on_new_connection(uv_stream_t *server, int status)
{
    if (status < 0)
        return;
    struct tcp_forwarder *fwd = (struct tcp_forwarder *)server->data;
    if (!fwd)
        return;

    tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)DATA_ALLOC(fwd, sizeof(tcp_conn_ctx_t));
    if (!ctx)
        return;
    
    memset(ctx, 0, sizeof(*ctx));
    ctx->forwarder = fwd;
    ctx->closed = 0;
    ctx->close_count = 0;
    ctx->expected_close_count = 0;
    ctx->active_counted = 0;

    uv_loop_t *loop = forwarder_runtime_get_loop(fwd->runtime);
    int init_rc = uv_tcp_init(loop, &ctx->client);
    if (init_rc != 0)
    {
        fprintf(stderr, "[tcp_on_new_connection] uv_tcp_init(client) failed: %s\n", uv_strerror(init_rc));
        DATA_FREE(fwd, ctx);
        return;
    }
    ctx->client.data = ctx;

    init_rc = uv_tcp_init(loop, &ctx->target);
    if (init_rc != 0)
    {
        fprintf(stderr, "[tcp_on_new_connection] uv_tcp_init(target) failed: %s\n", uv_strerror(init_rc));
        ctx->expected_close_count = 1;
        uv_close((uv_handle_t *)&ctx->client, tcp_conn_close_cb);
        return;
    }
    ctx->target.data = ctx;
    
    if (uv_accept(server, (uv_stream_t *)&ctx->client) == 0)
    {
        __atomic_fetch_add(&fwd->active_sessions, 1u, __ATOMIC_RELAXED);
        ctx->active_counted = 1;
        ctx->connect_req.data = ctx;
        int connect_rc = uv_tcp_connect(&ctx->connect_req, &ctx->target, (const struct sockaddr *)&fwd->cached_dest_addr, tcp_on_connect);
        if (connect_rc != 0)
        {
            ctx->expected_close_count = 2;
            uv_close((uv_handle_t *)&ctx->client, tcp_conn_close_cb);
            uv_close((uv_handle_t *)&ctx->target, tcp_conn_close_cb);
        }
        if (connect_rc == 0 && fwd->connect_timeout_ms > 0)
        {
            uv_timer_init(loop, &ctx->connect_timer);
            ctx->connect_timer.data = ctx;
            ctx->connect_timer_initialized = 1;
            uv_timer_start(&ctx->connect_timer, tcp_connect_timeout_cb, fwd->connect_timeout_ms, 0);
        }
    }
    else
    {
        ctx->expected_close_count = 2;
        uv_close((uv_handle_t *)&ctx->client, tcp_conn_close_cb);
        uv_close((uv_handle_t *)&ctx->target, tcp_conn_close_cb);
    }
}

static void tcp_forwarder_close_cb(uv_handle_t *handle)
{
    struct tcp_forwarder *fwd = (struct tcp_forwarder *)handle->data;
    if (!fwd)
        return;
    fwd->closed_handles++;
    if (fwd->closed_handles >= fwd->expected_closed_handles)
    {
        if (fwd->destroy_requested)
        {
            DATA_FREE(fwd, fwd->target_address);
            DATA_FREE(fwd, fwd);
        }
    }
}

static void tcp_close_walk_cb(uv_handle_t *handle, void *arg)
{
    struct tcp_forwarder *fwd = (struct tcp_forwarder *)arg;
    if (!handle || uv_is_closing(handle) || !fwd)
        return;

    if (handle == (uv_handle_t *)&fwd->server || handle == (uv_handle_t *)&fwd->stop_handle)
    {
        uv_close(handle, tcp_forwarder_close_cb);
        return;
    }

    if (handle->type == UV_TCP)
    {
        tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)handle->data;
        if (ctx && ctx->forwarder == fwd)
        {
            uv_handle_t *client_handle = (uv_handle_t *)&ctx->client;
            uv_handle_t *target_handle = (uv_handle_t *)&ctx->target;
            int close_target = !uv_is_closing(target_handle);
            int close_client = !uv_is_closing(client_handle);

            if (close_client || close_target)
            {
                int expected_close_count = ctx->close_count;
                if (close_client)
                    expected_close_count++;
                if (close_target)
                    expected_close_count++;
                if (ctx->expected_close_count < expected_close_count)
                    ctx->expected_close_count = expected_close_count;

                if (close_client)
                {
                    uv_read_stop((uv_stream_t *)client_handle);
                    uv_close(client_handle, tcp_conn_close_cb);
                }
                if (close_target)
                {
                    uv_read_stop((uv_stream_t *)target_handle);
                    uv_close(target_handle, tcp_conn_close_cb);
                }
            }
            return;
        }
    }

    if (handle->type == UV_TIMER)
    {
        tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)handle->data;
        if (ctx && ctx->forwarder == fwd && ctx->connect_timer_initialized && !uv_is_closing(handle))
        {
            uv_timer_stop(&ctx->connect_timer);
            uv_close(handle, tcp_connect_timer_close_cb);
        }
        return;
    }
}

static void tcp_stop_cb(uv_async_t *handle)
{
    struct tcp_forwarder *fwd = (struct tcp_forwarder *)handle->data;
    if (!fwd)
        return;

    uv_loop_t *loop = forwarder_runtime_get_loop(fwd->runtime);
    if (loop)
    {
        uv_walk(loop, tcp_close_walk_cb, fwd);
    }
}

static void set_forwarder_error(int *out_error, int error_code)
{
    if (out_error)
        *out_error = error_code;
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

static void fwd_error_close_cb(uv_handle_t *handle)
{
    struct tcp_forwarder *fwd = (struct tcp_forwarder *)handle->data;
    if (!fwd) return;
    fwd->stop_requested++; 
    if (fwd->stop_requested == 2)
    {
        DATA_FREE(fwd, fwd->target_address);
        DATA_FREE(fwd, fwd);
    }
}

tcp_forwarder_t *tcp_forwarder_create_on_runtime(
    forwarder_runtime_t *runtime,
    uint16_t listen_port,
    const char *target_address,
    uint16_t target_port,
    addr_family_t family,
    int enable_stats,
    uint32_t connect_timeout_ms,
    int *out_error)
{
    if (!runtime)
    {
        set_forwarder_error(out_error, FORWARDER_ERROR_UNKNOWN);
        return NULL;
    }

    forwarder_allocator_t allocator = forwarder_runtime_get_allocator(runtime);
    struct tcp_forwarder *fwd = (struct tcp_forwarder *)allocator.malloc_cb(allocator.ctx, sizeof(struct tcp_forwarder));
    if (!fwd)
    {
        set_forwarder_error(out_error, FORWARDER_ERROR_MALLOC);
        return NULL;
    }
    memset(fwd, 0, sizeof(*fwd));
    fwd->runtime = runtime;
    uv_loop_t *loop = forwarder_runtime_get_loop(runtime);

    int rc = uv_tcp_init(loop, &fwd->server);
    if (rc != 0)
    {
        set_forwarder_error(out_error, map_libuv_init_error(rc));
        DATA_FREE(fwd, fwd);
        return NULL;
    }
    fwd->server.data = fwd;

    rc = uv_async_init(loop, &fwd->stop_handle, tcp_stop_cb);
    if (rc != 0)
    {
        set_forwarder_error(out_error, map_libuv_init_error(rc));
        fwd->stop_requested = 1; // only server needs closing
        uv_close((uv_handle_t*)&fwd->server, fwd_error_close_cb);
        return NULL;
    }
    fwd->stop_handle.data = fwd;

    size_t target_len = strlen(target_address);
    fwd->target_address = (char *)DATA_ALLOC(fwd, target_len + 1);
    if (!fwd->target_address)
    {
        set_forwarder_error(out_error, FORWARDER_ERROR_MALLOC);
        fwd->stop_requested = 0;
        uv_close((uv_handle_t*)&fwd->server, fwd_error_close_cb);
        uv_close((uv_handle_t*)&fwd->stop_handle, fwd_error_close_cb);
        return NULL;
    }
    memcpy(fwd->target_address, target_address, target_len + 1);
    
    fwd->target_port = target_port;
    fwd->family = family;
    fwd->listen_port = listen_port;
    fwd->started = 0;
    fwd->stop_requested = 0;
    fwd->destroy_requested = 0;
    fwd->closed_handles = 0;
    fwd->expected_closed_handles = 2;
    fwd->enable_stats = enable_stats;
    fwd->connect_timeout_ms = connect_timeout_ms;
    __atomic_store_n(&fwd->bytes_in, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&fwd->bytes_out, 0, __ATOMIC_RELAXED);

    rc = cache_destination_addr(&fwd->cached_dest_addr, family, fwd->target_address, fwd->target_port);
    if (rc != 0)
    {
        set_forwarder_error(out_error, FORWARDER_ERROR_INVALID_ADDRESS);
        fwd->stop_requested = 0;
        uv_close((uv_handle_t*)&fwd->server, fwd_error_close_cb);
        uv_close((uv_handle_t*)&fwd->stop_handle, fwd_error_close_cb);
        return NULL;
    }

    struct sockaddr_storage addr;
    build_listen_addr(&addr, family, listen_port);
    int bind_result = uv_tcp_bind(&fwd->server, (const struct sockaddr *)&addr, 0);
    if (bind_result != 0)
    {
        set_forwarder_error(out_error, map_bind_error(bind_result));
        fwd->stop_requested = 0;
        uv_close((uv_handle_t*)&fwd->server, fwd_error_close_cb);
        uv_close((uv_handle_t*)&fwd->stop_handle, fwd_error_close_cb);
        return NULL;
    }

    set_forwarder_error(out_error, FORWARDER_OK);
    return fwd;
}

int tcp_forwarder_start(tcp_forwarder_t *forwarder)
{
    if (!forwarder)
        return -1;
    int r = uv_listen((uv_stream_t *)&forwarder->server, 128, tcp_on_new_connection);
    if (r != 0)
        return r;
    forwarder->started = 1;
    return 0;
}

void tcp_forwarder_request_stop(tcp_forwarder_t *forwarder)
{
    if (!forwarder || forwarder->stop_requested)
        return;
    forwarder->stop_requested = 1;
    uv_async_send(&forwarder->stop_handle);
}

void tcp_forwarder_destroy(tcp_forwarder_t *forwarder)
{
    if (!forwarder)
        return;
    
    forwarder->destroy_requested = 1;
    
    if (!uv_is_closing((uv_handle_t *)&forwarder->server))
        uv_close((uv_handle_t *)&forwarder->server, tcp_forwarder_close_cb);
    if (!uv_is_closing((uv_handle_t *)&forwarder->stop_handle))
        uv_close((uv_handle_t *)&forwarder->stop_handle, tcp_forwarder_close_cb);
        
    if (forwarder->closed_handles >= forwarder->expected_closed_handles)
    {
        DATA_FREE(forwarder, forwarder->target_address);
        forwarder->target_address = NULL;
        DATA_FREE(forwarder, forwarder);
    }
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
