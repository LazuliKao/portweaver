#include "forwarder.h"
#include "uv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TCP_INSPECTION_BUFFER_SIZE 16384
#define TCP_INSPECTION_TIMEOUT_MS 2000

typedef enum tcp_conn_phase
{
    TCP_CONN_ACCEPTED = 0,
    TCP_CONN_INSPECTING,
    TCP_CONN_WAKE_DELAY,
    TCP_CONN_CONNECTING,
    TCP_CONN_RETRY_DELAY,
    TCP_CONN_FORWARDING,
    TCP_CONN_CLOSING,
} tcp_conn_phase_t;

typedef enum tcp_action_timer_purpose
{
    TCP_TIMER_NONE = 0,
    TCP_TIMER_WAKE_DELAY,
    TCP_TIMER_RETRY_DELAY,
    TCP_TIMER_CONNECT_TIMEOUT,
} tcp_action_timer_purpose_t;

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
    unsigned int max_connections;
    unsigned long long bytes_in;
    unsigned long long bytes_out;
    unsigned int active_sessions;
    uint16_t listen_port;
    int destroy_requested;
    int closed_handles;
    int expected_closed_handles;
    int ref_count;
    tcp_first_packet_cb_t first_packet_cb;
    void *first_packet_user_data;
    tcp_first_packet_destroy_cb_t first_packet_destroy_cb;
    tcp_wol_trigger_mode_t wol_trigger_mode;
    uint32_t wol_wake_delay_ms;
    uint32_t wol_retry_interval_ms;
    uint32_t wol_retry_window_ms;
    tcp_wol_trigger_cb_t wol_trigger_cb;
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
    uv_timer_t action_timer;
    int action_timer_initialized;
    tcp_action_timer_purpose_t action_timer_purpose;
    uv_timer_t inspection_timer;
    int inspection_timer_initialized;
    tcp_conn_phase_t phase;
    int target_connected;
    int client_reading;
    int target_reading;
    uint64_t retry_deadline_ms;
    int first_packet_inspected;
    char *client_inspection_buffer;
    size_t client_inspection_length;
    char *target_inspection_buffer;
    size_t target_inspection_length;
} tcp_conn_ctx_t;

typedef struct fwd_write_req
{
    uv_write_t req;
    struct tcp_forwarder *fwd;
    tcp_conn_ctx_t *ctx;
} fwd_write_req_t;

static void tcp_forwarder_ref(struct tcp_forwarder *fwd)
{
    if (fwd)
    {
        fwd->ref_count++;
    }
}

static void tcp_forwarder_unref(struct tcp_forwarder *fwd)
{
    if (fwd)
    {
        fwd->ref_count--;
        if (fwd->ref_count == 0)
        {
            if (fwd->first_packet_destroy_cb && fwd->first_packet_user_data)
            {
                fwd->first_packet_destroy_cb(fwd->first_packet_user_data);
                fwd->first_packet_user_data = NULL;
            }
            DATA_FREE(fwd, fwd->target_address);
            fwd->target_address = NULL;
            DATA_FREE(fwd, fwd);
        }
    }
}

static void tcp_terminate_connection(tcp_conn_ctx_t *ctx);
static void tcp_conn_close_cb(uv_handle_t *handle);
static void tcp_start_connect(tcp_conn_ctx_t *ctx);
static void tcp_on_connect(uv_connect_t *req, int status);
static void tcp_begin_wol_connect(tcp_conn_ctx_t *ctx, uint32_t delay_ms);
static void tcp_start_forwarding(tcp_conn_ctx_t *ctx);
static void tcp_action_timer_cb(uv_timer_t *timer);
static void tcp_inspection_timeout_cb(uv_timer_t *timer);

static void tcp_free_context(tcp_conn_ctx_t *ctx)
{
    struct tcp_forwarder *fwd = ctx->forwarder;
    if (ctx->active_counted)
        __atomic_fetch_sub(&fwd->active_sessions, 1u, __ATOMIC_RELAXED);
    DATA_FREE(fwd, ctx->client_inspection_buffer);
    DATA_FREE(fwd, ctx->target_inspection_buffer);
    DATA_FREE(fwd, ctx);
    tcp_forwarder_unref(fwd);
}

static void tcp_maybe_free_context(tcp_conn_ctx_t *ctx)
{
    if (ctx && ctx->closed && ctx->close_count >= ctx->expected_close_count)
        tcp_free_context(ctx);
}

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

static int tcp_queue_write(tcp_conn_ctx_t *ctx, int client_to_target, char *data, size_t length)
{
    struct tcp_forwarder *fwd = ctx->forwarder;
    fwd_write_req_t *fw = (fwd_write_req_t *)DATA_ALLOC(fwd, sizeof(fwd_write_req_t));
    if (!fw)
    {
        DATA_FREE(fwd, data);
        tcp_terminate_connection(ctx);
        return -1;
    }
    fw->fwd = fwd;
    fw->ctx = ctx;
    uv_buf_t wbuf = uv_buf_init(data, (unsigned int)length);
    fw->req.data = data;
    uv_stream_t *destination = client_to_target ? (uv_stream_t *)&ctx->target : (uv_stream_t *)&ctx->client;
    uv_write_cb callback = client_to_target ? tcp_on_client_write : tcp_on_target_write;
    int r = uv_write(&fw->req, destination, &wbuf, 1, callback);
    if (r != 0)
    {
        fprintf(stderr, "[tcp_queue_write] uv_write failed: %s\n", uv_strerror(r));
        DATA_FREE(fwd, data);
        DATA_FREE(fwd, fw);
        tcp_terminate_connection(ctx);
        return -1;
    }
    return 0;
}

static int tcp_flush_inspection_buffers(tcp_conn_ctx_t *ctx)
{
    if (!ctx->target_connected)
        return 0;

    if (ctx->client_inspection_buffer)
    {
        char *data = ctx->client_inspection_buffer;
        size_t length = ctx->client_inspection_length;
        ctx->client_inspection_buffer = NULL;
        ctx->client_inspection_length = 0;
        if (tcp_queue_write(ctx, 1, data, length) != 0)
            return -1;
    }
    if (ctx->target_inspection_buffer)
    {
        char *data = ctx->target_inspection_buffer;
        size_t length = ctx->target_inspection_length;
        ctx->target_inspection_buffer = NULL;
        ctx->target_inspection_length = 0;
        if (tcp_queue_write(ctx, 0, data, length) != 0)
            return -1;
    }
    return 0;
}

static int tcp_inspect_data(tcp_conn_ctx_t *ctx, char *data, size_t length, int client_to_target)
{
    struct tcp_forwarder *fwd = ctx->forwarder;
    if (ctx->first_packet_inspected || !fwd->first_packet_cb)
        return tcp_queue_write(ctx, client_to_target, data, length);

    char **inspection_buffer = client_to_target ? &ctx->client_inspection_buffer : &ctx->target_inspection_buffer;
    size_t *inspection_length = client_to_target ? &ctx->client_inspection_length : &ctx->target_inspection_length;
    if (!*inspection_buffer)
    {
        *inspection_buffer = (char *)DATA_ALLOC(fwd, TCP_INSPECTION_BUFFER_SIZE);
        if (!*inspection_buffer)
        {
            DATA_FREE(fwd, data);
            tcp_terminate_connection(ctx);
            return -1;
        }
    }
    if (length > TCP_INSPECTION_BUFFER_SIZE - *inspection_length)
    {
        DATA_FREE(fwd, data);
        tcp_terminate_connection(ctx);
        return -1;
    }
    memcpy(*inspection_buffer + *inspection_length, data, length);
    *inspection_length += length;
    DATA_FREE(fwd, data);

    int result = fwd->first_packet_cb(fwd->first_packet_user_data,
                                      (const uint8_t *)*inspection_buffer,
                                      *inspection_length,
                                      client_to_target);
    if (result == TCP_INSPECTION_NEED_MORE)
        return 0;
    if (result != TCP_INSPECTION_ALLOW && result != TCP_INSPECTION_ALLOW_WAKE)
    {
        tcp_terminate_connection(ctx);
        return -1;
    }

    ctx->first_packet_inspected = 1;
    if (ctx->inspection_timer_initialized)
        uv_timer_stop(&ctx->inspection_timer);

    if (!ctx->target_connected)
    {
        if (ctx->client_reading)
        {
            uv_read_stop((uv_stream_t *)&ctx->client);
            ctx->client_reading = 0;
        }
        if (result == TCP_INSPECTION_ALLOW_WAKE && fwd->wol_trigger_mode == TCP_WOL_ON_PROTOCOL)
            tcp_begin_wol_connect(ctx, fwd->wol_wake_delay_ms);
        else
            tcp_start_connect(ctx);
        return 0;
    }

    if (tcp_flush_inspection_buffers(ctx) != 0)
        return -1;
    tcp_start_forwarding(ctx);
    return 0;
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
    struct tcp_forwarder *fwd = ctx->forwarder;
    if (nread > 0)
    {
        if (!buf->base)
        {
            tcp_terminate_connection(ctx);
            return;
        }
        if (fwd->enable_stats)
        {
            __atomic_fetch_add(&fwd->bytes_in, (uint64_t)nread, __ATOMIC_RELAXED);
        }
        tcp_inspect_data(ctx, buf->base, (size_t)nread, 1);
        return;
    }
    if (buf->base)
        DATA_FREE(ctx->forwarder, buf->base);
    if (nread < 0)
    {
        if (nread == UV_EOF)
        {
            ctx->client_eof = 1;
            ctx->client_reading = 0;
            uv_read_stop(client);
            if (!ctx->target_connected)
                return;
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
        tcp_inspect_data(ctx, buf->base, (size_t)nread, 0);
        return;
    }
    if (buf->base)
        DATA_FREE(ctx->forwarder, buf->base);
    if (nread < 0)
    {
        if (nread == UV_EOF)
        {
            ctx->target_eof = 1;
            ctx->target_reading = 0;
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
    tcp_maybe_free_context(ctx);
}

static void tcp_terminate_connection(tcp_conn_ctx_t *ctx)
{
    if (!ctx || ctx->closed)
        return;

    ctx->closed = 1;
    ctx->phase = TCP_CONN_CLOSING;

    int close_count = 0;
    uv_read_stop((uv_stream_t *)&ctx->client);
    uv_read_stop((uv_stream_t *)&ctx->target);

    if (ctx->action_timer_initialized && !uv_is_closing((uv_handle_t *)&ctx->action_timer))
    {
        uv_timer_stop(&ctx->action_timer);
        uv_close((uv_handle_t *)&ctx->action_timer, tcp_conn_close_cb);
    }
    if (ctx->inspection_timer_initialized && !uv_is_closing((uv_handle_t *)&ctx->inspection_timer))
    {
        uv_timer_stop(&ctx->inspection_timer);
        uv_close((uv_handle_t *)&ctx->inspection_timer, tcp_conn_close_cb);
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

    if (close_count == 0)
        tcp_maybe_free_context(ctx);
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

static int tcp_start_reading(tcp_conn_ctx_t *ctx, int client, int target)
{
    int r1 = 0;
    int r2 = 0;
    if (client && !ctx->client_reading)
    {
        r1 = uv_read_start((uv_stream_t *)&ctx->client, tcp_alloc_cb, tcp_on_client_read);
        if (r1 == 0)
            ctx->client_reading = 1;
    }
    if (target && !ctx->target_reading)
    {
        r2 = uv_read_start((uv_stream_t *)&ctx->target, tcp_alloc_cb, tcp_on_target_read);
        if (r2 == 0)
            ctx->target_reading = 1;
    }
    if (r1 != 0 || r2 != 0)
    {
        fprintf(stderr, "[tcp_start_reading] uv_read_start failed: client=%d target=%d\n", r1, r2);
        tcp_terminate_connection(ctx);
        return -1;
    }
    return 0;
}

static void tcp_start_inspection_timer(tcp_conn_ctx_t *ctx)
{
    if (!ctx->inspection_timer_initialized || ctx->first_packet_inspected)
        return;
    uv_timer_start(&ctx->inspection_timer, tcp_inspection_timeout_cb, TCP_INSPECTION_TIMEOUT_MS, 0);
}

static void tcp_start_forwarding(tcp_conn_ctx_t *ctx)
{
    if (ctx->closed || !ctx->target_connected)
        return;
    if (ctx->first_packet_inspected || !ctx->forwarder->first_packet_cb)
        ctx->phase = TCP_CONN_FORWARDING;
    else
        ctx->phase = TCP_CONN_INSPECTING;
    tcp_start_reading(ctx, !ctx->client_eof, !ctx->target_eof);
}

static void tcp_schedule_action(tcp_conn_ctx_t *ctx, tcp_action_timer_purpose_t purpose, uint32_t delay_ms)
{
    if (ctx->closed || !ctx->action_timer_initialized)
        return;
    ctx->action_timer_purpose = purpose;
    if (purpose == TCP_TIMER_WAKE_DELAY)
        ctx->phase = TCP_CONN_WAKE_DELAY;
    else if (purpose == TCP_TIMER_RETRY_DELAY)
        ctx->phase = TCP_CONN_RETRY_DELAY;
    uv_timer_start(&ctx->action_timer, tcp_action_timer_cb, delay_ms, 0);
}

static void tcp_retry_target_close_cb(uv_handle_t *handle)
{
    tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)handle->data;
    if (!ctx)
        return;
    ctx->close_count++;
    if (ctx->closed)
    {
        tcp_maybe_free_context(ctx);
        return;
    }

    uv_loop_t *loop = forwarder_runtime_get_loop(ctx->forwarder->runtime);
    int rc = uv_tcp_init(loop, &ctx->target);
    if (rc != 0)
    {
        fprintf(stderr, "[tcp_retry_target_close_cb] uv_tcp_init failed: %s\n", uv_strerror(rc));
        tcp_terminate_connection(ctx);
        return;
    }
    ctx->expected_close_count++;
    ctx->target.data = ctx;
    tcp_schedule_action(ctx, TCP_TIMER_RETRY_DELAY, ctx->forwarder->wol_retry_interval_ms);
}

static void tcp_handle_connect_failure(tcp_conn_ctx_t *ctx)
{
    uv_loop_t *loop = forwarder_runtime_get_loop(ctx->forwarder->runtime);
    if (ctx->retry_deadline_ms > 0 && uv_now(loop) < ctx->retry_deadline_ms)
    {
        ctx->target_connected = 0;
        uv_close((uv_handle_t *)&ctx->target, tcp_retry_target_close_cb);
        return;
    }
    tcp_terminate_connection(ctx);
}

static void tcp_action_timer_cb(uv_timer_t *timer)
{
    tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)timer->data;
    if (!ctx || ctx->closed)
        return;
    tcp_action_timer_purpose_t purpose = ctx->action_timer_purpose;
    ctx->action_timer_purpose = TCP_TIMER_NONE;
    if (purpose == TCP_TIMER_CONNECT_TIMEOUT)
    {
        uv_cancel((uv_req_t *)&ctx->connect_req);
        return;
    }
    if (purpose == TCP_TIMER_RETRY_DELAY && ctx->retry_deadline_ms > 0)
    {
        uv_loop_t *loop = forwarder_runtime_get_loop(ctx->forwarder->runtime);
        if (uv_now(loop) >= ctx->retry_deadline_ms)
        {
            tcp_terminate_connection(ctx);
            return;
        }
    }
    if (purpose == TCP_TIMER_WAKE_DELAY || purpose == TCP_TIMER_RETRY_DELAY)
        tcp_start_connect(ctx);
}

static void tcp_inspection_timeout_cb(uv_timer_t *timer)
{
    tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)timer->data;
    if (ctx && !ctx->closed && !ctx->first_packet_inspected)
        tcp_terminate_connection(ctx);
}

static void tcp_start_connect(tcp_conn_ctx_t *ctx)
{
    if (!ctx || ctx->closed)
        return;
    ctx->phase = TCP_CONN_CONNECTING;
    ctx->connect_req.data = ctx;
    int rc = uv_tcp_connect(&ctx->connect_req,
                            &ctx->target,
                            (const struct sockaddr *)&ctx->forwarder->cached_dest_addr,
                            tcp_on_connect);
    if (rc != 0)
    {
        tcp_handle_connect_failure(ctx);
        return;
    }
    if (ctx->forwarder->connect_timeout_ms > 0)
        tcp_schedule_action(ctx, TCP_TIMER_CONNECT_TIMEOUT, ctx->forwarder->connect_timeout_ms);
}

static void tcp_begin_wol_connect(tcp_conn_ctx_t *ctx, uint32_t delay_ms)
{
    uv_loop_t *loop = forwarder_runtime_get_loop(ctx->forwarder->runtime);
    ctx->retry_deadline_ms = uv_now(loop) + ctx->forwarder->wol_retry_window_ms;
    if (delay_ms > 0)
        tcp_schedule_action(ctx, TCP_TIMER_WAKE_DELAY, delay_ms);
    else
        tcp_start_connect(ctx);
}

static void tcp_on_connect(uv_connect_t *req, int status)
{
    tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)req->data;
    if (!ctx || ctx->closed)
        return;
    if (ctx->action_timer_initialized)
        uv_timer_stop(&ctx->action_timer);
    ctx->action_timer_purpose = TCP_TIMER_NONE;
    if (status == 0)
    {
        ctx->target_connected = 1;
        ctx->retry_deadline_ms = 0;
        if (!ctx->forwarder->first_packet_cb)
            ctx->first_packet_inspected = 1;
        if (ctx->first_packet_inspected && tcp_flush_inspection_buffers(ctx) != 0)
            return;
        if (!ctx->first_packet_inspected)
            tcp_start_inspection_timer(ctx);
        tcp_start_forwarding(ctx);
        if (ctx->client_eof)
        {
            tcp_shutdown_peer_write(ctx,
                                    (uv_stream_t *)&ctx->target,
                                    &ctx->target_shutdown_req,
                                    &ctx->target_shutdown_started,
                                    &ctx->target_shutdown_pending,
                                    "tcp_on_connect");
        }
    }
    else
    {
        tcp_handle_connect_failure(ctx);
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
    tcp_forwarder_ref(fwd);
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
        tcp_forwarder_unref(fwd);
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
    ctx->expected_close_count = 2;

    init_rc = uv_timer_init(loop, &ctx->action_timer);
    if (init_rc != 0)
    {
        fprintf(stderr, "[tcp_on_new_connection] uv_timer_init(action) failed: %s\n", uv_strerror(init_rc));
        tcp_terminate_connection(ctx);
        return;
    }
    ctx->action_timer.data = ctx;
    ctx->action_timer_initialized = 1;
    ctx->expected_close_count++;

    if (fwd->first_packet_cb)
    {
        init_rc = uv_timer_init(loop, &ctx->inspection_timer);
        if (init_rc != 0)
        {
            fprintf(stderr, "[tcp_on_new_connection] uv_timer_init(inspection) failed: %s\n", uv_strerror(init_rc));
            tcp_terminate_connection(ctx);
            return;
        }
        ctx->inspection_timer.data = ctx;
        ctx->inspection_timer_initialized = 1;
        ctx->expected_close_count++;
    }
    
    if (fwd->max_connections > 0 && __atomic_load_n(&fwd->active_sessions, __ATOMIC_RELAXED) >= fwd->max_connections)
    {
        uv_accept(server, (uv_stream_t *)&ctx->client);
        tcp_terminate_connection(ctx);
        return;
    }
    if (uv_accept(server, (uv_stream_t *)&ctx->client) == 0)
    {
        __atomic_fetch_add(&fwd->active_sessions, 1u, __ATOMIC_RELAXED);
        ctx->active_counted = 1;
        if (fwd->wol_trigger_mode == TCP_WOL_ON_CONNECT)
        {
            int queued = fwd->wol_trigger_cb && fwd->wol_trigger_cb(fwd->first_packet_user_data);
            if (fwd->first_packet_cb && tcp_start_reading(ctx, 1, 0) != 0)
                return;
            tcp_begin_wol_connect(ctx, queued ? fwd->wol_wake_delay_ms : 0);
        }
        else if (fwd->wol_trigger_mode == TCP_WOL_ON_PROTOCOL)
        {
            ctx->phase = TCP_CONN_INSPECTING;
            tcp_start_inspection_timer(ctx);
            tcp_start_reading(ctx, 1, 0);
        }
        else
            tcp_start_connect(ctx);
    }
    else
    {
        tcp_terminate_connection(ctx);
    }
}

static void tcp_forwarder_close_cb(uv_handle_t *handle)
{
    struct tcp_forwarder *fwd = (struct tcp_forwarder *)handle->data;
    if (!fwd)
        return;
    tcp_forwarder_unref(fwd);
}

static void tcp_close_walk_cb(uv_handle_t *handle, void *arg)
{
    struct tcp_forwarder *fwd = (struct tcp_forwarder *)arg;
    if (!handle || uv_is_closing(handle) || !fwd)
        return;

    if (handle == (uv_handle_t *)&fwd->server || handle == (uv_handle_t *)&fwd->stop_handle)
    {
        tcp_forwarder_ref(fwd);
        uv_close(handle, tcp_forwarder_close_cb);
        return;
    }

    if (handle->type == UV_TCP)
    {
        tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)handle->data;
        if (ctx && ctx->forwarder == fwd)
        {
            tcp_terminate_connection(ctx);
            return;
        }
    }

    if (handle->type == UV_TIMER)
    {
        tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)handle->data;
        if (ctx && ctx->forwarder == fwd)
        {
            tcp_terminate_connection(ctx);
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

static forwarder_error_t map_libuv_init_error(int status)
{
    if (status == UV_ENOMEM)
        return FORWARDER_ERROR_MALLOC;
    return FORWARDER_ERROR_UNKNOWN;
}

static forwarder_error_t map_bind_error(int status)
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
    uint32_t max_connections,
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
    fwd->ref_count = 1;
    fwd->enable_stats = enable_stats;
    fwd->connect_timeout_ms = connect_timeout_ms;
    fwd->max_connections = max_connections;
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

forwarder_error_t tcp_forwarder_start(tcp_forwarder_t *forwarder)
{
    if (!forwarder)
        return FORWARDER_ERROR_UNKNOWN;
    int r = uv_listen((uv_stream_t *)&forwarder->server, 128, tcp_on_new_connection);
    if (r != 0)
        return map_bind_error(r);
    forwarder->started = 1;
    return FORWARDER_OK;
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
    {
        tcp_forwarder_ref(forwarder);
        uv_close((uv_handle_t *)&forwarder->server, tcp_forwarder_close_cb);
    }
    if (!uv_is_closing((uv_handle_t *)&forwarder->stop_handle))
    {
        tcp_forwarder_ref(forwarder);
        uv_close((uv_handle_t *)&forwarder->stop_handle, tcp_forwarder_close_cb);
    }
    
    uv_loop_t *loop = forwarder_runtime_get_loop(forwarder->runtime);
    if (loop)
    {
        uv_walk(loop, tcp_close_walk_cb, forwarder);
    }
        
    // Release the owner reference
    tcp_forwarder_unref(forwarder);
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

void tcp_forwarder_set_first_packet_cb(tcp_forwarder_t *fwd, tcp_first_packet_cb_t cb, void *user_data, tcp_first_packet_destroy_cb_t destroy_cb)
{
    if (!fwd)
        return;
    fwd->first_packet_cb = cb;
    fwd->first_packet_user_data = user_data;
    fwd->first_packet_destroy_cb = destroy_cb;
}

void tcp_forwarder_set_wol_policy(tcp_forwarder_t *fwd,
                                  tcp_wol_trigger_mode_t mode,
                                  uint32_t wake_delay_ms,
                                  uint32_t retry_interval_ms,
                                  uint32_t retry_window_ms,
                                  tcp_wol_trigger_cb_t trigger_cb)
{
    if (!fwd)
        return;
    fwd->wol_trigger_mode = mode;
    fwd->wol_wake_delay_ms = wake_delay_ms;
    fwd->wol_retry_interval_ms = retry_interval_ms;
    fwd->wol_retry_window_ms = retry_window_ms;
    fwd->wol_trigger_cb = trigger_cb;
}
