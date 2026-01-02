#include "forwarder.h"
#include "uv.h"
#include <stdlib.h>
#include <string.h>
#ifdef DEBUG
// --- Memory Allocator Helpers ---

/* Data buffer allocator helpers (add magic header to detect/avoid double frees)
 * and a lightweight allocation map to verify ownership before freeing.
 */
static const uint32_t DATA_MAGIC = 0xF00DBEEF;

typedef struct alloc_entry
{
    void *ptr; /* user-facing pointer (after header) */
    size_t size;
    const char *file; /* allocation site file */
    int line;         /* allocation site line */
    struct alloc_entry *next;
} alloc_entry_t;

static alloc_entry_t *alloc_map_head = NULL;
static uv_mutex_t alloc_map_lock;
static int alloc_map_initialized = 0;

static void ensure_alloc_map_init(void)
{
    if (!alloc_map_initialized)
    {
        uv_mutex_init(&alloc_map_lock);
        alloc_map_initialized = 1;
    }
}

static void alloc_map_add(void *user_ptr, size_t size, const char *file, int line)
{
    ensure_alloc_map_init();
    alloc_entry_t *e = (alloc_entry_t *)malloc(sizeof(alloc_entry_t));
    if (!e)
    {
        fprintf(stderr, "[alloc_map_add] OOM when tracking %p\n", user_ptr);
        return;
    }
    e->ptr = user_ptr;
    e->size = size;
    e->file = file;
    e->line = line;

    uv_mutex_lock(&alloc_map_lock);
    e->next = alloc_map_head;
    alloc_map_head = e;
    uv_mutex_unlock(&alloc_map_lock);

    // fprintf(stderr, "[alloc_map_add] tracked user=%p size=%zu (%s:%d)\n", user_ptr, size, file, line);
}
static int link_list_len(alloc_entry_t *next)
{
    int len = 0;
    alloc_entry_t *cur = next;
    while (cur)
    {
        len++;
        cur = cur->next;
    }
    return len;
}

static int alloc_map_remove(void *user_ptr, size_t *size_out, const char **file_out, int *line_out)
{
    if (!alloc_map_initialized)
        return 0;
    uv_mutex_lock(&alloc_map_lock);
    alloc_entry_t *prev = NULL;
    alloc_entry_t *cur = alloc_map_head;
    while (cur)
    {
        if (cur->ptr == user_ptr)
        {
            if (size_out)
                *size_out = cur->size;
            if (file_out)
                *file_out = cur->file;
            if (line_out)
                *line_out = cur->line;
            if (prev)
                prev->next = cur->next;
            else
                alloc_map_head = cur->next;
            uv_mutex_unlock(&alloc_map_lock);
            // fprintf(stderr, "[alloc_map_remove] removing user=%p size=%zu current_size=%d (%s:%d)\n", user_ptr, cur->size, link_list_len(alloc_map_head), cur->file, cur->line);
            free(cur);
            return 1;
        }
        prev = cur;
        cur = cur->next;
    }
    uv_mutex_unlock(&alloc_map_lock);
    // fprintf(stderr, "[alloc_map_remove] user=%p not found\n", user_ptr);
    return 0;
}

static void *data_alloc(size_t size, const char *file, int line)
{
    size_t total = size + sizeof(uint32_t) * 2;
    uint8_t *p = (uint8_t *)malloc(total);
    if (!p)
        return NULL;
    uint32_t magic = DATA_MAGIC;
    memcpy(p, &magic, sizeof(uint32_t));
    void *user_ptr = (void *)(p + sizeof(uint32_t) * 2);

    /* Track ownership */
    alloc_map_add(user_ptr, size, file, line);

    // fprintf(stderr, "[data_alloc] alloc user=%p header=%p size=%zu (%s:%d) (malloc)\n", user_ptr, (void *)p, size, file, line);

    return user_ptr;
}
static int period = 1;
static void data_free(void *ptr, const char *file, int line)
{
    if (!ptr)
        return;
    uint8_t *p = (uint8_t *)ptr - sizeof(uint32_t) * 2;
    uint32_t magic = 0;
    memcpy(&magic, p, sizeof(uint32_t));
    if (magic != DATA_MAGIC)
    {
        /* Not our allocation header or already corrupted. Log for debugging. */
        fprintf(stderr, "[data_free] detected invalid free header: ptr=%p header=%p magic=0x%08x (%s:%d)\n", ptr, (void *)p, magic, file, line);
        /* Also check whether ptr was tracked but header corrupted */
        size_t tracked_size = 0;
        const char *tracked_file = NULL;
        int tracked_line = 0;
        if (!alloc_map_remove(ptr, &tracked_size, &tracked_file, &tracked_line))
        {
            fprintf(stderr, "[data_free] ptr %p was not tracked by alloc_map\n", ptr);
        }
        else
        {
            fprintf(stderr, "[data_free] ptr %p was tracked (size=%zu at %s:%d) but header corrupted, skipping free to avoid crash\n", ptr, tracked_size, tracked_file ? tracked_file : "?", tracked_line);
        }
        exit(1); /* likely double free or invalid free, abort to avoid undefined behavior */
        return;  /* avoid freeing memory not owned by our data_alloc */
    }

    /* Verify ownership in map and remove it */
    size_t tracked_size = 0;
    const char *tracked_file = NULL;
    int tracked_line = 0;
    if (!alloc_map_remove(ptr, &tracked_size, &tracked_file, &tracked_line))
    {
        fprintf(stderr, "[data_free] ptr %p had valid header but was not tracked by alloc_map\n", ptr);
        /* proceed with free anyway */
        exit(1); /* likely double free or invalid free, abort to avoid undefined behavior */
    }
    else
    {
        // Reduce logging frequency for performance (only every 100 frees)
        if (period++ > 100)
        {
            period = 0;
            int count = link_list_len(alloc_map_head);
            fprintf(stderr, "[data_free] alloc_map current size: %d\n", count);
            // Only print details if count is small (potential leak detection)
            if (count > 0 && count < 10)
            {
                for (alloc_entry_t *e = alloc_map_head; e != NULL; e = e->next)
                {
                    int current_magic = 0;
                    memcpy(&current_magic, (uint8_t *)e->ptr - sizeof(uint32_t) * 2, sizeof(uint32_t));
                    fprintf(stderr, "  -> user=%p size=%zu (%s:%d) magic=0x%08x\n", e->ptr, e->size, e->file ? e->file : "?", e->line, current_magic);
                }
            }
        }
    }

    magic = 0;
    memcpy(p, &magic, sizeof(uint32_t));

    /* Dump header bytes to help diagnose allocator canary corruption */
    // fprintf(stderr, "[data_free] dumping header bytes at %p: ", (void *)p);
    // for (int i = 0; i < 32; ++i)
    // {
    //     fprintf(stderr, "%02x ", ((unsigned char *)p)[i]);
    // }
    // fprintf(stderr, "\n");

    /* Use free() to avoid panics while debugging */
    free(p);
    // fprintf(stderr, "[data_free] freed user=%p header=%p (free)\n", ptr, (void *)p);
}

#define DATA_ALLOC(ctx, sz) data_alloc((sz), __FILE__, __LINE__)
#define DATA_FREE(ctx, sz) data_free((sz), __FILE__, __LINE__)
#else
#define DATA_ALLOC(ctx, sz) malloc(sz)
#define DATA_FREE(ctx, sz) free(sz)
#endif // DEBUG

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
} tcp_conn_ctx_t;

// Forward declarations for C callbacks
static void tcp_on_client_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buf);
static void tcp_on_target_read(uv_stream_t *target, ssize_t nread, const uv_buf_t *buf);
static void tcp_on_client_write(uv_write_t *req, int status);
static void tcp_on_target_write(uv_write_t *req, int status);
static void tcp_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void tcp_walk_close_cb(uv_handle_t *handle, void *arg);
static void udp_walk_close_cb(uv_handle_t *handle, void *arg);
static void udp_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf);
static void tcp_conn_close_cb(uv_handle_t *handle);
static int sockaddr_equal(const struct sockaddr *a, const struct sockaddr *b);

struct tcp_forwarder
{
    uv_loop_t *loop;
    uv_tcp_t server;
    char *target_address;
    uint16_t target_port;
    addr_family_t family;
    int running;
    struct sockaddr_storage cached_dest_addr; // added: cache destination addr
    int enable_stats;
    unsigned long long bytes_in;
    unsigned long long bytes_out;
};

/* Wrapper for write/send requests that carry a pointer back to the forwarder
 * so we can free memory with the right allocator in the completion callbacks.
 */
typedef struct fwd_write_req
{
    uv_write_t req;
    struct tcp_forwarder *fwd;
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
        // Stats: count bytes received from client (bytes_in)
        if (ctx->forwarder->enable_stats)
        {
            __atomic_fetch_add(&ctx->forwarder->bytes_in, (uint64_t)nread, __ATOMIC_RELAXED);
        }
        fwd_write_req_t *fw = (fwd_write_req_t *)DATA_ALLOC(ctx->forwarder, sizeof(fwd_write_req_t));
        if (!fw)
        {
            DATA_FREE(ctx->forwarder, buf->base);
            return;
        }
        fw->fwd = ctx->forwarder;
        uv_buf_t wbuf = uv_buf_init(buf->base, nread);
        fw->req.data = buf->base;
        int r = uv_write(&fw->req, (uv_stream_t *)&ctx->target, &wbuf, 1, tcp_on_client_write);
        if (r != 0)
        {
            fprintf(stderr, "[tcp_on_client_read] uv_write failed: %s\n", uv_strerror(r));
            if (fw->req.data)
                DATA_FREE(fw->fwd, fw->req.data);
            DATA_FREE(fw->fwd, fw);
        }
        return;
    }
    if (buf->base)
        DATA_FREE(ctx->forwarder, buf->base);
    if (nread < 0)
    {
        // Gracefully shutdown target's write side to flush pending data, then close client
        if (!uv_is_closing((uv_handle_t *)&ctx->target))
        {
            uv_shutdown(&ctx->shutdown_req_target, (uv_stream_t *)&ctx->target, NULL);
        }
        if (!uv_is_closing((uv_handle_t *)client))
            uv_close((uv_handle_t *)client, tcp_conn_close_cb);
    }
}

static void tcp_on_target_read(uv_stream_t *target, ssize_t nread, const uv_buf_t *buf)
{
    tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)target->data;
    if (nread > 0)
    {
        // Stats: count bytes received from target (bytes_out)
        if (ctx->forwarder->enable_stats)
        {
            __atomic_fetch_add(&ctx->forwarder->bytes_out, (uint64_t)nread, __ATOMIC_RELAXED);
        }
        fwd_write_req_t *fw = (fwd_write_req_t *)DATA_ALLOC(ctx->forwarder, sizeof(fwd_write_req_t));
        if (!fw)
        {
            DATA_FREE(ctx->forwarder, buf->base);
            return;
        }
        fw->fwd = ctx->forwarder;
        uv_buf_t wbuf = uv_buf_init(buf->base, nread);
        fw->req.data = buf->base;
        int r = uv_write(&fw->req, (uv_stream_t *)&ctx->client, &wbuf, 1, tcp_on_target_write);
        if (r != 0)
        {
            fprintf(stderr, "[tcp_on_target_read] uv_write failed: %s\n", uv_strerror(r));
            if (fw->req.data)
                DATA_FREE(fw->fwd, fw->req.data);
            DATA_FREE(fw->fwd, fw);
        }
        return;
    }
    if (buf->base)
        DATA_FREE(ctx->forwarder, buf->base);
    if (nread < 0)
    {
        // Gracefully shutdown client's write side to flush pending data, then close target
        if (!uv_is_closing((uv_handle_t *)&ctx->client))
        {
            uv_shutdown(&ctx->shutdown_req_client, (uv_stream_t *)&ctx->client, NULL);
        }
        if (!uv_is_closing((uv_handle_t *)target))
            uv_close((uv_handle_t *)target, tcp_conn_close_cb);
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
    buf->base = (char *)malloc(suggested_size);
    buf->len = (unsigned int)suggested_size;
}

// UDP buffer allocation callback (optimized for typical UDP packet size)
// #define UDP_BUFFER_SIZE 65536 // Max UDP datagram size
static void udp_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    // (void)suggested_size; // Ignore libuv suggestion, use optimized size
    // if (handle && handle->data)
    // {
    //     struct udp_forwarder *fwd = (struct udp_forwarder *)handle->data;
    //     buf->base = (char *)DATA_ALLOC(fwd, UDP_BUFFER_SIZE);
    //     buf->len = UDP_BUFFER_SIZE;
    //     return;
    // }
    // buf->base = (char *)malloc(UDP_BUFFER_SIZE);
    // buf->len = UDP_BUFFER_SIZE;

    if (handle && handle->data)
    {
        struct udp_forwarder *fwd = (struct udp_forwarder *)handle->data;
        buf->base = (char *)DATA_ALLOC(fwd, suggested_size);
        buf->len = suggested_size;
        return;
    }
    buf->base = (char *)malloc(suggested_size);
    buf->len = suggested_size;
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
        return memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr)) == 0;
    }
    return 0;
}

static void tcp_on_connect(uv_connect_t *req, int status)
{
    tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t *)req->data;
    if (status == 0)
    {
        uv_read_start((uv_stream_t *)&ctx->client, tcp_alloc_cb, tcp_on_client_read);
        uv_read_start((uv_stream_t *)&ctx->target, tcp_alloc_cb, tcp_on_target_read);
    }
    else
    {
        uv_close((uv_handle_t *)&ctx->client, tcp_conn_close_cb);
        uv_close((uv_handle_t *)&ctx->target, tcp_conn_close_cb);
    }
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
    uv_tcp_init(fwd->loop, &ctx->client);
    uv_tcp_init(fwd->loop, &ctx->target);
    ctx->client.data = ctx;
    ctx->target.data = ctx;
    if (uv_accept(server, (uv_stream_t *)&ctx->client) == 0)
    {
        ctx->connect_req.data = ctx;
        // Use cached target address (avoid per-connection uv_ip*_addr)
        uv_tcp_connect(&ctx->connect_req, &ctx->target, (const struct sockaddr *)&fwd->cached_dest_addr, tcp_on_connect);
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
    int *out_error)
{
    // Allocate forwarder directly (no external allocator support)
    struct tcp_forwarder *fwd = NULL;
    fwd = (struct tcp_forwarder *)malloc(sizeof(struct tcp_forwarder));
    if (!fwd)
    {
        if (out_error)
            *out_error = FORWARDER_ERROR_MALLOC;
        return NULL;
    }
    memset(fwd, 0, sizeof(*fwd));

    fwd->loop = uv_loop_new();
    if (!fwd->loop)
    {
        if (out_error)
            *out_error = FORWARDER_ERROR_MALLOC;
        free(fwd);
        return NULL;
    }

    uv_tcp_init(fwd->loop, &fwd->server);
    fwd->server.data = fwd;

    fwd->target_address = strdup(target_address);
    fwd->target_port = target_port;
    fwd->family = family;
    fwd->enable_stats = enable_stats;
    // Initialize atomic counters
    __atomic_store_n(&fwd->bytes_in, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&fwd->bytes_out, 0, __ATOMIC_RELAXED);
    // cache parsed destination sockaddr to avoid repeated parsing
    if (family == ADDR_FAMILY_IPV6)
    {
        struct sockaddr_in6 addr6;
        uv_ip6_addr(fwd->target_address, fwd->target_port, &addr6);
        memcpy(&fwd->cached_dest_addr, &addr6, sizeof(addr6));
    }
    else
    {
        struct sockaddr_in addr4;
        uv_ip4_addr(fwd->target_address, fwd->target_port, &addr4);
        memcpy(&fwd->cached_dest_addr, &addr4, sizeof(addr4));
    }
    struct sockaddr_storage addr;
    if (family == ADDR_FAMILY_IPV6)
    {
        struct sockaddr_in6 addr6;
        uv_ip6_addr("::", listen_port, &addr6);
        memcpy(&addr, &addr6, sizeof(addr6));
    }
    else
    {
        struct sockaddr_in addr4;
        uv_ip4_addr("0.0.0.0", listen_port, &addr4);
        memcpy(&addr, &addr4, sizeof(addr4));
    }
    int bind_result = uv_tcp_bind(&fwd->server, (const struct sockaddr *)&addr, 0);
    if (bind_result != 0)
    {
        // Determine specific error
        int error_code = FORWARDER_ERROR_BIND;
        if (bind_result == UV_EADDRINUSE)
        {
            error_code = FORWARDER_ERROR_ADDRESS_IN_USE;
        }
        else if (bind_result == UV_EACCES)
        {
            error_code = FORWARDER_ERROR_PERMISSION_DENIED;
        }
        if (out_error)
            *out_error = error_code;
        uv_loop_close(fwd->loop);
        free(fwd->loop);
        free(fwd->target_address);
        free(fwd);
        return NULL;
    }

    if (out_error)
        *out_error = FORWARDER_OK;
    return fwd;
}

int tcp_forwarder_start(tcp_forwarder_t *forwarder)
{
    int r = uv_listen((uv_stream_t *)&forwarder->server, 128, tcp_on_new_connection);
    if (r != 0)
        return r;
    forwarder->running = 1;
    return uv_run(forwarder->loop, UV_RUN_DEFAULT);
}

void tcp_forwarder_stop(tcp_forwarder_t *forwarder)
{
    if (!forwarder)
        return;
    if (forwarder->running)
    {
        uv_stop(forwarder->loop);
        forwarder->running = 0;
    }
}
void tcp_forwarder_destroy(tcp_forwarder_t *forwarder)
{
}

traffic_stats_t tcp_forwarder_get_stats(tcp_forwarder_t *forwarder)
{
    traffic_stats_t stats = {0, 0};
    if (forwarder && forwarder->enable_stats)
    {
        stats.bytes_in = __atomic_load_n(&forwarder->bytes_in, __ATOMIC_RELAXED);
        stats.bytes_out = __atomic_load_n(&forwarder->bytes_out, __ATOMIC_RELAXED);
    }
    return stats;
}

// --- UDP Forwarder Implementation ---

// [Moved up] client session struct must be declared before udp_forwarder_t_impl uses it
typedef struct udp_client_session
{
    uv_udp_t sock; // ephemeral socket bound for this client to talk to target
    struct sockaddr_storage client_addr;
    int client_addr_len;
    struct udp_forwarder *fwd;
    struct udp_client_session *next;
    uv_timer_t timeout_timer; // timer for session timeout
    uint64_t last_activity;   // timestamp of last activity (milliseconds)
    int close_count;          // count of closed handles (timer + sock = 2)
} udp_client_session_t;

#ifdef DEBUG
// 5s
#define UDP_SESSION_TIMEOUT_MS 5000
#else
// Session timeout in milliseconds (5 minutes of inactivity)
#define UDP_SESSION_TIMEOUT_MS 300000
#endif // DEBUG

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
        const uint32_t *words = (const uint32_t *)&a6->sin6_addr;
        for (int i = 0; i < 4; i++)
            hash = ((hash << 5) + hash) ^ words[i];
        hash = ((hash << 5) + hash) ^ a6->sin6_port;
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
static void udp_session_remove(udp_forwarder_t_impl *fwd, udp_client_session_t *session)
{
    // Remove from linked list
    udp_client_session_t **pp = &fwd->sessions;
    while (*pp)
    {
        if (*pp == session)
        {
            *pp = session->next;
            break;
        }
        pp = &(*pp)->next;
    }

    // Remove from hash table
    uint32_t hash = sockaddr_hash((const struct sockaddr *)&session->client_addr);
    pp = &fwd->session_hash[hash];
    while (*pp)
    {
        if (*pp == session)
        {
            *pp = session->next;
            return;
        }
        pp = &(*pp)->next;
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

    // Only free when both handles (timer + sock) are closed
    if (session->close_count >= 2)
    {
        // Remove from session list and free
        udp_session_remove((udp_forwarder_t_impl *)session->fwd, session);
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
        fprintf(stderr, "[udp_session_timeout] closing inactive session (elapsed=%llu ms)\n", (unsigned long long)elapsed);

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

static void tcp_walk_close_cb(uv_handle_t *handle, void *arg)
{
    struct tcp_forwarder *fwd = (struct tcp_forwarder *)arg;
    if (!handle)
        return;
    if (handle == (uv_handle_t *)&fwd->server)
    {
        if (!uv_is_closing(handle))
            uv_close(handle, NULL);
    }
    else if (handle->type == UV_TCP)
    {
        if (!uv_is_closing(handle))
            uv_close(handle, tcp_conn_close_cb);
    }
    else
    {
        if (!uv_is_closing(handle))
            uv_close(handle, NULL);
    }
}

static void udp_walk_close_cb(uv_handle_t *handle, void *arg)
{
    (void)arg;
    if (!handle)
        return;
    if (!uv_is_closing(handle))
        uv_close(handle, NULL);
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
        DATA_FREE(ctx->forwarder, ctx);
    }
}

static void udp_session_on_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                                const struct sockaddr *addr, unsigned flags)
{
    udp_client_session_t *session = (udp_client_session_t *)handle->data;
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
static udp_client_session_t *udp_session_create(udp_forwarder_t_impl *fwd, const struct sockaddr *client_addr, int addr_len)
{
    udp_client_session_t *s = (udp_client_session_t *)DATA_ALLOC((struct udp_forwarder *)fwd, sizeof(udp_client_session_t));
    if (!s)
        return NULL;
    memset(s, 0, sizeof(*s));
    s->fwd = (struct udp_forwarder *)fwd;
    s->client_addr_len = addr_len;
    s->close_count = 0;
    memcpy(&s->client_addr, client_addr, addr_len);
    uv_udp_init(fwd->loop, &s->sock);
    s->sock.data = s;

    // Initialize timeout timer
    uv_timer_init(fwd->loop, &s->timeout_timer);
    s->timeout_timer.data = s;
    s->last_activity = uv_now(fwd->loop);

    // Start timeout timer
    uv_timer_start(&s->timeout_timer, udp_session_timeout_cb, UDP_SESSION_TIMEOUT_MS, 0);

    // bind ephemeral port (0)
    if (fwd->family == ADDR_FAMILY_IPV6)
    {
        struct sockaddr_in6 bind6;
        uv_ip6_addr("::", 0, &bind6);
        uv_udp_bind(&s->sock, (const struct sockaddr *)&bind6, 0);
    }
    else
    {
        struct sockaddr_in bind4;
        uv_ip4_addr("0.0.0.0", 0, &bind4);
        uv_udp_bind(&s->sock, (const struct sockaddr *)&bind4, 0);
    }
    uv_udp_recv_start(&s->sock, udp_alloc_cb, udp_session_on_recv);
    // prepend to session list
    s->next = fwd->sessions;
    fwd->sessions = s;

    // Add to hash table for fast lookup
    uint32_t hash = sockaddr_hash((const struct sockaddr *)&s->client_addr);
    s->next = fwd->session_hash[hash];
    fwd->session_hash[hash] = s;

    return s;
}

// find session by client addr (O(1) hash lookup)
static udp_client_session_t *udp_find_session(udp_forwarder_t_impl *fwd, const struct sockaddr *client_addr)
{
    uint32_t hash = sockaddr_hash(client_addr);
    udp_client_session_t *it = fwd->session_hash[hash];
    while (it)
    {
        if (sockaddr_equal((const struct sockaddr *)&it->client_addr, client_addr))
            return it;
        it = it->next;
    }
    return NULL;
}

static void udp_on_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                        const struct sockaddr *addr, unsigned flags)
{
    udp_forwarder_t_impl *fwd = (udp_forwarder_t_impl *)handle->data;
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

udp_forwarder_t *udp_forwarder_create(
    uint16_t listen_port,
    const char *target_address,
    uint16_t target_port,
    addr_family_t family,
    int enable_stats,
    int *out_error)
{
    udp_forwarder_t_impl *fwd = NULL;

    fwd = (udp_forwarder_t_impl *)malloc(sizeof(udp_forwarder_t_impl));
    if (!fwd)
    {
        if (out_error)
            *out_error = FORWARDER_ERROR_MALLOC;
        return NULL;
    }
    memset(fwd, 0, sizeof(*fwd));

    fwd->loop = uv_loop_new();
    if (!fwd->loop)
    {
        if (out_error)
            *out_error = FORWARDER_ERROR_MALLOC;
        free(fwd);
        return NULL;
    }

    uv_udp_init(fwd->loop, &fwd->server);
    fwd->server.data = fwd;
    fwd->target_address = strdup(target_address);
    fwd->target_port = target_port;
    fwd->family = family;
    fwd->running = 0;
    fwd->sessions = NULL;
    fwd->enable_stats = enable_stats;
    // Initialize atomic counters
    __atomic_store_n(&fwd->bytes_in, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&fwd->bytes_out, 0, __ATOMIC_RELAXED);
    memset(fwd->session_hash, 0, sizeof(fwd->session_hash));
    // cache target addr
    if (family == ADDR_FAMILY_IPV6)
    {
        struct sockaddr_in6 addr6;
        uv_ip6_addr(fwd->target_address, fwd->target_port, &addr6);
        memcpy(&fwd->cached_dest_addr, &addr6, sizeof(addr6));
    }
    else
    {
        struct sockaddr_in addr4;
        uv_ip4_addr(fwd->target_address, fwd->target_port, &addr4);
        memcpy(&fwd->cached_dest_addr, &addr4, sizeof(addr4));
    }
    struct sockaddr_storage addr;
    if (family == ADDR_FAMILY_IPV6)
    {
        struct sockaddr_in6 addr6;
        uv_ip6_addr("::", listen_port, &addr6);
        memcpy(&addr, &addr6, sizeof(addr6));
    }
    else
    {
        struct sockaddr_in addr4;
        uv_ip4_addr("0.0.0.0", listen_port, &addr4);
        memcpy(&addr, &addr4, sizeof(addr4));
    }
    int bind_result = uv_udp_bind(&fwd->server, (const struct sockaddr *)&addr, 0);
    if (bind_result != 0)
    {
        int error_code = FORWARDER_ERROR_BIND;
        if (bind_result == UV_EADDRINUSE)
        {
            error_code = FORWARDER_ERROR_ADDRESS_IN_USE;
        }
        else if (bind_result == UV_EACCES)
        {
            error_code = FORWARDER_ERROR_PERMISSION_DENIED;
        }
        if (out_error)
            *out_error = error_code;
        uv_loop_close(fwd->loop);
        free(fwd->loop);
        free(fwd->target_address);
        free(fwd);
        return NULL;
    }

    if (out_error)
        *out_error = FORWARDER_OK;
    return (udp_forwarder_t *)fwd;
}

int udp_forwarder_start(udp_forwarder_t *forwarder)
{
    udp_forwarder_t_impl *fwd = (udp_forwarder_t_impl *)forwarder;
    if (!fwd)
        return UV_EINVAL;
    int r = uv_udp_recv_start(&fwd->server, udp_alloc_cb, udp_on_recv);
    if (r != 0)
        return r;
    fwd->running = 1;
    return uv_run(fwd->loop, UV_RUN_DEFAULT);
}

void udp_forwarder_stop(udp_forwarder_t *forwarder)
{
    if (!forwarder)
        return;

    if (forwarder->running)
    {
        udp_forwarder_t_impl *fwd = (udp_forwarder_t_impl *)forwarder;
        uv_stop(fwd->loop);
        forwarder->running = 0;
    }
}
void udp_forwarder_destroy(udp_forwarder_t *forwarder)
{
    if (!forwarder)
        return;
  
}

traffic_stats_t udp_forwarder_get_stats(udp_forwarder_t *forwarder)
{
    traffic_stats_t stats = {0, 0};
    udp_forwarder_t_impl *fwd = (udp_forwarder_t_impl *)forwarder;
    if (fwd && fwd->enable_stats)
    {
        stats.bytes_in = __atomic_load_n(&fwd->bytes_in, __ATOMIC_RELAXED);
        stats.bytes_out = __atomic_load_n(&fwd->bytes_out, __ATOMIC_RELAXED);
    }
    return stats;
}

// --- Utility ---
const char *uv_get_version_string(void)
{
    return uv_version_string();
}
