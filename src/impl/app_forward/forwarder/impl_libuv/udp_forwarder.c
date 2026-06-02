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

#ifdef DEBUG
#define UDP_SESSION_TIMEOUT_MS 5000
#else
#define UDP_SESSION_TIMEOUT_MS 60000
#endif

#define UDP_MAX_SESSIONS 4000
#define UDP_SESSION_FD_RESERVE 128
#define UDP_SESSION_HASH_SIZE 1024

struct udp_client_session;

struct udp_forwarder
{
    forwarder_runtime_t *runtime;
    uv_udp_t server;
    uv_async_t stop_handle;
    char *target_address;
    uint16_t target_port;
    addr_family_t family;
    int started;
    int stop_requested;
    struct udp_client_session *sessions;
    struct udp_client_session *session_hash[UDP_SESSION_HASH_SIZE];
    struct sockaddr_storage cached_dest_addr;
    int enable_stats;
    unsigned long long bytes_in;
    unsigned long long bytes_out;
    unsigned int active_sessions;
    unsigned int max_sessions;
    uint16_t listen_port;
    int destroy_requested;
    int closed_handles;
    int expected_closed_handles;
};

typedef struct udp_client_session
{
    uv_udp_t sock;
    struct sockaddr_storage client_addr;
    int client_addr_len;
    struct udp_forwarder *fwd;
    struct udp_client_session *list_next;
    struct udp_client_session *hash_next;
    uv_timer_t timeout_timer;
    uint64_t last_activity;
    int close_count;
    int expected_close_count;
    int tracked_in_forwarder;
} udp_client_session_t;

typedef struct fwd_udp_send_req
{
    uv_udp_send_t req;
    struct udp_forwarder *fwd;
} fwd_udp_send_req_t;

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

static void udp_session_remove(struct udp_forwarder *fwd, udp_client_session_t *session)
{
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

static void udp_session_close_cb(uv_handle_t *handle)
{
    if (!handle || !handle->data)
        return;
    udp_client_session_t *session = (udp_client_session_t *)handle->data;

    session->close_count++;
    if (session->close_count >= session->expected_close_count)
    {
        if (session->tracked_in_forwarder)
        {
            udp_session_remove(session->fwd, session);
            __atomic_fetch_sub(&session->fwd->active_sessions, 1u, __ATOMIC_RELAXED);
        }
        DATA_FREE(session->fwd, session);
    }
}

static void udp_session_timeout_cb(uv_timer_t *timer)
{
    udp_client_session_t *session = (udp_client_session_t *)timer->data;
    if (!session)
        return;

    uint64_t now = uv_now(timer->loop);
    uint64_t elapsed = now - session->last_activity;

    if (elapsed >= UDP_SESSION_TIMEOUT_MS)
    {
        uv_udp_recv_stop(&session->sock);
        if (!uv_is_closing((uv_handle_t *)&session->timeout_timer))
            uv_close((uv_handle_t *)&session->timeout_timer, udp_session_close_cb);
        if (!uv_is_closing((uv_handle_t *)&session->sock))
            uv_close((uv_handle_t *)&session->sock, udp_session_close_cb);
    }
    else
    {
        uint64_t remaining = UDP_SESSION_TIMEOUT_MS - elapsed;
        uv_timer_start(&session->timeout_timer, udp_session_timeout_cb, remaining, 0);
    }
}

static void udp_server_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    if (handle && handle->data)
    {
        struct udp_forwarder *fwd = (struct udp_forwarder *)handle->data;
        buf->base = (char *)DATA_ALLOC(fwd, suggested_size);
        buf->len = (unsigned int)suggested_size;
        return;
    }
    buf->base = NULL;
    buf->len = 0;
}

static void udp_session_alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    if (handle && handle->data)
    {
        udp_client_session_t *session = (udp_client_session_t *)handle->data;
        if (session && session->fwd)
        {
            buf->base = (char *)DATA_ALLOC(session->fwd, suggested_size);
            buf->len = (unsigned int)suggested_size;
            return;
        }
    }
    buf->base = NULL;
    buf->len = 0;
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

static void udp_session_on_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                                const struct sockaddr *addr, unsigned flags)
{
    udp_client_session_t *session = (udp_client_session_t *)handle->data;

    if ((flags & UV_UDP_PARTIAL) != 0)
    {
        if (buf->base)
            DATA_FREE(session->fwd, buf->base);
        return;
    }

    if (nread > 0)
    {
        if (session->fwd->enable_stats)
        {
            __atomic_fetch_add(&session->fwd->bytes_out, (uint64_t)nread, __ATOMIC_RELAXED);
        }
        session->last_activity = uv_now(handle->loop);

        fwd_udp_send_req_t *fw = (fwd_udp_send_req_t *)DATA_ALLOC(session->fwd, sizeof(fwd_udp_send_req_t));
        if (!fw)
        {
            DATA_FREE(session->fwd, buf->base);
            return;
        }
        fw->fwd = session->fwd;
        uv_buf_t wbuf = uv_buf_init(buf->base, (unsigned int)nread);
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
        return; 
    }
    if (buf->base)
        DATA_FREE(session->fwd, buf->base);
}

static udp_client_session_t *udp_session_create(struct udp_forwarder *fwd, const struct sockaddr *client_addr, int addr_len)
{
    unsigned int session_limit = fwd->max_sessions > 0 ? fwd->max_sessions : UDP_MAX_SESSIONS;
    unsigned int active_sessions = __atomic_load_n(&fwd->active_sessions, __ATOMIC_RELAXED);
    if (active_sessions >= session_limit)
    {
        return NULL;
    }

    udp_client_session_t *s = (udp_client_session_t *)DATA_ALLOC(fwd, sizeof(udp_client_session_t));
    if (!s)
        return NULL;
    memset(s, 0, sizeof(*s));

    s->fwd = fwd;
    s->client_addr_len = addr_len;
    s->close_count = 0;
    s->expected_close_count = 0;
    s->tracked_in_forwarder = 0;
    memcpy(&s->client_addr, client_addr, addr_len);

    uv_loop_t *loop = forwarder_runtime_get_loop(fwd->runtime);
    int r = uv_udp_init(loop, &s->sock);
    if (r < 0)
    {
        DATA_FREE(fwd, s);
        return NULL;
    }
    s->expected_close_count = 1;
    s->sock.data = s;

    r = uv_timer_init(loop, &s->timeout_timer);
    if (r < 0)
    {
        if (!uv_is_closing((uv_handle_t *)&s->sock))
            uv_close((uv_handle_t *)&s->sock, udp_session_close_cb);
        return NULL;
    }
    s->expected_close_count = 2;
    s->timeout_timer.data = s;
    s->last_activity = uv_now(loop);

    r = uv_timer_start(&s->timeout_timer, udp_session_timeout_cb, UDP_SESSION_TIMEOUT_MS, 0);
    if (r < 0)
    {
        if (!uv_is_closing((uv_handle_t *)&s->timeout_timer))
            uv_close((uv_handle_t *)&s->timeout_timer, udp_session_close_cb);
        if (!uv_is_closing((uv_handle_t *)&s->sock))
            uv_close((uv_handle_t *)&s->sock, udp_session_close_cb);
        return NULL;
    }

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
        if (!uv_is_closing((uv_handle_t *)&s->timeout_timer))
            uv_close((uv_handle_t *)&s->timeout_timer, udp_session_close_cb);
        if (!uv_is_closing((uv_handle_t *)&s->sock))
            uv_close((uv_handle_t *)&s->sock, udp_session_close_cb);
        return NULL;
    }

    r = uv_udp_recv_start(&s->sock, udp_session_alloc_cb, udp_session_on_recv);
    if (r < 0)
    {
        if (!uv_is_closing((uv_handle_t *)&s->timeout_timer))
            uv_close((uv_handle_t *)&s->timeout_timer, udp_session_close_cb);
        if (!uv_is_closing((uv_handle_t *)&s->sock))
            uv_close((uv_handle_t *)&s->sock, udp_session_close_cb);
        return NULL;
    }

    s->list_next = fwd->sessions;
    fwd->sessions = s;

    uint32_t hash = sockaddr_hash((const struct sockaddr *)&s->client_addr);
    s->hash_next = fwd->session_hash[hash];
    fwd->session_hash[hash] = s;
    __atomic_fetch_add(&fwd->active_sessions, 1u, __ATOMIC_RELAXED);
    s->tracked_in_forwarder = 1;

    return s;
}

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

static udp_client_session_t *udp_find_session(struct udp_forwarder *fwd, const struct sockaddr *client_addr)
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
    struct udp_forwarder *fwd = (struct udp_forwarder *)handle->data;

    if ((flags & UV_UDP_PARTIAL) != 0)
    {
        if (buf->base)
            DATA_FREE(fwd, buf->base);
        return;
    }

    if (nread > 0 && addr)
    {
        if (fwd->enable_stats)
        {
            __atomic_fetch_add(&fwd->bytes_in, (uint64_t)nread, __ATOMIC_RELAXED);
        }
        udp_client_session_t *session = udp_find_session(fwd, addr);
        if (!session)
        {
            session = udp_session_create(fwd, addr, (addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
            if (!session)
            {
                DATA_FREE(fwd, buf->base);
                return;
            }
        }
        else
        {
            session->last_activity = uv_now(forwarder_runtime_get_loop(fwd->runtime));
        }

        fwd_udp_send_req_t *fw = (fwd_udp_send_req_t *)DATA_ALLOC(fwd, sizeof(fwd_udp_send_req_t));
        if (!fw)
        {
            DATA_FREE(fwd, buf->base);
            return;
        }
        fw->fwd = fwd;
        uv_buf_t wbuf = uv_buf_init(buf->base, (unsigned int)nread);
        fw->req.data = buf->base;
        if (uv_is_closing((uv_handle_t *)&session->sock))
        {
            DATA_FREE(fw->fwd, fw->req.data);
            DATA_FREE(fw->fwd, fw);
            return;
        }
        int r = uv_udp_send(&fw->req, &session->sock, &wbuf, 1, (const struct sockaddr *)&fwd->cached_dest_addr, udp_on_send);
        if (r != 0)
        {
            fprintf(stderr, "[udp_on_recv] uv_udp_send failed: %s\n", uv_strerror(r));
            if (fw->req.data)
                DATA_FREE(fw->fwd, fw->req.data);
            DATA_FREE(fw->fwd, fw);
        }
        return; 
    }
    if (buf->base)
        DATA_FREE(fwd, buf->base);
}

static void udp_forwarder_close_cb(uv_handle_t *handle)
{
    struct udp_forwarder *fwd = (struct udp_forwarder *)handle->data;
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

static void udp_stop_cb(uv_async_t *handle)
{
    struct udp_forwarder *fwd = (struct udp_forwarder *)handle->data;
    if (!fwd)
        return;

    if (!uv_is_closing((uv_handle_t *)&fwd->server))
        uv_close((uv_handle_t *)&fwd->server, udp_forwarder_close_cb);
    if (!uv_is_closing((uv_handle_t *)&fwd->stop_handle))
        uv_close((uv_handle_t *)&fwd->stop_handle, udp_forwarder_close_cb);

    // Iterating linked list instead of uv_walk to be safe in shared loop
    udp_client_session_t *session = fwd->sessions;
    while (session)
    {
        // Safe to close here because udp_session_close_cb only frees when expected_close_count is reached
        if (!uv_is_closing((uv_handle_t *)&session->sock))
        {
            uv_udp_recv_stop(&session->sock);
            uv_close((uv_handle_t *)&session->sock, udp_session_close_cb);
        }
        if (!uv_is_closing((uv_handle_t *)&session->timeout_timer))
            uv_close((uv_handle_t *)&session->timeout_timer, udp_session_close_cb);
        
        session = session->list_next;
    }
}

static void fwd_error_close_cb(uv_handle_t *handle)
{
    struct udp_forwarder *fwd = (struct udp_forwarder *)handle->data;
    if (!fwd) return;
    fwd->stop_requested++; 
    if (fwd->stop_requested == 2)
    {
        DATA_FREE(fwd, fwd->target_address);
        DATA_FREE(fwd, fwd);
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

udp_forwarder_t *udp_forwarder_create_on_runtime(
    forwarder_runtime_t *runtime,
    uint16_t listen_port,
    const char *target_address,
    uint16_t target_port,
    addr_family_t family,
    int enable_stats,
    int *out_error)
{
    if (!runtime)
    {
        set_forwarder_error(out_error, FORWARDER_ERROR_UNKNOWN);
        return NULL;
    }

    forwarder_allocator_t allocator = forwarder_runtime_get_allocator(runtime);
    struct udp_forwarder *fwd = (struct udp_forwarder *)allocator.malloc_cb(allocator.ctx, sizeof(struct udp_forwarder));
    if (!fwd)
    {
        set_forwarder_error(out_error, FORWARDER_ERROR_MALLOC);
        return NULL;
    }
    memset(fwd, 0, sizeof(*fwd));
    fwd->runtime = runtime;
    uv_loop_t *loop = forwarder_runtime_get_loop(runtime);

    int rc = uv_udp_init(loop, &fwd->server);
    if (rc != 0)
    {
        set_forwarder_error(out_error, map_libuv_init_error(rc));
        DATA_FREE(fwd, fwd);
        return NULL;
    }
    fwd->server.data = fwd;

    rc = uv_async_init(loop, &fwd->stop_handle, udp_stop_cb);
    if (rc != 0)
    {
        set_forwarder_error(out_error, map_libuv_init_error(rc));
        fwd->stop_requested = 1; 
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
    fwd->sessions = NULL;
    fwd->enable_stats = enable_stats;
    __atomic_store_n(&fwd->bytes_in, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&fwd->bytes_out, 0, __ATOMIC_RELAXED);
    fwd->max_sessions = udp_compute_session_limit();
    memset(fwd->session_hash, 0, sizeof(fwd->session_hash));

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
    int bind_result = uv_udp_bind(&fwd->server, (const struct sockaddr *)&addr, 0);
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

int udp_forwarder_start(udp_forwarder_t *forwarder)
{
    if (!forwarder)
        return -1;
    int r = uv_udp_recv_start(&forwarder->server, udp_server_alloc_cb, udp_on_recv);
    if (r != 0)
        return r;
    forwarder->started = 1;
    return 0;
}

void udp_forwarder_request_stop(udp_forwarder_t *forwarder)
{
    if (!forwarder || forwarder->stop_requested)
        return;
    forwarder->stop_requested = 1;
    uv_async_send(&forwarder->stop_handle);
}

void udp_forwarder_destroy(udp_forwarder_t *forwarder)
{
    if (!forwarder)
        return;
    
    forwarder->destroy_requested = 1;
    
    if (!uv_is_closing((uv_handle_t *)&forwarder->server))
        uv_close((uv_handle_t *)&forwarder->server, udp_forwarder_close_cb);
    if (!uv_is_closing((uv_handle_t *)&forwarder->stop_handle))
        uv_close((uv_handle_t *)&forwarder->stop_handle, udp_forwarder_close_cb);
        
    if (forwarder->closed_handles >= forwarder->expected_closed_handles)
    {
        DATA_FREE(forwarder, forwarder->target_address);
        forwarder->target_address = NULL;
        DATA_FREE(forwarder, forwarder);
    }
}

traffic_stats_t udp_forwarder_get_stats(udp_forwarder_t *forwarder)
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
