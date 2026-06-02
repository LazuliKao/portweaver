#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "io_uring_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#define UDP_SESSION_HASH_SIZE 256
#define UDP_SESSION_TIMEOUT_SEC 60
#define UDP_BUF_SIZE 65536

struct udp_forwarder;
struct udp_session;

struct udp_recv_op {
    struct uring_op base;
    struct udp_forwarder *forwarder;
    struct udp_session *session;
    struct msghdr msg;
    struct iovec iov;
    char buf[UDP_BUF_SIZE];
    struct sockaddr_storage src_addr;
    socklen_t src_addr_len;
    char control[256];
};

struct udp_send_op {
    struct uring_op base;
    struct udp_forwarder *forwarder;
    struct udp_session *session;
    struct msghdr msg;
    struct iovec iov;
    char buf[UDP_BUF_SIZE];
    struct sockaddr_storage dst_addr;
};

struct udp_close_op {
    struct uring_op base;
    struct udp_forwarder *forwarder;
    struct udp_session *session;
};

struct udp_session {
    struct udp_forwarder *forwarder;
    int session_fd;
    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;
    time_t last_activity;
    struct udp_session *hash_next;
    
    struct udp_recv_op target_recv_op;
    struct udp_send_op target_send_op;
    struct udp_send_op client_send_op;
    struct udp_close_op close_op;
    
    int closing;
    int pending_ops;   /* total outstanding SQEs for this session */
    int active_counted;
};

struct udp_forwarder {
    forwarder_runtime_t *runtime;
    int listen_fd;
    uint16_t listen_port;
    uint16_t target_port;
    char *target_address;
    addr_family_t family;
    struct sockaddr_storage cached_dest_addr;
    int enable_stats;
    uint32_t max_connections;
    int started;
    int stop_requested;
    int destroy_requested;
    unsigned long long bytes_in;
    unsigned long long bytes_out;
    unsigned int active_sessions;
    int ref_count;
    
    struct udp_session *session_hash[UDP_SESSION_HASH_SIZE];
    
    struct udp_recv_op listener_recv_op;
};

#define DATA_ALLOC(fwd, sz) (forwarder_runtime_get_allocator((fwd)->runtime).malloc_cb(forwarder_runtime_get_allocator((fwd)->runtime).ctx, (sz)))
#define DATA_FREE(fwd, ptr) \
    do { \
        if (ptr) { \
            forwarder_runtime_get_allocator((fwd)->runtime).free_cb(forwarder_runtime_get_allocator((fwd)->runtime).ctx, (ptr)); \
        } \
    } while(0)

static unsigned int hash_addr(struct sockaddr_storage *addr) {
    unsigned int hash = 5381;
    unsigned char *p = (unsigned char *)addr;
    size_t len = (addr->ss_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + p[i];
    }
    return hash % UDP_SESSION_HASH_SIZE;
}

static int addrs_equal(struct sockaddr_storage *a, struct sockaddr_storage *b) {
    if (a->ss_family != b->ss_family) return 0;
    if (a->ss_family == AF_INET) {
        struct sockaddr_in *a4 = (struct sockaddr_in *)a;
        struct sockaddr_in *b4 = (struct sockaddr_in *)b;
        return a4->sin_port == b4->sin_port && a4->sin_addr.s_addr == b4->sin_addr.s_addr;
    } else {
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)a;
        struct sockaddr_in6 *b6 = (struct sockaddr_in6 *)b;
        return a6->sin6_port == b6->sin6_port && memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(struct in6_addr)) == 0;
    }
}

static void submit_listener_recv(struct udp_forwarder *fwd);
static void submit_target_recv(struct udp_session *session);

static void udp_forwarder_unref(struct udp_forwarder *fwd) {
    if (!fwd) return;
    fwd->ref_count--;
    if (fwd->ref_count <= 0) {
        DATA_FREE(fwd, fwd->target_address);
        DATA_FREE(fwd, fwd);
    }
}

/* Decrement the per-session pending_ops counter and free session if it has
 * reached zero while in the closing state. Every CQE callback must call
 * this instead of directly calling dec_active. */
static void udp_session_release_op(struct udp_session *session) {
    forwarder_runtime_dec_active(session->forwarder->runtime);
    session->pending_ops--;
    if (session->closing && session->pending_ops <= 0) {
        struct udp_forwarder *fwd = session->forwarder;
        if (session->active_counted) {
            __atomic_fetch_sub(&fwd->active_sessions, 1u, __ATOMIC_RELAXED);
        }
        DATA_FREE(fwd, session);
        udp_forwarder_unref(fwd);
    }
}

static void close_session(struct udp_session *session) {
    if (session->closing) return;
    session->closing = 1;
    
    struct udp_forwarder *fwd = session->forwarder;
    
    /* Remove from hash table before any async close. */
    unsigned int h = hash_addr(&session->client_addr);
    struct udp_session **p = &fwd->session_hash[h];
    while (*p) {
        if (*p == session) {
            *p = session->hash_next;
            break;
        }
        p = &(*p)->hash_next;
    }
    
    struct io_uring *ring = forwarder_runtime_get_ring(fwd->runtime);
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (sqe) {
        io_uring_prep_close(sqe, session->session_fd);
        sqe->user_data = (uint64_t)(uintptr_t)&session->close_op;
        forwarder_runtime_inc_active(fwd->runtime);
        session->pending_ops++;
    } else {
        /* Fallback: close synchronously and free if possible. */
        close(session->session_fd);
    }
    
    if (session->pending_ops <= 0) {
        if (session->active_counted) {
            __atomic_fetch_sub(&fwd->active_sessions, 1u, __ATOMIC_RELAXED);
        }
        DATA_FREE(fwd, session);
        udp_forwarder_unref(fwd);
    }
}

static void on_session_close_cqe(struct io_uring_cqe *cqe, void *ctx) {
    (void)cqe;
    struct udp_close_op *op = (struct udp_close_op *)ctx;
    udp_session_release_op(op->session);
}

static void cleanup_expired_sessions(struct udp_forwarder *fwd) {
    time_t now = time(NULL);
    for (int i = 0; i < UDP_SESSION_HASH_SIZE; i++) {
        struct udp_session *session = fwd->session_hash[i];
        while (session) {
            struct udp_session *next = session->hash_next;
            if (now - session->last_activity > UDP_SESSION_TIMEOUT_SEC) {
                close_session(session);
            }
            session = next;
        }
    }
}

static void on_client_send_cqe(struct io_uring_cqe *cqe, void *ctx) {
    (void)cqe;
    struct udp_send_op *op = (struct udp_send_op *)ctx;
    udp_session_release_op(op->session);
}

static void on_target_send_cqe(struct io_uring_cqe *cqe, void *ctx) {
    (void)cqe;
    struct udp_send_op *op = (struct udp_send_op *)ctx;
    udp_session_release_op(op->session);
}

static void submit_target_send(struct udp_session *session, char *data, size_t len) {
    if (session->closing) return;
    
    struct udp_forwarder *fwd = session->forwarder;
    struct io_uring *ring = forwarder_runtime_get_ring(fwd->runtime);
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) return;
    
    struct udp_send_op *op = &session->target_send_op;
    memcpy(op->buf, data, len);
    
    op->iov.iov_base = op->buf;
    op->iov.iov_len = len;
    
    memset(&op->msg, 0, sizeof(op->msg));
    op->msg.msg_iov = &op->iov;
    op->msg.msg_iovlen = 1;
    
    io_uring_prep_sendmsg(sqe, session->session_fd, &op->msg, 0);
    sqe->user_data = (uint64_t)(uintptr_t)op;
    forwarder_runtime_inc_active(fwd->runtime);
    session->pending_ops++;
}

static void submit_client_send(struct udp_session *session, char *data, size_t len) {
    if (session->closing) return;
    
    struct udp_forwarder *fwd = session->forwarder;
    struct io_uring *ring = forwarder_runtime_get_ring(fwd->runtime);
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) return;
    
    struct udp_send_op *op = &session->client_send_op;
    memcpy(op->buf, data, len);
    
    op->iov.iov_base = op->buf;
    op->iov.iov_len = len;
    
    memset(&op->msg, 0, sizeof(op->msg));
    op->msg.msg_iov = &op->iov;
    op->msg.msg_iovlen = 1;
    op->msg.msg_name = &session->client_addr;
    op->msg.msg_namelen = session->client_addr_len;
    
    io_uring_prep_sendmsg(sqe, fwd->listen_fd, &op->msg, 0);
    sqe->user_data = (uint64_t)(uintptr_t)op;
    forwarder_runtime_inc_active(fwd->runtime);
    session->pending_ops++;
}

static void on_target_recv_cqe(struct io_uring_cqe *cqe, void *ctx) {
    struct udp_recv_op *op = (struct udp_recv_op *)ctx;
    struct udp_session *session = op->session;
    struct udp_forwarder *fwd = session->forwarder;
    
    if (session->closing) {
        udp_session_release_op(session);
        return;
    }
    
    udp_session_release_op(session);
    
    if (cqe->res <= 0) {
        if (cqe->res != -ECANCELED && !fwd->stop_requested) {
            close_session(session);
        }
        return;
    }
    
    session->last_activity = time(NULL);
    
    if (fwd->enable_stats) {
        __atomic_fetch_add(&fwd->bytes_out, cqe->res, __ATOMIC_RELAXED);
    }
    
    submit_client_send(session, op->buf, cqe->res);
    submit_target_recv(session);
}

static void submit_target_recv(struct udp_session *session) {
    if (session->closing) return;
    
    struct udp_forwarder *fwd = session->forwarder;
    struct io_uring *ring = forwarder_runtime_get_ring(fwd->runtime);
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) return;
    
    struct udp_recv_op *op = &session->target_recv_op;
    
    op->iov.iov_base = op->buf;
    op->iov.iov_len = UDP_BUF_SIZE;
    
    memset(&op->msg, 0, sizeof(op->msg));
    op->msg.msg_iov = &op->iov;
    op->msg.msg_iovlen = 1;
    
    io_uring_prep_recvmsg(sqe, session->session_fd, &op->msg, 0);
    sqe->user_data = (uint64_t)(uintptr_t)op;
    forwarder_runtime_inc_active(fwd->runtime);
    session->pending_ops++;
}

static void on_listener_recv_cqe(struct io_uring_cqe *cqe, void *ctx) {
    struct udp_recv_op *op = (struct udp_recv_op *)ctx;
    struct udp_forwarder *fwd = op->forwarder;
    forwarder_runtime_dec_active(fwd->runtime);
    
    if (cqe->res <= 0) {
        if (cqe->res != -ECANCELED && !fwd->stop_requested) {
            submit_listener_recv(fwd);
        }
        udp_forwarder_unref(fwd);
        return;
    }
    
    cleanup_expired_sessions(fwd);
    
    if (fwd->enable_stats) {
        __atomic_fetch_add(&fwd->bytes_in, cqe->res, __ATOMIC_RELAXED);
    }
    
    unsigned int h = hash_addr(&op->src_addr);
    struct udp_session *session = fwd->session_hash[h];
    while (session) {
        if (addrs_equal(&session->client_addr, &op->src_addr)) break;
        session = session->hash_next;
    }
    
    if (!session) {
        session = (struct udp_session *)DATA_ALLOC(fwd, sizeof(struct udp_session));
        if (session) {
            memset(session, 0, sizeof(*session));
            session->forwarder = fwd;
            session->client_addr = op->src_addr;
            session->client_addr_len = op->msg.msg_namelen;
            session->last_activity = time(NULL);
            session->pending_ops = 0;
            
            int domain = (fwd->family == ADDR_FAMILY_IPV6) ? AF_INET6 : AF_INET;
            session->session_fd = socket(domain, SOCK_DGRAM, 0);
            
            if (session->session_fd >= 0) {
                if (connect(session->session_fd, (struct sockaddr *)&fwd->cached_dest_addr, 
                           (fwd->family == ADDR_FAMILY_IPV6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)) == 0) {
                    
                    fwd->ref_count++; // Increment forwarder ref count
                    session->hash_next = fwd->session_hash[h];
                    fwd->session_hash[h] = session;
                    
                    __atomic_fetch_add(&fwd->active_sessions, 1u, __ATOMIC_RELAXED);
                    session->active_counted = 1;
                    
                    session->target_recv_op.base.callback = on_target_recv_cqe;
                    session->target_recv_op.session = session;
                    session->target_recv_op.forwarder = fwd;
                    
                    session->target_send_op.base.callback = on_target_send_cqe;
                    session->target_send_op.session = session;
                    session->target_send_op.forwarder = fwd;
                    
                    session->client_send_op.base.callback = on_client_send_cqe;
                    session->client_send_op.session = session;
                    session->client_send_op.forwarder = fwd;
                    
                    session->close_op.base.callback = on_session_close_cqe;
                    session->close_op.session = session;
                    session->close_op.forwarder = fwd;
                    
                    submit_target_recv(session);
                } else {
                    close(session->session_fd);
                    DATA_FREE(fwd, session);
                    session = NULL;
                }
            } else {
                DATA_FREE(fwd, session);
                session = NULL;
            }
        }
    }
    
    if (session && !session->closing) {
        session->last_activity = time(NULL);
        submit_target_send(session, op->buf, cqe->res);
    }
    
    submit_listener_recv(fwd);
    udp_forwarder_unref(fwd);
}

static void submit_listener_recv(struct udp_forwarder *fwd) {
    if (fwd->stop_requested) return;
    
    struct io_uring *ring = forwarder_runtime_get_ring(fwd->runtime);
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) return;
    
    fwd->ref_count++; // Increment for in-flight listener recv
    struct udp_recv_op *op = &fwd->listener_recv_op;
    
    op->iov.iov_base = op->buf;
    op->iov.iov_len = UDP_BUF_SIZE;
    
    memset(&op->msg, 0, sizeof(op->msg));
    op->msg.msg_name = &op->src_addr;
    op->msg.msg_namelen = sizeof(op->src_addr);
    op->msg.msg_iov = &op->iov;
    op->msg.msg_iovlen = 1;
    op->msg.msg_control = op->control;
    op->msg.msg_controllen = sizeof(op->control);
    
    io_uring_prep_recvmsg(sqe, fwd->listen_fd, &op->msg, 0);
    sqe->user_data = (uint64_t)(uintptr_t)op;
    forwarder_runtime_inc_active(fwd->runtime);
}

static void set_forwarder_error(int *out_error, int error_code) {
    if (out_error) *out_error = error_code;
}

static int cache_destination_addr(struct sockaddr_storage *dest, addr_family_t family, const char *target_address, uint16_t target_port) {
    memset(dest, 0, sizeof(*dest));
    if (family == ADDR_FAMILY_IPV6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)dest;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(target_port);
        if (inet_pton(AF_INET6, target_address, &addr6->sin6_addr) <= 0) return -1;
    } else {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)dest;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(target_port);
        if (inet_pton(AF_INET, target_address, &addr4->sin_addr) <= 0) return -1;
    }
    return 0;
}

static void build_listen_addr(struct sockaddr_storage *addr, addr_family_t family, uint16_t listen_port) {
    memset(addr, 0, sizeof(*addr));
    if (family == ADDR_FAMILY_IPV4) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(listen_port);
        addr4->sin_addr.s_addr = INADDR_ANY;
    } else {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(listen_port);
        addr6->sin6_addr = in6addr_any;
    }
}

udp_forwarder_t *udp_forwarder_create_on_runtime(
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
    (void)connect_timeout_ms;
    if (!runtime) {
        set_forwarder_error(out_error, FORWARDER_ERROR_UNKNOWN);
        return NULL;
    }

    forwarder_allocator_t allocator = forwarder_runtime_get_allocator(runtime);
    struct udp_forwarder *fwd = (struct udp_forwarder *)allocator.malloc_cb(allocator.ctx, sizeof(struct udp_forwarder));
    if (!fwd) {
        set_forwarder_error(out_error, FORWARDER_ERROR_MALLOC);
        return NULL;
    }
    memset(fwd, 0, sizeof(*fwd));
    fwd->runtime = runtime;
    
    size_t target_len = strlen(target_address);
    fwd->target_address = (char *)DATA_ALLOC(fwd, target_len + 1);
    if (!fwd->target_address) {
        set_forwarder_error(out_error, FORWARDER_ERROR_MALLOC);
        DATA_FREE(fwd, fwd);
        return NULL;
    }
    memcpy(fwd->target_address, target_address, target_len + 1);
    
    fwd->target_port = target_port;
    fwd->family = family;
    fwd->listen_port = listen_port;
    fwd->enable_stats = enable_stats;
    fwd->max_connections = max_connections;
    fwd->listener_recv_op.base.callback = on_listener_recv_cqe;
    fwd->listener_recv_op.forwarder = fwd;

    int rc = cache_destination_addr(&fwd->cached_dest_addr, family, fwd->target_address, fwd->target_port);
    if (rc != 0) {
        set_forwarder_error(out_error, FORWARDER_ERROR_INVALID_ADDRESS);
        DATA_FREE(fwd, fwd->target_address);
        DATA_FREE(fwd, fwd);
        return NULL;
    }

    int domain = (family == ADDR_FAMILY_IPV6) ? AF_INET6 : AF_INET;
    fwd->listen_fd = socket(domain, SOCK_DGRAM, 0);
    if (fwd->listen_fd < 0) {
        set_forwarder_error(out_error, FORWARDER_ERROR_UNKNOWN);
        DATA_FREE(fwd, fwd->target_address);
        DATA_FREE(fwd, fwd);
        return NULL;
    }
    
    int opt = 1;
    setsockopt(fwd->listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fwd->listen_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    struct sockaddr_storage addr;
    build_listen_addr(&addr, family, listen_port);
    
    socklen_t addr_len = (family == ADDR_FAMILY_IPV6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    if (bind(fwd->listen_fd, (struct sockaddr *)&addr, addr_len) < 0) {
        if (errno == EADDRINUSE) set_forwarder_error(out_error, FORWARDER_ERROR_ADDRESS_IN_USE);
        else if (errno == EACCES) set_forwarder_error(out_error, FORWARDER_ERROR_PERMISSION_DENIED);
        else set_forwarder_error(out_error, FORWARDER_ERROR_BIND);
        
        close(fwd->listen_fd);
        DATA_FREE(fwd, fwd->target_address);
        DATA_FREE(fwd, fwd);
        return NULL;
    }

    fwd->ref_count = 1;
    set_forwarder_error(out_error, FORWARDER_OK);
    return fwd;
}

int udp_forwarder_start(udp_forwarder_t *forwarder) {
    if (!forwarder) return -1;
    forwarder->started = 1;
    submit_listener_recv(forwarder);
    forwarder_runtime_wake(forwarder->runtime);
    return 0;
}

void udp_forwarder_request_stop(udp_forwarder_t *forwarder) {
    if (!forwarder || forwarder->stop_requested) return;
    forwarder->stop_requested = 1;
    
    struct io_uring *ring = forwarder_runtime_get_ring(forwarder->runtime);
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (sqe) {
        io_uring_prep_cancel(sqe, &forwarder->listener_recv_op, 0);
        sqe->user_data = 0;
    }
    
    /* Close all active sessions. Iterate carefully: close_session removes the
     * session from the hash table, so we must capture next before calling it. */
    for (int i = 0; i < UDP_SESSION_HASH_SIZE; i++) {
        struct udp_session *session = forwarder->session_hash[i];
        while (session) {
            struct udp_session *next = session->hash_next;
            close_session(session);
            session = next;
        }
    }
    
    forwarder_runtime_wake(forwarder->runtime);
}

void udp_forwarder_destroy(udp_forwarder_t *forwarder) {
    if (!forwarder) return;
    forwarder->destroy_requested = 1;
    
    /* Close the listen fd. Session cleanup is handled by close_session's
     * async CQE callbacks — the memory is freed when the close CQE fires.
     * The caller must ensure the runtime stays alive until then. */
    if (forwarder->listen_fd >= 0) {
        close(forwarder->listen_fd);
        forwarder->listen_fd = -1;
    }
    
    if (!forwarder->stop_requested) {
        forwarder->stop_requested = 1;
        struct io_uring *ring = forwarder_runtime_get_ring(forwarder->runtime);
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        if (sqe) {
            io_uring_prep_cancel(sqe, &forwarder->listener_recv_op, 0);
            sqe->user_data = 0;
            forwarder_runtime_wake(forwarder->runtime);
        }
    }
    
    udp_forwarder_unref(forwarder);
}

traffic_stats_t udp_forwarder_get_stats(udp_forwarder_t *forwarder) {
    traffic_stats_t stats = {0};
    if (forwarder && forwarder->enable_stats) {
        stats.bytes_in = __atomic_load_n(&forwarder->bytes_in, __ATOMIC_RELAXED);
        stats.bytes_out = __atomic_load_n(&forwarder->bytes_out, __ATOMIC_RELAXED);
    }
    if (forwarder) {
        stats.active_sessions = __atomic_load_n(&forwarder->active_sessions, __ATOMIC_RELAXED);
        stats.listen_port = forwarder->listen_port;
    }
    return stats;
}
