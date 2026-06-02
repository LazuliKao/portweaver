#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "io_uring_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define TCP_BUF_SIZE 65536

struct tcp_forwarder;
struct tcp_conn;

struct tcp_accept_op {
    struct uring_op base;
    struct tcp_forwarder *forwarder;
};

struct tcp_connect_op {
    struct uring_op base;
    struct tcp_conn *conn;
};

struct tcp_recv_op {
    struct uring_op base;
    struct tcp_conn *conn;
    int is_client; 
};

struct tcp_send_op {
    struct uring_op base;
    struct tcp_conn *conn;
    int is_client; 
};

struct tcp_splice_op {
    struct uring_op base;
    struct tcp_conn *conn;
    int is_client_to_target; 
    int pipe_rd;
    int pipe_wr;
    int src_fd;
    int dst_fd;
    int step;
};

struct tcp_close_op {
    struct uring_op base;
    struct tcp_conn *conn;
    int fd;
};

struct tcp_timeout_op {
    struct uring_op base;
    struct tcp_conn *conn;
    struct __kernel_timespec ts;
};

struct tcp_forwarder {
    forwarder_runtime_t *runtime;
    int listen_fd;
    char *target_address;
    uint16_t target_port;
    uint16_t listen_port;
    addr_family_t family;
    struct sockaddr_storage cached_dest_addr;
    int enable_stats;
    uint32_t connect_timeout_ms;
    int started;
    int stop_requested;
    int destroy_requested;
    unsigned long long bytes_in;
    unsigned long long bytes_out;
    unsigned int active_sessions;
    
    struct tcp_accept_op accept_op;
};

struct tcp_conn {
    struct tcp_forwarder *forwarder;
    int client_fd;
    int target_fd;
    int c2t_pipe[2];
    int t2c_pipe[2];
    int connected;
    int client_eof;
    int target_eof;
    int closing;
    int closed_count;
    int active_counted;
    
    struct tcp_connect_op connect_op;
    struct tcp_recv_op client_recv_op;
    struct tcp_recv_op target_recv_op;
    struct tcp_send_op client_send_op;
    struct tcp_send_op target_send_op;
    
    struct tcp_splice_op c2t_splice1_op; 
    struct tcp_splice_op c2t_splice2_op; 
    struct tcp_splice_op t2c_splice1_op; 
    struct tcp_splice_op t2c_splice2_op; 
    
    struct tcp_close_op client_close_op;
    struct tcp_close_op target_close_op;
    struct tcp_timeout_op timeout_op;
    
    char client_recv_buf[TCP_BUF_SIZE];
    char target_recv_buf[TCP_BUF_SIZE];
};

#define DATA_ALLOC(fwd, sz) (forwarder_runtime_get_allocator((fwd)->runtime).malloc_cb(forwarder_runtime_get_allocator((fwd)->runtime).ctx, (sz)))
#define DATA_FREE(fwd, ptr) \
    do { \
        if (ptr) { \
            forwarder_runtime_get_allocator((fwd)->runtime).free_cb(forwarder_runtime_get_allocator((fwd)->runtime).ctx, (ptr)); \
        } \
    } while(0)

static void tcp_conn_close(struct tcp_conn *conn);
static void submit_recv(struct tcp_conn *conn, int is_client);
static void submit_splice1(struct tcp_conn *conn, int is_c2t);

static void on_client_close_cqe(struct io_uring_cqe *cqe, void *ctx) {
    struct tcp_close_op *op = (struct tcp_close_op *)ctx;
    struct tcp_conn *conn = op->conn;
    forwarder_runtime_dec_active(conn->forwarder->runtime);
    conn->closed_count++;
    if (conn->closed_count >= 2) {
        if (conn->active_counted) {
            __atomic_fetch_sub(&conn->forwarder->active_sessions, 1u, __ATOMIC_RELAXED);
        }
        DATA_FREE(conn->forwarder, conn);
    }
}

static void on_target_close_cqe(struct io_uring_cqe *cqe, void *ctx) {
    struct tcp_close_op *op = (struct tcp_close_op *)ctx;
    struct tcp_conn *conn = op->conn;
    forwarder_runtime_dec_active(conn->forwarder->runtime);
    conn->closed_count++;
    if (conn->closed_count >= 2) {
        if (conn->active_counted) {
            __atomic_fetch_sub(&conn->forwarder->active_sessions, 1u, __ATOMIC_RELAXED);
        }
        DATA_FREE(conn->forwarder, conn);
    }
}

static void tcp_conn_close(struct tcp_conn *conn) {
    if (conn->closing) return;
    conn->closing = 1;
    
    struct io_uring *ring = forwarder_runtime_get_ring(conn->forwarder->runtime);
    
    if (!conn->forwarder->enable_stats) {
        if (conn->c2t_pipe[0] != -1) close(conn->c2t_pipe[0]);
        if (conn->c2t_pipe[1] != -1) close(conn->c2t_pipe[1]);
        if (conn->t2c_pipe[0] != -1) close(conn->t2c_pipe[0]);
        if (conn->t2c_pipe[1] != -1) close(conn->t2c_pipe[1]);
    }
    
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (sqe) {
        io_uring_prep_close(sqe, conn->client_fd);
        sqe->user_data = (uint64_t)(uintptr_t)&conn->client_close_op;
        forwarder_runtime_inc_active(conn->forwarder->runtime);
    } else {
        close(conn->client_fd);
        on_client_close_cqe(NULL, &conn->client_close_op); 
    }
    
    if (conn->target_fd >= 0) {
        sqe = io_uring_get_sqe(ring);
        if (sqe) {
            io_uring_prep_close(sqe, conn->target_fd);
            sqe->user_data = (uint64_t)(uintptr_t)&conn->target_close_op;
            forwarder_runtime_inc_active(conn->forwarder->runtime);
        } else {
            close(conn->target_fd);
            on_target_close_cqe(NULL, &conn->target_close_op);
        }
    } else {
        on_target_close_cqe(NULL, &conn->target_close_op);
    }
}

static void on_send_cqe(struct io_uring_cqe *cqe, void *ctx) {
    struct tcp_send_op *op = (struct tcp_send_op *)ctx;
    struct tcp_conn *conn = op->conn;
    forwarder_runtime_dec_active(conn->forwarder->runtime);
    
    if (cqe->res < 0) {
        tcp_conn_close(conn);
        return;
    }
    
    submit_recv(conn, !op->is_client);
}

static void submit_send(struct tcp_conn *conn, int is_client, int len) {
    struct io_uring *ring = forwarder_runtime_get_ring(conn->forwarder->runtime);
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        tcp_conn_close(conn);
        return;
    }
    
    struct tcp_send_op *op = is_client ? &conn->client_send_op : &conn->target_send_op;
    char *buf = is_client ? conn->target_recv_buf : conn->client_recv_buf; 
    int fd = is_client ? conn->client_fd : conn->target_fd;
    
    io_uring_prep_send(sqe, fd, buf, len, 0);
    sqe->user_data = (uint64_t)(uintptr_t)op;
    forwarder_runtime_inc_active(conn->forwarder->runtime);
}

static void on_recv_cqe(struct io_uring_cqe *cqe, void *ctx) {
    struct tcp_recv_op *op = (struct tcp_recv_op *)ctx;
    struct tcp_conn *conn = op->conn;
    forwarder_runtime_dec_active(conn->forwarder->runtime);
    
    if (cqe->res <= 0) {
        if (op->is_client) conn->client_eof = 1;
        else conn->target_eof = 1;
        tcp_conn_close(conn);
        return;
    }
    
    if (conn->forwarder->enable_stats) {
        if (op->is_client) {
            __atomic_fetch_add(&conn->forwarder->bytes_in, cqe->res, __ATOMIC_RELAXED);
        } else {
            __atomic_fetch_add(&conn->forwarder->bytes_out, cqe->res, __ATOMIC_RELAXED);
        }
    }
    
    submit_send(conn, !op->is_client, cqe->res);
}

static void submit_recv(struct tcp_conn *conn, int is_client) {
    struct io_uring *ring = forwarder_runtime_get_ring(conn->forwarder->runtime);
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        tcp_conn_close(conn);
        return;
    }
    
    struct tcp_recv_op *op = is_client ? &conn->client_recv_op : &conn->target_recv_op;
    char *buf = is_client ? conn->client_recv_buf : conn->target_recv_buf;
    int fd = is_client ? conn->client_fd : conn->target_fd;
    
    io_uring_prep_recv(sqe, fd, buf, TCP_BUF_SIZE, 0);
    sqe->user_data = (uint64_t)(uintptr_t)op;
    forwarder_runtime_inc_active(conn->forwarder->runtime);
}

static void submit_splice2(struct tcp_conn *conn, int is_c2t, int len);

static void on_splice2_cqe(struct io_uring_cqe *cqe, void *ctx) {
    struct tcp_splice_op *op = (struct tcp_splice_op *)ctx;
    struct tcp_conn *conn = op->conn;
    forwarder_runtime_dec_active(conn->forwarder->runtime);
    
    if (cqe->res <= 0) {
        tcp_conn_close(conn);
        return;
    }
    
    submit_splice1(conn, op->is_client_to_target);
}

static void submit_splice2(struct tcp_conn *conn, int is_c2t, int len) {
    struct io_uring *ring = forwarder_runtime_get_ring(conn->forwarder->runtime);
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        tcp_conn_close(conn);
        return;
    }
    
    struct tcp_splice_op *op = is_c2t ? &conn->c2t_splice2_op : &conn->t2c_splice2_op;
    io_uring_prep_splice(sqe, op->pipe_rd, -1, op->dst_fd, -1, len, SPLICE_F_MOVE);
    sqe->user_data = (uint64_t)(uintptr_t)op;
    forwarder_runtime_inc_active(conn->forwarder->runtime);
}

static void on_splice1_cqe(struct io_uring_cqe *cqe, void *ctx) {
    struct tcp_splice_op *op = (struct tcp_splice_op *)ctx;
    struct tcp_conn *conn = op->conn;
    forwarder_runtime_dec_active(conn->forwarder->runtime);
    
    if (cqe->res <= 0) {
        tcp_conn_close(conn);
        return;
    }
    
    submit_splice2(conn, op->is_client_to_target, cqe->res);
}

static void submit_splice1(struct tcp_conn *conn, int is_c2t) {
    struct io_uring *ring = forwarder_runtime_get_ring(conn->forwarder->runtime);
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) {
        tcp_conn_close(conn);
        return;
    }
    
    struct tcp_splice_op *op = is_c2t ? &conn->c2t_splice1_op : &conn->t2c_splice1_op;
    io_uring_prep_splice(sqe, op->src_fd, -1, op->pipe_wr, -1, TCP_BUF_SIZE, SPLICE_F_MOVE);
    sqe->user_data = (uint64_t)(uintptr_t)op;
    forwarder_runtime_inc_active(conn->forwarder->runtime);
}

static void on_connect_timeout_cqe(struct io_uring_cqe *cqe, void *ctx) {
    struct tcp_timeout_op *op = (struct tcp_timeout_op *)ctx;
    struct tcp_conn *conn = op->conn;
    forwarder_runtime_dec_active(conn->forwarder->runtime);
    
    if (conn->connected) return;
    
    /* Closing target_fd cancels the in-flight connect with -ECANCELED.
     * The connect CQE handler will then call tcp_conn_close(). */
    close(conn->target_fd);
    conn->target_fd = -1;
}

static void on_connect_cqe(struct io_uring_cqe *cqe, void *ctx) {
    struct tcp_connect_op *op = (struct tcp_connect_op *)ctx;
    struct tcp_conn *conn = op->conn;
    forwarder_runtime_dec_active(conn->forwarder->runtime);
    
    if (cqe->res < 0) {
        tcp_conn_close(conn);
        return;
    }
    
    conn->connected = 1;
    
    /* Cancel the pending connect timeout to prevent use-after-free.
     * The timeout callback checks conn->connected and is a no-op,
     * but we must ensure the timeout CQE arrives before conn is freed. */
    if (conn->forwarder->connect_timeout_ms > 0) {
        struct io_uring *ring = forwarder_runtime_get_ring(conn->forwarder->runtime);
        struct io_uring_sqe *timeout_sqe = io_uring_get_sqe(ring);
        if (timeout_sqe) {
            io_uring_prep_timeout_remove(timeout_sqe, (uint64_t)(uintptr_t)&conn->timeout_op, 0);
            timeout_sqe->user_data = (uint64_t)(uintptr_t)&conn->timeout_op;
            forwarder_runtime_inc_active(conn->forwarder->runtime);
        }
    }
    
    if (conn->forwarder->enable_stats) {
        submit_recv(conn, 1);
        submit_recv(conn, 0);
    } else {
        submit_splice1(conn, 1);
        submit_splice1(conn, 0);
    }
}

static void submit_accept(struct tcp_forwarder *fwd);

static void on_accept_cqe(struct io_uring_cqe *cqe, void *ctx) {
    struct tcp_accept_op *op = (struct tcp_accept_op *)ctx;
    struct tcp_forwarder *fwd = op->forwarder;
    forwarder_runtime_dec_active(fwd->runtime);
    
    if (cqe->res < 0) {
        if (cqe->res != -ECANCELED && !fwd->stop_requested) {
            submit_accept(fwd);
        }
        return;
    }
    
    int client_fd = cqe->res;
    
    if (fwd->stop_requested) {
        close(client_fd);
        return;
    }
    
    struct tcp_conn *conn = (struct tcp_conn *)DATA_ALLOC(fwd, sizeof(struct tcp_conn));
    if (!conn) {
        close(client_fd);
        submit_accept(fwd);
        return;
    }
    
    memset(conn, 0, sizeof(*conn));
    conn->forwarder = fwd;
    conn->client_fd = client_fd;
    conn->target_fd = -1;
    conn->c2t_pipe[0] = -1;
    conn->c2t_pipe[1] = -1;
    conn->t2c_pipe[0] = -1;
    conn->t2c_pipe[1] = -1;
    
    conn->connect_op.base.callback = on_connect_cqe;
    conn->connect_op.conn = conn;
    
    conn->client_recv_op.base.callback = on_recv_cqe;
    conn->client_recv_op.conn = conn;
    conn->client_recv_op.is_client = 1;
    
    conn->target_recv_op.base.callback = on_recv_cqe;
    conn->target_recv_op.conn = conn;
    conn->target_recv_op.is_client = 0;
    
    conn->client_send_op.base.callback = on_send_cqe;
    conn->client_send_op.conn = conn;
    conn->client_send_op.is_client = 1;
    
    conn->target_send_op.base.callback = on_send_cqe;
    conn->target_send_op.conn = conn;
    conn->target_send_op.is_client = 0;
    
    conn->client_close_op.base.callback = on_client_close_cqe;
    conn->client_close_op.conn = conn;
    
    conn->target_close_op.base.callback = on_target_close_cqe;
    conn->target_close_op.conn = conn;
    
    if (!fwd->enable_stats) {
        if (pipe(conn->c2t_pipe) < 0 || pipe(conn->t2c_pipe) < 0) {
            close(client_fd);
            DATA_FREE(fwd, conn);
            submit_accept(fwd);
            return;
        }
        fcntl(conn->c2t_pipe[0], F_SETFL, O_NONBLOCK);
        fcntl(conn->c2t_pipe[1], F_SETFL, O_NONBLOCK);
        fcntl(conn->t2c_pipe[0], F_SETFL, O_NONBLOCK);
        fcntl(conn->t2c_pipe[1], F_SETFL, O_NONBLOCK);
        
        conn->c2t_splice1_op.base.callback = on_splice1_cqe;
        conn->c2t_splice1_op.conn = conn;
        conn->c2t_splice1_op.is_client_to_target = 1;
        conn->c2t_splice1_op.src_fd = conn->client_fd;
        conn->c2t_splice1_op.pipe_wr = conn->c2t_pipe[1];
        
        conn->c2t_splice2_op.base.callback = on_splice2_cqe;
        conn->c2t_splice2_op.conn = conn;
        conn->c2t_splice2_op.is_client_to_target = 1;
        conn->c2t_splice2_op.pipe_rd = conn->c2t_pipe[0];
        
        conn->t2c_splice1_op.base.callback = on_splice1_cqe;
        conn->t2c_splice1_op.conn = conn;
        conn->t2c_splice1_op.is_client_to_target = 0;
        conn->t2c_splice1_op.pipe_wr = conn->t2c_pipe[1];
        
        conn->t2c_splice2_op.base.callback = on_splice2_cqe;
        conn->t2c_splice2_op.conn = conn;
        conn->t2c_splice2_op.is_client_to_target = 0;
        conn->t2c_splice2_op.pipe_rd = conn->t2c_pipe[0];
        conn->t2c_splice2_op.dst_fd = conn->client_fd;
    }
    
    int domain = (fwd->family == ADDR_FAMILY_IPV6) ? AF_INET6 : AF_INET;
    conn->target_fd = socket(domain, SOCK_STREAM, 0);
    if (conn->target_fd < 0) {
        close(client_fd);
        DATA_FREE(fwd, conn);
        submit_accept(fwd);
        return;
    }
    
    if (!fwd->enable_stats) {
        conn->c2t_splice2_op.dst_fd = conn->target_fd;
        conn->t2c_splice1_op.src_fd = conn->target_fd;
    }
    
    struct io_uring *ring = forwarder_runtime_get_ring(fwd->runtime);
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (sqe) {
        io_uring_prep_connect(sqe, conn->target_fd, (struct sockaddr *)&fwd->cached_dest_addr, 
                              (fwd->family == ADDR_FAMILY_IPV6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in));
        sqe->user_data = (uint64_t)(uintptr_t)&conn->connect_op;
        forwarder_runtime_inc_active(fwd->runtime);
        
        __atomic_fetch_add(&fwd->active_sessions, 1u, __ATOMIC_RELAXED);
        conn->active_counted = 1;
        
        if (fwd->connect_timeout_ms > 0) {
            conn->timeout_op.base.callback = on_connect_timeout_cqe;
            conn->timeout_op.conn = conn;
            conn->timeout_op.ts.tv_sec = fwd->connect_timeout_ms / 1000;
            conn->timeout_op.ts.tv_nsec = (fwd->connect_timeout_ms % 1000) * 1000000L;
            
            struct io_uring_sqe *timeout_sqe = io_uring_get_sqe(ring);
            if (timeout_sqe) {
                io_uring_prep_timeout(timeout_sqe, &conn->timeout_op.ts, 0, 0);
                timeout_sqe->user_data = (uint64_t)(uintptr_t)&conn->timeout_op;
                forwarder_runtime_inc_active(fwd->runtime);
            }
        }
    } else {
        close(client_fd);
        close(conn->target_fd);
        DATA_FREE(fwd, conn);
    }
    
    submit_accept(fwd);
}

static void submit_accept(struct tcp_forwarder *fwd) {
    if (fwd->stop_requested) return;
    
    struct io_uring *ring = forwarder_runtime_get_ring(fwd->runtime);
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe) return;
    
    io_uring_prep_accept(sqe, fwd->listen_fd, NULL, NULL, 0);
    sqe->user_data = (uint64_t)(uintptr_t)&fwd->accept_op;
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
    if (!runtime) {
        set_forwarder_error(out_error, FORWARDER_ERROR_UNKNOWN);
        return NULL;
    }

    forwarder_allocator_t allocator = forwarder_runtime_get_allocator(runtime);
    struct tcp_forwarder *fwd = (struct tcp_forwarder *)allocator.malloc_cb(allocator.ctx, sizeof(struct tcp_forwarder));
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
    fwd->connect_timeout_ms = connect_timeout_ms;
    fwd->accept_op.base.callback = on_accept_cqe;
    fwd->accept_op.forwarder = fwd;

    int rc = cache_destination_addr(&fwd->cached_dest_addr, family, fwd->target_address, fwd->target_port);
    if (rc != 0) {
        set_forwarder_error(out_error, FORWARDER_ERROR_INVALID_ADDRESS);
        DATA_FREE(fwd, fwd->target_address);
        DATA_FREE(fwd, fwd);
        return NULL;
    }

    int domain = (family == ADDR_FAMILY_IPV6) ? AF_INET6 : AF_INET;
    fwd->listen_fd = socket(domain, SOCK_STREAM, 0);
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

    set_forwarder_error(out_error, FORWARDER_OK);
    return fwd;
}

int tcp_forwarder_start(tcp_forwarder_t *forwarder) {
    if (!forwarder) return -1;
    if (listen(forwarder->listen_fd, 128) < 0) return -1;
    
    forwarder->started = 1;
    submit_accept(forwarder);
    return 0;
}

void tcp_forwarder_request_stop(tcp_forwarder_t *forwarder) {
    if (!forwarder || forwarder->stop_requested) return;
    forwarder->stop_requested = 1;
    
    struct io_uring *ring = forwarder_runtime_get_ring(forwarder->runtime);
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (sqe) {
        io_uring_prep_cancel(sqe, &forwarder->accept_op, 0);
        sqe->user_data = 0;
    }
}

void tcp_forwarder_destroy(tcp_forwarder_t *forwarder) {
    if (!forwarder) return;
    forwarder->destroy_requested = 1;
    
    if (forwarder->listen_fd >= 0) {
        close(forwarder->listen_fd);
        forwarder->listen_fd = -1;
    }
    
    DATA_FREE(forwarder, forwarder->target_address);
    DATA_FREE(forwarder, forwarder);
}

traffic_stats_t tcp_forwarder_get_stats(tcp_forwarder_t *forwarder) {
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
