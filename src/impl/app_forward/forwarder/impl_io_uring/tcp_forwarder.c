#include "io_uring_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define TCP_BUFFER_SIZE 16384
#define TCP_INSPECTION_TIMEOUT_MS 2000

struct tcp_connection;

struct accept_operation {
    struct uring_op op;
    struct tcp_forwarder *forwarder;
    struct sockaddr_storage address;
    socklen_t address_len;
};

struct connect_operation {
    struct uring_op op;
    struct tcp_connection *connection;
    int pending;
};

struct timeout_operation {
    struct uring_op op;
    struct tcp_connection *connection;
    int pending;
};

enum timer_purpose {
    TIMER_WAKE_DELAY,
    TIMER_RETRY_DELAY,
    TIMER_INSPECTION,
};

struct timer_operation {
    struct uring_op op;
    struct tcp_connection *connection;
    struct __kernel_timespec timeout;
    enum timer_purpose purpose;
    int pending;
};

struct stream_operation {
    struct uring_op op;
    struct tcp_connection *connection;
    int source_fd;
    int destination_fd;
    int client_to_target;
    int sending;
    int finished;
    int pending;
    size_t length;
    size_t offset;
    unsigned char buffer[TCP_BUFFER_SIZE];
};

struct tcp_forwarder {
    forwarder_runtime_t *runtime;
    int listen_fd;
    char *target_address;
    struct sockaddr_storage destination;
    socklen_t destination_len;
    addr_family_t family;
    uint32_t connect_timeout_ms;
    unsigned int max_connections;
    unsigned long long bytes_in;
    unsigned long long bytes_out;
    unsigned int active_sessions;
    uint16_t listen_port;
    int enable_stats;
    int started;
    int stop_requested;
    int destroy_requested;
    int accept_pending;
    struct accept_operation accept_op;
    struct tcp_connection *connections;
    tcp_first_packet_cb_t first_packet_cb;
    void *first_packet_user_data;
    tcp_first_packet_destroy_cb_t first_packet_destroy_cb;
    tcp_wol_trigger_mode_t wol_mode;
    uint32_t wol_wake_delay_ms;
    uint32_t wol_retry_interval_ms;
    uint32_t wol_retry_window_ms;
    tcp_wol_trigger_cb_t wol_trigger_cb;
};

struct tcp_connection {
    struct tcp_forwarder *forwarder;
    struct tcp_connection *next;
    int client_fd;
    int target_fd;
    int closing;
    int pending;
    int target_connected;
    int first_packet_inspected;
    int retry_enabled;
    uint64_t retry_deadline_ms;
    int connect_result;
    int connect_timed_out;
    struct connect_operation connect_op;
    struct timeout_operation timeout_op;
    struct __kernel_timespec timeout;
    struct timer_operation action_timer;
    struct timer_operation inspection_timer;
    struct stream_operation client_to_target;
    struct stream_operation target_to_client;
};

static void *fwd_alloc(struct tcp_forwarder *fwd, size_t size)
{
    forwarder_allocator_t allocator = forwarder_runtime_get_allocator(fwd->runtime);
    return allocator.malloc_cb(allocator.ctx, size);
}

static void fwd_free(struct tcp_forwarder *fwd, void *pointer)
{
    if (pointer == NULL)
        return;
    forwarder_allocator_t allocator = forwarder_runtime_get_allocator(fwd->runtime);
    allocator.free_cb(allocator.ctx, pointer);
}

static struct io_uring_sqe *get_sqe(struct tcp_forwarder *fwd)
{
    struct io_uring *ring = forwarder_runtime_get_ring(fwd->runtime);
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (sqe == NULL) {
        if (io_uring_submit(ring) < 0)
            return NULL;
        sqe = io_uring_get_sqe(ring);
    }
    return sqe;
}

static void free_forwarder_storage(struct tcp_forwarder *fwd)
{
    if (fwd->first_packet_destroy_cb != NULL && fwd->first_packet_user_data != NULL) {
        fwd->first_packet_destroy_cb(fwd->first_packet_user_data);
        fwd->first_packet_user_data = NULL;
    }
    fwd_free(fwd, fwd->target_address);
    fwd_free(fwd, fwd);
}

static void maybe_free_forwarder(struct tcp_forwarder *fwd)
{
    if (fwd->destroy_requested && !fwd->accept_pending && fwd->connections == NULL)
        free_forwarder_storage(fwd);
}

static void remove_connection(struct tcp_connection *connection)
{
    struct tcp_forwarder *fwd = connection->forwarder;
    struct tcp_connection **cursor = &fwd->connections;
    while (*cursor != NULL) {
        if (*cursor == connection) {
            *cursor = connection->next;
            break;
        }
        cursor = &(*cursor)->next;
    }
    __atomic_fetch_sub(&fwd->active_sessions, 1u, __ATOMIC_RELAXED);
    fwd_free(fwd, connection);
    maybe_free_forwarder(fwd);
}

static void maybe_free_connection(struct tcp_connection *connection)
{
    if (connection->closing && connection->pending == 0)
        remove_connection(connection);
}

static void cancel_operation(struct tcp_forwarder *fwd, void *operation);

static void terminate_connection(struct tcp_connection *connection)
{
    if (connection == NULL || connection->closing)
        return;
    connection->closing = 1;
    if (connection->connect_op.pending)
        cancel_operation(connection->forwarder, &connection->connect_op);
    if (connection->timeout_op.pending)
        cancel_operation(connection->forwarder, &connection->timeout_op);
    if (connection->action_timer.pending)
        cancel_operation(connection->forwarder, &connection->action_timer);
    if (connection->inspection_timer.pending)
        cancel_operation(connection->forwarder, &connection->inspection_timer);
    if (connection->client_to_target.pending)
        cancel_operation(connection->forwarder, &connection->client_to_target);
    if (connection->target_to_client.pending)
        cancel_operation(connection->forwarder, &connection->target_to_client);
    if (connection->client_fd >= 0) {
        shutdown(connection->client_fd, SHUT_RDWR);
        close(connection->client_fd);
        connection->client_fd = -1;
    }
    if (connection->target_fd >= 0) {
        shutdown(connection->target_fd, SHUT_RDWR);
        close(connection->target_fd);
        connection->target_fd = -1;
    }
    maybe_free_connection(connection);
}

static void maybe_finish_streams(struct tcp_connection *connection)
{
    if (connection->client_to_target.finished && connection->target_to_client.finished)
        terminate_connection(connection);
}

static int submit_stream(struct stream_operation *operation);
static int start_connect(struct tcp_connection *connection);
static void maybe_start_forwarding(struct tcp_connection *connection);

static uint64_t monotonic_millis(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (uint64_t)now.tv_sec * 1000ULL + (uint64_t)now.tv_nsec / 1000000ULL;
}

static void set_timeout_ms(struct __kernel_timespec *timeout, uint32_t timeout_ms)
{
    timeout->tv_sec = timeout_ms / 1000;
    timeout->tv_nsec = (timeout_ms % 1000) * 1000000ULL;
}

static int submit_timer(struct timer_operation *operation, enum timer_purpose purpose, uint32_t timeout_ms);

static void finish_inspection(struct tcp_connection *connection, int result)
{
    struct tcp_forwarder *fwd = connection->forwarder;
    if (result != TCP_INSPECTION_ALLOW && result != TCP_INSPECTION_ALLOW_WAKE) {
        terminate_connection(connection);
        return;
    }

    connection->first_packet_inspected = 1;
    if (connection->inspection_timer.pending)
        cancel_operation(fwd, &connection->inspection_timer);
    if (connection->client_to_target.pending)
        cancel_operation(fwd, &connection->client_to_target);
    if (connection->target_to_client.pending)
        cancel_operation(fwd, &connection->target_to_client);

    if (!connection->target_connected && fwd->wol_mode == TCP_WOL_ON_PROTOCOL) {
        if (result == TCP_INSPECTION_ALLOW_WAKE) {
            connection->retry_enabled = 1;
            connection->retry_deadline_ms = monotonic_millis() + fwd->wol_retry_window_ms;
            if (submit_timer(&connection->action_timer, TIMER_WAKE_DELAY, fwd->wol_wake_delay_ms) != 0)
                terminate_connection(connection);
        } else if (start_connect(connection) != 0) {
            terminate_connection(connection);
        }
        return;
    }
    maybe_start_forwarding(connection);
}

static void stream_complete(struct io_uring_cqe *cqe, void *runtime_context)
{
    (void)runtime_context;
    struct stream_operation *operation = (struct stream_operation *)io_uring_cqe_get_data(cqe);
    struct tcp_connection *connection = operation->connection;
    struct tcp_forwarder *fwd = connection->forwarder;
    operation->pending = 0;
    connection->pending--;
    forwarder_runtime_dec_active(fwd->runtime);

    if (connection->closing) {
        maybe_free_connection(connection);
        return;
    }

    if (!operation->sending) {
        if (cqe->res == 0) {
            if (!connection->first_packet_inspected && fwd->first_packet_cb != NULL) {
                terminate_connection(connection);
                return;
            }
            operation->finished = 1;
            if (operation->length > 0) {
                maybe_start_forwarding(connection);
                return;
            }
            if (operation->destination_fd >= 0)
                (void)shutdown(operation->destination_fd, SHUT_WR);
            maybe_finish_streams(connection);
            return;
        }
        if (cqe->res < 0) {
            if (cqe->res == -ECANCELED && connection->first_packet_inspected) {
                maybe_start_forwarding(connection);
                return;
            }
            terminate_connection(connection);
            return;
        }
        size_t received = (size_t)cqe->res;
        if (fwd->enable_stats) {
            if (operation->client_to_target)
                __atomic_fetch_add(&fwd->bytes_in, received, __ATOMIC_RELAXED);
            else
                __atomic_fetch_add(&fwd->bytes_out, received, __ATOMIC_RELAXED);
        }

        if (!connection->first_packet_inspected && fwd->first_packet_cb != NULL) {
            operation->length += received;
            int result = fwd->first_packet_cb(fwd->first_packet_user_data, operation->buffer,
                                              operation->length, operation->client_to_target);
            if (result == TCP_INSPECTION_NEED_MORE) {
                if (submit_stream(operation) != 0)
                    terminate_connection(connection);
                return;
            }
            finish_inspection(connection, result);
            return;
        }

        if (connection->first_packet_inspected && operation->length > 0) {
            operation->length += received;
            maybe_start_forwarding(connection);
            return;
        }

        operation->length = received;
        operation->offset = 0;
        operation->sending = 1;
    } else {
        if (cqe->res <= 0) {
            terminate_connection(connection);
            return;
        }
        operation->offset += (size_t)cqe->res;
        if (operation->offset == operation->length) {
            operation->sending = 0;
            operation->length = 0;
            if (operation->finished) {
                if (operation->destination_fd >= 0)
                    (void)shutdown(operation->destination_fd, SHUT_WR);
                maybe_finish_streams(connection);
                return;
            }
        }
    }

    if (submit_stream(operation) != 0)
        terminate_connection(connection);
}

static int submit_stream(struct stream_operation *operation)
{
    struct tcp_connection *connection = operation->connection;
    if (operation->pending || connection->closing)
        return 0;
    size_t buffered = 0;
    if (!operation->sending &&
        ((!connection->first_packet_inspected && connection->forwarder->first_packet_cb != NULL) ||
         operation->length > 0)) {
        buffered = operation->length;
        if (buffered >= sizeof(operation->buffer))
            return -ENOBUFS;
    }
    struct io_uring_sqe *sqe = get_sqe(connection->forwarder);
    if (sqe == NULL)
        return -ENOMEM;
    operation->op.callback = stream_complete;
    if (operation->sending) {
        io_uring_prep_send(sqe, operation->destination_fd,
                           operation->buffer + operation->offset,
                           operation->length - operation->offset, MSG_NOSIGNAL);
    } else {
        io_uring_prep_recv(sqe, operation->source_fd, operation->buffer + buffered,
                           sizeof(operation->buffer) - buffered, 0);
    }
    io_uring_sqe_set_data(sqe, operation);
    operation->pending = 1;
    connection->pending++;
    forwarder_runtime_inc_active(connection->forwarder->runtime);
    return 0;
}

static void maybe_finish_connect(struct tcp_connection *connection);

static void timeout_complete(struct io_uring_cqe *cqe, void *runtime_context)
{
    (void)runtime_context;
    struct timeout_operation *operation = (struct timeout_operation *)io_uring_cqe_get_data(cqe);
    struct tcp_connection *connection = operation->connection;
    operation->pending = 0;
    connection->pending--;
    forwarder_runtime_dec_active(connection->forwarder->runtime);
    if (cqe->res == -ETIME)
        connection->connect_timed_out = 1;
    if (connection->closing) {
        maybe_free_connection(connection);
        return;
    }
    maybe_finish_connect(connection);
}

static void connect_complete(struct io_uring_cqe *cqe, void *runtime_context)
{
    (void)runtime_context;
    struct connect_operation *operation = (struct connect_operation *)io_uring_cqe_get_data(cqe);
    struct tcp_connection *connection = operation->connection;
    operation->pending = 0;
    connection->connect_result = cqe->res;
    connection->pending--;
    forwarder_runtime_dec_active(connection->forwarder->runtime);

    if (connection->closing) {
        maybe_free_connection(connection);
        return;
    }
    maybe_finish_connect(connection);
}

static void handle_connect_failure(struct tcp_connection *connection)
{
    struct tcp_forwarder *fwd = connection->forwarder;
    if (connection->target_fd >= 0) {
        close(connection->target_fd);
        connection->target_fd = -1;
    }
    connection->client_to_target.destination_fd = -1;
    connection->target_to_client.source_fd = -1;

    uint64_t now = monotonic_millis();
    if (!connection->retry_enabled || now >= connection->retry_deadline_ms ||
        now + fwd->wol_retry_interval_ms >= connection->retry_deadline_ms) {
        terminate_connection(connection);
        return;
    }
    if (submit_timer(&connection->action_timer, TIMER_RETRY_DELAY, fwd->wol_retry_interval_ms) != 0)
        terminate_connection(connection);
}

static void maybe_finish_connect(struct tcp_connection *connection)
{
    if (connection->connect_op.pending || connection->timeout_op.pending)
        return;
    if (connection->connect_result < 0 || connection->connect_timed_out) {
        handle_connect_failure(connection);
        return;
    }
    connection->target_connected = 1;
    maybe_start_forwarding(connection);
}

static int start_connect(struct tcp_connection *connection)
{
    struct tcp_forwarder *fwd = connection->forwarder;
    if (connection->closing)
        return -ECANCELED;
    if (connection->retry_enabled && monotonic_millis() >= connection->retry_deadline_ms)
        return -ETIMEDOUT;

    int domain = fwd->destination.ss_family;
    connection->target_fd = socket(domain, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (connection->target_fd < 0)
        return -errno;
    connection->client_to_target.destination_fd = connection->target_fd;
    connection->target_to_client.source_fd = connection->target_fd;
    connection->connect_result = -EINPROGRESS;
    connection->connect_timed_out = 0;

    struct io_uring_sqe *connect_sqe = get_sqe(fwd);
    if (connect_sqe == NULL)
        return -ENOMEM;
    connection->connect_op.op.callback = connect_complete;
    io_uring_prep_connect(connect_sqe, connection->target_fd,
                          (const struct sockaddr *)&fwd->destination,
                          fwd->destination_len);
    io_uring_sqe_set_data(connect_sqe, &connection->connect_op);
    connection->connect_op.pending = 1;
    connection->pending++;
    forwarder_runtime_inc_active(fwd->runtime);

    if (fwd->connect_timeout_ms > 0) {
        struct io_uring_sqe *timeout_sqe = get_sqe(fwd);
        if (timeout_sqe == NULL) {
            return -ENOMEM;
        }
        connect_sqe->flags |= IOSQE_IO_LINK;
        set_timeout_ms(&connection->timeout, fwd->connect_timeout_ms);
        connection->timeout_op.op.callback = timeout_complete;
        io_uring_prep_link_timeout(timeout_sqe, &connection->timeout, 0);
        io_uring_sqe_set_data(timeout_sqe, &connection->timeout_op);
        connection->timeout_op.pending = 1;
        connection->pending++;
        forwarder_runtime_inc_active(fwd->runtime);
    }
    return 0;
}

static void timer_complete(struct io_uring_cqe *cqe, void *runtime_context)
{
    (void)runtime_context;
    struct timer_operation *operation = (struct timer_operation *)io_uring_cqe_get_data(cqe);
    struct tcp_connection *connection = operation->connection;
    operation->pending = 0;
    connection->pending--;
    forwarder_runtime_dec_active(connection->forwarder->runtime);

    if (connection->closing) {
        maybe_free_connection(connection);
        return;
    }
    if (cqe->res != -ETIME)
        return;
    if (operation->purpose == TIMER_INSPECTION) {
        if (!connection->first_packet_inspected)
            terminate_connection(connection);
        return;
    }
    if (connection->retry_enabled && monotonic_millis() >= connection->retry_deadline_ms) {
        terminate_connection(connection);
        return;
    }
    if (start_connect(connection) != 0)
        handle_connect_failure(connection);
}

static int submit_timer(struct timer_operation *operation, enum timer_purpose purpose, uint32_t timeout_ms)
{
    struct tcp_connection *connection = operation->connection;
    if (operation->pending || connection->closing)
        return -EBUSY;
    if (timeout_ms == 0) {
        if (purpose == TIMER_INSPECTION)
            return -EINVAL;
        return start_connect(connection);
    }
    struct io_uring_sqe *sqe = get_sqe(connection->forwarder);
    if (sqe == NULL)
        return -ENOMEM;
    operation->op.callback = timer_complete;
    operation->purpose = purpose;
    set_timeout_ms(&operation->timeout, timeout_ms);
    io_uring_prep_timeout(sqe, &operation->timeout, 0, 0);
    io_uring_sqe_set_data(sqe, operation);
    operation->pending = 1;
    connection->pending++;
    forwarder_runtime_inc_active(connection->forwarder->runtime);
    return 0;
}

static void maybe_start_forwarding(struct tcp_connection *connection)
{
    struct tcp_forwarder *fwd = connection->forwarder;
    if (connection->closing || !connection->target_connected ||
        connection->client_to_target.pending || connection->target_to_client.pending)
        return;

    if (!connection->first_packet_inspected && fwd->first_packet_cb != NULL) {
        if (!connection->inspection_timer.pending &&
            submit_timer(&connection->inspection_timer, TIMER_INSPECTION, TCP_INSPECTION_TIMEOUT_MS) != 0) {
            terminate_connection(connection);
            return;
        }
    }

    struct stream_operation *client = &connection->client_to_target;
    struct stream_operation *target = &connection->target_to_client;
    if (connection->first_packet_inspected && client->length > 0) {
        client->sending = 1;
        client->offset = 0;
    }
    if (connection->first_packet_inspected && target->length > 0) {
        target->sending = 1;
        target->offset = 0;
    }
    int client_rc = 0;
    int target_rc = 0;
    if (client->length > 0 || !client->finished)
        client_rc = submit_stream(client);
    else if (client->destination_fd >= 0)
        (void)shutdown(client->destination_fd, SHUT_WR);
    if (target->length > 0 || !target->finished)
        target_rc = submit_stream(target);
    else if (target->destination_fd >= 0)
        (void)shutdown(target->destination_fd, SHUT_WR);
    if (client_rc != 0 || target_rc != 0)
        terminate_connection(connection);
}

static int start_connection(struct tcp_forwarder *fwd, int client_fd)
{
    if (fwd->max_connections > 0 &&
        __atomic_load_n(&fwd->active_sessions, __ATOMIC_RELAXED) >= fwd->max_connections) {
        close(client_fd);
        return 0;
    }

    struct tcp_connection *connection = fwd_alloc(fwd, sizeof(*connection));
    if (connection == NULL) {
        close(client_fd);
        return -ENOMEM;
    }
    memset(connection, 0, sizeof(*connection));
    connection->forwarder = fwd;
    connection->client_fd = client_fd;
    connection->target_fd = -1;
    connection->client_to_target.connection = connection;
    connection->client_to_target.source_fd = client_fd;
    connection->client_to_target.destination_fd = -1;
    connection->client_to_target.client_to_target = 1;
    connection->target_to_client.connection = connection;
    connection->target_to_client.source_fd = -1;
    connection->target_to_client.destination_fd = client_fd;
    connection->connect_op.connection = connection;
    connection->timeout_op.connection = connection;
    connection->action_timer.connection = connection;
    connection->inspection_timer.connection = connection;
    connection->next = fwd->connections;
    fwd->connections = connection;
    __atomic_fetch_add(&fwd->active_sessions, 1u, __ATOMIC_RELAXED);

    int rc;
    if (fwd->wol_mode == TCP_WOL_ON_PROTOCOL && fwd->first_packet_cb != NULL) {
        rc = submit_timer(&connection->inspection_timer, TIMER_INSPECTION, TCP_INSPECTION_TIMEOUT_MS);
        if (rc == 0)
            rc = submit_stream(&connection->client_to_target);
    } else if (fwd->wol_mode == TCP_WOL_ON_CONNECT) {
        connection->retry_enabled = 1;
        connection->retry_deadline_ms = monotonic_millis() + fwd->wol_retry_window_ms;
        int wake_queued = fwd->wol_trigger_cb != NULL && fwd->wol_trigger_cb(fwd->first_packet_user_data) != 0;
        rc = 0;
        if (fwd->first_packet_cb != NULL)
            rc = submit_stream(&connection->client_to_target);
        if (rc == 0)
            rc = submit_timer(&connection->action_timer, TIMER_WAKE_DELAY,
                              wake_queued ? fwd->wol_wake_delay_ms : 0);
    } else {
        rc = start_connect(connection);
    }
    if (rc != 0)
        terminate_connection(connection);
    return rc;
}

static int submit_accept(struct tcp_forwarder *fwd);
static void cancel_operation(struct tcp_forwarder *fwd, void *operation);

static void accept_complete(struct io_uring_cqe *cqe, void *runtime_context)
{
    (void)runtime_context;
    struct accept_operation *operation = (struct accept_operation *)io_uring_cqe_get_data(cqe);
    struct tcp_forwarder *fwd = operation->forwarder;
    fwd->accept_pending = 0;
    forwarder_runtime_dec_active(fwd->runtime);

    int accepted_fd = cqe->res;
    if (!fwd->stop_requested && !fwd->destroy_requested) {
        if (submit_accept(fwd) != 0)
            fwd->stop_requested = 1;
        if (accepted_fd >= 0)
            (void)start_connection(fwd, accepted_fd);
    } else {
        if (accepted_fd >= 0)
            close(accepted_fd);
        int listen_fd = __atomic_exchange_n(&fwd->listen_fd, -1, __ATOMIC_ACQ_REL);
        if (listen_fd >= 0)
            close(listen_fd);
        struct tcp_connection *connection = fwd->connections;
        while (connection != NULL) {
            struct tcp_connection *next = connection->next;
            terminate_connection(connection);
            connection = next;
        }
    }
    maybe_free_forwarder(fwd);
}

static int submit_accept(struct tcp_forwarder *fwd)
{
    struct io_uring_sqe *sqe = get_sqe(fwd);
    if (sqe == NULL)
        return -ENOMEM;
    fwd->accept_op.op.callback = accept_complete;
    fwd->accept_op.forwarder = fwd;
    fwd->accept_op.address_len = sizeof(fwd->accept_op.address);
    io_uring_prep_accept(sqe, fwd->listen_fd,
                         (struct sockaddr *)&fwd->accept_op.address,
                         &fwd->accept_op.address_len,
                         SOCK_CLOEXEC);
    io_uring_sqe_set_data(sqe, &fwd->accept_op);
    fwd->accept_pending = 1;
    forwarder_runtime_inc_active(fwd->runtime);
    return 0;
}

static forwarder_error_t map_bind_error(int error_number)
{
    if (error_number == EADDRINUSE)
        return FORWARDER_ERROR_ADDRESS_IN_USE;
    if (error_number == EACCES)
        return FORWARDER_ERROR_PERMISSION_DENIED;
    return FORWARDER_ERROR_BIND;
}

static int make_address(struct sockaddr_storage *storage, socklen_t *length,
                        addr_family_t family, const char *address, uint16_t port)
{
    memset(storage, 0, sizeof(*storage));
    if (family == ADDR_FAMILY_IPV6) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)storage;
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons(port);
        if (inet_pton(AF_INET6, address, &ipv6->sin6_addr) != 1)
            return -1;
        *length = sizeof(*ipv6);
    } else {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)storage;
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons(port);
        if (inet_pton(AF_INET, address, &ipv4->sin_addr) != 1)
            return -1;
        *length = sizeof(*ipv4);
    }
    return 0;
}

static void set_error(int *out_error, int value)
{
    if (out_error != NULL)
        *out_error = value;
}

tcp_forwarder_t *tcp_forwarder_create_on_runtime(
    forwarder_runtime_t *runtime, uint16_t listen_port,
    const char *target_address, uint16_t target_port, addr_family_t family,
    int enable_stats, uint32_t connect_timeout_ms, uint32_t max_connections,
    int *out_error)
{
    if (runtime == NULL || target_address == NULL) {
        set_error(out_error, FORWARDER_ERROR_UNKNOWN);
        return NULL;
    }
    forwarder_allocator_t allocator = forwarder_runtime_get_allocator(runtime);
    struct tcp_forwarder *fwd = allocator.malloc_cb(allocator.ctx, sizeof(*fwd));
    if (fwd == NULL) {
        set_error(out_error, FORWARDER_ERROR_MALLOC);
        return NULL;
    }
    memset(fwd, 0, sizeof(*fwd));
    fwd->runtime = runtime;
    fwd->listen_fd = -1;
    fwd->family = family;
    fwd->listen_port = listen_port;
    fwd->enable_stats = enable_stats;
    fwd->connect_timeout_ms = connect_timeout_ms;
    fwd->max_connections = max_connections;
    size_t target_length = strlen(target_address) + 1;
    fwd->target_address = fwd_alloc(fwd, target_length);
    if (fwd->target_address == NULL) {
        set_error(out_error, FORWARDER_ERROR_MALLOC);
        fwd_free(fwd, fwd);
        return NULL;
    }
    memcpy(fwd->target_address, target_address, target_length);

    if (make_address(&fwd->destination, &fwd->destination_len, family,
                     fwd->target_address, target_port) != 0) {
        set_error(out_error, FORWARDER_ERROR_INVALID_ADDRESS);
        free_forwarder_storage(fwd);
        return NULL;
    }

    int domain = family == ADDR_FAMILY_IPV4 ? AF_INET : AF_INET6;
    fwd->listen_fd = socket(domain, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fwd->listen_fd < 0) {
        set_error(out_error, FORWARDER_ERROR_UNKNOWN);
        free_forwarder_storage(fwd);
        return NULL;
    }
    int reuse = 1;
    (void)setsockopt(fwd->listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    if (domain == AF_INET6) {
        int v6_only = family == ADDR_FAMILY_IPV6;
        (void)setsockopt(fwd->listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6_only, sizeof(v6_only));
    }

    struct sockaddr_storage listen_address;
    socklen_t listen_length;
    memset(&listen_address, 0, sizeof(listen_address));
    if (domain == AF_INET) {
        struct sockaddr_in *address = (struct sockaddr_in *)&listen_address;
        address->sin_family = AF_INET;
        address->sin_addr.s_addr = htonl(INADDR_ANY);
        address->sin_port = htons(listen_port);
        listen_length = sizeof(*address);
    } else {
        struct sockaddr_in6 *address = (struct sockaddr_in6 *)&listen_address;
        address->sin6_family = AF_INET6;
        address->sin6_addr = in6addr_any;
        address->sin6_port = htons(listen_port);
        listen_length = sizeof(*address);
    }
    if (bind(fwd->listen_fd, (struct sockaddr *)&listen_address, listen_length) != 0) {
        int error_number = errno;
        close(fwd->listen_fd);
        set_error(out_error, map_bind_error(error_number));
        free_forwarder_storage(fwd);
        return NULL;
    }
    set_error(out_error, FORWARDER_OK);
    return fwd;
}

static forwarder_error_t map_start_error(int result)
{
    if (result == -ENOMEM)
        return FORWARDER_ERROR_MALLOC;
    if (result < 0)
    {
        int error_number = -result;
        if (error_number == EADDRINUSE || error_number == EACCES)
            return map_bind_error(error_number);
    }
    return FORWARDER_ERROR_UNKNOWN;
}

forwarder_error_t tcp_forwarder_start(tcp_forwarder_t *fwd)
{
    if (fwd == NULL || fwd->started)
        return FORWARDER_ERROR_UNKNOWN;
    if (listen(fwd->listen_fd, 128) != 0) {
        int error_number = errno;
        return map_bind_error(error_number);
    }
    int rc = submit_accept(fwd);
    if (rc == 0) {
        fwd->started = 1;
        rc = io_uring_submit(forwarder_runtime_get_ring(fwd->runtime));
        if (rc >= 0)
            return FORWARDER_OK;
    }
    return map_start_error(rc);
}

void tcp_forwarder_request_stop(tcp_forwarder_t *fwd)
{
    if (fwd == NULL || __atomic_exchange_n(&fwd->stop_requested, 1, __ATOMIC_ACQ_REL))
        return;
    int domain = fwd->family == ADDR_FAMILY_IPV4 ? AF_INET : AF_INET6;
    int wake_fd = socket(domain, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (wake_fd >= 0) {
        if (domain == AF_INET) {
            struct sockaddr_in address = {0};
            address.sin_family = AF_INET;
            address.sin_port = htons(fwd->listen_port);
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            (void)connect(wake_fd, (const struct sockaddr *)&address, sizeof(address));
        } else {
            struct sockaddr_in6 address = {0};
            address.sin6_family = AF_INET6;
            address.sin6_port = htons(fwd->listen_port);
            address.sin6_addr = in6addr_loopback;
            (void)connect(wake_fd, (const struct sockaddr *)&address, sizeof(address));
        }
        close(wake_fd);
    }
    (void)forwarder_runtime_wake(fwd->runtime);
}

static void cancel_operation(struct tcp_forwarder *fwd, void *operation)
{
    struct io_uring_sqe *sqe = get_sqe(fwd);
    if (sqe == NULL)
        return;
    io_uring_prep_cancel(sqe, operation, 0);
    io_uring_sqe_set_data(sqe, NULL);
}

void tcp_forwarder_destroy(tcp_forwarder_t *fwd)
{
    if (fwd == NULL || fwd->destroy_requested)
        return;
    fwd->destroy_requested = 1;
    tcp_forwarder_request_stop(fwd);
    if (fwd->accept_pending)
        cancel_operation(fwd, &fwd->accept_op);
    struct tcp_connection *connection = fwd->connections;
    while (connection != NULL) {
        struct tcp_connection *next = connection->next;
        terminate_connection(connection);
        connection = next;
    }
    (void)io_uring_submit(forwarder_runtime_get_ring(fwd->runtime));
    maybe_free_forwarder(fwd);
}

traffic_stats_t tcp_forwarder_get_stats(tcp_forwarder_t *fwd)
{
    traffic_stats_t stats = {0};
    if (fwd == NULL)
        return stats;
    if (fwd->enable_stats) {
        stats.bytes_in = __atomic_load_n(&fwd->bytes_in, __ATOMIC_RELAXED);
        stats.bytes_out = __atomic_load_n(&fwd->bytes_out, __ATOMIC_RELAXED);
    }
    stats.active_sessions = __atomic_load_n(&fwd->active_sessions, __ATOMIC_RELAXED);
    stats.listen_port = fwd->listen_port;
    return stats;
}

void tcp_forwarder_set_first_packet_cb(tcp_forwarder_t *fwd,
                                       tcp_first_packet_cb_t callback,
                                       void *user_data,
                                       tcp_first_packet_destroy_cb_t destroy_cb)
{
    if (fwd != NULL) {
        fwd->first_packet_cb = callback;
        fwd->first_packet_user_data = user_data;
        fwd->first_packet_destroy_cb = destroy_cb;
    }
}

void tcp_forwarder_set_wol_policy(tcp_forwarder_t *fwd,
                                  tcp_wol_trigger_mode_t mode,
                                  uint32_t wake_delay_ms,
                                  uint32_t retry_interval_ms,
                                  uint32_t retry_window_ms,
                                  tcp_wol_trigger_cb_t trigger_cb)
{
    if (fwd == NULL)
        return;
    fwd->wol_mode = mode;
    fwd->wol_wake_delay_ms = wake_delay_ms;
    fwd->wol_retry_interval_ms = retry_interval_ms;
    fwd->wol_retry_window_ms = retry_window_ms;
    fwd->wol_trigger_cb = trigger_cb;
}
