#include "io_uring_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

#ifdef DEBUG
#define UDP_SESSION_TIMEOUT_SECONDS 5
#else
#define UDP_SESSION_TIMEOUT_SECONDS 60
#endif
#define UDP_BUFFER_SIZE 65536
#define UDP_SESSION_HASH_SIZE 1024
#define UDP_MAX_SESSIONS 4000

struct udp_session;

struct receive_operation {
    struct uring_op op;
    struct udp_forwarder *forwarder;
    struct udp_session *session;
    struct msghdr message;
    struct iovec iovec;
    struct sockaddr_storage address;
    unsigned char buffer[UDP_BUFFER_SIZE];
};

struct timer_operation {
    struct uring_op op;
    struct udp_session *session;
    uint64_t expirations;
};

struct send_operation {
    struct uring_op op;
    struct udp_forwarder *forwarder;
    struct udp_session *session;
    struct msghdr message;
    struct iovec iovec;
    struct sockaddr_storage destination;
    size_t length;
    unsigned char buffer[];
};

struct udp_session {
    struct udp_forwarder *forwarder;
    struct udp_session *list_next;
    struct udp_session *hash_next;
    struct sockaddr_storage client_address;
    socklen_t client_address_len;
    int socket_fd;
    int timer_fd;
    int closing;
    int pending;
    struct receive_operation receive_op;
    struct timer_operation timer_op;
};

struct udp_forwarder {
    forwarder_runtime_t *runtime;
    int listen_fd;
    char *target_address;
    struct sockaddr_storage destination;
    socklen_t destination_len;
    addr_family_t family;
    unsigned int max_sessions;
    unsigned long long bytes_in;
    unsigned long long bytes_out;
    unsigned int active_sessions;
    uint16_t listen_port;
    int enable_stats;
    int started;
    int stop_requested;
    int destroy_requested;
    int receive_pending;
    struct receive_operation receive_op;
    struct udp_session *sessions;
    struct udp_session *session_hash[UDP_SESSION_HASH_SIZE];
};

static void *fwd_alloc(struct udp_forwarder *fwd, size_t size)
{
    forwarder_allocator_t allocator = forwarder_runtime_get_allocator(fwd->runtime);
    return allocator.malloc_cb(allocator.ctx, size);
}

static void fwd_free(struct udp_forwarder *fwd, void *pointer)
{
    if (pointer == NULL)
        return;
    forwarder_allocator_t allocator = forwarder_runtime_get_allocator(fwd->runtime);
    allocator.free_cb(allocator.ctx, pointer);
}

static struct io_uring_sqe *get_sqe(struct udp_forwarder *fwd)
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

static uint32_t address_hash(const struct sockaddr *address)
{
    uint32_t hash = 5381;
    if (address->sa_family == AF_INET) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address;
        hash = ((hash << 5) + hash) ^ ipv4->sin_addr.s_addr;
        hash = ((hash << 5) + hash) ^ ipv4->sin_port;
    } else {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)address;
        const unsigned char *bytes = (const unsigned char *)&ipv6->sin6_addr;
        for (unsigned int index = 0; index < 16; ++index)
            hash = ((hash << 5) + hash) ^ bytes[index];
        hash = ((hash << 5) + hash) ^ ipv6->sin6_port;
        hash = ((hash << 5) + hash) ^ ipv6->sin6_scope_id;
    }
    return hash % UDP_SESSION_HASH_SIZE;
}

static int addresses_equal(const struct sockaddr *left, const struct sockaddr *right)
{
    if (left->sa_family != right->sa_family)
        return 0;
    if (left->sa_family == AF_INET) {
        const struct sockaddr_in *a = (const struct sockaddr_in *)left;
        const struct sockaddr_in *b = (const struct sockaddr_in *)right;
        return a->sin_port == b->sin_port && a->sin_addr.s_addr == b->sin_addr.s_addr;
    }
    const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)left;
    const struct sockaddr_in6 *b = (const struct sockaddr_in6 *)right;
    return a->sin6_port == b->sin6_port && a->sin6_scope_id == b->sin6_scope_id &&
           memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(a->sin6_addr)) == 0;
}

static void free_forwarder_storage(struct udp_forwarder *fwd)
{
    fwd_free(fwd, fwd->target_address);
    fwd_free(fwd, fwd);
}

static void maybe_free_forwarder(struct udp_forwarder *fwd)
{
    if (fwd->destroy_requested && !fwd->receive_pending && fwd->sessions == NULL)
        free_forwarder_storage(fwd);
}

static void remove_session(struct udp_session *session)
{
    struct udp_forwarder *fwd = session->forwarder;
    struct udp_session **cursor = &fwd->sessions;
    while (*cursor != NULL) {
        if (*cursor == session) {
            *cursor = session->list_next;
            break;
        }
        cursor = &(*cursor)->list_next;
    }
    uint32_t hash = address_hash((const struct sockaddr *)&session->client_address);
    cursor = &fwd->session_hash[hash];
    while (*cursor != NULL) {
        if (*cursor == session) {
            *cursor = session->hash_next;
            break;
        }
        cursor = &(*cursor)->hash_next;
    }
    __atomic_fetch_sub(&fwd->active_sessions, 1u, __ATOMIC_RELAXED);
    fwd_free(fwd, session);
    maybe_free_forwarder(fwd);
}

static void maybe_free_session(struct udp_session *session)
{
    if (session->closing && session->pending == 0)
        remove_session(session);
}

static void cancel_operation(struct udp_forwarder *fwd, void *operation);

static void close_session(struct udp_session *session)
{
    if (session == NULL || session->closing)
        return;
    session->closing = 1;
    cancel_operation(session->forwarder, &session->receive_op);
    cancel_operation(session->forwarder, &session->timer_op);
    if (session->socket_fd >= 0) {
        close(session->socket_fd);
        session->socket_fd = -1;
    }
    if (session->timer_fd >= 0) {
        close(session->timer_fd);
        session->timer_fd = -1;
    }
    (void)io_uring_submit(forwarder_runtime_get_ring(session->forwarder->runtime));
    maybe_free_session(session);
}

static void touch_session(struct udp_session *session)
{
    struct itimerspec timeout = {0};
    timeout.it_value.tv_sec = UDP_SESSION_TIMEOUT_SECONDS;
    (void)timerfd_settime(session->timer_fd, 0, &timeout, NULL);
}

static int submit_session_receive(struct udp_session *session);

static void send_complete(struct io_uring_cqe *cqe, void *runtime_context)
{
    (void)runtime_context;
    struct send_operation *operation = (struct send_operation *)io_uring_cqe_get_data(cqe);
    struct udp_forwarder *fwd = operation->forwarder;
    struct udp_session *session = operation->session;
    if (session != NULL) {
        session->pending--;
        forwarder_runtime_dec_active(fwd->runtime);
    }
    fwd_free(fwd, operation);
    if (session != NULL)
        maybe_free_session(session);
}

static int submit_send(struct udp_session *session, int socket_fd,
                       const struct sockaddr *destination, socklen_t destination_len,
                       const unsigned char *data, size_t length)
{
    struct udp_forwarder *fwd = session->forwarder;
    struct send_operation *operation = fwd_alloc(fwd, sizeof(*operation) + length);
    if (operation == NULL)
        return -ENOMEM;
    memset(operation, 0, sizeof(*operation));
    operation->op.callback = send_complete;
    operation->forwarder = fwd;
    operation->session = session;
    operation->length = length;
    memcpy(&operation->destination, destination, destination_len);
    if (length > 0)
        memcpy(operation->buffer, data, length);
    operation->iovec.iov_base = operation->buffer;
    operation->iovec.iov_len = length;
    operation->message.msg_name = &operation->destination;
    operation->message.msg_namelen = destination_len;
    operation->message.msg_iov = &operation->iovec;
    operation->message.msg_iovlen = 1;

    struct io_uring_sqe *sqe = get_sqe(fwd);
    if (sqe == NULL) {
        fwd_free(fwd, operation);
        return -ENOMEM;
    }
    io_uring_prep_sendmsg(sqe, socket_fd, &operation->message, MSG_NOSIGNAL);
    io_uring_sqe_set_data(sqe, operation);
    session->pending++;
    forwarder_runtime_inc_active(fwd->runtime);
    return 0;
}

static void session_receive_complete(struct io_uring_cqe *cqe, void *runtime_context)
{
    (void)runtime_context;
    struct receive_operation *operation = (struct receive_operation *)io_uring_cqe_get_data(cqe);
    struct udp_session *session = operation->session;
    struct udp_forwarder *fwd = session->forwarder;
    session->pending--;
    forwarder_runtime_dec_active(fwd->runtime);

    if (session->closing) {
        maybe_free_session(session);
        return;
    }
    if (cqe->res >= 0) {
        size_t length = (size_t)cqe->res;
        if (fwd->enable_stats)
            __atomic_fetch_add(&fwd->bytes_out, length, __ATOMIC_RELAXED);
        touch_session(session);
        (void)submit_send(session, fwd->listen_fd,
                          (const struct sockaddr *)&session->client_address,
                          session->client_address_len, operation->buffer, length);
    } else if (cqe->res != -EINTR && cqe->res != -EAGAIN) {
        close_session(session);
        return;
    }
    if (submit_session_receive(session) != 0)
        close_session(session);
}

static int submit_session_receive(struct udp_session *session)
{
    struct receive_operation *operation = &session->receive_op;
    struct io_uring_sqe *sqe = get_sqe(session->forwarder);
    if (sqe == NULL)
        return -ENOMEM;
    memset(&operation->message, 0, sizeof(operation->message));
    operation->op.callback = session_receive_complete;
    operation->forwarder = session->forwarder;
    operation->session = session;
    operation->iovec.iov_base = operation->buffer;
    operation->iovec.iov_len = sizeof(operation->buffer);
    operation->message.msg_name = &operation->address;
    operation->message.msg_namelen = sizeof(operation->address);
    operation->message.msg_iov = &operation->iovec;
    operation->message.msg_iovlen = 1;
    io_uring_prep_recvmsg(sqe, session->socket_fd, &operation->message, 0);
    io_uring_sqe_set_data(sqe, operation);
    session->pending++;
    forwarder_runtime_inc_active(session->forwarder->runtime);
    return 0;
}

static void timer_complete(struct io_uring_cqe *cqe, void *runtime_context)
{
    (void)runtime_context;
    struct timer_operation *operation = (struct timer_operation *)io_uring_cqe_get_data(cqe);
    struct udp_session *session = operation->session;
    session->pending--;
    forwarder_runtime_dec_active(session->forwarder->runtime);
    if (!session->closing && cqe->res >= 0)
        close_session(session);
    else
        maybe_free_session(session);
}

static int submit_timer(struct udp_session *session)
{
    struct io_uring_sqe *sqe = get_sqe(session->forwarder);
    if (sqe == NULL)
        return -ENOMEM;
    session->timer_op.op.callback = timer_complete;
    session->timer_op.session = session;
    io_uring_prep_read(sqe, session->timer_fd, &session->timer_op.expirations,
                       sizeof(session->timer_op.expirations), 0);
    io_uring_sqe_set_data(sqe, &session->timer_op);
    session->pending++;
    forwarder_runtime_inc_active(session->forwarder->runtime);
    return 0;
}

static struct udp_session *find_session(struct udp_forwarder *fwd,
                                        const struct sockaddr *address)
{
    struct udp_session *session = fwd->session_hash[address_hash(address)];
    while (session != NULL) {
        if (!session->closing &&
            addresses_equal((const struct sockaddr *)&session->client_address, address))
            return session;
        session = session->hash_next;
    }
    return NULL;
}

static struct udp_session *create_session(struct udp_forwarder *fwd,
                                          const struct sockaddr *address,
                                          socklen_t address_len)
{
    if (__atomic_load_n(&fwd->active_sessions, __ATOMIC_RELAXED) >= fwd->max_sessions)
        return NULL;
    struct udp_session *session = fwd_alloc(fwd, sizeof(*session));
    if (session == NULL)
        return NULL;
    memset(session, 0, sizeof(*session));
    session->forwarder = fwd;
    session->socket_fd = -1;
    session->timer_fd = -1;
    memcpy(&session->client_address, address, address_len);
    session->client_address_len = address_len;

    int domain = fwd->destination.ss_family;
    session->socket_fd = socket(domain, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (session->socket_fd < 0)
        goto fail;
    session->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (session->timer_fd < 0)
        goto fail;
    touch_session(session);

    session->list_next = fwd->sessions;
    fwd->sessions = session;
    uint32_t hash = address_hash(address);
    session->hash_next = fwd->session_hash[hash];
    fwd->session_hash[hash] = session;
    __atomic_fetch_add(&fwd->active_sessions, 1u, __ATOMIC_RELAXED);

    if (submit_session_receive(session) != 0 || submit_timer(session) != 0) {
        close_session(session);
        return NULL;
    }
    return session;

fail:
    if (session->socket_fd >= 0)
        close(session->socket_fd);
    if (session->timer_fd >= 0)
        close(session->timer_fd);
    fwd_free(fwd, session);
    return NULL;
}

static int submit_server_receive(struct udp_forwarder *fwd);

static void server_receive_complete(struct io_uring_cqe *cqe, void *runtime_context)
{
    (void)runtime_context;
    struct receive_operation *operation = (struct receive_operation *)io_uring_cqe_get_data(cqe);
    struct udp_forwarder *fwd = operation->forwarder;
    fwd->receive_pending = 0;
    forwarder_runtime_dec_active(fwd->runtime);

    if (!fwd->stop_requested && !fwd->destroy_requested) {
        if (cqe->res >= 0 && operation->message.msg_namelen > 0) {
            size_t length = (size_t)cqe->res;
            struct sockaddr *client = (struct sockaddr *)&operation->address;
            struct udp_session *session = find_session(fwd, client);
            if (session == NULL)
                session = create_session(fwd, client, operation->message.msg_namelen);
            if (session != NULL) {
                if (fwd->enable_stats)
                    __atomic_fetch_add(&fwd->bytes_in, length, __ATOMIC_RELAXED);
                touch_session(session);
                (void)submit_send(session, session->socket_fd,
                                  (const struct sockaddr *)&fwd->destination,
                                  fwd->destination_len, operation->buffer, length);
            }
        }
        if (submit_server_receive(fwd) != 0)
            fwd->stop_requested = 1;
    }
    else {
        int listen_fd = __atomic_exchange_n(&fwd->listen_fd, -1, __ATOMIC_ACQ_REL);
        if (listen_fd >= 0)
            close(listen_fd);
        struct udp_session *session = fwd->sessions;
        while (session != NULL) {
            struct udp_session *next = session->list_next;
            close_session(session);
            session = next;
        }
    }
    maybe_free_forwarder(fwd);
}

static int submit_server_receive(struct udp_forwarder *fwd)
{
    struct receive_operation *operation = &fwd->receive_op;
    struct io_uring_sqe *sqe = get_sqe(fwd);
    if (sqe == NULL)
        return -ENOMEM;
    memset(&operation->message, 0, sizeof(operation->message));
    operation->op.callback = server_receive_complete;
    operation->forwarder = fwd;
    operation->session = NULL;
    operation->iovec.iov_base = operation->buffer;
    operation->iovec.iov_len = sizeof(operation->buffer);
    operation->message.msg_name = &operation->address;
    operation->message.msg_namelen = sizeof(operation->address);
    operation->message.msg_iov = &operation->iovec;
    operation->message.msg_iovlen = 1;
    io_uring_prep_recvmsg(sqe, fwd->listen_fd, &operation->message, 0);
    io_uring_sqe_set_data(sqe, operation);
    fwd->receive_pending = 1;
    forwarder_runtime_inc_active(fwd->runtime);
    return 0;
}

static int make_destination(struct sockaddr_storage *storage, socklen_t *length,
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

static int map_bind_error(int error_number)
{
    if (error_number == EADDRINUSE)
        return FORWARDER_ERROR_ADDRESS_IN_USE;
    if (error_number == EACCES)
        return FORWARDER_ERROR_PERMISSION_DENIED;
    return FORWARDER_ERROR_BIND;
}

static void set_error(int *out_error, int value)
{
    if (out_error != NULL)
        *out_error = value;
}

udp_forwarder_t *udp_forwarder_create_on_runtime(
    forwarder_runtime_t *runtime, uint16_t listen_port,
    const char *target_address, uint16_t target_port, addr_family_t family,
    int enable_stats, uint32_t connect_timeout_ms, uint32_t max_connections,
    int *out_error)
{
    (void)connect_timeout_ms;
    if (runtime == NULL || target_address == NULL) {
        set_error(out_error, FORWARDER_ERROR_UNKNOWN);
        return NULL;
    }
    forwarder_allocator_t allocator = forwarder_runtime_get_allocator(runtime);
    struct udp_forwarder *fwd = allocator.malloc_cb(allocator.ctx, sizeof(*fwd));
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
    fwd->max_sessions = max_connections > 0 && max_connections < UDP_MAX_SESSIONS
                            ? max_connections : UDP_MAX_SESSIONS;
    size_t target_length = strlen(target_address) + 1;
    fwd->target_address = fwd_alloc(fwd, target_length);
    if (fwd->target_address == NULL) {
        set_error(out_error, FORWARDER_ERROR_MALLOC);
        fwd_free(fwd, fwd);
        return NULL;
    }
    memcpy(fwd->target_address, target_address, target_length);
    if (make_destination(&fwd->destination, &fwd->destination_len, family,
                         fwd->target_address, target_port) != 0) {
        set_error(out_error, FORWARDER_ERROR_INVALID_ADDRESS);
        free_forwarder_storage(fwd);
        return NULL;
    }

    int domain = family == ADDR_FAMILY_IPV4 ? AF_INET : AF_INET6;
    fwd->listen_fd = socket(domain, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fwd->listen_fd < 0) {
        set_error(out_error, FORWARDER_ERROR_UNKNOWN);
        free_forwarder_storage(fwd);
        return NULL;
    }
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

int udp_forwarder_start(udp_forwarder_t *fwd)
{
    if (fwd == NULL || fwd->started)
        return -EINVAL;
    int rc = submit_server_receive(fwd);
    if (rc == 0) {
        fwd->started = 1;
        rc = io_uring_submit(forwarder_runtime_get_ring(fwd->runtime));
        if (rc >= 0)
            rc = 0;
    }
    return rc;
}

void udp_forwarder_request_stop(udp_forwarder_t *fwd)
{
    if (fwd == NULL || __atomic_exchange_n(&fwd->stop_requested, 1, __ATOMIC_ACQ_REL))
        return;
    int domain = fwd->family == ADDR_FAMILY_IPV4 ? AF_INET : AF_INET6;
    int wake_fd = socket(domain, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (wake_fd >= 0) {
        unsigned char byte = 0;
        if (domain == AF_INET) {
            struct sockaddr_in address = {0};
            address.sin_family = AF_INET;
            address.sin_port = htons(fwd->listen_port);
            address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            (void)sendto(wake_fd, &byte, sizeof(byte), 0,
                         (const struct sockaddr *)&address, sizeof(address));
        } else {
            struct sockaddr_in6 address = {0};
            address.sin6_family = AF_INET6;
            address.sin6_port = htons(fwd->listen_port);
            address.sin6_addr = in6addr_loopback;
            (void)sendto(wake_fd, &byte, sizeof(byte), 0,
                         (const struct sockaddr *)&address, sizeof(address));
        }
        close(wake_fd);
    }
    (void)forwarder_runtime_wake(fwd->runtime);
}

static void cancel_operation(struct udp_forwarder *fwd, void *operation)
{
    struct io_uring_sqe *sqe = get_sqe(fwd);
    if (sqe == NULL)
        return;
    io_uring_prep_cancel(sqe, operation, 0);
    io_uring_sqe_set_data(sqe, NULL);
}

void udp_forwarder_destroy(udp_forwarder_t *fwd)
{
    if (fwd == NULL || fwd->destroy_requested)
        return;
    fwd->destroy_requested = 1;
    udp_forwarder_request_stop(fwd);
    if (fwd->receive_pending)
        cancel_operation(fwd, &fwd->receive_op);
    struct udp_session *session = fwd->sessions;
    while (session != NULL) {
        struct udp_session *next = session->list_next;
        cancel_operation(fwd, &session->receive_op);
        cancel_operation(fwd, &session->timer_op);
        close_session(session);
        session = next;
    }
    (void)io_uring_submit(forwarder_runtime_get_ring(fwd->runtime));
    maybe_free_forwarder(fwd);
}

traffic_stats_t udp_forwarder_get_stats(udp_forwarder_t *fwd)
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
