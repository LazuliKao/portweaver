#include "io_uring_internal.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

struct wake_operation {
    struct uring_op op;
    uint64_t value;
};

struct forwarder_runtime {
    struct io_uring ring;
    int wake_fd;
    forwarder_runtime_wake_cb_t wake_cb;
    void *user_data;
    forwarder_allocator_t allocator;
    struct wake_operation wake_op;
    unsigned int active_operations;
    int ring_initialized;
    int wake_initialized;
    int wake_closing;
    int wake_drained;
};

static struct io_uring_sqe *runtime_get_sqe(forwarder_runtime_t *runtime)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&runtime->ring);
    if (sqe == NULL) {
        int rc = io_uring_submit(&runtime->ring);
        if (rc < 0)
            return NULL;
        sqe = io_uring_get_sqe(&runtime->ring);
    }
    return sqe;
}

static int arm_wake(forwarder_runtime_t *runtime);

static void wake_complete(struct io_uring_cqe *cqe, void *ctx)
{
    forwarder_runtime_t *runtime = ctx;
    if (runtime->wake_closing) {
        runtime->wake_drained = 1;
        return;
    }

    if (cqe->res == (int)sizeof(runtime->wake_op.value)) {
        if (runtime->wake_cb != NULL)
            runtime->wake_cb(runtime->user_data);
    } else if (cqe->res < 0 && cqe->res != -EAGAIN && cqe->res != -EINTR) {
        runtime->wake_closing = 1;
        runtime->wake_drained = 1;
        return;
    }

    if (arm_wake(runtime) != 0) {
        runtime->wake_closing = 1;
        runtime->wake_drained = 1;
    }
}

static int arm_wake(forwarder_runtime_t *runtime)
{
    struct io_uring_sqe *sqe = runtime_get_sqe(runtime);
    if (sqe == NULL)
        return -ENOMEM;
    runtime->wake_op.op.callback = wake_complete;
    runtime->wake_op.value = 0;
    io_uring_prep_read(sqe, runtime->wake_fd, &runtime->wake_op.value,
                       sizeof(runtime->wake_op.value), 0);
    io_uring_sqe_set_data(sqe, &runtime->wake_op);
    return 0;
}

forwarder_runtime_t *forwarder_runtime_alloc(void)
{
    return calloc(1, sizeof(forwarder_runtime_t));
}

int forwarder_runtime_init(forwarder_runtime_t *runtime,
                           forwarder_runtime_wake_cb_t wake_cb,
                           void *user_data,
                           forwarder_allocator_t allocator)
{
    if (runtime == NULL || allocator.malloc_cb == NULL || allocator.free_cb == NULL)
        return -EINVAL;

    memset(runtime, 0, sizeof(*runtime));
    runtime->wake_fd = -1;
    runtime->wake_cb = wake_cb;
    runtime->user_data = user_data;
    runtime->allocator = allocator;

    int rc = io_uring_queue_init(256, &runtime->ring, 0);
    if (rc < 0)
        return rc;
    runtime->ring_initialized = 1;

    runtime->wake_fd = eventfd(0, EFD_CLOEXEC);
    if (runtime->wake_fd < 0) {
        rc = -errno;
        io_uring_queue_exit(&runtime->ring);
        runtime->ring_initialized = 0;
        return rc;
    }
    runtime->wake_initialized = 1;

    rc = arm_wake(runtime);
    if (rc != 0) {
        close(runtime->wake_fd);
        runtime->wake_fd = -1;
        runtime->wake_initialized = 0;
        io_uring_queue_exit(&runtime->ring);
        runtime->ring_initialized = 0;
        return rc;
    }
    rc = io_uring_submit(&runtime->ring);
    return rc < 0 ? rc : 0;
}

int forwarder_runtime_run(forwarder_runtime_t *runtime)
{
    if (runtime == NULL || !runtime->ring_initialized)
        return -EINVAL;

    for (;;) {
        if (runtime->wake_closing && runtime->wake_drained &&
            __atomic_load_n(&runtime->active_operations, __ATOMIC_ACQUIRE) == 0)
            return 0;

        int rc = io_uring_submit_and_wait(&runtime->ring, 1);
        if (rc < 0) {
            if (rc == -EINTR)
                continue;
            return rc;
        }

        struct io_uring_cqe *cqe;
        unsigned int head;
        unsigned int count = 0;
        io_uring_for_each_cqe(&runtime->ring, head, cqe) {
            ++count;
            struct uring_op *op = io_uring_cqe_get_data(cqe);
            if (op != NULL && op->callback != NULL)
                op->callback(cqe, runtime);
        }
        io_uring_cq_advance(&runtime->ring, count);
    }
}

int forwarder_runtime_wake(forwarder_runtime_t *runtime)
{
    if (runtime == NULL || !runtime->wake_initialized ||
        __atomic_load_n(&runtime->wake_closing, __ATOMIC_ACQUIRE))
        return -EINVAL;

    uint64_t value = 1;
    ssize_t written;
    do {
        written = write(runtime->wake_fd, &value, sizeof(value));
    } while (written < 0 && errno == EINTR);
    if (written == (ssize_t)sizeof(value) || (written < 0 && errno == EAGAIN))
        return 0;
    return written < 0 ? -errno : -EIO;
}

int forwarder_runtime_is_wake_closing(forwarder_runtime_t *runtime)
{
    return runtime == NULL || __atomic_load_n(&runtime->wake_closing, __ATOMIC_ACQUIRE);
}

void forwarder_runtime_close_wake(forwarder_runtime_t *runtime)
{
    if (runtime == NULL)
        return;
    if (__atomic_exchange_n(&runtime->wake_closing, 1, __ATOMIC_ACQ_REL))
        return;
    if (runtime->wake_initialized) {
        struct io_uring_sqe *sqe = runtime_get_sqe(runtime);
        if (sqe != NULL) {
            io_uring_prep_cancel(sqe, &runtime->wake_op, 0);
            io_uring_sqe_set_data(sqe, NULL);
            (void)io_uring_submit(&runtime->ring);
        } else {
            runtime->wake_drained = 1;
        }
        close(runtime->wake_fd);
        runtime->wake_fd = -1;
        runtime->wake_initialized = 0;
    } else {
        runtime->wake_drained = 1;
    }
}

void forwarder_runtime_close_owned_handles(forwarder_runtime_t *runtime)
{
    forwarder_runtime_close_wake(runtime);
}

int forwarder_runtime_close(forwarder_runtime_t *runtime)
{
    if (runtime == NULL || !runtime->ring_initialized)
        return -EINVAL;
    if (__atomic_load_n(&runtime->active_operations, __ATOMIC_ACQUIRE) != 0)
        return -EBUSY;
    io_uring_queue_exit(&runtime->ring);
    runtime->ring_initialized = 0;
    return 0;
}

void forwarder_runtime_free(forwarder_runtime_t *runtime)
{
    free(runtime);
}

const char *uv_get_version_string(void)
{
    return "io_uring-liburing";
}

struct io_uring *forwarder_runtime_get_ring(forwarder_runtime_t *runtime)
{
    return runtime != NULL ? &runtime->ring : NULL;
}

forwarder_allocator_t forwarder_runtime_get_allocator(forwarder_runtime_t *runtime)
{
    forwarder_allocator_t empty = {0};
    return runtime != NULL ? runtime->allocator : empty;
}

void forwarder_runtime_inc_active(forwarder_runtime_t *runtime)
{
    if (runtime != NULL)
        __atomic_fetch_add(&runtime->active_operations, 1u, __ATOMIC_RELAXED);
}

void forwarder_runtime_dec_active(forwarder_runtime_t *runtime)
{
    if (runtime != NULL)
        __atomic_fetch_sub(&runtime->active_operations, 1u, __ATOMIC_RELEASE);
}
