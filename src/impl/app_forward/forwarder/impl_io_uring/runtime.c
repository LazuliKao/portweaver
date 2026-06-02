#include "io_uring_internal.h"
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <stdio.h>
#include <poll.h>

struct forwarder_runtime {
    struct io_uring ring;
    int eventfd;
    forwarder_runtime_wake_cb_t wake_cb;
    void *user_data;
    forwarder_allocator_t allocator;
    int wake_closing;
    int initialized;
    int active_ops;
    struct uring_op eventfd_op;
};

#define DATA_ALLOC(runtime, sz) ((runtime)->allocator.malloc_cb((runtime)->allocator.ctx, (sz)))
#define DATA_FREE(runtime, ptr) \
    do { \
        if (ptr) { \
            (runtime)->allocator.free_cb((runtime)->allocator.ctx, (ptr)); \
        } \
    } while(0)

struct io_uring *forwarder_runtime_get_ring(forwarder_runtime_t *runtime) {
    return &runtime->ring;
}

forwarder_allocator_t forwarder_runtime_get_allocator(forwarder_runtime_t *runtime) {
    return runtime->allocator;
}

void forwarder_runtime_inc_active(forwarder_runtime_t *runtime) {
    runtime->active_ops++;
}

void forwarder_runtime_dec_active(forwarder_runtime_t *runtime) {
    runtime->active_ops--;
}

static void on_eventfd_cqe(struct io_uring_cqe *cqe, void *ctx) {
    struct forwarder_runtime *runtime = (struct forwarder_runtime *)((char *)ctx - offsetof(struct forwarder_runtime, eventfd_op));
    
    if (cqe->res < 0) {
        if (cqe->res != -ECANCELED) {
            fprintf(stderr, "[runtime] eventfd poll failed: %d\n", cqe->res);
        }
        forwarder_runtime_dec_active(runtime);
        return;
    }

    uint64_t val;
    ssize_t n = read(runtime->eventfd, &val, sizeof(val));
    (void)n;

    if (!runtime->wake_closing) {
        if (runtime->wake_cb) {
            runtime->wake_cb(runtime->user_data);
        }
        
        struct io_uring_sqe *sqe = io_uring_get_sqe(&runtime->ring);
        if (sqe) {
            io_uring_prep_poll_add(sqe, runtime->eventfd, POLLIN);
            sqe->user_data = (uint64_t)(uintptr_t)&runtime->eventfd_op;
        } else {
            forwarder_runtime_dec_active(runtime);
        }
    } else {
        forwarder_runtime_dec_active(runtime);
    }
}

forwarder_runtime_t *forwarder_runtime_alloc(void) {
    return calloc(1, sizeof(forwarder_runtime_t));
}

int forwarder_runtime_init(forwarder_runtime_t *runtime, forwarder_runtime_wake_cb_t wake_cb, void *user_data, forwarder_allocator_t allocator) {
    if (!runtime) return -1;
    
    memset(runtime, 0, sizeof(*runtime));
    runtime->allocator = allocator;
    runtime->wake_cb = wake_cb;
    runtime->user_data = user_data;
    
    int ret = io_uring_queue_init(1024, &runtime->ring, 0);
    if (ret < 0) return ret;
    
    runtime->eventfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (runtime->eventfd < 0) {
        io_uring_queue_exit(&runtime->ring);
        return -1;
    }
    
    runtime->eventfd_op.callback = on_eventfd_cqe;
    
    struct io_uring_sqe *sqe = io_uring_get_sqe(&runtime->ring);
    if (sqe) {
        io_uring_prep_poll_add(sqe, runtime->eventfd, POLLIN);
        sqe->user_data = (uint64_t)(uintptr_t)&runtime->eventfd_op;
        runtime->active_ops++;
    }
    
    runtime->initialized = 1;
    return 0;
}

/* Process all pending CQEs. Returns the number of CQEs dispatched. */
static int dispatch_cqes(struct forwarder_runtime *runtime) {
    struct io_uring_cqe *cqe;
    unsigned head;
    unsigned count = 0;

    io_uring_for_each_cqe(&runtime->ring, head, cqe) {
        if (cqe->user_data) {
            struct uring_op *op = (struct uring_op *)(uintptr_t)cqe->user_data;
            if (op->callback) {
                op->callback(cqe, op);
            }
        }
        count++;
    }
    io_uring_cq_advance(&runtime->ring, count);
    return (int)count;
}

int forwarder_runtime_run(forwarder_runtime_t *runtime) {
    if (!runtime || !runtime->initialized) return -1;
    fprintf(stderr, "[runtime] run loop started. active_ops=%d\n", runtime->active_ops);
    
    while (1) {
        if (runtime->wake_closing && runtime->active_ops <= 0) {
            fprintf(stderr, "[runtime] run loop breaking due to wake_closing and active_ops<=0\n");
            break;
        }
        
        unsigned sq_ready = io_uring_sq_ready(&runtime->ring);
        if (runtime->active_ops <= 0 && sq_ready == 0) {
            fprintf(stderr, "[runtime] run loop breaking due to active_ops=%d and sq_ready=0\n", runtime->active_ops);
            break;
        }
        
        fprintf(stderr, "[runtime] calling io_uring_submit_and_wait. active_ops=%d, sq_ready=%u\n", runtime->active_ops, sq_ready);
        int ret = io_uring_submit_and_wait(&runtime->ring, 1);
        fprintf(stderr, "[runtime] io_uring_submit_and_wait returned: %d\n", ret);
        if (ret < 0) {
            if (ret == -EINTR) continue;
            break;
        }
        
        dispatch_cqes(runtime);
    }
    fprintf(stderr, "[runtime] run loop exited.\n");
    return 0;
}

int forwarder_runtime_wake(forwarder_runtime_t *runtime) {
    if (!runtime || !runtime->initialized) return -1;
    fprintf(stderr, "[runtime] waking up. eventfd=%d\n", runtime->eventfd);
    uint64_t val = 1;
    ssize_t n = write(runtime->eventfd, &val, sizeof(val));
    return n == sizeof(val) ? 0 : -1;
}

int forwarder_runtime_is_wake_closing(forwarder_runtime_t *runtime) {
    return runtime ? runtime->wake_closing : 1;
}

void forwarder_runtime_close_wake(forwarder_runtime_t *runtime) {
    if (!runtime || !runtime->initialized || runtime->wake_closing) return;
    fprintf(stderr, "[runtime] close_wake called. setting wake_closing=1\n");
    runtime->wake_closing = 1;
    
    struct io_uring_sqe *sqe = io_uring_get_sqe(&runtime->ring);
    if (sqe) {
        io_uring_prep_cancel(sqe, &runtime->eventfd_op, 0);
        sqe->user_data = 0; /* Don't care about cancel result */
    }
    // Decrement active_ops to account for the cancel SQE's CQE which has
    // user_data=0 and will be silently ignored by the CQE processing loop.
    // The original poll's CQE (ECANCELED) will be handled by on_eventfd_cqe
    // and decrement active_ops a second time, correctly reaching zero.
    forwarder_runtime_dec_active(runtime);
}

void forwarder_runtime_close_owned_handles(forwarder_runtime_t *runtime) {
    if (!runtime || !runtime->initialized) return;
    fprintf(stderr, "[runtime] close_owned_handles called. canceling all\n");
    
    struct io_uring_sqe *sqe = io_uring_get_sqe(&runtime->ring);
    if (sqe) {
        io_uring_prep_cancel(sqe, 0, IORING_ASYNC_CANCEL_ALL);
        sqe->user_data = 0;
    }
}

int forwarder_runtime_close(forwarder_runtime_t *runtime) {
    if (!runtime || !runtime->initialized) return -1;
    io_uring_queue_exit(&runtime->ring);
    close(runtime->eventfd);
    runtime->initialized = 0;
    return 0;
}

void forwarder_runtime_free(forwarder_runtime_t *runtime) {
    if (runtime) {
        free(runtime);
    }
}

const char *uv_get_version_string(void) {
    return "io_uring";
}
