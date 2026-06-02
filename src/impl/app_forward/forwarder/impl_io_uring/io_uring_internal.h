#ifndef IO_URING_INTERNAL_H
#define IO_URING_INTERNAL_H

#include "forwarder.h"
#include <liburing.h>

/* Callback for CQE dispatch. Every SQE's user_data must point to a struct
 * whose first member is a uring_cqe_cb_t. */
typedef void (*uring_cqe_cb_t)(struct io_uring_cqe *cqe, void *ctx);

/* Base operation context. Embed this as the first field of any per-operation
 * struct so the CQE dispatcher can invoke the right callback. */
struct uring_op {
    uring_cqe_cb_t callback;
};

/* Backend-internal accessors (not part of forwarder.h ABI). */
struct io_uring *forwarder_runtime_get_ring(forwarder_runtime_t *runtime);
forwarder_allocator_t forwarder_runtime_get_allocator(forwarder_runtime_t *runtime);
void forwarder_runtime_inc_active(forwarder_runtime_t *runtime);
void forwarder_runtime_dec_active(forwarder_runtime_t *runtime);

#endif // IO_URING_INTERNAL_H
