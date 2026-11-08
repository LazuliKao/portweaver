#include "udp_budget.h"
#include <limits.h>
#include <assert.h>
#ifndef _WIN32
#include <sys/resource.h>
#endif

static unsigned int limit = UINT_MAX;
static unsigned int active;
static unsigned int rejected;

unsigned int udp_budget_limit(void)
{
    unsigned int value = __atomic_load_n(&limit, __ATOMIC_RELAXED);
    if (value != UINT_MAX) return value;
    value = 4000;
#ifndef _WIN32
    struct rlimit descriptors;
    if (getrlimit(RLIMIT_NOFILE, &descriptors) == 0 && descriptors.rlim_cur != RLIM_INFINITY) {
        /* Reserve headroom for listeners/control plane; conservatively charge
         * two descriptors per session (socket + io_uring timerfd) on all backends.
         * This is an admission ceiling, not a reservation against other fd users. */
        rlim_t slots = descriptors.rlim_cur > 128 ? (descriptors.rlim_cur - 128) / 2 : 0;
        if (slots < value) value = (unsigned int)slots;
    }
#endif
    unsigned int expected = UINT_MAX;
    if (!__atomic_compare_exchange_n(&limit, &expected, value, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
        value = expected;
    return value;
}

int udp_budget_try_acquire(void)
{
    unsigned int ceiling = udp_budget_limit();
    unsigned int value = __atomic_load_n(&active, __ATOMIC_RELAXED);
    while (value < ceiling) {
        if (__atomic_compare_exchange_n(&active, &value, value + 1, 1, __ATOMIC_RELAXED, __ATOMIC_RELAXED))
            return 1;
    }
    __atomic_fetch_add(&rejected, 1u, __ATOMIC_RELAXED);
    return 0;
}

void udp_budget_release(void)
{
    unsigned int previous = __atomic_fetch_sub(&active, 1u, __ATOMIC_RELAXED);
    assert(previous > 0);
    (void)previous;
}

unsigned int udp_budget_active(void) { return __atomic_load_n(&active, __ATOMIC_RELAXED); }
unsigned int udp_budget_rejected(void) { return __atomic_load_n(&rejected, __ATOMIC_RELAXED); }

#ifdef PORTWEAVER_TEST
unsigned int udp_budget_test_set_limit(unsigned int value)
{
    assert(udp_budget_active() == 0);
    unsigned int previous = udp_budget_limit();
    __atomic_store_n(&limit, value, __ATOMIC_RELAXED);
    return previous;
}
#endif
