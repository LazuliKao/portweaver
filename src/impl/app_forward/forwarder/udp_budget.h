#ifndef PORTWEAVER_UDP_BUDGET_H
#define PORTWEAVER_UDP_BUDGET_H

#ifdef __cplusplus
extern "C" {
#endif

/* One process-wide budget across all runtimes/listeners. Acquire before opening
 * session sockets; release only when sockets and outstanding callbacks are gone.
 * A zero configured listener limit means the backend safety ceiling, not an
 * exemption from this budget. Nonzero limits can only lower that ceiling. */
int udp_budget_try_acquire(void);
void udp_budget_release(void);
unsigned int udp_budget_limit(void);
unsigned int udp_budget_active(void);
unsigned int udp_budget_rejected(void);

#ifdef PORTWEAVER_TEST
/* Tests may override only while no sessions are alive. Returns the old limit. */
unsigned int udp_budget_test_set_limit(unsigned int limit);
#endif

#ifdef __cplusplus
}
#endif
#endif
