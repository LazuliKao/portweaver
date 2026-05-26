#include "forwarder.h"

tcp_forwarder_t *tcp_forwarder_create_on_runtime(
    forwarder_runtime_t *runtime,
    uint16_t listen_port,
    const char *target_address,
    uint16_t target_port,
    addr_family_t family,
    int enable_stats,
    int *out_error)
{
    (void)runtime;
    (void)listen_port;
    (void)target_address;
    (void)target_port;
    (void)family;
    (void)enable_stats;

    if (out_error != NULL)
    {
        *out_error = FORWARDER_ERROR_UNKNOWN;
    }

    return NULL;
}

int tcp_forwarder_start(tcp_forwarder_t *forwarder)
{
    (void)forwarder;
    return FORWARDER_ERROR_UNKNOWN;
}

void tcp_forwarder_request_stop(tcp_forwarder_t *forwarder)
{
    (void)forwarder;
}

void tcp_forwarder_destroy(tcp_forwarder_t *forwarder)
{
    (void)forwarder;
}

traffic_stats_t tcp_forwarder_get_stats(tcp_forwarder_t *forwarder)
{
    (void)forwarder;
    traffic_stats_t stats = {0};
    return stats;
}
