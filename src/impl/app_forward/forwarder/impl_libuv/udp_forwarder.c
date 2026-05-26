#include "forwarder.h"

udp_forwarder_t *udp_forwarder_create_on_runtime(
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

int udp_forwarder_start(udp_forwarder_t *forwarder)
{
    (void)forwarder;
    return FORWARDER_ERROR_UNKNOWN;
}

void udp_forwarder_request_stop(udp_forwarder_t *forwarder)
{
    (void)forwarder;
}

void udp_forwarder_destroy(udp_forwarder_t *forwarder)
{
    (void)forwarder;
}

traffic_stats_t udp_forwarder_get_stats(udp_forwarder_t *forwarder)
{
    (void)forwarder;
    traffic_stats_t stats = {0};
    return stats;
}
