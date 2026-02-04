#ifndef FORWARDER_H
#define FORWARDER_H

#include <stdint.h>
#include <stddef.h>
#include "uv.h"

#ifdef __cplusplus
extern "C"
{
#endif

    // Address family types
    typedef enum
    {
        ADDR_FAMILY_IPV4 = 0,
        ADDR_FAMILY_IPV6 = 1,
        ADDR_FAMILY_ANY = 2,
    } addr_family_t;

    // Error codes for forwarder operations
    typedef enum
    {
        FORWARDER_OK = 0,
        FORWARDER_ERROR_MALLOC = -1,
        FORWARDER_ERROR_BIND = -2,
        FORWARDER_ERROR_ADDRESS_IN_USE = -3,
        FORWARDER_ERROR_PERMISSION_DENIED = -4,
        FORWARDER_ERROR_INVALID_ADDRESS = -5,
        FORWARDER_ERROR_UNKNOWN = -99,
    } forwarder_error_t;

    // Forward declarations for opaque handles
    typedef struct tcp_forwarder tcp_forwarder_t;
    typedef struct udp_forwarder udp_forwarder_t;

// Traffic statistics structure
    typedef struct
    {
        uint64_t bytes_in;
        uint64_t bytes_out;
        unsigned int active_sessions; /* active client sessions */
        uint16_t listen_port;         /* the listening port for this forwarder */
    } traffic_stats_t;

    // Internal forward declaration for UDP client session
    typedef struct udp_client_session udp_client_session_t;

#define UDP_SESSION_HASH_SIZE 256

    // TCP Forwarder API
    // Returns forwarder pointer on success, NULL on failure. Error code written to out_error if provided.
    tcp_forwarder_t *tcp_forwarder_create(
        uint16_t listen_port,
        const char *target_address,
        uint16_t target_port,
        addr_family_t family,
        int enable_stats,
        int *out_error);

    int tcp_forwarder_start(tcp_forwarder_t *forwarder);
    void tcp_forwarder_stop(tcp_forwarder_t *forwarder);
    void tcp_forwarder_destroy(tcp_forwarder_t *forwarder);
    traffic_stats_t tcp_forwarder_get_stats(tcp_forwarder_t *forwarder);

    // UDP Forwarder API
    // Returns forwarder pointer on success, NULL on failure. Error code written to out_error if provided.
    udp_forwarder_t *udp_forwarder_create(
        uint16_t listen_port,
        const char *target_address,
        uint16_t target_port,
        addr_family_t family,
        int enable_stats,
        int *out_error);

    int udp_forwarder_start(udp_forwarder_t *forwarder);
    void udp_forwarder_stop(udp_forwarder_t *forwarder);
    void udp_forwarder_destroy(udp_forwarder_t *forwarder);
    traffic_stats_t udp_forwarder_get_stats(udp_forwarder_t *forwarder);

    // Utility functions
    const char *uv_get_version_string(void);

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_H
