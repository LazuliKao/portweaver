#ifndef FORWARDER_H
#define FORWARDER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Address family types
typedef enum {
    ADDR_FAMILY_IPV4 = 0,
    ADDR_FAMILY_IPV6 = 1,
    ADDR_FAMILY_ANY = 2,
} addr_family_t;

// Forward declarations for opaque handles
typedef struct tcp_forwarder tcp_forwarder_t;
typedef struct udp_forwarder udp_forwarder_t;

// Memory allocator callbacks (for Zig allocator integration)
typedef void* (*alloc_fn)(void* ctx, size_t size);
typedef void (*free_fn)(void* ctx, void* ptr);

typedef struct {
    void* ctx;
    alloc_fn alloc;
    free_fn free;
} allocator_t;

// TCP Forwarder API
tcp_forwarder_t* tcp_forwarder_create(
    allocator_t* allocator,
    uint16_t listen_port,
    const char* target_address,
    uint16_t target_port,
    addr_family_t family
);

int tcp_forwarder_start(tcp_forwarder_t* forwarder);
void tcp_forwarder_stop(tcp_forwarder_t* forwarder);
void tcp_forwarder_destroy(tcp_forwarder_t* forwarder);

// UDP Forwarder API
udp_forwarder_t* udp_forwarder_create(
    allocator_t* allocator,
    uint16_t listen_port,
    const char* target_address,
    uint16_t target_port,
    addr_family_t family
);

int udp_forwarder_start(udp_forwarder_t* forwarder);
void udp_forwarder_stop(udp_forwarder_t* forwarder);
void udp_forwarder_destroy(udp_forwarder_t* forwarder);

// Utility functions
const char* uv_get_version_string(void);

#ifdef __cplusplus
}
#endif

#endif // FORWARDER_H
