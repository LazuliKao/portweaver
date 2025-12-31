#ifndef FORWARDER_H
#define FORWARDER_H

#include <stdint.h>
#include <stddef.h>
#include "uv.h"

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

// Internal forward declaration for UDP client session
typedef struct udp_client_session udp_client_session_t;

// Expose an implementation alias used by the C file
typedef struct udp_forwarder udp_forwarder_t_impl;

// Memory allocator callbacks (for Zig allocator integration)
typedef void* (*alloc_fn)(void* ctx, size_t size);
typedef void (*free_fn)(void* ctx, void* ptr);

typedef struct {
    void* ctx;
    alloc_fn alloc;
    free_fn free;
} allocator_t;

// Full UDP forwarder definition (kept here so C code can access members)
struct udp_forwarder {
	allocator_t *allocator;
	allocator_t allocator_storage;
	uv_loop_t *loop;
	uv_udp_t server;
	char *target_address;
	uint16_t target_port;
	addr_family_t family;
	int running;
	udp_client_session_t *sessions;
	struct sockaddr_storage cached_dest_addr;
};

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
