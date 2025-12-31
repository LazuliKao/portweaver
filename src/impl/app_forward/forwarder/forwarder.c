#include "forwarder.h"
#include "uv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BUFFER_SIZE (64 * 1024)

// TCP Connection structure
typedef struct tcp_conn {
    tcp_forwarder_t* forwarder;
    uv_tcp_t client;
    uv_tcp_t upstream;
    uv_connect_t connect_req;
    uv_getaddrinfo_t gai_req;
    char* target_node;
    char* target_service;
    int strings_freed;
    int client_closed;
    int upstream_closed;
} tcp_conn_t;

// TCP Write request
typedef struct tcp_write_req {
    uv_write_t req;
    uv_buf_t buf;
    char* data;
    size_t data_len;
    allocator_t* allocator;
} tcp_write_req_t;

// UDP Send request
typedef struct udp_send_req {
    uv_udp_send_t req;
    uv_buf_t buf;
    char* data;
    size_t data_len;
    allocator_t* allocator;
} udp_send_req_t;

// TCP Forwarder structure
struct tcp_forwarder {
    allocator_t* allocator;
    uint16_t listen_port;
    char* target_address;
    uint16_t target_port;
    addr_family_t family;
    uv_loop_t loop;
    uv_tcp_t server;
    int running;
};

// UDP Forwarder structure
struct udp_forwarder {
    allocator_t* allocator;
    uint16_t listen_port;
    char* target_address;
    uint16_t target_port;
    addr_family_t family;
    uv_loop_t loop;
    uv_udp_t udp;
    struct sockaddr_storage target_addr;
    int target_addr_len;
    int running;
};

// Forward declarations
static void tcp_on_connection(uv_stream_t* server, int status);
static void tcp_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
static void tcp_on_client_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
static void tcp_on_upstream_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
static void tcp_on_write(uv_write_t* req, int status);
static void tcp_on_resolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res);
static void tcp_on_connected(uv_connect_t* req, int status);
static void tcp_on_close_client(uv_handle_t* handle);
static void tcp_on_close_upstream(uv_handle_t* handle);

static void udp_on_resolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res);
static void udp_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
static void udp_on_recv(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf, 
                        const struct sockaddr* addr, unsigned flags);
static void udp_on_send(uv_udp_send_t* req, int status);

// Utility functions
const char* uv_get_version_string(void) {
    return uv_version_string();
}

/* Data buffer allocator helpers (add magic header to detect/avoid double frees)
 * and a lightweight allocation map to verify ownership before freeing.
 */
static const uint32_t DATA_MAGIC = 0xF00DBEEF;

typedef struct alloc_entry {
    void* ptr; /* user-facing pointer (after header) */
    size_t size;
    struct alloc_entry* next;
} alloc_entry_t;

static alloc_entry_t* alloc_map_head = NULL;
static uv_mutex_t alloc_map_lock;
static int alloc_map_initialized = 0;

static void ensure_alloc_map_init(void) {
    if (!alloc_map_initialized) {
        uv_mutex_init(&alloc_map_lock);
        alloc_map_initialized = 1;
    }
}

static void alloc_map_add(void* user_ptr, size_t size) {
    ensure_alloc_map_init();
    alloc_entry_t* e = (alloc_entry_t*)malloc(sizeof(alloc_entry_t));
    if (!e) {
        fprintf(stderr, "[alloc_map_add] OOM when tracking %p\n", user_ptr);
        return;
    }
    e->ptr = user_ptr;
    e->size = size;

    uv_mutex_lock(&alloc_map_lock);
    e->next = alloc_map_head;
    alloc_map_head = e;
    uv_mutex_unlock(&alloc_map_lock);

    fprintf(stderr, "[alloc_map_add] tracked user=%p size=%zu\n", user_ptr, size);
}

static int alloc_map_remove(void* user_ptr) {
    if (!alloc_map_initialized) return 0;
    uv_mutex_lock(&alloc_map_lock);
    alloc_entry_t* prev = NULL;
    alloc_entry_t* cur = alloc_map_head;
    while (cur) {
        if (cur->ptr == user_ptr) {
            if (prev) prev->next = cur->next; else alloc_map_head = cur->next;
            uv_mutex_unlock(&alloc_map_lock);
            fprintf(stderr, "[alloc_map_remove] removing user=%p size=%zu\n", user_ptr, cur->size);
            free(cur);
            return 1;
        }
        prev = cur;
        cur = cur->next;
    }
    uv_mutex_unlock(&alloc_map_lock);
    fprintf(stderr, "[alloc_map_remove] user=%p not found\n", user_ptr);
    return 0;
}

static void* data_alloc(allocator_t* allocator, void* ctx, size_t size) {
    (void)allocator;
    (void)ctx;
    size_t total = size + sizeof(uint32_t);
    uint8_t* p = (uint8_t*)malloc(total);
    if (!p) return NULL;
    uint32_t magic = DATA_MAGIC;
    memcpy(p, &magic, sizeof(uint32_t));
    void* user_ptr = (void*)(p + sizeof(uint32_t));

    /* Track ownership */
    alloc_map_add(user_ptr, size);

    fprintf(stderr, "[data_alloc] alloc user=%p header=%p size=%zu (malloc)\n",
            user_ptr, (void*)p, size);

    return user_ptr;
}

static void data_free(allocator_t* allocator, void* ctx, void* ptr) {
    if (!ptr) return;
    uint8_t* p = (uint8_t*)ptr - sizeof(uint32_t);
    uint32_t magic = 0;
    memcpy(&magic, p, sizeof(uint32_t));
    fprintf(stderr, "[data_free] attempt free user=%p header=%p magic=0x%08x ctx=%p allocator=%p\n",
            ptr, (void*)p, magic, ctx, (void*)allocator);
    if (magic != DATA_MAGIC) {
        /* Not our allocation header or already corrupted. Log for debugging. */
        fprintf(stderr, "[data_free] detected invalid free header: ptr=%p header=%p magic=0x%08x\n", ptr, (void*)p, magic);
        /* Also check whether ptr was tracked but header corrupted */
        if (!alloc_map_remove(ptr)) {
            fprintf(stderr, "[data_free] ptr %p was not tracked by alloc_map\n", ptr);
        } else {
            fprintf(stderr, "[data_free] ptr %p was tracked but header corrupted, skipping free to avoid crash\n", ptr);
        }
        return; /* avoid freeing memory not owned by our data_alloc */
    }

    /* Verify ownership in map and remove it */
    if (!alloc_map_remove(ptr)) {
        fprintf(stderr, "[data_free] ptr %p had valid header but was not tracked by alloc_map\n", ptr);
        /* proceed with free anyway */
    }

    magic = 0;
    memcpy(p, &magic, sizeof(uint32_t));

    /* Dump header bytes to help diagnose allocator canary corruption */
    fprintf(stderr, "[data_free] dumping header bytes at %p: ", (void*)p);
    for (int i = 0; i < 32; ++i) {
        fprintf(stderr, "%02x ", ((unsigned char*)p)[i]);
    }
    fprintf(stderr, "\n");

    /* Use free() to avoid panics in the external allocator while debugging */
    free(p);
    fprintf(stderr, "[data_free] freed user=%p header=%p (free)\n", ptr, (void*)p);
}

// TCP Forwarder implementation
tcp_forwarder_t* tcp_forwarder_create(
    allocator_t* allocator,
    uint16_t listen_port,
    const char* target_address,
    uint16_t target_port,
    addr_family_t family
) {
    tcp_forwarder_t* forwarder = (tcp_forwarder_t*)allocator->alloc(allocator->ctx, sizeof(tcp_forwarder_t));
    if (!forwarder) return NULL;

    forwarder->allocator = allocator;
    forwarder->listen_port = listen_port;
    forwarder->target_port = target_port;
    forwarder->family = family;
    forwarder->running = 0;

    size_t addr_len = strlen(target_address) + 1;
    forwarder->target_address = (char*)allocator->alloc(allocator->ctx, addr_len);
    if (!forwarder->target_address) {
        allocator->free(allocator->ctx, forwarder);
        return NULL;
    }
    memcpy(forwarder->target_address, target_address, addr_len);

    return forwarder;
}

int tcp_forwarder_start(tcp_forwarder_t* forwarder) {
    if (uv_loop_init(&forwarder->loop) != 0) {
        return -1;
    }

    if (uv_tcp_init(&forwarder->loop, &forwarder->server) != 0) {
        uv_loop_close(&forwarder->loop);
        return -1;
    }

    forwarder->server.data = forwarder;

    // Bind
    struct sockaddr_storage addr_storage;
    struct sockaddr* addr = (struct sockaddr*)&addr_storage;
    int bind_ok = 0;

    switch (forwarder->family) {
        case ADDR_FAMILY_IPV4: {
            struct sockaddr_in a4;
            if (uv_ip4_addr("0.0.0.0", forwarder->listen_port, &a4) == 0) {
                addr = (struct sockaddr*)&a4;
                bind_ok = (uv_tcp_bind(&forwarder->server, addr, 0) == 0);
            }
            break;
        }
        case ADDR_FAMILY_IPV6: {
            struct sockaddr_in6 a6;
            if (uv_ip6_addr("::", forwarder->listen_port, &a6) == 0) {
                addr = (struct sockaddr*)&a6;
                bind_ok = (uv_tcp_bind(&forwarder->server, addr, 0) == 0);
            }
            break;
        }
        case ADDR_FAMILY_ANY: {
            struct sockaddr_in6 a6;
            if (uv_ip6_addr("::", forwarder->listen_port, &a6) == 0) {
                addr = (struct sockaddr*)&a6;
                bind_ok = (uv_tcp_bind(&forwarder->server, addr, 0) == 0);
            }
            if (!bind_ok) {
                struct sockaddr_in a4;
                if (uv_ip4_addr("0.0.0.0", forwarder->listen_port, &a4) == 0) {
                    addr = (struct sockaddr*)&a4;
                    bind_ok = (uv_tcp_bind(&forwarder->server, addr, 0) == 0);
                }
            }
            break;
        }
    }

    if (!bind_ok) {
        uv_loop_close(&forwarder->loop);
        return -1;
    }

    if (uv_listen((uv_stream_t*)&forwarder->server, 128, tcp_on_connection) != 0) {
        uv_loop_close(&forwarder->loop);
        return -1;
    }

    printf("[TCP] Listening on port %d, forwarding to %s:%d\n",
           forwarder->listen_port, forwarder->target_address, forwarder->target_port);

    forwarder->running = 1;
    uv_run(&forwarder->loop, UV_RUN_DEFAULT);
    uv_loop_close(&forwarder->loop);

    return 0;
}

void tcp_forwarder_stop(tcp_forwarder_t* forwarder) {
    forwarder->running = 0;
    uv_stop(&forwarder->loop);
}

void tcp_forwarder_destroy(tcp_forwarder_t* forwarder) {
    if (!forwarder) return;
    if (forwarder->target_address) {
        forwarder->allocator->free(forwarder->allocator->ctx, forwarder->target_address);
    }
    forwarder->allocator->free(forwarder->allocator->ctx, forwarder);
}

static void tcp_on_connection(uv_stream_t* server, int status) {
    if (status < 0) {
        fprintf(stderr, "[TCP] Accept error: %d\n", status);
        return;
    }

    tcp_forwarder_t* forwarder = (tcp_forwarder_t*)server->data;
    tcp_conn_t* conn = (tcp_conn_t*)forwarder->allocator->alloc(forwarder->allocator->ctx, sizeof(tcp_conn_t));
    if (!conn) {
        fprintf(stderr, "[TCP] Accept error: OOM\n");
        return;
    }

    memset(conn, 0, sizeof(tcp_conn_t));
    conn->forwarder = forwarder;

    if (uv_tcp_init(&forwarder->loop, &conn->client) != 0) {
        forwarder->allocator->free(forwarder->allocator->ctx, conn);
        return;
    }
    conn->client.data = conn;

    if (uv_accept(server, (uv_stream_t*)&conn->client) != 0) {
        conn->upstream_closed = 1;
        uv_close((uv_handle_t*)&conn->client, tcp_on_close_client);
        return;
    }

    // Resolve target
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", forwarder->target_port);

    size_t node_len = strlen(forwarder->target_address) + 1;
    conn->target_node = (char*)forwarder->allocator->alloc(forwarder->allocator->ctx, node_len);
    if (!conn->target_node) {
        conn->upstream_closed = 1;
        uv_close((uv_handle_t*)&conn->client, tcp_on_close_client);
        return;
    }
    memcpy(conn->target_node, forwarder->target_address, node_len);

    size_t service_len = strlen(port_str) + 1;
    conn->target_service = (char*)forwarder->allocator->alloc(forwarder->allocator->ctx, service_len);
    if (!conn->target_service) {
        forwarder->allocator->free(forwarder->allocator->ctx, conn->target_node);
        conn->upstream_closed = 1;
        uv_close((uv_handle_t*)&conn->client, tcp_on_close_client);
        return;
    }
    memcpy(conn->target_service, port_str, service_len);

    conn->gai_req.data = conn;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = (forwarder->family == ADDR_FAMILY_IPV4) ? AF_INET :
                      (forwarder->family == ADDR_FAMILY_IPV6) ? AF_INET6 : AF_UNSPEC;

    if (uv_getaddrinfo(&forwarder->loop, &conn->gai_req, tcp_on_resolved, 
                       conn->target_node, conn->target_service, &hints) != 0) {
        fprintf(stderr, "[TCP] Failed to resolve target\n");
        conn->upstream_closed = 1;
        uv_close((uv_handle_t*)&conn->client, tcp_on_close_client);
    }
}

static void tcp_on_resolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    tcp_conn_t* conn = (tcp_conn_t*)req->data;

    if (status < 0 || !res) {
        fprintf(stderr, "[TCP] Failed to resolve target\n");
        uv_freeaddrinfo(res);
        conn->upstream_closed = 1;
        uv_close((uv_handle_t*)&conn->client, tcp_on_close_client);
        return;
    }

    if (uv_tcp_init(&conn->forwarder->loop, &conn->upstream) != 0) {
        uv_freeaddrinfo(res);
        conn->upstream_closed = 1;
        uv_close((uv_handle_t*)&conn->client, tcp_on_close_client);
        return;
    }
    conn->upstream.data = conn;
    conn->connect_req.data = conn;

    int rc = uv_tcp_connect(&conn->connect_req, &conn->upstream, res->ai_addr, tcp_on_connected);
    uv_freeaddrinfo(res);

    if (rc != 0) {
        fprintf(stderr, "[TCP] Failed to connect to target\n");
        uv_close((uv_handle_t*)&conn->upstream, tcp_on_close_upstream);
        uv_close((uv_handle_t*)&conn->client, tcp_on_close_client);
    }
}

static void tcp_on_connected(uv_connect_t* req, int status) {
    tcp_conn_t* conn = (tcp_conn_t*)req->data;

    if (status < 0) {
        fprintf(stderr, "[TCP] Failed to connect to target: %d\n", status);
        uv_close((uv_handle_t*)&conn->upstream, tcp_on_close_upstream);
        uv_close((uv_handle_t*)&conn->client, tcp_on_close_client);
        return;
    }

    printf("[TCP] Connected to target %s:%d\n", conn->forwarder->target_address, conn->forwarder->target_port);

    uv_read_start((uv_stream_t*)&conn->client, tcp_alloc_cb, tcp_on_client_read);
    uv_read_start((uv_stream_t*)&conn->upstream, tcp_alloc_cb, tcp_on_upstream_read);
}

static void tcp_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    (void)suggested_size;
    if (!handle || !buf) return;

    tcp_conn_t* conn = (tcp_conn_t*)handle->data;
    if (!conn) {
        buf->base = NULL;
        buf->len = 0;
        return;
    }

    char* mem = (char*)data_alloc(conn->forwarder->allocator, conn->forwarder->allocator->ctx, BUFFER_SIZE);
    if (!mem) {
        buf->base = NULL;
        buf->len = 0;
        return;
    }

    buf->base = mem;
    buf->len = BUFFER_SIZE;
}

static void tcp_on_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf, int from_client) {
    if (!stream || !buf) return;
    tcp_conn_t* conn = (tcp_conn_t*)stream->data;
    if (!conn) return;

    if (buf->base && buf->len > 0 && nread == 0) {
        fprintf(stderr, "[tcp_on_read] EOF read: nread=%zd buf.len=%zu base=%p from_client=%d\n", nread, buf->len, (void*)buf->base, from_client);
        data_free(conn->forwarder->allocator, conn->forwarder->allocator->ctx, buf->base);
        return;
    }

    if (nread < 0) {
        if (buf->base && buf->len > 0) {
            fprintf(stderr, "[tcp_on_read] error read: nread=%zd buf.len=%zu base=%p from_client=%d\n", nread, buf->len, (void*)buf->base, from_client);
            data_free(conn->forwarder->allocator, conn->forwarder->allocator->ctx, buf->base);
        }

        if (from_client) {
            conn->client_closed = 1;
        } else {
            conn->upstream_closed = 1;
        }

        uv_read_stop(stream);
        uv_close((uv_handle_t*)stream, from_client ? tcp_on_close_client : tcp_on_close_upstream);

        if (from_client && !conn->upstream_closed) {
            conn->upstream_closed = 1;
            uv_read_stop((uv_stream_t*)&conn->upstream);
            uv_close((uv_handle_t*)&conn->upstream, tcp_on_close_upstream);
        } else if (!from_client && !conn->client_closed) {
            conn->client_closed = 1;
            uv_read_stop((uv_stream_t*)&conn->client);
            uv_close((uv_handle_t*)&conn->client, tcp_on_close_client);
        }
        return;
    }

    uv_stream_t* dst_stream = from_client ? (uv_stream_t*)&conn->upstream : (uv_stream_t*)&conn->client;

    tcp_write_req_t* wr = (tcp_write_req_t*)malloc(sizeof(tcp_write_req_t));
    if (!wr) {
        data_free(conn->forwarder->allocator, conn->forwarder->allocator->ctx, buf->base);
        return;
    }
    memset(wr, 0, sizeof(tcp_write_req_t));
    /* mark allocator NULL since wr is malloc'd */
    wr->allocator = NULL;
    fprintf(stderr, "[tcp_on_read] allocated wr=%p (malloc)\n", (void*)wr);

    /* Allocate a buffer owned by the write request and copy only the received bytes.
     * This avoids double-free/race conditions where the original read buffer may be
     * freed elsewhere (e.g., on read errors or connection close) while a pending
     * write still references it.
     */
    wr->data = (char*)data_alloc(conn->forwarder->allocator, conn->forwarder->allocator->ctx, (size_t)nread);
    if (!wr->data) {
        data_free(conn->forwarder->allocator, conn->forwarder->allocator->ctx, buf->base);
        conn->forwarder->allocator->free(conn->forwarder->allocator->ctx, wr);
        return;
    }
    memcpy(wr->data, buf->base, (size_t)nread);
    /* Free the original buffer immediately since ownership of the sent data
     * has been transferred to wr->data.
     */
    data_free(conn->forwarder->allocator, conn->forwarder->allocator->ctx, buf->base);

    wr->buf.base = wr->data;
    wr->buf.len = nread;
    wr->data_len = (size_t)nread;
    /* wr is malloc'd so do not use the forwarder allocator to free it */
    wr->allocator = NULL;
    wr->req.data = wr;

    if (uv_write(&wr->req, dst_stream, &wr->buf, 1, tcp_on_write) != 0) {
        /* On synchronous write failure free the write-owned buffer and the request */
        fprintf(stderr, "[tcp_on_read] uv_write failed synchronously for wr=%p, freeing wr and data\n", (void*)wr);
        data_free(conn->forwarder->allocator, conn->forwarder->allocator->ctx, wr->data);
        free(wr);
        uv_close((uv_handle_t*)&conn->client, tcp_on_close_client);
        uv_close((uv_handle_t*)&conn->upstream, tcp_on_close_upstream);
    }
}

static void tcp_on_client_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    tcp_on_read(stream, nread, buf, 1);
}

static void tcp_on_upstream_read(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    tcp_on_read(stream, nread, buf, 0);
}

static void tcp_on_write(uv_write_t* req, int status) {
    if (!req) return;
    tcp_write_req_t* wr = (tcp_write_req_t*)req->data;
    if (!wr) return;

    if (status < 0) {
        fprintf(stderr, "[TCP] Write error: %d\n", status);
    }

    /* Debug info about the write request */
    fprintf(stderr, "[tcp_on_write] wr=%p buf.base=%p buf.len=%zu data=%p data_len=%zu allocator=%p status=%d\n",
            (void*)wr,
            (void*)(wr->buf.base),
            (size_t)wr->buf.len,
            (void*)wr->data,
            (size_t)wr->data_len,
            (void*)wr->allocator,
            status);

    /* Free the data buffer first (allocated by data_alloc/malloc) */
    if (wr->data) {
        data_free(wr->allocator, wr->allocator ? wr->allocator->ctx : NULL, wr->data);
    }

    /* Dump the first bytes of wr to see if it has been corrupted */
    fprintf(stderr, "[tcp_on_write] dumping wr bytes at %p: ", (void*)wr);
    size_t dump_len = sizeof(tcp_write_req_t) < 64 ? sizeof(tcp_write_req_t) : 64;
    for (size_t i = 0; i < dump_len; ++i) {
        fprintf(stderr, "%02x ", ((unsigned char*)wr)[i]);
    }
    fprintf(stderr, "\n");

    /* Determine the expected allocator from the stream's connection data, and
     * prefer that for freeing wr if the stored allocator pointer appears corrupted.
     */
    uv_stream_t* stream = NULL;
    tcp_conn_t* conn = NULL;
    if (req->handle) {
        stream = (uv_stream_t*)req->handle;
        conn = (tcp_conn_t*)stream->data;
    }

    allocator_t* expected_alloc = conn ? conn->forwarder->allocator : NULL;

    if (wr->allocator && expected_alloc && wr->allocator == expected_alloc) {
        wr->allocator->free(wr->allocator->ctx, wr);
    } else if (wr->allocator) {
        /* wr has an allocator that doesn't match expected; try to use it */
        fprintf(stderr, "[tcp_on_write] wr->allocator (%p) doesn't match expected (%p), using wr->allocator to free wr\n",
                (void*)wr->allocator, (void*)expected_alloc);
        wr->allocator->free(wr->allocator->ctx, wr);
    } else {
        /* wr was malloc'd or allocator unknown: use free() */
        fprintf(stderr, "[tcp_on_write] freeing wr=%p with free() (malloc'd or unknown allocator)\n", (void*)wr);
        free(wr);
    }
}

static void tcp_free_strings_once(tcp_conn_t* conn) {
    if (conn->strings_freed) return;
    conn->strings_freed = 1;
    if (conn->target_node) {
        conn->forwarder->allocator->free(conn->forwarder->allocator->ctx, conn->target_node);
        conn->target_node = NULL;
    }
    if (conn->target_service) {
        conn->forwarder->allocator->free(conn->forwarder->allocator->ctx, conn->target_service);
        conn->target_service = NULL;
    }
}

static void tcp_on_close_client(uv_handle_t* handle) {
    if (!handle) return;
    tcp_conn_t* conn = (tcp_conn_t*)handle->data;
    if (!conn) return;
    handle->data = NULL;

    conn->client_closed = 1;
    tcp_free_strings_once(conn);
    if (conn->client_closed && conn->upstream_closed) {
        conn->forwarder->allocator->free(conn->forwarder->allocator->ctx, conn);
    }
}

static void tcp_on_close_upstream(uv_handle_t* handle) {
    if (!handle) return;
    tcp_conn_t* conn = (tcp_conn_t*)handle->data;
    if (!conn) return;
    handle->data = NULL;

    conn->upstream_closed = 1;
    tcp_free_strings_once(conn);
    if (conn->client_closed && conn->upstream_closed) {
        conn->forwarder->allocator->free(conn->forwarder->allocator->ctx, conn);
    }
}

// UDP Forwarder implementation
udp_forwarder_t* udp_forwarder_create(
    allocator_t* allocator,
    uint16_t listen_port,
    const char* target_address,
    uint16_t target_port,
    addr_family_t family
) {
    udp_forwarder_t* forwarder = (udp_forwarder_t*)allocator->alloc(allocator->ctx, sizeof(udp_forwarder_t));
    if (!forwarder) return NULL;

    forwarder->allocator = allocator;
    forwarder->listen_port = listen_port;
    forwarder->target_port = target_port;
    forwarder->family = family;
    forwarder->running = 0;
    forwarder->target_addr_len = 0;

    size_t addr_len = strlen(target_address) + 1;
    forwarder->target_address = (char*)allocator->alloc(allocator->ctx, addr_len);
    if (!forwarder->target_address) {
        allocator->free(allocator->ctx, forwarder);
        return NULL;
    }
    memcpy(forwarder->target_address, target_address, addr_len);

    return forwarder;
}

int udp_forwarder_start(udp_forwarder_t* forwarder) {
    if (uv_loop_init(&forwarder->loop) != 0) {
        return -1;
    }

    if (uv_udp_init(&forwarder->loop, &forwarder->udp) != 0) {
        uv_loop_close(&forwarder->loop);
        return -1;
    }

    forwarder->udp.data = forwarder;

    // Bind
    int bind_ok = 0;
    switch (forwarder->family) {
        case ADDR_FAMILY_IPV4: {
            struct sockaddr_in a4;
            if (uv_ip4_addr("0.0.0.0", forwarder->listen_port, &a4) == 0) {
                bind_ok = (uv_udp_bind(&forwarder->udp, (struct sockaddr*)&a4, UV_UDP_REUSEADDR) == 0);
            }
            break;
        }
        case ADDR_FAMILY_IPV6: {
            struct sockaddr_in6 a6;
            if (uv_ip6_addr("::", forwarder->listen_port, &a6) == 0) {
                bind_ok = (uv_udp_bind(&forwarder->udp, (struct sockaddr*)&a6, UV_UDP_REUSEADDR) == 0);
            }
            break;
        }
        case ADDR_FAMILY_ANY: {
            struct sockaddr_in6 a6;
            if (uv_ip6_addr("::", forwarder->listen_port, &a6) == 0) {
                bind_ok = (uv_udp_bind(&forwarder->udp, (struct sockaddr*)&a6, UV_UDP_REUSEADDR) == 0);
            }
            if (!bind_ok) {
                struct sockaddr_in a4;
                if (uv_ip4_addr("0.0.0.0", forwarder->listen_port, &a4) == 0) {
                    bind_ok = (uv_udp_bind(&forwarder->udp, (struct sockaddr*)&a4, UV_UDP_REUSEADDR) == 0);
                }
            }
            break;
        }
    }

    if (!bind_ok) {
        uv_loop_close(&forwarder->loop);
        return -1;
    }

    printf("[UDP] Listening on port %d, forwarding to %s:%d\n",
           forwarder->listen_port, forwarder->target_address, forwarder->target_port);

    // Resolve target
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", forwarder->target_port);

    uv_getaddrinfo_t gai_req;
    gai_req.data = forwarder;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = (forwarder->family == ADDR_FAMILY_IPV4) ? AF_INET :
                      (forwarder->family == ADDR_FAMILY_IPV6) ? AF_INET6 : AF_UNSPEC;

    if (uv_getaddrinfo(&forwarder->loop, &gai_req, udp_on_resolved,
                       forwarder->target_address, port_str, &hints) != 0) {
        uv_loop_close(&forwarder->loop);
        return -1;
    }

    forwarder->running = 1;
    uv_run(&forwarder->loop, UV_RUN_DEFAULT);
    uv_loop_close(&forwarder->loop);

    return 0;
}

void udp_forwarder_stop(udp_forwarder_t* forwarder) {
    forwarder->running = 0;
    uv_stop(&forwarder->loop);
}

void udp_forwarder_destroy(udp_forwarder_t* forwarder) {
    if (!forwarder) return;
    if (forwarder->target_address) {
        forwarder->allocator->free(forwarder->allocator->ctx, forwarder->target_address);
    }
    forwarder->allocator->free(forwarder->allocator->ctx, forwarder);
}

static void udp_on_resolved(uv_getaddrinfo_t* req, int status, struct addrinfo* res) {
    udp_forwarder_t* forwarder = (udp_forwarder_t*)req->data;

    if (status < 0 || !res) {
        fprintf(stderr, "[UDP] Invalid target address\n");
        uv_freeaddrinfo(res);
        uv_close((uv_handle_t*)&forwarder->udp, NULL);
        return;
    }

    memset(&forwarder->target_addr, 0, sizeof(forwarder->target_addr));
    memcpy(&forwarder->target_addr, res->ai_addr, res->ai_addrlen);
    forwarder->target_addr_len = res->ai_addrlen;

    uv_freeaddrinfo(res);

    if (uv_udp_recv_start(&forwarder->udp, udp_alloc_cb, udp_on_recv) != 0) {
        fprintf(stderr, "[UDP] Receive start error\n");
        uv_close((uv_handle_t*)&forwarder->udp, NULL);
    }
}

static void udp_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    (void)suggested_size;
    if (!handle || !buf) return;

    udp_forwarder_t* forwarder = (udp_forwarder_t*)handle->data;
    if (!forwarder) {
        buf->base = NULL;
        buf->len = 0;
        return;
    }

    char* mem = (char*)data_alloc(forwarder->allocator, forwarder->allocator->ctx, BUFFER_SIZE);
    if (!mem) {
        buf->base = NULL;
        buf->len = 0;
        return;
    }

    buf->base = mem;
    buf->len = BUFFER_SIZE;
}

static void udp_on_recv(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
                        const struct sockaddr* addr, unsigned flags) {
    (void)flags;
    if (!handle || !buf) return;

    udp_forwarder_t* forwarder = (udp_forwarder_t*)handle->data;
    if (!forwarder) return;

    if (buf->base && buf->len > 0 && nread <= 0) {
        data_free(forwarder->allocator, forwarder->allocator->ctx, buf->base);
        return;
    }

    if (forwarder->target_addr_len == 0) {
        data_free(forwarder->allocator, forwarder->allocator->ctx, buf->base);
        return;
    }

    udp_send_req_t* sr = (udp_send_req_t*)forwarder->allocator->alloc(
        forwarder->allocator->ctx, sizeof(udp_send_req_t));
    if (!sr) {
        forwarder->allocator->free(forwarder->allocator->ctx, buf->base);
        return;
    }

    sr->buf.base = buf->base;
    sr->buf.len = nread;
    sr->data = buf->base;
    sr->data_len = buf->len;
    sr->allocator = forwarder->allocator;
    sr->req.data = sr;

    if (uv_udp_send(&sr->req, handle, &sr->buf, 1,
                    (struct sockaddr*)&forwarder->target_addr, udp_on_send) != 0) {
        fprintf(stderr, "[UDP] Send to target error\n");
        forwarder->allocator->free(forwarder->allocator->ctx, buf->base);
        forwarder->allocator->free(forwarder->allocator->ctx, sr);
        return;
    }

    if (addr) {
        printf("[UDP] Forwarded %ld bytes to %s:%d\n",
               (long)nread, forwarder->target_address, forwarder->target_port);
    }
}

static void udp_on_send(uv_udp_send_t* req, int status) {
    if (!req) return;
    udp_send_req_t* sr = (udp_send_req_t*)req->data;
    if (!sr) return;

    if (status < 0) {
        fprintf(stderr, "[UDP] Send error: %d\n", status);
    }

    data_free(sr->allocator, sr->allocator->ctx, sr->data);
    sr->allocator->free(sr->allocator->ctx, sr);
}
