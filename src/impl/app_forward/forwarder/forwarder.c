#include "forwarder.h"
#include "uv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>


// --- TCP Forwarder Implementation ---
typedef struct tcp_conn_ctx {
	uv_tcp_t client;
	uv_tcp_t target;
	uv_connect_t connect_req;
	uv_shutdown_t shutdown_req_client; // changed: separate shutdown reqs
	uv_shutdown_t shutdown_req_target;
	struct tcp_forwarder *forwarder;
	int closed;
	int use_allocator;
	int close_count;
} tcp_conn_ctx_t;

static void* default_alloc(void* ctx, size_t size) {
	(void)ctx;
	return malloc(size);
}

static void default_free(void* ctx, void* ptr) {
	(void)ctx;
	free(ptr);
}
// Forward declarations for C callbacks
static void tcp_on_client_read(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf);
static void tcp_on_target_read(uv_stream_t* target, ssize_t nread, const uv_buf_t* buf);
static void tcp_on_client_write(uv_write_t* req, int status);
static void tcp_on_target_write(uv_write_t* req, int status);
static void tcp_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
static void tcp_walk_close_cb(uv_handle_t* handle, void* arg);
static void udp_walk_close_cb(uv_handle_t* handle, void* arg);
static void udp_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
static int sockaddr_equal(const struct sockaddr* a, const struct sockaddr* b);

struct tcp_forwarder {
	allocator_t *allocator;
	uv_loop_t *loop;
	uv_tcp_t server;
	char *target_address;
	uint16_t target_port;
	addr_family_t family;
	int running;
	allocator_t allocator_storage;
	struct sockaddr_storage cached_dest_addr; // added: cache destination addr
};

static void tcp_close_cb(uv_handle_t* handle) {
	tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t*)handle->data;
	if (!ctx) return;
	ctx->close_count++;
	if (ctx->close_count >= 2) {
		// both handles closed -> free ctx
		if (ctx->use_allocator && ctx->forwarder && ctx->forwarder->allocator && ctx->forwarder->allocator->free) {
			ctx->forwarder->allocator->free(ctx->forwarder->allocator->ctx, ctx);
		} else {
			free(ctx);
		}
	}
}

static void tcp_on_client_write(uv_write_t* req, int status) {
	if (status != 0) {
		fprintf(stderr, "[tcp_on_client_write] write error: %s\n", uv_strerror(status));
	}
	if (req->data) free(req->data);
	free(req);
}

static void tcp_on_target_write(uv_write_t* req, int status) {
	if (status != 0) {
		fprintf(stderr, "[tcp_on_target_write] write error: %s\n", uv_strerror(status));
	}
	if (req->data) free(req->data);
	free(req);
}

static void tcp_on_client_read(uv_stream_t* client, ssize_t nread, const uv_buf_t* buf) {
	tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t*)client->data;
	if (nread > 0) {
		uv_write_t *write_req = (uv_write_t*)malloc(sizeof(uv_write_t));
		if (!write_req) {
			free(buf->base);
			return;
		}
		uv_buf_t wbuf = uv_buf_init(buf->base, nread);
		write_req->data = buf->base;
		int r = uv_write(write_req, (uv_stream_t*)&ctx->target, &wbuf, 1, tcp_on_client_write);
		if (r != 0) {
			fprintf(stderr, "[tcp_on_client_read] uv_write failed: %s\n", uv_strerror(r));
			if (write_req->data) free(write_req->data);
			free(write_req);
		}
		return;
	}
	if (buf->base) free(buf->base);
	if (nread < 0) {
		// Gracefully shutdown target's write side to flush pending data, then close client
		if (!uv_is_closing((uv_handle_t*)&ctx->target)) {
			uv_shutdown(&ctx->shutdown_req_target, (uv_stream_t*)&ctx->target, NULL);
		}
		if (!uv_is_closing((uv_handle_t*)client)) uv_close((uv_handle_t*)client, tcp_close_cb);
	}
}

static void tcp_on_target_read(uv_stream_t* target, ssize_t nread, const uv_buf_t* buf) {
	tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t*)target->data;
	if (nread > 0) {
		uv_write_t *write_req = (uv_write_t*)malloc(sizeof(uv_write_t));
		if (!write_req) {
			free(buf->base);
			return;
		}
		uv_buf_t wbuf = uv_buf_init(buf->base, nread);
		write_req->data = buf->base;
		int r = uv_write(write_req, (uv_stream_t*)&ctx->client, &wbuf, 1, tcp_on_target_write);
		if (r != 0) {
			fprintf(stderr, "[tcp_on_target_read] uv_write failed: %s\n", uv_strerror(r));
			if (write_req->data) free(write_req->data);
			free(write_req);
		}
		return;
	}
	if (buf->base) free(buf->base);
	if (nread < 0) {
		// Gracefully shutdown client's write side to flush pending data, then close target
		if (!uv_is_closing((uv_handle_t*)&ctx->client)) {
			uv_shutdown(&ctx->shutdown_req_client, (uv_stream_t*)&ctx->client, NULL);
		}
		if (!uv_is_closing((uv_handle_t*)target)) uv_close((uv_handle_t*)target, tcp_close_cb);
	}
}

static void tcp_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
	buf->base = (char*)malloc(suggested_size);
	buf->len = (unsigned int)suggested_size;
}

// UDP buffer allocation callback
static void udp_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
	(void)handle;
	buf->base = (char*)malloc(suggested_size);
	buf->len = (unsigned int)suggested_size;
}

// Compare two sockaddr structures for equality (supports IPv4 and IPv6)
static int sockaddr_equal(const struct sockaddr* a, const struct sockaddr* b) {
	if (!a || !b) return 0;
	if (a->sa_family != b->sa_family) return 0;
	if (a->sa_family == AF_INET) {
		const struct sockaddr_in *ai = (const struct sockaddr_in*)a;
		const struct sockaddr_in *bi = (const struct sockaddr_in*)b;
		return ai->sin_port == bi->sin_port && ai->sin_addr.s_addr == bi->sin_addr.s_addr;
	} else if (a->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a6 = (const struct sockaddr_in6*)a;
		const struct sockaddr_in6 *b6 = (const struct sockaddr_in6*)b;
		if (a6->sin6_port != b6->sin6_port) return 0;
		return memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr)) == 0;
	}
	return 0;
}

static void tcp_on_connect(uv_connect_t* req, int status) {
	tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t*)req->data;
	if (status == 0) {
		uv_read_start((uv_stream_t*)&ctx->client, tcp_alloc_cb, tcp_on_client_read);
		uv_read_start((uv_stream_t*)&ctx->target, tcp_alloc_cb, tcp_on_target_read);
	} else {
		uv_close((uv_handle_t*)&ctx->client, tcp_close_cb);
		uv_close((uv_handle_t*)&ctx->target, tcp_close_cb);
	}
}

static void tcp_on_new_connection(uv_stream_t* server, int status) {
	if (status < 0) return;
	struct tcp_forwarder *fwd = (struct tcp_forwarder*)server->data;
	if (!fwd) {
		fprintf(stderr, "[tcp_on_new_connection] fwd is NULL!\n");
		return;
	}
	// Allocate per-connection context using malloc to avoid invoking external allocators
	// from libuv's thread callbacks (safer across thread contexts).
	tcp_conn_ctx_t *ctx = (tcp_conn_ctx_t*)malloc(sizeof(tcp_conn_ctx_t));
	if (!ctx) {
		fprintf(stderr, "[tcp_on_new_connection] malloc for ctx failed\n");
		return;
	}
	ctx->use_allocator = 0;
	memset(ctx, 0, sizeof(*ctx));
	ctx->forwarder = fwd;
	ctx->closed = 0;
	ctx->close_count = 0;
	uv_tcp_init(fwd->loop, &ctx->client);
	uv_tcp_init(fwd->loop, &ctx->target);
	ctx->client.data = ctx;
	ctx->target.data = ctx;
	if (uv_accept(server, (uv_stream_t*)&ctx->client) == 0) {
		ctx->connect_req.data = ctx;
		// Use cached target address (avoid per-connection uv_ip*_addr)
		uv_tcp_connect(&ctx->connect_req, &ctx->target, (const struct sockaddr*)&fwd->cached_dest_addr, tcp_on_connect);
	} else {
		uv_close((uv_handle_t*)&ctx->client, tcp_close_cb);
		uv_close((uv_handle_t*)&ctx->target, tcp_close_cb);
	}
}

tcp_forwarder_t* tcp_forwarder_create(
	allocator_t* allocator,
	uint16_t listen_port,
	const char* target_address,
	uint16_t target_port,
	addr_family_t family
) {
	// If allocator is NULL or missing callbacks, use default malloc/free wrappers
	struct tcp_forwarder *fwd = NULL;
	if (allocator && allocator->alloc && allocator->free) {
		fwd = (struct tcp_forwarder*)allocator->alloc(allocator->ctx, sizeof(struct tcp_forwarder));
		if (!fwd) return NULL;
		memset(fwd, 0, sizeof(*fwd));
		fwd->allocator = allocator;
	} else {
		// allocate with malloc and populate allocator_storage
		fwd = (struct tcp_forwarder*)malloc(sizeof(struct tcp_forwarder));
		if (!fwd) return NULL;
		memset(fwd, 0, sizeof(*fwd));
		fwd->allocator_storage.ctx = NULL;
		fwd->allocator_storage.alloc = default_alloc;
		fwd->allocator_storage.free = default_free;
		fwd->allocator = &fwd->allocator_storage;
	}
	fwd->loop = uv_loop_new();
	uv_tcp_init(fwd->loop, &fwd->server);
	fwd->server.data = fwd;
	fwd->target_address = strdup(target_address);
	fwd->target_port = target_port;
	fwd->family = family;
	// cache parsed destination sockaddr to avoid repeated parsing
	if (family == ADDR_FAMILY_IPV6) {
		struct sockaddr_in6 addr6;
		uv_ip6_addr(fwd->target_address, fwd->target_port, &addr6);
		memcpy(&fwd->cached_dest_addr, &addr6, sizeof(addr6));
	} else {
		struct sockaddr_in addr4;
		uv_ip4_addr(fwd->target_address, fwd->target_port, &addr4);
		memcpy(&fwd->cached_dest_addr, &addr4, sizeof(addr4));
	}
	struct sockaddr_storage addr;
	if (family == ADDR_FAMILY_IPV6) {
		struct sockaddr_in6 addr6;
		uv_ip6_addr("::", listen_port, &addr6);
		memcpy(&addr, &addr6, sizeof(addr6));
	} else {
		struct sockaddr_in addr4;
		uv_ip4_addr("0.0.0.0", listen_port, &addr4);
		memcpy(&addr, &addr4, sizeof(addr4));
	}
	uv_tcp_bind(&fwd->server, (const struct sockaddr*)&addr, 0);
	return fwd;
}

int tcp_forwarder_start(tcp_forwarder_t* forwarder) {
	int r = uv_listen((uv_stream_t*)&forwarder->server, 128, tcp_on_new_connection);
	if (r != 0) return r;
	forwarder->running = 1;
	return uv_run(forwarder->loop, UV_RUN_DEFAULT);
}

void tcp_forwarder_stop(tcp_forwarder_t* forwarder) {
	if (forwarder->running) {
		uv_stop(forwarder->loop);
		forwarder->running = 0;
	}
}

void tcp_forwarder_destroy(tcp_forwarder_t* forwarder) {
	if (!forwarder) return;
	// stop loop and close all handles; ensure per-connection ctx are freed by tcp_close_cb
	uv_stop(forwarder->loop);
	uv_walk(forwarder->loop, tcp_walk_close_cb, forwarder);
	while (uv_loop_alive(forwarder->loop)) uv_run(forwarder->loop, UV_RUN_DEFAULT);
	// close and free loop to avoid memory leak
	if (forwarder->loop) {
		uv_loop_close(forwarder->loop);
		free(forwarder->loop);
		forwarder->loop = NULL;
	}
	if (forwarder->target_address) free(forwarder->target_address);
	if (forwarder->allocator == &forwarder->allocator_storage) {
		free(forwarder);
	} else {
		forwarder->allocator->free(forwarder->allocator->ctx, forwarder);
	}
}

// --- UDP Forwarder Implementation ---

// [Moved up] client session struct must be declared before udp_forwarder_t_impl uses it
typedef struct udp_client_session {
	uv_udp_t sock; // ephemeral socket bound for this client to talk to target
	struct sockaddr_storage client_addr;
	int client_addr_len;
	struct udp_forwarder *fwd;
	struct udp_client_session *next;
} udp_client_session_t;

static void udp_on_send(uv_udp_send_t* req, int status) {
	if (status != 0) {
		fprintf(stderr, "[udp_on_send] send error: %s\n", uv_strerror(status));
	}
	if (req->data) free(req->data);
	free(req);
}

static void tcp_walk_close_cb(uv_handle_t* handle, void* arg) {
	struct tcp_forwarder *fwd = (struct tcp_forwarder*)arg;
	if (!handle) return;
	if (handle == (uv_handle_t*)&fwd->server) {
		if (!uv_is_closing(handle)) uv_close(handle, NULL);
	} else if (handle->type == UV_TCP) {
		if (!uv_is_closing(handle)) uv_close(handle, tcp_close_cb);
	} else {
		if (!uv_is_closing(handle)) uv_close(handle, NULL);
	}
}

static void udp_walk_close_cb(uv_handle_t* handle, void* arg) {
	(void)arg;
	if (!handle) return;
	if (!uv_is_closing(handle)) uv_close(handle, NULL);
}

static void udp_session_on_recv(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
						const struct sockaddr* addr, unsigned flags) {
	udp_client_session_t *session = (udp_client_session_t*)handle->data;
	if (nread > 0) {
		// forward to original client via the server socket
		uv_udp_send_t *send_req = malloc(sizeof(uv_udp_send_t));
		if (!send_req) {
			free(buf->base);
			return;
		}
		char *data = malloc(nread);
		if (!data) {
			free(send_req);
			free(buf->base);
			return;
		}
		memcpy(data, buf->base, nread);
		uv_buf_t wbuf = uv_buf_init(data, nread);
		send_req->data = data;
		int r = uv_udp_send(send_req, &session->fwd->server, &wbuf, 1, (const struct sockaddr*)&session->client_addr, udp_on_send);
		if (r != 0) {
			fprintf(stderr, "[udp_session_on_recv] uv_udp_send failed: %s\n", uv_strerror(r));
			if (send_req->data) free(send_req->data);
			free(send_req);
		}
	}
	if (buf->base) free(buf->base);
}

// create a session (ephemeral socket) for a client address
static udp_client_session_t* udp_session_create(udp_forwarder_t_impl *fwd, const struct sockaddr* client_addr, int addr_len) {
	udp_client_session_t *s = (udp_client_session_t*)malloc(sizeof(udp_client_session_t));
	if (!s) return NULL;
	memset(s, 0, sizeof(*s));
	s->fwd = (struct udp_forwarder*)fwd;
	s->client_addr_len = addr_len;
	memcpy(&s->client_addr, client_addr, addr_len);
	uv_udp_init(fwd->loop, &s->sock);
	s->sock.data = s;
	// bind ephemeral port (0)
	if (fwd->family == ADDR_FAMILY_IPV6) {
		struct sockaddr_in6 bind6;
		uv_ip6_addr("::", 0, &bind6);
		uv_udp_bind(&s->sock, (const struct sockaddr*)&bind6, 0);
	} else {
		struct sockaddr_in bind4;
		uv_ip4_addr("0.0.0.0", 0, &bind4);
		uv_udp_bind(&s->sock, (const struct sockaddr*)&bind4, 0);
	}
	uv_udp_recv_start(&s->sock, udp_alloc_cb, udp_session_on_recv);
	// prepend to session list
	s->next = fwd->sessions;
	fwd->sessions = s;
	return s;
}

// find session by client addr
static udp_client_session_t* udp_find_session(udp_forwarder_t_impl *fwd, const struct sockaddr* client_addr) {
	udp_client_session_t *it = fwd->sessions;
	while (it) {
		if (sockaddr_equal((const struct sockaddr*)&it->client_addr, client_addr)) return it;
		it = it->next;
	}
	return NULL;
}

static void udp_on_recv(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf,
						const struct sockaddr* addr, unsigned flags) {
	udp_forwarder_t_impl *fwd = (udp_forwarder_t_impl*)handle->data;
	if (nread > 0 && addr) {
		// create/find session for this client and send to cached target using per-client socket
		udp_client_session_t *session = udp_find_session(fwd, addr);
		if (!session) {
			session = udp_session_create(fwd, addr, (addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
			if (!session) {
				free(buf->base);
				return;
			}
		}
		uv_udp_send_t *send_req = malloc(sizeof(uv_udp_send_t));
		if (!send_req) {
			free(buf->base);
			return;
		}
		char *data = malloc(nread);
		if (!data) {
			free(send_req);
			free(buf->base);
			return;
		}
		memcpy(data, buf->base, nread);
		uv_buf_t wbuf = uv_buf_init(data, nread);
		send_req->data = data;
		// send from session socket to cached target addr
		int r = uv_udp_send(send_req, &session->sock, &wbuf, 1, (const struct sockaddr*)&fwd->cached_dest_addr, udp_on_send);
		if (r != 0) {
			fprintf(stderr, "[udp_on_recv] uv_udp_send failed: %s\n", uv_strerror(r));
			if (send_req->data) free(send_req->data);
			free(send_req);
		}
	}
	if (buf->base) free(buf->base);
}

udp_forwarder_t* udp_forwarder_create(
	allocator_t* allocator,
	uint16_t listen_port,
	const char* target_address,
	uint16_t target_port,
	addr_family_t family
) {
	udp_forwarder_t_impl *fwd = NULL;
	if (allocator && allocator->alloc && allocator->free) {
		fwd = (udp_forwarder_t_impl*)allocator->alloc(allocator->ctx, sizeof(udp_forwarder_t_impl));
		if (!fwd) return NULL;
		memset(fwd, 0, sizeof(*fwd));
		fwd->allocator = allocator;
	} else {
		fwd = (udp_forwarder_t_impl*)malloc(sizeof(udp_forwarder_t_impl));
		if (!fwd) return NULL;
		memset(fwd, 0, sizeof(*fwd));
		fwd->allocator_storage.ctx = NULL;
		fwd->allocator_storage.alloc = default_alloc;
		fwd->allocator_storage.free = default_free;
		fwd->allocator = &fwd->allocator_storage;
	}
	fwd->loop = uv_loop_new();
	uv_udp_init(fwd->loop, &fwd->server);
	fwd->server.data = fwd;
	fwd->target_address = strdup(target_address);
	fwd->target_port = target_port;
	fwd->family = family;
	fwd->running = 0;
	fwd->sessions = NULL;
	// cache target addr
	if (family == ADDR_FAMILY_IPV6) {
		struct sockaddr_in6 addr6;
		uv_ip6_addr(fwd->target_address, fwd->target_port, &addr6);
		memcpy(&fwd->cached_dest_addr, &addr6, sizeof(addr6));
	} else {
		struct sockaddr_in addr4;
		uv_ip4_addr(fwd->target_address, fwd->target_port, &addr4);
		memcpy(&fwd->cached_dest_addr, &addr4, sizeof(addr4));
	}
	struct sockaddr_storage addr;
	if (family == ADDR_FAMILY_IPV6) {
		struct sockaddr_in6 addr6;
		uv_ip6_addr("::", listen_port, &addr6);
		memcpy(&addr, &addr6, sizeof(addr6));
	} else {
		struct sockaddr_in addr4;
		uv_ip4_addr("0.0.0.0", listen_port, &addr4);
		memcpy(&addr, &addr4, sizeof(addr4));
	}
	uv_udp_bind(&fwd->server, (const struct sockaddr*)&addr, 0);
	return (udp_forwarder_t*)fwd;
}

int udp_forwarder_start(udp_forwarder_t* forwarder) {
	udp_forwarder_t_impl *fwd = (udp_forwarder_t_impl*)forwarder;
	if (!fwd) return UV_EINVAL;
	int r = uv_udp_recv_start(&fwd->server, udp_alloc_cb, udp_on_recv);
	if (r != 0) return r;
	fwd->running = 1;
	return uv_run(fwd->loop, UV_RUN_DEFAULT);
}

void udp_forwarder_destroy(udp_forwarder_t* forwarder) {
	udp_forwarder_t_impl *fwd = (udp_forwarder_t_impl*)forwarder;
	if (!fwd) return;
	// stop loop and close all handles
	uv_stop(fwd->loop);
	// walk handles and close
	uv_walk(fwd->loop, udp_walk_close_cb, fwd);
	// run loop until all handles closed
	while (uv_loop_alive(fwd->loop)) uv_run(fwd->loop, UV_RUN_DEFAULT);
	// free session structs (their handles are closed)
	udp_client_session_t *it = fwd->sessions;
	while (it) {
		udp_client_session_t *next = it->next;
		free(it);
		it = next;
	}
	if (fwd->target_address) free(fwd->target_address);
	// [FIX] close and free loop
	if (fwd->loop) {
		uv_loop_close(fwd->loop);
		free(fwd->loop);
		fwd->loop = NULL;
	}
	if (fwd->allocator == &fwd->allocator_storage) {
		free(fwd);
	} else {
		fwd->allocator->free(fwd->allocator->ctx, fwd);
	}
}

// --- Utility ---
const char* uv_get_version_string(void) {
	return uv_version_string();
}
