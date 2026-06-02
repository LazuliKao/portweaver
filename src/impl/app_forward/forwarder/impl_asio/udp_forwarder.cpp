#if !defined(PORTWEAVER_BACKEND_ASIO)
#define PORTWEAVER_BACKEND_ASIO 1
#endif

#if defined(PORTWEAVER_BACKEND_ASIO)

#include "forwarder.h"

#include <asio.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <system_error>
#include <unordered_map>
#include <utility>

#if !defined(_WIN32)
#include <unistd.h>
#endif

extern asio::io_context &forwarder_runtime_get_io_context(forwarder_runtime_t *runtime);
extern "C" forwarder_allocator_t forwarder_runtime_get_allocator(forwarder_runtime_t *runtime);

static void *runtime_alloc(forwarder_runtime_t *runtime, std::size_t size)
{
    forwarder_allocator_t allocator = forwarder_runtime_get_allocator(runtime);
    if (!allocator.malloc_cb)
    {
        return nullptr;
    }
    return allocator.malloc_cb(allocator.ctx, size);
}

static void runtime_free(forwarder_runtime_t *runtime, void *ptr)
{
    if (ptr == nullptr)
    {
        return;
    }

    forwarder_allocator_t allocator = forwarder_runtime_get_allocator(runtime);
    if (allocator.free_cb)
    {
        allocator.free_cb(allocator.ctx, ptr);
    }
}

#define DATA_ALLOC(fwd, sz) runtime_alloc((fwd)->runtime, (sz))
#define DATA_FREE(fwd, ptr) runtime_free((fwd)->runtime, (ptr))

#ifdef DEBUG
#define UDP_SESSION_TIMEOUT_MS 5000
#else
#define UDP_SESSION_TIMEOUT_MS 60000
#endif

#define UDP_MAX_SESSIONS 4000
#define UDP_SESSION_FD_RESERVE 128
#define UDP_SESSION_HASH_SIZE 1024
#define UDP_RECV_BUFFER_SIZE 65536

struct udp_forwarder;

struct endpoint_key
{
    int family;
    uint16_t port;
    uint32_t scope_id;
    std::array<unsigned char, 16> address_bytes;

    endpoint_key()
        : family(AF_UNSPEC),
          port(0),
          scope_id(0),
          address_bytes{}
    {
    }

    explicit endpoint_key(const asio::ip::udp::endpoint &endpoint)
        : family(endpoint.protocol().family()),
          port(endpoint.port()),
          scope_id(0),
          address_bytes{}
    {
        if (endpoint.address().is_v4())
        {
            const auto bytes = endpoint.address().to_v4().to_bytes();
            for (std::size_t i = 0; i < bytes.size(); ++i)
            {
                address_bytes[i] = bytes[i];
            }
        }
        else if (endpoint.address().is_v6())
        {
            const auto bytes = endpoint.address().to_v6().to_bytes();
            address_bytes = bytes;
            scope_id = endpoint.address().to_v6().scope_id();
        }
    }

    bool operator==(const endpoint_key &other) const
    {
        return family == other.family &&
               port == other.port &&
               scope_id == other.scope_id &&
               address_bytes == other.address_bytes;
    }
};

namespace std
{
template <>
struct hash<endpoint_key>
{
    std::size_t operator()(const endpoint_key &key) const noexcept
    {
        std::size_t value = 5381u;
        value = (value * 33u) ^ static_cast<std::size_t>(key.family);
        value = (value * 33u) ^ static_cast<std::size_t>(key.port);
        value = (value * 33u) ^ static_cast<std::size_t>(key.scope_id);
        for (unsigned char byte : key.address_bytes)
        {
            value = (value * 33u) ^ static_cast<std::size_t>(byte);
        }
        return value;
    }
};
} // namespace std

class udp_client_session : public std::enable_shared_from_this<udp_client_session>
{
  public:
    asio::ip::udp::socket sock;
    asio::ip::udp::endpoint client_addr;
    asio::steady_timer timeout_timer;
    std::chrono::steady_clock::time_point last_activity;
    udp_forwarder *fwd;

    udp_client_session(asio::io_context &io_ctx, udp_forwarder *forwarder, const asio::ip::udp::endpoint &client)
        : sock(io_ctx),
          client_addr(client),
          timeout_timer(io_ctx),
          last_activity(std::chrono::steady_clock::now()),
          fwd(forwarder),
          closing(false),
          recv_from_endpoint(),
          recv_buffer{}
    {
    }

    bool open_and_bind();
    void start_recv();
    void refresh_timeout();
    void close();

  private:
    std::atomic<bool> closing;
    asio::ip::udp::endpoint recv_from_endpoint;
    std::array<char, UDP_RECV_BUFFER_SIZE> recv_buffer;

    void handle_recv(const std::error_code &ec, std::size_t bytes_received);
    void handle_timeout(const std::error_code &ec);
};

struct udp_forwarder
{
    forwarder_runtime_t *runtime;
    asio::ip::udp::socket server_socket;
    asio::io_context &io_ctx;
    char *target_address;
    uint16_t listen_port;
    uint16_t target_port;
    addr_family_t family;
    int enable_stats;
    int started;
    std::atomic<int> stop_requested{0};
    std::atomic<int> destroy_requested{0};
    std::atomic<int> pending_close_count{0};
    std::atomic<unsigned long long> bytes_in;
    std::atomic<unsigned long long> bytes_out;
    std::atomic<unsigned int> active_sessions;
    asio::ip::udp::endpoint cached_dest_addr;
    std::mutex sessions_mutex;
    std::unordered_map<endpoint_key, std::shared_ptr<udp_client_session>> session_map;
    unsigned int max_sessions;
    uint32_t max_connections;

    udp_forwarder(forwarder_runtime_t *runtime_in, asio::io_context &ctx)
        : runtime(runtime_in),
          server_socket(ctx),
          io_ctx(ctx),
          target_address(nullptr),
          listen_port(0),
          target_port(0),
          family(ADDR_FAMILY_IPV4),
          enable_stats(0),
          started(0),
          stop_requested(0),
          destroy_requested(0),
          pending_close_count(0),
          bytes_in(0),
          bytes_out(0),
          active_sessions(0),
          cached_dest_addr(),
          sessions_mutex(),
          session_map(),
          max_sessions(UDP_MAX_SESSIONS),
          max_connections(0),
          server_recv_from_endpoint(),
          server_recv_buffer{}
    {
        session_map.reserve(UDP_SESSION_HASH_SIZE);
    }

    void start_server_recv();
    std::shared_ptr<udp_client_session> find_session(const asio::ip::udp::endpoint &client_addr);
    std::shared_ptr<udp_client_session> create_session(const asio::ip::udp::endpoint &client_addr);
    std::shared_ptr<udp_client_session> find_or_create_session(const asio::ip::udp::endpoint &client_addr);
    void remove_session(const endpoint_key &key, const std::shared_ptr<udp_client_session> &session);
    void close_all_sessions();
    void try_free_if_destroyed();

  private:
    asio::ip::udp::endpoint server_recv_from_endpoint;
    std::array<char, UDP_RECV_BUFFER_SIZE> server_recv_buffer;
};

void udp_forwarder::try_free_if_destroyed()
{
    if (destroy_requested.load(std::memory_order_acquire) &&
        pending_close_count.load(std::memory_order_acquire) == 0)
    {
        forwarder_runtime_t *runtime_copy = runtime;
        DATA_FREE(this, target_address);
        target_address = nullptr;
        this->~udp_forwarder();
        runtime_free(runtime_copy, this);
    }
}

static unsigned int udp_compute_session_limit(void)
{
    unsigned int max_sessions = UDP_MAX_SESSIONS;
#if !defined(_WIN32)
    long fd_limit = sysconf(_SC_OPEN_MAX);
    if (fd_limit > 0)
    {
        long derived = fd_limit - UDP_SESSION_FD_RESERVE;
        if (derived < 1)
        {
            derived = fd_limit / 2;
        }
        if (derived < 1)
        {
            derived = 1;
        }
        if (derived < static_cast<long>(max_sessions))
        {
            max_sessions = static_cast<unsigned int>(derived);
        }
    }
#endif
    return max_sessions;
}

static void set_forwarder_error(int *out_error, int error_code)
{
    if (out_error != nullptr)
    {
        *out_error = error_code;
    }
}

static int map_asio_error(const std::error_code &ec)
{
    if (ec == asio::error::address_in_use)
    {
        return FORWARDER_ERROR_ADDRESS_IN_USE;
    }
    if (ec == asio::error::access_denied)
    {
        return FORWARDER_ERROR_PERMISSION_DENIED;
    }
    if (ec == asio::error::invalid_argument || ec == asio::error::fault)
    {
        return FORWARDER_ERROR_INVALID_ADDRESS;
    }
    if (ec == asio::error::no_memory)
    {
        return FORWARDER_ERROR_MALLOC;
    }
    return FORWARDER_ERROR_BIND;
}

static int map_open_error(const std::error_code &ec)
{
    if (ec == asio::error::no_memory)
    {
        return FORWARDER_ERROR_MALLOC;
    }
    return FORWARDER_ERROR_UNKNOWN;
}

static int map_socket_error(const std::error_code &ec)
{
    if (ec == asio::error::already_open)
    {
        return map_open_error(ec);
    }
    return map_asio_error(ec);
}

template <typename T, typename... Args>
static std::shared_ptr<T> forwarder_make_shared(udp_forwarder *fwd, Args &&...args)
{
    void *raw = DATA_ALLOC(fwd, sizeof(T));
    if (raw == nullptr)
    {
        return nullptr;
    }

    T *object = nullptr;
    try
    {
        object = new (raw) T(std::forward<Args>(args)...);
    }
    catch (...)
    {
        DATA_FREE(fwd, raw);
        return nullptr;
    }

    forwarder_runtime_t *runtime = fwd->runtime;
    return std::shared_ptr<T>(object, [runtime](T *ptr) {
        if (ptr != nullptr)
        {
            ptr->~T();
            runtime_free(runtime, ptr);
        }
    });
}

static std::shared_ptr<char> forwarder_make_buffer(udp_forwarder *fwd, const char *data, std::size_t size)
{
    char *buffer = static_cast<char *>(DATA_ALLOC(fwd, size));
    if (buffer == nullptr)
    {
        return nullptr;
    }

    std::memcpy(buffer, data, size);
    forwarder_runtime_t *runtime = fwd->runtime;
    return std::shared_ptr<char>(buffer, [runtime](char *ptr) {
        runtime_free(runtime, ptr);
    });
}

static bool cache_destination_addr(asio::ip::udp::endpoint *dest, addr_family_t family, const char *target_address, uint16_t target_port)
{
    std::error_code ec;
    asio::ip::address parsed = asio::ip::make_address(target_address, ec);
    if (ec)
    {
        return false;
    }
    if (family == ADDR_FAMILY_IPV6)
    {
        if (!parsed.is_v6())
        {
            return false;
        }
    }
    else
    {
        if (!parsed.is_v4())
        {
            return false;
        }
    }
    *dest = asio::ip::udp::endpoint(parsed, target_port);
    return true;
}

static asio::ip::udp::endpoint build_listen_endpoint(addr_family_t family, uint16_t listen_port)
{
    if (family != ADDR_FAMILY_IPV4)
    {
        return asio::ip::udp::endpoint(asio::ip::address_v6::any(), listen_port);
    }
    return asio::ip::udp::endpoint(asio::ip::address_v4::any(), listen_port);
}

bool udp_client_session::open_and_bind()
{
    std::error_code ec;
    const auto protocol = (fwd->family == ADDR_FAMILY_IPV6) ? asio::ip::udp::v6() : asio::ip::udp::v4();
    sock.open(protocol, ec);
    if (ec)
    {
        return false;
    }

    sock.bind(build_listen_endpoint(fwd->family, 0), ec);
    if (ec)
    {
        std::error_code ignored;
        sock.close(ignored);
        return false;
    }

    refresh_timeout();
    return true;
}

void udp_client_session::refresh_timeout()
{
    last_activity = std::chrono::steady_clock::now();
    timeout_timer.expires_after(std::chrono::milliseconds(UDP_SESSION_TIMEOUT_MS));
    auto self = shared_from_this();
    timeout_timer.async_wait([self](const std::error_code &ec) {
        self->handle_timeout(ec);
    });
}

void udp_client_session::start_recv()
{
    if (fwd->stop_requested.load(std::memory_order_acquire) || !sock.is_open())
    {
        return;
    }

    auto self = shared_from_this();
    sock.async_receive_from(
        asio::buffer(recv_buffer),
        recv_from_endpoint,
        [self](const std::error_code &ec, std::size_t bytes_received) {
            self->handle_recv(ec, bytes_received);
        });
}

void udp_client_session::handle_recv(const std::error_code &ec, std::size_t bytes_received)
{
    if (ec)
    {
        if (ec != asio::error::operation_aborted)
        {
            std::fprintf(stderr, "[udp_session_on_recv] receive error: %s\n", ec.message().c_str());
            close();
        }
        return;
    }

    if (fwd->enable_stats)
    {
        fwd->bytes_out.fetch_add(static_cast<unsigned long long>(bytes_received), std::memory_order_relaxed);
    }

    refresh_timeout();

    auto self = shared_from_this();
    fwd->server_socket.async_send_to(
        asio::buffer(recv_buffer.data(), bytes_received),
        client_addr,
        [self](const std::error_code &send_ec, std::size_t) {
            if (send_ec)
            {
                if (send_ec != asio::error::operation_aborted)
                {
                    std::fprintf(stderr, "[udp_session_on_recv] send error: %s\n", send_ec.message().c_str());
                    self->close();
                }
                return;
            }
            self->start_recv();
        });
}

void udp_client_session::handle_timeout(const std::error_code &ec)
{
    if (ec == asio::error::operation_aborted)
    {
        return;
    }

    const auto elapsed = std::chrono::steady_clock::now() - last_activity;
    if (elapsed >= std::chrono::milliseconds(UDP_SESSION_TIMEOUT_MS))
    {
        close();
        return;
    }

    refresh_timeout();
}

void udp_client_session::close()
{
    bool expected = false;
    if (!closing.compare_exchange_strong(expected, true, std::memory_order_relaxed))
    {
        return;
    }

    std::error_code ignored;
    timeout_timer.cancel();
    if (sock.is_open())
    {
        sock.cancel(ignored);
        sock.close(ignored);
    }
    fwd->remove_session(endpoint_key(client_addr), shared_from_this());
    fwd->pending_close_count.fetch_sub(1, std::memory_order_release);
    fwd->try_free_if_destroyed();
}

std::shared_ptr<udp_client_session> udp_forwarder::find_session(const asio::ip::udp::endpoint &client_addr)
{
    std::lock_guard<std::mutex> lock(sessions_mutex);
    const endpoint_key key(client_addr);
    const auto it = session_map.find(key);
    if (it == session_map.end())
    {
        return nullptr;
    }
    if (!it->second || !it->second->sock.is_open())
    {
        return nullptr;
    }
    return it->second;
}

std::shared_ptr<udp_client_session> udp_forwarder::create_session(const asio::ip::udp::endpoint &client_addr)
{
    std::lock_guard<std::mutex> lock(sessions_mutex);
    const endpoint_key key(client_addr);
    const auto existing = session_map.find(key);
    if (existing != session_map.end() && existing->second && existing->second->sock.is_open())
    {
        return existing->second;
    }
    if (active_sessions.load(std::memory_order_relaxed) >= max_sessions)
    {
        return nullptr;
    }

    auto session = forwarder_make_shared<udp_client_session>(this, io_ctx, this, client_addr);
    if (!session || !session->open_and_bind())
    {
        return nullptr;
    }

    session_map[key] = session;
    active_sessions.fetch_add(1u, std::memory_order_relaxed);
    pending_close_count.fetch_add(1, std::memory_order_release);
    session->start_recv();
    return session;
}

std::shared_ptr<udp_client_session> udp_forwarder::find_or_create_session(const asio::ip::udp::endpoint &client_addr)
{
    if (auto session = find_session(client_addr))
    {
        return session;
    }
    return create_session(client_addr);
}

void udp_forwarder::remove_session(const endpoint_key &key, const std::shared_ptr<udp_client_session> &session)
{
    std::lock_guard<std::mutex> lock(sessions_mutex);
    const auto it = session_map.find(key);
    if (it != session_map.end() && it->second == session)
    {
        session_map.erase(it);
        active_sessions.fetch_sub(1u, std::memory_order_relaxed);
    }
}

void udp_forwarder::close_all_sessions()
{
    std::unordered_map<endpoint_key, std::shared_ptr<udp_client_session>> sessions_copy;
    {
        std::lock_guard<std::mutex> lock(sessions_mutex);
        sessions_copy = session_map;
    }

    for (auto &entry : sessions_copy)
    {
        if (entry.second)
        {
            entry.second->close();
        }
    }
}

void udp_forwarder::start_server_recv()
{
    if (stop_requested.load(std::memory_order_acquire) || !server_socket.is_open())
    {
        return;
    }

    pending_close_count.fetch_add(1, std::memory_order_release);
    server_socket.async_receive_from(
        asio::buffer(server_recv_buffer),
        server_recv_from_endpoint,
        [this](const std::error_code &ec, std::size_t bytes_received) {
            if (ec)
            {
                if (ec != asio::error::operation_aborted)
                {
                    std::fprintf(stderr, "[udp_on_recv] receive error: %s\n", ec.message().c_str());
                    start_server_recv();
                }
                pending_close_count.fetch_sub(1, std::memory_order_release);
                try_free_if_destroyed();
                return;
            }

            if (enable_stats)
            {
                bytes_in.fetch_add(static_cast<unsigned long long>(bytes_received), std::memory_order_relaxed);
            }

            auto session = find_or_create_session(server_recv_from_endpoint);
            if (session)
            {
                session->refresh_timeout();
                auto send_buffer = forwarder_make_buffer(this, server_recv_buffer.data(), bytes_received);
                if (send_buffer)
                {
                    session->sock.async_send_to(
                        asio::buffer(send_buffer.get(), bytes_received),
                        cached_dest_addr,
                        [session, send_buffer](const std::error_code &send_ec, std::size_t) {
                            if (send_ec && send_ec != asio::error::operation_aborted)
                            {
                                std::fprintf(stderr, "[udp_on_recv] send error: %s\n", send_ec.message().c_str());
                                session->close();
                            }
                        });
                }
            }

            pending_close_count.fetch_sub(1, std::memory_order_release);
            start_server_recv();
            try_free_if_destroyed();
        });
}

extern "C"
{

udp_forwarder_t *udp_forwarder_create_on_runtime(
    forwarder_runtime_t *runtime,
    uint16_t listen_port,
    const char *target_address,
    uint16_t target_port,
    addr_family_t family,
    int enable_stats,
    uint32_t connect_timeout_ms,
    uint32_t max_connections,
    int *out_error)
{
    if (runtime == nullptr || target_address == nullptr)
    {
        set_forwarder_error(out_error, FORWARDER_ERROR_UNKNOWN);
        return nullptr;
    }

    asio::io_context &io_ctx = forwarder_runtime_get_io_context(runtime);

    forwarder_allocator_t allocator = forwarder_runtime_get_allocator(runtime);
    void *raw = allocator.malloc_cb ? allocator.malloc_cb(allocator.ctx, sizeof(udp_forwarder)) : nullptr;
    if (raw == nullptr)
    {
        set_forwarder_error(out_error, FORWARDER_ERROR_MALLOC);
        return nullptr;
    }

    udp_forwarder *fwd = nullptr;
    try
    {
        fwd = new (raw) udp_forwarder(runtime, io_ctx);
    }
    catch (...)
    {
        if (allocator.free_cb)
        {
            allocator.free_cb(allocator.ctx, raw);
        }
        set_forwarder_error(out_error, FORWARDER_ERROR_MALLOC);
        return nullptr;
    }

    const std::size_t target_len = std::strlen(target_address);
    fwd->target_address = static_cast<char *>(DATA_ALLOC(fwd, target_len + 1));
    if (fwd->target_address == nullptr)
    {
        fwd->~udp_forwarder();
        DATA_FREE(fwd, raw);
        set_forwarder_error(out_error, FORWARDER_ERROR_MALLOC);
        return nullptr;
    }
    std::memcpy(fwd->target_address, target_address, target_len + 1);

    fwd->listen_port = listen_port;
    fwd->target_port = target_port;
    fwd->family = family;
    fwd->enable_stats = enable_stats;
    fwd->max_sessions = udp_compute_session_limit();
    fwd->max_connections = max_connections;
    if (max_connections > 0)
        fwd->max_sessions = max_connections;

    if (!cache_destination_addr(&fwd->cached_dest_addr, family, fwd->target_address, target_port))
    {
        DATA_FREE(fwd, fwd->target_address);
        fwd->target_address = nullptr;
        fwd->~udp_forwarder();
        DATA_FREE(fwd, raw);
        set_forwarder_error(out_error, FORWARDER_ERROR_INVALID_ADDRESS);
        return nullptr;
    }

    std::error_code ec;
    const auto listen_endpoint = build_listen_endpoint(family, listen_port);
    fwd->server_socket.open(listen_endpoint.protocol(), ec);
    if (!ec)
    {
        fwd->server_socket.bind(listen_endpoint, ec);
    }
    if (ec)
    {
        DATA_FREE(fwd, fwd->target_address);
        fwd->target_address = nullptr;
        fwd->~udp_forwarder();
        DATA_FREE(fwd, raw);
        set_forwarder_error(out_error, map_socket_error(ec));
        return nullptr;
    }

    set_forwarder_error(out_error, FORWARDER_OK);
    return fwd;
}

int udp_forwarder_start(udp_forwarder_t *forwarder)
{
    if (forwarder == nullptr || forwarder->started)
    {
        return -1;
    }

    forwarder->started = 1;
    forwarder->start_server_recv();
    return 0;
}

void udp_forwarder_request_stop(udp_forwarder_t *forwarder)
{
    if (forwarder == nullptr)
    {
        return;
    }

    int expected = 0;
    if (!forwarder->stop_requested.compare_exchange_strong(expected, 1))
    {
        return;
    }

    asio::post(forwarder->io_ctx, [forwarder]() {
        std::error_code ignored;
        if (forwarder->server_socket.is_open())
        {
            forwarder->server_socket.cancel(ignored);
            forwarder->server_socket.close(ignored);
        }
        forwarder->close_all_sessions();
        forwarder->try_free_if_destroyed();
    });
}

void udp_forwarder_destroy(udp_forwarder_t *forwarder)
{
    if (forwarder == nullptr)
    {
        return;
    }

    forwarder->destroy_requested.store(1, std::memory_order_release);

    // Already on the runtime thread — do cleanup synchronously.
    // cancel/close trigger operation_aborted handlers that decrement pending_close_count.
    // try_free_if_destroyed() frees the forwarder when all handlers drain.
    std::error_code ignored;
    if (forwarder->server_socket.is_open())
    {
        forwarder->server_socket.cancel(ignored);
        forwarder->server_socket.close(ignored);
    }
    forwarder->close_all_sessions();
    forwarder->try_free_if_destroyed();
}


traffic_stats_t udp_forwarder_get_stats(udp_forwarder_t *forwarder)
{
    traffic_stats_t stats = {};
    if (forwarder == nullptr)
    {
        return stats;
    }

    if (forwarder->enable_stats)
    {
        stats.bytes_in = forwarder->bytes_in.load(std::memory_order_relaxed);
        stats.bytes_out = forwarder->bytes_out.load(std::memory_order_relaxed);
    }
    stats.active_sessions = forwarder->active_sessions.load(std::memory_order_relaxed);
    stats.listen_port = forwarder->listen_port;
    return stats;
}
} // extern "C"

#endif
