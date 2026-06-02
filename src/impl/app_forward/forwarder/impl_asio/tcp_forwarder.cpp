#if !defined(PORTWEAVER_BACKEND_ASIO)
#define PORTWEAVER_BACKEND_ASIO 1
#endif

#if defined(PORTWEAVER_BACKEND_ASIO)

#include "forwarder.h"

#include <asio.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <mutex>
#include <new>
#include <vector>

extern "C" forwarder_allocator_t forwarder_runtime_get_allocator(forwarder_runtime_t *runtime);
extern asio::io_context &forwarder_runtime_get_io_context(forwarder_runtime_t *runtime);

namespace
{
constexpr std::size_t TCP_FORWARD_BUFFER_SIZE = 16 * 1024;

void *runtime_alloc(forwarder_runtime_t *runtime, std::size_t size)
{
    forwarder_allocator_t allocator = forwarder_runtime_get_allocator(runtime);
    if (!allocator.malloc_cb)
        return nullptr;
    return allocator.malloc_cb(allocator.ctx, size);
}

void runtime_free(forwarder_runtime_t *runtime, void *ptr)
{
    if (!ptr)
        return;
    forwarder_allocator_t allocator = forwarder_runtime_get_allocator(runtime);
    if (allocator.free_cb)
        allocator.free_cb(allocator.ctx, ptr);
}

#define DATA_ALLOC(fwd, sz) runtime_alloc((fwd)->runtime, (sz))
#define DATA_FREE(fwd, ptr) runtime_free((fwd)->runtime, (ptr))

void set_forwarder_error(int *out_error, int error_code)
{
    if (out_error)
        *out_error = error_code;
}

int map_asio_init_error(const asio::error_code &ec)
{
    if (ec == asio::error::no_memory)
        return FORWARDER_ERROR_MALLOC;
    return FORWARDER_ERROR_UNKNOWN;
}

int map_bind_error(const asio::error_code &ec)
{
    if (ec == asio::error::address_in_use)
        return FORWARDER_ERROR_ADDRESS_IN_USE;
    if (ec == asio::error::access_denied)
        return FORWARDER_ERROR_PERMISSION_DENIED;
    if (ec == asio::error::invalid_argument || ec == asio::error::address_family_not_supported)
        return FORWARDER_ERROR_INVALID_ADDRESS;
    return FORWARDER_ERROR_BIND;
}

asio::ip::tcp::endpoint make_target_endpoint(addr_family_t family, const char *target_address, uint16_t target_port, asio::error_code &ec)
{
    if (family == ADDR_FAMILY_IPV6)
        return asio::ip::tcp::endpoint(asio::ip::make_address_v6(target_address, ec), target_port);
    return asio::ip::tcp::endpoint(asio::ip::make_address_v4(target_address, ec), target_port);
}

asio::ip::tcp::endpoint make_listen_endpoint(addr_family_t family, uint16_t listen_port)
{
    if (family == ADDR_FAMILY_IPV4)
        return asio::ip::tcp::endpoint(asio::ip::tcp::v4(), listen_port);
    return asio::ip::tcp::endpoint(asio::ip::tcp::v6(), listen_port);
}

bool is_ignored_shutdown_error(const asio::error_code &ec)
{
    return !ec || ec == asio::error::not_connected || ec == asio::error::broken_pipe ||
           ec == asio::error::bad_descriptor || ec == asio::error::shut_down ||
           ec == asio::error::operation_aborted;
}
} // namespace

struct tcp_forwarder;

class tcp_conn_ctx : public std::enable_shared_from_this<tcp_conn_ctx>
{
  public:
    tcp_conn_ctx(asio::io_context &io_ctx, tcp_forwarder *owner_forwarder);

    static std::shared_ptr<tcp_conn_ctx> create(tcp_forwarder *owner_forwarder);

    void async_connect_to_target();
    void start_forwarding();
    void force_close();

    asio::ip::tcp::socket client_socket;
    asio::ip::tcp::socket target_socket;
    std::array<unsigned char, TCP_FORWARD_BUFFER_SIZE> client_buffer;
    std::array<unsigned char, TCP_FORWARD_BUFFER_SIZE> target_buffer;
    bool client_eof;
    bool target_eof;

  private:
    void start_client_read();
    void start_target_read();
    void on_client_read(const asio::error_code &ec, std::size_t bytes_transferred);
    void on_target_read(const asio::error_code &ec, std::size_t bytes_transferred);
    void write_to_target(std::size_t bytes_transferred);
    void write_to_client(std::size_t bytes_transferred);
    void on_target_write(const asio::error_code &ec);
    void on_client_write(const asio::error_code &ec);
    void handle_client_eof();
    void handle_target_eof();
    void shutdown_socket_write(asio::ip::tcp::socket &socket);
    void maybe_finish();
    void close_internal();

    tcp_forwarder *owner;
    bool closing;
    bool target_write_pending;
    bool client_write_pending;
    std::shared_ptr<asio::steady_timer> connect_timer;
};

struct tcp_forwarder
{
    forwarder_runtime_t *runtime;
    asio::ip::tcp::acceptor acceptor;
    asio::io_context &io_ctx;
    char *target_address;
    uint16_t listen_port;
    uint16_t target_port;
    addr_family_t family;
    int enable_stats;
    uint32_t connect_timeout_ms;
    uint32_t max_connections;
    int started;
    std::atomic<int> stop_requested{0};
    std::atomic<int> destroy_requested{0};
    std::atomic<int> pending_close_count{0};
    std::atomic<unsigned long long> bytes_in;
    std::atomic<unsigned long long> bytes_out;
    std::atomic<unsigned int> active_sessions;
    asio::ip::tcp::endpoint cached_dest_addr;
    std::mutex sessions_mutex;
    std::vector<std::shared_ptr<tcp_conn_ctx>> active_conns;

    tcp_forwarder(forwarder_runtime_t *runtime_value, asio::io_context &io_ctx_value)
        : runtime(runtime_value), acceptor(io_ctx_value), io_ctx(io_ctx_value), target_address(nullptr), listen_port(0),
          target_port(0), family(ADDR_FAMILY_IPV4), enable_stats(0), connect_timeout_ms(0), max_connections(0), started(0), stop_requested(0), destroy_requested(0),
          pending_close_count(0), bytes_in(0), bytes_out(0), active_sessions(0), cached_dest_addr()
    {
    }

    ~tcp_forwarder()
    {
        if (target_address)
        {
            DATA_FREE(this, target_address);
            target_address = nullptr;
        }
    }

    void start_accept_loop()
    {
        if (!acceptor.is_open())
            return;

        std::shared_ptr<tcp_conn_ctx> conn = tcp_conn_ctx::create(this);
        if (!conn)
            return;

        pending_close_count.fetch_add(1, std::memory_order_release);
        acceptor.async_accept(conn->client_socket, [this, conn](const asio::error_code &ec) {
            if (!ec)
            {
                if (max_connections > 0 && active_sessions.load(std::memory_order_relaxed) >= max_connections)
                {
                    asio::error_code ignored;
                    conn->client_socket.close(ignored);
                }
                else
                {
                    {
                        std::lock_guard<std::mutex> lock(sessions_mutex);
                        active_conns.push_back(conn);
                    }
                    active_sessions.fetch_add(1u, std::memory_order_relaxed);
                    pending_close_count.fetch_add(1, std::memory_order_release);
                    conn->async_connect_to_target();
                }
            }

            pending_close_count.fetch_sub(1, std::memory_order_release);
            if (!ec || ec != asio::error::operation_aborted)
                start_accept_loop();
            try_free_if_destroyed();
        });
    }

    void remove_connection(tcp_conn_ctx *conn)
    {
        std::lock_guard<std::mutex> lock(sessions_mutex);
        auto it = std::remove_if(active_conns.begin(), active_conns.end(), [conn](const std::shared_ptr<tcp_conn_ctx> &item) {
            return item.get() == conn;
        });
        if (it != active_conns.end())
            active_conns.erase(it, active_conns.end());
    }

    void close_acceptor()
    {
        asio::error_code ec;
        acceptor.cancel(ec);
        acceptor.close(ec);
    }

    void close_all_sessions()
    {
        std::vector<std::shared_ptr<tcp_conn_ctx>> snapshot;
        {
            std::lock_guard<std::mutex> lock(sessions_mutex);
            snapshot = active_conns;
        }

        for (const std::shared_ptr<tcp_conn_ctx> &conn : snapshot)
        {
            if (conn)
                conn->force_close();
        }
    }

    void stop_on_runtime_thread()
    {
        close_acceptor();
        close_all_sessions();
        try_free_if_destroyed();
    }

    void try_free_if_destroyed()
    {
        if (!destroy_requested.load(std::memory_order_acquire))
            return;
        if (pending_close_count.load(std::memory_order_acquire) > 0)
            return;

        forwarder_runtime_t *runtime_copy = runtime;
        this->~tcp_forwarder();
        runtime_free(runtime_copy, this);
    }
};

tcp_conn_ctx::tcp_conn_ctx(asio::io_context &io_ctx, tcp_forwarder *owner_forwarder)
    : client_socket(io_ctx), target_socket(io_ctx), client_buffer(), target_buffer(), client_eof(false), target_eof(false),
      owner(owner_forwarder), closing(false), target_write_pending(false), client_write_pending(false)
{
}

std::shared_ptr<tcp_conn_ctx> tcp_conn_ctx::create(tcp_forwarder *owner_forwarder)
{
    void *memory = DATA_ALLOC(owner_forwarder, sizeof(tcp_conn_ctx));
    if (!memory)
        return {};

    forwarder_runtime_t *runtime = owner_forwarder->runtime;
    auto deleter = [runtime](tcp_conn_ctx *ctx) {
        if (!ctx)
            return;
        ctx->~tcp_conn_ctx();
        runtime_free(runtime, ctx);
    };

    return std::shared_ptr<tcp_conn_ctx>(new (memory) tcp_conn_ctx(owner_forwarder->io_ctx, owner_forwarder), deleter);
}

void tcp_conn_ctx::async_connect_to_target()
{
    std::shared_ptr<tcp_conn_ctx> self = shared_from_this();

    if (owner->connect_timeout_ms > 0)
    {
        connect_timer = std::make_shared<asio::steady_timer>(target_socket.get_executor());
        connect_timer->expires_after(std::chrono::milliseconds(owner->connect_timeout_ms));
        connect_timer->async_wait([self](const asio::error_code &ec) {
            if (ec || self->closing)
                return;
            self->target_socket.close();
        });
    }

    target_socket.async_connect(owner->cached_dest_addr, [self](const asio::error_code &ec) {
        if (self->connect_timer)
        {
            self->connect_timer->cancel();
            self->connect_timer.reset();
        }
        if (ec)
        {
            self->force_close();
            return;
        }
        self->start_forwarding();
    });
}

void tcp_conn_ctx::start_forwarding()
{
    start_client_read();
    start_target_read();
}

void tcp_conn_ctx::start_client_read()
{
    if (closing || client_eof)
        return;

    std::shared_ptr<tcp_conn_ctx> self = shared_from_this();
    client_socket.async_read_some(asio::buffer(client_buffer), [self](const asio::error_code &ec, std::size_t bytes_transferred) {
        self->on_client_read(ec, bytes_transferred);
    });
}

void tcp_conn_ctx::start_target_read()
{
    if (closing || target_eof)
        return;

    std::shared_ptr<tcp_conn_ctx> self = shared_from_this();
    target_socket.async_read_some(asio::buffer(target_buffer), [self](const asio::error_code &ec, std::size_t bytes_transferred) {
        self->on_target_read(ec, bytes_transferred);
    });
}

void tcp_conn_ctx::on_client_read(const asio::error_code &ec, std::size_t bytes_transferred)
{
    if (closing)
        return;

    if (!ec)
    {
        if (owner->enable_stats)
            owner->bytes_in.fetch_add(static_cast<unsigned long long>(bytes_transferred), std::memory_order_relaxed);
        write_to_target(bytes_transferred);
        return;
    }

    if (ec == asio::error::eof)
    {
        handle_client_eof();
        return;
    }

    if (ec != asio::error::operation_aborted)
        force_close();
}

void tcp_conn_ctx::on_target_read(const asio::error_code &ec, std::size_t bytes_transferred)
{
    if (closing)
        return;

    if (!ec)
    {
        if (owner->enable_stats)
            owner->bytes_out.fetch_add(static_cast<unsigned long long>(bytes_transferred), std::memory_order_relaxed);
        write_to_client(bytes_transferred);
        return;
    }

    if (ec == asio::error::eof)
    {
        handle_target_eof();
        return;
    }

    if (ec != asio::error::operation_aborted)
        force_close();
}

void tcp_conn_ctx::write_to_target(std::size_t bytes_transferred)
{
    if (closing)
        return;

    target_write_pending = true;
    std::shared_ptr<tcp_conn_ctx> self = shared_from_this();
    asio::async_write(target_socket, asio::buffer(client_buffer.data(), bytes_transferred),
                      [self](const asio::error_code &ec, std::size_t) { self->on_target_write(ec); });
}

void tcp_conn_ctx::write_to_client(std::size_t bytes_transferred)
{
    if (closing)
        return;

    client_write_pending = true;
    std::shared_ptr<tcp_conn_ctx> self = shared_from_this();
    asio::async_write(client_socket, asio::buffer(target_buffer.data(), bytes_transferred),
                      [self](const asio::error_code &ec, std::size_t) { self->on_client_write(ec); });
}

void tcp_conn_ctx::on_target_write(const asio::error_code &ec)
{
    target_write_pending = false;

    if (closing)
        return;

    if (ec)
    {
        if (ec != asio::error::operation_aborted)
            force_close();
        return;
    }

    if (client_eof)
    {
        maybe_finish();
        return;
    }

    start_client_read();
}

void tcp_conn_ctx::on_client_write(const asio::error_code &ec)
{
    client_write_pending = false;

    if (closing)
        return;

    if (ec)
    {
        if (ec != asio::error::operation_aborted)
            force_close();
        return;
    }

    if (target_eof)
    {
        maybe_finish();
        return;
    }

    start_target_read();
}

void tcp_conn_ctx::handle_client_eof()
{
    if (closing || client_eof)
        return;

    client_eof = true;
    shutdown_socket_write(target_socket);
    maybe_finish();
}

void tcp_conn_ctx::handle_target_eof()
{
    if (closing || target_eof)
        return;

    target_eof = true;
    shutdown_socket_write(client_socket);
    maybe_finish();
}

void tcp_conn_ctx::shutdown_socket_write(asio::ip::tcp::socket &socket)
{
    asio::error_code ec;
    socket.shutdown(asio::ip::tcp::socket::shutdown_send, ec);
    if (!is_ignored_shutdown_error(ec))
        force_close();
}

void tcp_conn_ctx::maybe_finish()
{
    if (closing)
        return;
    if (client_eof && target_eof && !client_write_pending && !target_write_pending)
        close_internal();
}

void tcp_conn_ctx::close_internal()
{
    if (closing)
        return;

    closing = true;

    if (connect_timer)
    {
        connect_timer->cancel();
        connect_timer.reset();
    }

    asio::error_code ec;
    client_socket.cancel(ec);
    target_socket.cancel(ec);
    client_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    target_socket.shutdown(asio::ip::tcp::socket::shutdown_both, ec);
    client_socket.close(ec);
    target_socket.close(ec);

    owner->remove_connection(this);
    owner->active_sessions.fetch_sub(1u, std::memory_order_relaxed);
    owner->pending_close_count.fetch_sub(1, std::memory_order_release);
    owner->try_free_if_destroyed();
}

void tcp_conn_ctx::force_close()
{
    close_internal();
}

extern "C" tcp_forwarder_t *tcp_forwarder_create_on_runtime(
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
    if (!runtime || !target_address)
    {
        set_forwarder_error(out_error, FORWARDER_ERROR_UNKNOWN);
        return nullptr;
    }

    void *memory = runtime_alloc(runtime, sizeof(tcp_forwarder));
    if (!memory)
    {
        set_forwarder_error(out_error, FORWARDER_ERROR_MALLOC);
        return nullptr;
    }

    tcp_forwarder *forwarder = nullptr;
    try
    {
        asio::io_context &io_ctx = forwarder_runtime_get_io_context(runtime);
        forwarder = new (memory) tcp_forwarder(runtime, io_ctx);

        const std::size_t target_len = std::strlen(target_address);
        forwarder->target_address = static_cast<char *>(DATA_ALLOC(forwarder, target_len + 1));
        if (!forwarder->target_address)
        {
            forwarder->~tcp_forwarder();
            runtime_free(runtime, forwarder);
            set_forwarder_error(out_error, FORWARDER_ERROR_MALLOC);
            return nullptr;
        }

        std::memcpy(forwarder->target_address, target_address, target_len + 1);
        forwarder->listen_port = listen_port;
        forwarder->target_port = target_port;
        forwarder->family = family;
        forwarder->enable_stats = enable_stats;
        forwarder->connect_timeout_ms = connect_timeout_ms;
        forwarder->max_connections = max_connections;

        asio::error_code ec;
        forwarder->cached_dest_addr = make_target_endpoint(family, forwarder->target_address, target_port, ec);
        if (ec)
        {
            forwarder->~tcp_forwarder();
            runtime_free(runtime, forwarder);
            set_forwarder_error(out_error, FORWARDER_ERROR_INVALID_ADDRESS);
            return nullptr;
        }

        const asio::ip::tcp::endpoint listen_endpoint = make_listen_endpoint(family, listen_port);
        forwarder->acceptor.open(listen_endpoint.protocol(), ec);
        if (ec)
        {
            forwarder->~tcp_forwarder();
            runtime_free(runtime, forwarder);
            set_forwarder_error(out_error, map_asio_init_error(ec));
            return nullptr;
        }

        forwarder->acceptor.bind(listen_endpoint, ec);
        if (ec)
        {
            forwarder->~tcp_forwarder();
            runtime_free(runtime, forwarder);
            set_forwarder_error(out_error, map_bind_error(ec));
            return nullptr;
        }
    }
    catch (const std::bad_alloc &)
    {
        if (forwarder)
            forwarder->~tcp_forwarder();
        runtime_free(runtime, memory);
        set_forwarder_error(out_error, FORWARDER_ERROR_MALLOC);
        return nullptr;
    }
    catch (...)
    {
        if (forwarder)
            forwarder->~tcp_forwarder();
        runtime_free(runtime, memory);
        set_forwarder_error(out_error, FORWARDER_ERROR_UNKNOWN);
        return nullptr;
    }

    set_forwarder_error(out_error, FORWARDER_OK);
    return forwarder;
}

extern "C" int tcp_forwarder_start(tcp_forwarder_t *forwarder)
{
    if (!forwarder)
        return -1;

    {
        std::lock_guard<std::mutex> lock(forwarder->sessions_mutex);
        if (forwarder->started || forwarder->stop_requested.load(std::memory_order_acquire))
            return -1;
        forwarder->started = 1;
    }

    asio::error_code ec;
    forwarder->acceptor.listen(128, ec);
    if (ec)
    {
        std::lock_guard<std::mutex> lock(forwarder->sessions_mutex);
        forwarder->started = 0;
        return ec.value() != 0 ? ec.value() : -1;
    }

    forwarder->start_accept_loop();
    return 0;
}

extern "C" void tcp_forwarder_request_stop(tcp_forwarder_t *forwarder)
{
    if (!forwarder)
        return;

    int expected = 0;
    if (!forwarder->stop_requested.compare_exchange_strong(expected, 1))
        return;

    asio::post(forwarder->io_ctx, [forwarder]() { forwarder->stop_on_runtime_thread(); });
}

extern "C" void tcp_forwarder_destroy(tcp_forwarder_t *forwarder)
{
    if (!forwarder)
        return;

    forwarder->destroy_requested.store(1, std::memory_order_release);

    // Already on the runtime thread — do cleanup synchronously.
    // close_acceptor() and close_all_sessions() trigger operation_aborted
    // handlers that decrement pending_close_count.
    // try_free_if_destroyed() frees the forwarder when all handlers drain.
    forwarder->stop_on_runtime_thread();
}

extern "C" traffic_stats_t tcp_forwarder_get_stats(tcp_forwarder_t *forwarder)
{
    traffic_stats_t stats = {};
    if (!forwarder)
        return stats;

    if (forwarder->enable_stats)
    {
        stats.bytes_in = forwarder->bytes_in.load(std::memory_order_relaxed);
        stats.bytes_out = forwarder->bytes_out.load(std::memory_order_relaxed);
    }
    stats.active_sessions = forwarder->active_sessions.load(std::memory_order_relaxed);
    stats.listen_port = forwarder->listen_port;
    return stats;
}

#endif
