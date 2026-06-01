#if !defined(PORTWEAVER_BACKEND_ASIO)
#define PORTWEAVER_BACKEND_ASIO 1
#endif

#if defined(PORTWEAVER_BACKEND_ASIO)

#include "forwarder.h"

#include <asio.hpp>

#include <cstdlib>
#include <mutex>
#include <new>
#include <optional>

using forwarder_work_guard_t = asio::executor_work_guard<asio::io_context::executor_type>;

struct forwarder_runtime
{
    asio::io_context io_ctx;
    std::optional<forwarder_work_guard_t> work_guard;
    forwarder_runtime_wake_cb_t wake_cb;
    void *user_data;
    forwarder_allocator_t allocator;
    int wake_closing;
    int initialized;
    std::mutex wake_mutex;
};

extern "C"
{

forwarder_runtime_t *forwarder_runtime_alloc(void)
{
    void *storage = std::calloc(1, sizeof(forwarder_runtime_t));
    if (storage == nullptr)
    {
        return nullptr;
    }

    try
    {
        return new (storage) forwarder_runtime_t();
    }
    catch (...)
    {
        std::free(storage);
        return nullptr;
    }
}

int forwarder_runtime_init(forwarder_runtime_t *runtime, forwarder_runtime_wake_cb_t wake_cb, void *user_data, forwarder_allocator_t allocator)
{
    if (runtime == nullptr)
    {
        return -1;
    }

    std::lock_guard<std::mutex> lock(runtime->wake_mutex);
    if (runtime->initialized)
    {
        return -1;
    }

    try
    {
        runtime->io_ctx.restart();
        runtime->work_guard.emplace(asio::make_work_guard(runtime->io_ctx));
    }
    catch (...)
    {
        runtime->work_guard.reset();
        return -1;
    }

    runtime->wake_cb = wake_cb;
    runtime->user_data = user_data;
    runtime->allocator = allocator;
    runtime->wake_closing = 0;
    runtime->initialized = 1;

    return 0;
}

int forwarder_runtime_run(forwarder_runtime_t *runtime)
{
    if (runtime == nullptr || !runtime->initialized)
    {
        return -1;
    }

    try
    {
        runtime->io_ctx.restart();
        runtime->io_ctx.run();
    }
    catch (...)
    {
        return -1;
    }

    return 0;
}

int forwarder_runtime_wake(forwarder_runtime_t *runtime)
{
    if (runtime == nullptr)
    {
        return -1;
    }

    {
        std::lock_guard<std::mutex> lock(runtime->wake_mutex);
        if (!runtime->initialized || runtime->wake_closing)
        {
            return -1;
        }
    }

    try
    {
        asio::post(runtime->io_ctx, [runtime]() {
            forwarder_runtime_wake_cb_t wake_cb = nullptr;
            void *user_data = nullptr;

            {
                std::lock_guard<std::mutex> lock(runtime->wake_mutex);
                if (!runtime->initialized || runtime->wake_closing)
                {
                    return;
                }
                wake_cb = runtime->wake_cb;
                user_data = runtime->user_data;
            }

            if (wake_cb != nullptr)
            {
                wake_cb(user_data);
            }
        });
    }
    catch (...)
    {
        return -1;
    }

    return 0;
}

int forwarder_runtime_is_wake_closing(forwarder_runtime_t *runtime)
{
    if (runtime == nullptr)
    {
        return 1;
    }

    std::lock_guard<std::mutex> lock(runtime->wake_mutex);
    return (!runtime->initialized || runtime->wake_closing) ? 1 : 0;
}

void forwarder_runtime_close_wake(forwarder_runtime_t *runtime)
{
    if (runtime == nullptr)
    {
        return;
    }

    std::lock_guard<std::mutex> lock(runtime->wake_mutex);
    if (runtime->wake_closing)
    {
        return;
    }

    runtime->wake_closing = 1;
    runtime->work_guard.reset();
}

void forwarder_runtime_close_owned_handles(forwarder_runtime_t *runtime)
{
    if (runtime == nullptr)
    {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(runtime->wake_mutex);
        if (!runtime->initialized)
        {
            return;
        }
        runtime->wake_closing = 1;
        runtime->work_guard.reset();
    }

    // Don't call io_ctx.stop() - let pending handlers drain
    // Resetting work_guard above allows run() to return when work completes
}

int forwarder_runtime_close(forwarder_runtime_t *runtime)
{
    if (runtime == nullptr)
    {
        return -1;
    }

    {
        std::lock_guard<std::mutex> lock(runtime->wake_mutex);
        if (!runtime->initialized)
        {
            return -1;
        }
        runtime->wake_closing = 1;
        runtime->work_guard.reset();
        runtime->initialized = 0;
    }

    // Don't call io_ctx.stop() - let pending handlers drain
    // Resetting work_guard above allows run() to return when work completes
    return 0;
}

void forwarder_runtime_free(forwarder_runtime_t *runtime)
{
    if (runtime == nullptr)
    {
        return;
    }

    runtime->~forwarder_runtime_t();
    std::free(runtime);
}

const char *uv_get_version_string(void)
{
    return "asio-standalone";
}

forwarder_allocator_t forwarder_runtime_get_allocator(forwarder_runtime_t *runtime)
{
    if (runtime != nullptr)
    {
        return runtime->allocator;
    }

    forwarder_allocator_t empty = {};
    return empty;
}

}

asio::io_context &forwarder_runtime_get_io_context(forwarder_runtime_t *runtime)
{
    if (runtime != nullptr)
    {
        return runtime->io_ctx;
    }

    static asio::io_context empty_io_ctx;
    return empty_io_ctx;
}

#endif
