#include "forwarder.h"
#include "uv.h"
#include <stdlib.h>

struct forwarder_runtime
{
    uv_loop_t loop;
    uv_async_t wake_handle;
    forwarder_runtime_wake_cb_t wake_cb;
    void *user_data;
    forwarder_allocator_t allocator;
    int wake_closing;
    int wake_initialized;
    int loop_initialized;
};

forwarder_runtime_t *forwarder_runtime_alloc(void)
{
    return (forwarder_runtime_t *)calloc(1, sizeof(forwarder_runtime_t));
}

static void uv_async_callback(uv_async_t *handle)
{
    forwarder_runtime_t *runtime = (forwarder_runtime_t *)handle->data;
    if (runtime && runtime->wake_cb && !runtime->wake_closing)
    {
        runtime->wake_cb(runtime->user_data);
    }
}

int forwarder_runtime_init(forwarder_runtime_t *runtime, forwarder_runtime_wake_cb_t wake_cb, void *user_data, forwarder_allocator_t allocator)
{
    if (runtime == NULL)
    {
        return -1;
    }

    runtime->wake_cb = wake_cb;
    runtime->user_data = user_data;
    runtime->allocator = allocator;
    runtime->wake_closing = 0;
    runtime->wake_initialized = 0;
    runtime->loop_initialized = 0;

    int rc = uv_loop_init(&runtime->loop);
    if (rc != 0)
    {
        return rc;
    }
    runtime->loop_initialized = 1;

    rc = uv_async_init(&runtime->loop, &runtime->wake_handle, uv_async_callback);
    if (rc != 0)
    {
        uv_loop_close(&runtime->loop);
        runtime->loop_initialized = 0;
        return rc;
    }
    runtime->wake_handle.data = runtime;
    runtime->wake_initialized = 1;

    return 0;
}

int forwarder_runtime_run(forwarder_runtime_t *runtime)
{
    if (runtime == NULL || !runtime->loop_initialized)
    {
        return -1;
    }
    return uv_run(&runtime->loop, UV_RUN_DEFAULT);
}

int forwarder_runtime_wake(forwarder_runtime_t *runtime)
{
    if (runtime == NULL || !runtime->wake_initialized || runtime->wake_closing)
    {
        return -1;
    }
    return uv_async_send(&runtime->wake_handle);
}

int forwarder_runtime_is_wake_closing(forwarder_runtime_t *runtime)
{
    if (runtime == NULL)
    {
        return 1;
    }
    return runtime->wake_closing || uv_is_closing((uv_handle_t *)&runtime->wake_handle);
}

static void on_wake_close(uv_handle_t *handle)
{
    (void)handle;
}

void forwarder_runtime_close_wake(forwarder_runtime_t *runtime)
{
    if (runtime != NULL && runtime->wake_initialized && !runtime->wake_closing)
    {
        runtime->wake_closing = 1;
        if (!uv_is_closing((uv_handle_t *)&runtime->wake_handle))
        {
            uv_close((uv_handle_t *)&runtime->wake_handle, on_wake_close);
        }
    }
}

static void walk_cb_close_owned(uv_handle_t *handle, void *arg)
{
    (void)arg;
    if (handle != NULL && !uv_is_closing(handle))
    {
        uv_close(handle, NULL);
    }
}

void forwarder_runtime_close_owned_handles(forwarder_runtime_t *runtime)
{
    if (runtime != NULL && runtime->loop_initialized)
    {
        uv_walk(&runtime->loop, walk_cb_close_owned, NULL);
    }
}

int forwarder_runtime_close(forwarder_runtime_t *runtime)
{
    if (runtime == NULL || !runtime->loop_initialized)
    {
        return -1;
    }

    int lr = uv_loop_close(&runtime->loop);
    while (lr == UV_EBUSY)
    {
        uv_walk(&runtime->loop, walk_cb_close_owned, NULL);
        uv_run(&runtime->loop, UV_RUN_NOWAIT);
        lr = uv_loop_close(&runtime->loop);
    }

    if (lr == 0)
    {
        runtime->loop_initialized = 0;
        runtime->wake_initialized = 0;
    }

    return lr;
}

void forwarder_runtime_free(forwarder_runtime_t *runtime)
{
    if (runtime != NULL)
    {
        free(runtime);
    }
}

const char *uv_get_version_string(void)
{
    return uv_version_string();
}

uv_loop_t *forwarder_runtime_get_loop(forwarder_runtime_t *runtime)
{
    return runtime ? &runtime->loop : NULL;
}

forwarder_allocator_t forwarder_runtime_get_allocator(forwarder_runtime_t *runtime)
{
    if (runtime) return runtime->allocator;
    forwarder_allocator_t empty = {0};
    return empty;
}
