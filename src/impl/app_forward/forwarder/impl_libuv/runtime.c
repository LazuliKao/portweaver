#include "forwarder.h"
#include "uv.h"

#include <stdlib.h>

struct forwarder_runtime
{
    forwarder_runtime_wake_cb_t wake_cb;
    void *user_data;
    forwarder_allocator_t allocator;
    int wake_closing;
};

forwarder_runtime_t *forwarder_runtime_alloc(void)
{
    return (forwarder_runtime_t *)calloc(1, sizeof(forwarder_runtime_t));
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
    return 0;
}

int forwarder_runtime_run(forwarder_runtime_t *runtime)
{
    (void)runtime;
    return 0;
}

int forwarder_runtime_wake(forwarder_runtime_t *runtime)
{
    if (runtime == NULL)
    {
        return -1;
    }

    if (runtime->wake_cb != NULL && runtime->wake_closing == 0)
    {
        runtime->wake_cb(runtime->user_data);
    }

    return 0;
}

int forwarder_runtime_is_wake_closing(forwarder_runtime_t *runtime)
{
    if (runtime == NULL)
    {
        return 1;
    }

    return runtime->wake_closing;
}

void forwarder_runtime_close_wake(forwarder_runtime_t *runtime)
{
    if (runtime != NULL)
    {
        runtime->wake_closing = 1;
    }
}

void forwarder_runtime_close_owned_handles(forwarder_runtime_t *runtime)
{
    (void)runtime;
}

int forwarder_runtime_close(forwarder_runtime_t *runtime)
{
    (void)runtime;
    return 0;
}

void forwarder_runtime_free(forwarder_runtime_t *runtime)
{
    free(runtime);
}

const char *uv_get_version_string(void)
{
    return uv_version_string();
}
