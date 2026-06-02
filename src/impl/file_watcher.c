/*
 * file_watcher.c — Cross-platform file change watcher using libuv.
 *
 * Uses uv_fs_event (inotify on Linux, ReadDirectoryChangesW on Windows)
 * to detect config file changes with zero polling overhead.
 */

#include <uv.h>
#include <stdlib.h>
#include <string.h>

typedef void (*file_watcher_cb_t)(void *user_data);

struct file_watcher {
    uv_loop_t loop;
    uv_fs_event_t fs_event;
    uv_async_t stop_async;
    file_watcher_cb_t callback;
    void *user_data;
    uv_thread_t thread;
    char path[1];
};

static void fs_event_cb(uv_fs_event_t *handle, const char *filename, int events, int status) {
    (void)filename;
    if (status < 0) return;
    if (!(events & UV_CHANGE)) return;

    struct file_watcher *w = handle->data;
    if (w && w->callback) {
        w->callback(w->user_data);
    }
}

static void stop_async_cb(uv_async_t *handle) {
    struct file_watcher *w = handle->data;
    uv_fs_event_stop(&w->fs_event);
    uv_close((uv_handle_t *)&w->fs_event, NULL);
    uv_close((uv_handle_t *)&w->stop_async, NULL);
}

static void walk_close_cb(uv_handle_t *handle, void *arg) {
    (void)arg;
    if (!uv_is_closing(handle)) {
        uv_close(handle, NULL);
    }
}

static void watcher_thread(void *arg) {
    struct file_watcher *w = arg;
    uv_run(&w->loop, UV_RUN_DEFAULT);
    uv_walk(&w->loop, walk_close_cb, NULL);
    uv_run(&w->loop, UV_RUN_DEFAULT);
    uv_loop_close(&w->loop);
}

void *file_watcher_start(const char *path, file_watcher_cb_t callback, void *user_data) {
    size_t path_len = strlen(path);
    struct file_watcher *w = calloc(1, sizeof(*w) + path_len);
    if (!w) return NULL;

    w->callback = callback;
    w->user_data = user_data;
    memcpy(w->path, path, path_len + 1);

    if (uv_loop_init(&w->loop) != 0) { free(w); return NULL; }

    w->fs_event.data = w;
    if (uv_fs_event_init(&w->loop, &w->fs_event) != 0) {
        uv_loop_close(&w->loop);
        free(w);
        return NULL;
    }

    if (uv_fs_event_start(&w->fs_event, fs_event_cb, w->path, 0) != 0) {
        uv_close((uv_handle_t *)&w->fs_event, NULL);
        uv_run(&w->loop, UV_RUN_DEFAULT);
        uv_loop_close(&w->loop);
        free(w);
        return NULL;
    }

    w->stop_async.data = w;
    if (uv_async_init(&w->loop, &w->stop_async, stop_async_cb) != 0) {
        uv_fs_event_stop(&w->fs_event);
        uv_close((uv_handle_t *)&w->fs_event, NULL);
        uv_run(&w->loop, UV_RUN_DEFAULT);
        uv_loop_close(&w->loop);
        free(w);
        return NULL;
    }

    if (uv_thread_create(&w->thread, watcher_thread, w) != 0) {
        uv_close((uv_handle_t *)&w->stop_async, NULL);
        uv_close((uv_handle_t *)&w->fs_event, NULL);
        uv_run(&w->loop, UV_RUN_DEFAULT);
        uv_loop_close(&w->loop);
        free(w);
        return NULL;
    }

    return w;
}

void file_watcher_stop(void *handle) {
    if (!handle) return;
    struct file_watcher *w = handle;
    uv_async_send(&w->stop_async);
    uv_thread_join(&w->thread);
    free(w);
}
