const std = @import("std");
const types = @import("../../config/types.zig");
const forwarder_runtime = @import("forwarder_runtime.zig");
const project_status = @import("../project_status.zig");
const compat = @import("../../compat.zig");

const c = forwarder_runtime.c;

pub const LoopError = error{
    RuntimeStopped,
    RuntimeStartFailed,
    MarshalFailed,
    LoopInitFailed,
};

pub const LoopJob = struct {
    callback: *const fn (*anyopaque) anyerror!void,
    context: *anyopaque,
};

const QueuedJob = struct {
    job: LoopJob,
    next: ?*QueuedJob = null,
};

/// Owns one forwarder runtime and the thread that runs it.
/// Uses an opaque C runtime wrapper so Zig never includes backend headers directly.
pub const LoopRuntime = struct {
    allocator: std.mem.Allocator,
    ctx: ?*c.forwarder_runtime_t = null,
    thread: ?std.Thread = null,
    lock: std.Io.Mutex = .init,
    condition: std.Io.Condition = .init,
    head: ?*QueuedJob = null,
    tail: ?*QueuedJob = null,
    shutdown_head: ?*QueuedJob = null,
    shutdown_tail: ?*QueuedJob = null,
    active_jobs: usize = 0,
    active_wakes: usize = 0,
    started: bool = false,
    stopping: bool = false,
    stop_requested: bool = false,
    init_done: bool = false,
    init_status: c_int = 0,
    last_job_error: ?anyerror = null,

    pub fn init(allocator: std.mem.Allocator) LoopRuntime {
        return .{
            .allocator = allocator,
        };
    }

    pub fn start(self: *LoopRuntime) !void {
        self.lock.lockUncancelable(compat.io());
        if (self.started) {
            self.lock.unlock(compat.io());
            return;
        }
        self.started = true;
        self.lock.unlock(compat.io());

        self.thread = std.Thread.spawn(.{}, loopThreadMain, .{self}) catch |err| {
            self.lock.lockUncancelable(compat.io());
            self.started = false;
            self.lock.unlock(compat.io());
            return err;
        };

        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());
        while (!self.init_done) {
            self.condition.waitUncancelable(compat.io(), &self.lock);
        }
        if (self.init_status != 0) {
            return LoopError.LoopInitFailed;
        }
    }

    pub fn marshal(self: *LoopRuntime, job: LoopJob) !void {
        const node = try self.allocator.create(QueuedJob);
        node.* = .{ .job = job };

        self.lock.lockUncancelable(compat.io());
        if (self.stopping or !self.started) {
            self.lock.unlock(compat.io());
            self.allocator.destroy(node);
            return LoopError.RuntimeStopped;
        }

        const runtime_ctx = self.ctx orelse {
            self.lock.unlock(compat.io());
            self.allocator.destroy(node);
            return LoopError.RuntimeStopped;
        };

        self.active_jobs += 1;
        self.active_wakes += 1;
        if (self.tail) |tail| {
            tail.next = node;
        } else {
            self.head = node;
        }
        self.tail = node;
        self.condition.broadcast(compat.io());
        self.lock.unlock(compat.io());

        _ = c.forwarder_runtime_wake(runtime_ctx);

        self.lock.lockUncancelable(compat.io());
        self.active_wakes -= 1;
        self.condition.broadcast(compat.io());
        self.lock.unlock(compat.io());

        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());
        while (self.active_jobs > 0 and self.last_job_error == null) {
            self.condition.waitUncancelable(compat.io(), &self.lock);
        }
        if (self.last_job_error) |err| {
            self.last_job_error = null;
            return err;
        }
    }

    pub fn addShutdownJob(self: *LoopRuntime, job: LoopJob) !void {
        const node = try self.allocator.create(QueuedJob);
        node.* = .{ .job = job };

        self.lock.lockUncancelable(compat.io());
        if (!self.started) {
            self.lock.unlock(compat.io());
            self.allocator.destroy(node);
            return LoopError.RuntimeStopped;
        }

        if (self.shutdown_tail) |tail| {
            tail.next = node;
        } else {
            self.shutdown_head = node;
        }
        self.shutdown_tail = node;
        self.condition.broadcast(compat.io());
        self.lock.unlock(compat.io());
    }

    pub fn stop(self: *LoopRuntime) void {
        self.lock.lockUncancelable(compat.io());
        if (!self.started or self.stopping) {
            self.lock.unlock(compat.io());
            return;
        }
        const runtime_ctx = self.ctx orelse {
            self.lock.unlock(compat.io());
            return;
        };
        self.stopping = true;
        self.stop_requested = true;
        self.active_wakes += 1;
        self.condition.broadcast(compat.io());
        self.lock.unlock(compat.io());
        _ = c.forwarder_runtime_wake(runtime_ctx);
        self.lock.lockUncancelable(compat.io());
        self.active_wakes -= 1;
        self.condition.broadcast(compat.io());
        self.lock.unlock(compat.io());
    }

    pub fn join(self: *LoopRuntime) void {
        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }
    }

    pub fn deinit(self: *LoopRuntime) void {
        self.stop();
        self.join();
    }

    fn loopThreadMain(self: *LoopRuntime) void {
        self.ctx = c.forwarder_runtime_alloc();
        if (self.ctx == null) {
            self.publishInit(-1);
            return;
        }

        const fwd_allocator = forwarder_runtime.buildAllocator(&self.allocator);
        const rc = c.forwarder_runtime_init(self.ctx, zigAsyncCallback, self, fwd_allocator);
        self.publishInit(rc);
        if (rc != 0) {
            c.forwarder_runtime_free(self.ctx);
            self.ctx = null;
            return;
        }

        _ = c.forwarder_runtime_run(self.ctx);

        self.runFallbackExecutorIfNeeded();

        self.waitForActiveWakes();

        // Close async handle if not already closing, then drain its close callback.
        if (c.forwarder_runtime_is_wake_closing(self.ctx) == 0) {
            c.forwarder_runtime_close_wake(self.ctx);
            _ = c.forwarder_runtime_run(self.ctx);
        }

        // Walk and close any remaining handles left behind by forwarders.
        c.forwarder_runtime_close_owned_handles(self.ctx);
        _ = c.forwarder_runtime_run(self.ctx);

        self.drainShutdownJobs();

        _ = c.forwarder_runtime_close(self.ctx);
        c.forwarder_runtime_free(self.ctx);
        self.ctx = null;

        self.lock.lockUncancelable(compat.io());
        self.started = false;
        self.lock.unlock(compat.io());
    }

    fn publishInit(self: *LoopRuntime, status: c_int) void {
        self.lock.lockUncancelable(compat.io());
        self.init_status = status;
        self.init_done = true;
        self.condition.broadcast(compat.io());
        self.lock.unlock(compat.io());
    }

    fn zigAsyncCallback(user_data: ?*anyopaque) callconv(.c) void {
        const self_ptr: *LoopRuntime = @ptrCast(@alignCast(user_data orelse return));
        self_ptr.drainJobs();

        self_ptr.lock.lockUncancelable(compat.io());
        const should_stop = self_ptr.stop_requested and self_ptr.head == null and self_ptr.active_jobs == 0;
        self_ptr.lock.unlock(compat.io());
        if (should_stop) {
            if (self_ptr.ctx) |ctx| {
                if (c.forwarder_runtime_is_wake_closing(ctx) == 0) {
                    c.forwarder_runtime_close_wake(ctx);
                }
            }
        }
    }

    fn drainJobs(self: *LoopRuntime) void {
        while (true) {
            self.lock.lockUncancelable(compat.io());
            const node = self.head orelse {
                self.lock.unlock(compat.io());
                return;
            };
            self.head = node.next;
            if (self.head == null) self.tail = null;
            self.lock.unlock(compat.io());

            const result = node.job.callback(node.job.context);
            self.allocator.destroy(node);

            self.lock.lockUncancelable(compat.io());
            self.active_jobs -= 1;
            if (result) |_| {} else |err| {
                self.last_job_error = err;
            }
            self.condition.broadcast(compat.io());
            self.lock.unlock(compat.io());
        }
    }

    /// Keeps the Zig-owned runtime thread alive if the backend run function
    /// returns before shutdown is requested. This preserves the public Zig
    /// lifetime contract while the C backend is still a compile-only stub.
    fn runFallbackExecutorIfNeeded(self: *LoopRuntime) void {
        while (true) {
            self.lock.lockUncancelable(compat.io());
            while (!self.stop_requested and self.head == null) {
                self.condition.waitUncancelable(compat.io(), &self.lock);
            }
            const should_stop = self.stop_requested and self.head == null and self.active_jobs == 0;
            self.lock.unlock(compat.io());

            self.drainJobs();
            if (should_stop) return;
        }
    }

    fn drainShutdownJobs(self: *LoopRuntime) void {
        while (true) {
            self.lock.lockUncancelable(compat.io());
            const node = self.shutdown_head orelse {
                self.lock.unlock(compat.io());
                return;
            };
            self.shutdown_head = node.next;
            if (self.shutdown_head == null) self.shutdown_tail = null;
            self.lock.unlock(compat.io());

            const result = node.job.callback(node.job.context);
            if (result) |_| {} else |err| {
                std.log.err("Loop runtime shutdown job failed: {}", .{err});
            }
            self.allocator.destroy(node);
        }
    }

    fn waitForActiveWakes(self: *LoopRuntime) void {
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());
        while (self.active_wakes > 0) {
            self.condition.waitUncancelable(compat.io(), &self.lock);
        }
    }
};

const RuntimeRef = struct {
    runtime: *LoopRuntime,
    refs: usize,
    mode: types.LoopMode,
    project: ?*project_status.ProjectHandle = null,
};

const GlobalProjectRef = struct {
    project: *project_status.ProjectHandle,
    refs: usize,
};

pub const RuntimeLease = struct {
    runtime: *LoopRuntime,
    mode: types.LoopMode,
    project: ?*project_status.ProjectHandle = null,
};

const RuntimeForwarderDestroyContext = struct {
    allocator: std.mem.Allocator,
    project: *project_status.ProjectHandle,
    runtime: *LoopRuntime,

    fn run(ptr: *anyopaque) !void {
        const ctx: *@This() = @ptrCast(@alignCast(ptr));
        defer ctx.allocator.destroy(ctx);

        if (ctx.runtime.ctx) |runtime_ctx| {
            ctx.project.destroySharedForwarderCResourcesForRuntime(runtime_ctx);
        }
    }
};

pub const LoopManager = struct {
    allocator: std.mem.Allocator,
    lock: std.Io.Mutex = .init,
    global: ?RuntimeRef = null,
    global_project_refs: std.array_list.Managed(GlobalProjectRef),
    project_runtimes: std.array_list.Managed(RuntimeRef),
    listener_runtimes: std.array_list.Managed(RuntimeRef),

    pub fn init(allocator: std.mem.Allocator) !LoopManager {
        return .{
            .allocator = allocator,
            .global_project_refs = std.array_list.Managed(GlobalProjectRef).init(allocator),
            .project_runtimes = std.array_list.Managed(RuntimeRef).init(allocator),
            .listener_runtimes = std.array_list.Managed(RuntimeRef).init(allocator),
        };
    }

    pub fn deinit(self: *LoopManager) void {
        if (self.global) |*entry| destroyRuntime(self.allocator, entry.runtime);
        self.global = null;
        for (self.project_runtimes.items) |entry| destroyRuntime(self.allocator, entry.runtime);
        for (self.listener_runtimes.items) |entry| destroyRuntime(self.allocator, entry.runtime);
        self.global_project_refs.deinit();
        self.project_runtimes.deinit();
        self.listener_runtimes.deinit();
    }

    pub fn acquire(self: *LoopManager, mode: types.LoopMode, project: *project_status.ProjectHandle) !RuntimeLease {
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());

        switch (mode) {
            .global => {
                if (self.global) |*entry| {
                    entry.refs += 1;
                    try self.addGlobalProjectRef(project);
                    return .{ .runtime = entry.runtime, .mode = mode, .project = project };
                }
                const runtime = try createStartedRuntime(self.allocator);
                self.global = .{ .runtime = runtime, .refs = 1, .mode = mode };
                try self.addGlobalProjectRef(project);
                return .{ .runtime = runtime, .mode = mode, .project = project };
            },
            .per_project => {
                for (self.project_runtimes.items) |*entry| {
                    if (entry.project == project) {
                        entry.refs += 1;
                        return .{ .runtime = entry.runtime, .mode = mode, .project = project };
                    }
                }
                const runtime = try createStartedRuntime(self.allocator);
                try self.project_runtimes.append(.{ .runtime = runtime, .refs = 1, .mode = mode, .project = project });
                return .{ .runtime = runtime, .mode = mode, .project = project };
            },
            .per_listener => {
                const runtime = try createStartedRuntime(self.allocator);
                try self.listener_runtimes.append(.{ .runtime = runtime, .refs = 1, .mode = mode, .project = project });
                return .{ .runtime = runtime, .mode = mode, .project = project };
            },
        }
    }

    pub fn release(self: *LoopManager, lease: RuntimeLease) void {
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());

        switch (lease.mode) {
            .global => self.releaseGlobalLease(lease),
            .per_project => self.releaseFromList(&self.project_runtimes, lease.runtime),
            .per_listener => self.releaseFromList(&self.listener_runtimes, lease.runtime),
        }
    }

    pub fn releaseProjectRuntime(self: *LoopManager, project: *project_status.ProjectHandle) !void {
        var runtimes_to_destroy = std.array_list.Managed(*LoopRuntime).init(self.allocator);
        defer runtimes_to_destroy.deinit();
        var runtimes_to_cleanup = std.array_list.Managed(*LoopRuntime).init(self.allocator);
        defer runtimes_to_cleanup.deinit();

        self.lock.lockUncancelable(compat.io());

        var index: usize = 0;
        while (index < self.project_runtimes.items.len) {
            if (self.project_runtimes.items[index].project == project) {
                const entry = self.project_runtimes.swapRemove(index);
                runtimes_to_destroy.append(entry.runtime) catch |err| {
                    self.lock.unlock(compat.io());
                    return err;
                };
                continue;
            }
            index += 1;
        }
        index = 0;
        while (index < self.listener_runtimes.items.len) {
            if (self.listener_runtimes.items[index].project == project) {
                const entry = self.listener_runtimes.swapRemove(index);
                runtimes_to_destroy.append(entry.runtime) catch |err| {
                    self.lock.unlock(compat.io());
                    return err;
                };
                continue;
            }
            index += 1;
        }
        if (self.global) |*global_entry| {
            const removed_refs = self.removeGlobalProjectRefs(project);
            if (removed_refs > 0) {
                if (global_entry.refs > removed_refs) {
                    global_entry.refs -= removed_refs;
                    runtimes_to_cleanup.append(global_entry.runtime) catch |err| {
                        self.lock.unlock(compat.io());
                        return err;
                    };
                } else {
                    runtimes_to_destroy.append(global_entry.runtime) catch |err| {
                        self.lock.unlock(compat.io());
                        return err;
                    };
                    self.global = null;
                }
            } else if (project.active_ports > 0 and self.global_project_refs.items.len == 0) {
                runtimes_to_destroy.append(global_entry.runtime) catch |err| {
                    self.lock.unlock(compat.io());
                    return err;
                };
                self.global = null;
            }
        }
        self.lock.unlock(compat.io());

        for (runtimes_to_destroy.items) |runtime| {
            try scheduleForwarderDestroy(self.allocator, runtime, project);
        }
        try project.stopSharedForwarders();
        for (runtimes_to_cleanup.items) |runtime| {
            try runForwarderDestroyOnRuntime(self.allocator, runtime, project);
        }
        for (runtimes_to_destroy.items) |runtime| {
            runtime.deinit();
        }
        try project.destroySharedForwardersAfterRuntimeStop();
        for (runtimes_to_destroy.items) |runtime| {
            self.allocator.destroy(runtime);
        }
    }

    pub fn debugRuntimeCount(self: *LoopManager, mode: types.LoopMode) usize {
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());
        return switch (mode) {
            .global => if (self.global == null) 0 else 1,
            .per_project => self.project_runtimes.items.len,
            .per_listener => self.listener_runtimes.items.len,
        };
    }

    fn releaseFromList(self: *LoopManager, list: *std.array_list.Managed(RuntimeRef), runtime: *LoopRuntime) void {
        for (list.items, 0..) |*entry, index| {
            if (entry.runtime == runtime) {
                if (entry.refs > 1) {
                    entry.refs -= 1;
                } else {
                    const removed = list.swapRemove(index);
                    destroyRuntime(self.allocator, removed.runtime);
                }
                return;
            }
        }
    }

    fn addGlobalProjectRef(self: *LoopManager, project: *project_status.ProjectHandle) !void {
        for (self.global_project_refs.items) |*entry| {
            if (entry.project == project) {
                entry.refs += 1;
                return;
            }
        }
        try self.global_project_refs.append(.{ .project = project, .refs = 1 });
    }

    fn releaseGlobalLease(self: *LoopManager, lease: RuntimeLease) void {
        if (lease.project) |project| {
            _ = self.removeOneGlobalProjectRef(project);
        }
        if (self.global) |*entry| {
            if (entry.refs > 1) {
                entry.refs -= 1;
                return;
            }
            destroyRuntime(self.allocator, entry.runtime);
            self.global = null;
        }
    }

    fn removeOneGlobalProjectRef(self: *LoopManager, project: *project_status.ProjectHandle) bool {
        for (self.global_project_refs.items, 0..) |*entry, index| {
            if (entry.project == project) {
                if (entry.refs > 1) {
                    entry.refs -= 1;
                } else {
                    _ = self.global_project_refs.swapRemove(index);
                }
                return true;
            }
        }
        return false;
    }

    fn removeGlobalProjectRefs(self: *LoopManager, project: *project_status.ProjectHandle) usize {
        for (self.global_project_refs.items, 0..) |entry, index| {
            if (entry.project == project) {
                const refs = entry.refs;
                _ = self.global_project_refs.swapRemove(index);
                return refs;
            }
        }
        return 0;
    }

    fn decrementOrDestroyGlobal(self: *LoopManager, entry: *RuntimeRef) void {
        if (entry.refs > 1) {
            entry.refs -= 1;
            return;
        }
        destroyRuntime(self.allocator, entry.runtime);
        self.global = null;
    }
};

fn scheduleForwarderDestroy(allocator: std.mem.Allocator, runtime: *LoopRuntime, project: *project_status.ProjectHandle) !void {
    const ctx = try allocator.create(RuntimeForwarderDestroyContext);
    ctx.* = .{
        .allocator = allocator,
        .project = project,
        .runtime = runtime,
    };
    errdefer allocator.destroy(ctx);
    try runtime.addShutdownJob(.{ .callback = RuntimeForwarderDestroyContext.run, .context = ctx });
}

fn runForwarderDestroyOnRuntime(allocator: std.mem.Allocator, runtime: *LoopRuntime, project: *project_status.ProjectHandle) !void {
    const ctx = try allocator.create(RuntimeForwarderDestroyContext);
    ctx.* = .{
        .allocator = allocator,
        .project = project,
        .runtime = runtime,
    };
    errdefer allocator.destroy(ctx);
    try runtime.marshal(.{ .callback = RuntimeForwarderDestroyContext.run, .context = ctx });
}

fn createStartedRuntime(allocator: std.mem.Allocator) !*LoopRuntime {
    const runtime = try allocator.create(LoopRuntime);
    runtime.* = LoopRuntime.init(allocator);
    runtime.start() catch |err| {
        allocator.destroy(runtime);
        return err;
    };
    return runtime;
}

fn destroyRuntime(allocator: std.mem.Allocator, runtime: *LoopRuntime) void {
    runtime.deinit();
    allocator.destroy(runtime);
}

test "loop runtime marshal executes on runtime thread" {
    var runtime = LoopRuntime.init(std.testing.allocator);
    try runtime.start();
    defer runtime.deinit();

    const Context = struct {
        ran: bool = false,
        fn run(ptr: *anyopaque) !void {
            const ctx: *@This() = @ptrCast(@alignCast(ptr));
            ctx.ran = true;
        }
    };

    var ctx = Context{};
    try runtime.marshal(.{ .callback = Context.run, .context = &ctx });
    try std.testing.expect(ctx.ran);
}

test "loop manager reference accounting" {
    var manager = try LoopManager.init(std.testing.allocator);
    defer manager.deinit();

    var project = project_status.ProjectHandle.init(std.testing.allocator, 1, .{
        .enabled = true,
        .family = .ipv4,
        .protocol = .tcp,
        .target_address = "127.0.0.1",
        .target_port = 1,
        .listen_port = 2,
    });
    defer project.deinit();

    const first = try manager.acquire(.per_project, &project);
    const second = try manager.acquire(.per_project, &project);
    try std.testing.expectEqual(@as(usize, 1), manager.debugRuntimeCount(.per_project));
    manager.release(first);
    try std.testing.expectEqual(@as(usize, 1), manager.debugRuntimeCount(.per_project));
    manager.release(second);
    try std.testing.expectEqual(@as(usize, 0), manager.debugRuntimeCount(.per_project));
}
