const std = @import("std");
const testing = std.testing;

const types = @import("./config/types.zig");
const app_forward = @import("./impl/app_forward.zig");
const loop_manager = @import("./impl/app_forward/loop_manager.zig");
const project_status = @import("./impl/project_status.zig");
const forwarder_runtime = @import("./impl/app_forward/forwarder_runtime.zig");
const compat = @import("./compat.zig");

const run_duration_ns = 1 * std.time.ns_per_s;
const forwarder_ready_ns = 100 * std.time.ns_per_ms;
const ForwarderKind = enum { tcp, udp };

const ThreadSafeFailingAllocator = struct {
    backing: std.mem.Allocator,
    mutex: std.atomic.Mutex = .unlocked,
    index: usize = 0,
    fail_index: usize,
    has_induced_failure: bool = false,

    pub fn init(backing: std.mem.Allocator, fail_index: usize) ThreadSafeFailingAllocator {
        return .{
            .backing = backing,
            .fail_index = fail_index,
        };
    }

    pub fn allocator(self: *ThreadSafeFailingAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable = std.mem.Allocator.VTable{
        .alloc = alloc,
        .resize = resize,
        .remap = remap,
        .free = free,
    };

    fn lock(self: *ThreadSafeFailingAllocator) void {
        while (!self.mutex.tryLock()) {
            std.atomic.spinLoopHint();
        }
    }

    fn unlock(self: *ThreadSafeFailingAllocator) void {
        self.mutex.unlock();
    }

    fn alloc(ctx: *anyopaque, len: usize, ptr_align: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.lock();
        defer self.unlock();

        const current_index = self.index;
        self.index += 1;
        if (current_index == self.fail_index) {
            self.has_induced_failure = true;
            return null;
        }

        return self.backing.vtable.alloc(self.backing.ptr, len, ptr_align, ret_addr);
    }

    fn resize(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.lock();
        defer self.unlock();
        return self.backing.vtable.resize(self.backing.ptr, buf, buf_align, new_len, ret_addr);
    }

    fn remap(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.lock();
        defer self.unlock();
        return self.backing.vtable.remap(self.backing.ptr, buf, buf_align, new_len, ret_addr);
    }

    fn free(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, ret_addr: usize) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.lock();
        defer self.unlock();
        self.backing.vtable.free(self.backing.ptr, buf, buf_align, ret_addr);
    }
};

fn testListenPort(id: u16, offset: u16) u16 {
    return 40000 + id * 4 + offset;
}

fn testTargetPort(id: u16, offset: u16) u16 {
    return 50000 + id * 4 + offset;
}

const TcpRunContext = struct {
    handle: *project_status.ProjectHandle,
    runtime: *loop_manager.LoopRuntime,
    forwarder: *app_forward.TcpForwarder,
    start_error: ?anyerror = null,
};

const UdpRunContext = struct {
    handle: *project_status.ProjectHandle,
    runtime: *loop_manager.LoopRuntime,
    forwarder: *app_forward.UdpForwarder,
    start_error: ?anyerror = null,
};

const TcpCreateContext = struct {
    allocator: std.mem.Allocator,
    handle: *project_status.ProjectHandle,
    runtime: *loop_manager.LoopRuntime,
    listen_port: u16,
    target_port: u16,
    forwarder: ?*app_forward.TcpForwarder = null,

    fn run(ptr: *anyopaque) !void {
        const ctx: *@This() = @ptrCast(@alignCast(ptr));
        const token = forwarder_runtime.runtimeToken(ctx.runtime.ctx.?);
        ctx.forwarder = try app_forward.TcpForwarder.createOnRuntimeThread(ctx.allocator, ctx.handle, token, ctx.listen_port, ctx.target_port);
    }
};

const UdpCreateContext = struct {
    allocator: std.mem.Allocator,
    handle: *project_status.ProjectHandle,
    runtime: *loop_manager.LoopRuntime,
    listen_port: u16,
    target_port: u16,
    forwarder: ?*app_forward.UdpForwarder = null,

    fn run(ptr: *anyopaque) !void {
        const ctx: *@This() = @ptrCast(@alignCast(ptr));
        const token = forwarder_runtime.runtimeToken(ctx.runtime.ctx.?);
        ctx.forwarder = try app_forward.UdpForwarder.createOnRuntimeThread(ctx.allocator, ctx.handle, token, ctx.listen_port, ctx.target_port);
    }
};

const TcpDestroyContext = struct {
    runtime: *loop_manager.LoopRuntime,
    forwarder: *app_forward.TcpForwarder,

    fn run(ptr: *anyopaque) !void {
        const ctx: *@This() = @ptrCast(@alignCast(ptr));
        const token = forwarder_runtime.runtimeToken(ctx.runtime.ctx.?);
        ctx.forwarder.destroyOnRuntimeThread(token);
    }
};

const UdpDestroyContext = struct {
    runtime: *loop_manager.LoopRuntime,
    forwarder: *app_forward.UdpForwarder,

    fn run(ptr: *anyopaque) !void {
        const ctx: *@This() = @ptrCast(@alignCast(ptr));
        const token = forwarder_runtime.runtimeToken(ctx.runtime.ctx.?);
        ctx.forwarder.destroyOnRuntimeThread(token);
    }
};

const UdpEchoServerContext = struct {
    port: u16,
    max_messages: usize,
    start_error: ?anyerror = null,
};

const TcpSizedEchoServerContext = struct {
    port: u16,
    max_connections: usize,
    start_error: ?anyerror = null,
};

const TcpCloseServerContext = struct {
    port: u16,
    start_error: ?anyerror = null,
};

const TcpPeerCloseClientContext = struct {
    port: u16,
    completed: bool = false,
    err: ?anyerror = null,
};

fn cleanupProjectHandle(handle: *project_status.ProjectHandle) void {
    handle.deinit();
    handle.cfg.deinit(handle.allocator);
}

fn createTcpForwarderOnRuntime(allocator: std.mem.Allocator, handle: *project_status.ProjectHandle, runtime: *loop_manager.LoopRuntime, listen_port: u16, target_port: u16) !*app_forward.TcpForwarder {
    var ctx = TcpCreateContext{
        .allocator = allocator,
        .handle = handle,
        .runtime = runtime,
        .listen_port = listen_port,
        .target_port = target_port,
    };
    try runtime.marshal(.{ .callback = TcpCreateContext.run, .context = &ctx });
    return ctx.forwarder.?;
}

fn createUdpForwarderOnRuntime(allocator: std.mem.Allocator, handle: *project_status.ProjectHandle, runtime: *loop_manager.LoopRuntime, listen_port: u16, target_port: u16) !*app_forward.UdpForwarder {
    var ctx = UdpCreateContext{
        .allocator = allocator,
        .handle = handle,
        .runtime = runtime,
        .listen_port = listen_port,
        .target_port = target_port,
    };
    try runtime.marshal(.{ .callback = UdpCreateContext.run, .context = &ctx });
    return ctx.forwarder.?;
}

fn destroyTcpForwarderOnRuntime(runtime: *loop_manager.LoopRuntime, forwarder: *app_forward.TcpForwarder) void {
    var ctx = TcpDestroyContext{ .runtime = runtime, .forwarder = forwarder };
    runtime.marshal(.{ .callback = TcpDestroyContext.run, .context = &ctx }) catch |err| {
        std.log.err("Failed to destroy TCP forwarder on runtime thread: {}", .{err});
    };
    forwarder.destroyWrapper();
}

fn destroyUdpForwarderOnRuntime(runtime: *loop_manager.LoopRuntime, forwarder: *app_forward.UdpForwarder) void {
    var ctx = UdpDestroyContext{ .runtime = runtime, .forwarder = forwarder };
    runtime.marshal(.{ .callback = UdpDestroyContext.run, .context = &ctx }) catch |err| {
        std.log.err("Failed to destroy UDP forwarder on runtime thread: {}", .{err});
    };
    forwarder.destroyWrapper();
}

fn makeSinglePortHandle(
    allocator: std.mem.Allocator,
    id: usize,
    protocol: types.Protocol,
    listen_port: u16,
    target_port: u16,
) !project_status.ProjectHandle {
    return makeSinglePortHandleWithOptions(allocator, id, protocol, listen_port, "127.0.0.1", target_port, false);
}

fn makeSinglePortHandleWithOptions(
    allocator: std.mem.Allocator,
    id: usize,
    protocol: types.Protocol,
    listen_port: u16,
    target_address_input: []const u8,
    target_port: u16,
    enable_app_stats: bool,
) !project_status.ProjectHandle {
    const remark = try allocator.dupe(u8, "forwarder leak test");
    errdefer allocator.free(remark);

    const target_address = try allocator.dupe(u8, target_address_input);
    errdefer allocator.free(target_address);

    return project_status.ProjectHandle.init(allocator, id, .{
        .remark = remark,
        .protocol = protocol,
        .family = .ipv4,
        .listen_port = listen_port,
        .target_address = target_address,
        .target_port = target_port,
        .enable_app_forward = true,
        .enable_app_stats = enable_app_stats,
        .reuseaddr = true,
    });
}

fn makePortMapping(allocator: std.mem.Allocator, protocol: types.Protocol, listen_port: []const u8, target_port: []const u8) !types.PortMapping {
    const listen_port_copy = try allocator.dupe(u8, listen_port);
    errdefer allocator.free(listen_port_copy);

    const target_port_copy = try allocator.dupe(u8, target_port);
    errdefer allocator.free(target_port_copy);

    return .{
        .listen_port = listen_port_copy,
        .target_port = target_port_copy,
        .protocol = protocol,
    };
}

fn makeRangeMappingHandle(
    allocator: std.mem.Allocator,
    id: usize,
    protocol: types.Protocol,
    listen_range: []const u8,
    target_range: []const u8,
) !project_status.ProjectHandle {
    const remark = try allocator.dupe(u8, "forwarder range leak test");
    errdefer allocator.free(remark);

    const target_address = try allocator.dupe(u8, "127.0.0.1");
    errdefer allocator.free(target_address);

    const mappings = try allocator.alloc(types.PortMapping, 1);
    errdefer allocator.free(mappings);
    mappings[0] = try makePortMapping(allocator, protocol, listen_range, target_range);
    errdefer mappings[0].deinit(allocator);

    return project_status.ProjectHandle.init(allocator, id, .{
        .remark = remark,
        .protocol = .both,
        .family = .ipv4,
        .listen_port = 0,
        .target_address = target_address,
        .target_port = 0,
        .port_mappings = mappings,
        .enable_app_forward = true,
        .enable_app_stats = false,
        .reuseaddr = true,
    });
}

fn tcpStartThread(ctx: *TcpRunContext) void {
    ctx.runtime.marshal(.{
        .callback = struct {
            fn run(ptr: *anyopaque) !void {
                const start_ctx: *TcpRunContext = @ptrCast(@alignCast(ptr));
                const token = forwarder_runtime.runtimeToken(start_ctx.runtime.ctx.?);
                try start_ctx.forwarder.startOnRuntimeThread(token, start_ctx.handle);
            }
        }.run,
        .context = ctx,
    }) catch |err| {
        ctx.start_error = err;
        return;
    };

    ctx.start_error = null;
}

fn udpStartThread(ctx: *UdpRunContext) void {
    ctx.runtime.marshal(.{
        .callback = struct {
            fn run(ptr: *anyopaque) !void {
                const start_ctx: *UdpRunContext = @ptrCast(@alignCast(ptr));
                const token = forwarder_runtime.runtimeToken(start_ctx.runtime.ctx.?);
                try start_ctx.forwarder.startOnRuntimeThread(token, start_ctx.handle);
            }
        }.run,
        .context = ctx,
    }) catch |err| {
        ctx.start_error = err;
        return;
    };

    ctx.start_error = null;
}

test "app forward: tcp forwarder init/deinit no leak" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(1, 0);
    const target_port = testTargetPort(1, 0);

    var handle = try makeSinglePortHandle(alloc, 1, .tcp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    var runtime = loop_manager.LoopRuntime.init(alloc);
    try runtime.start();
    defer runtime.deinit();

    const forwarder = try createTcpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port);
    defer destroyTcpForwarderOnRuntime(&runtime, forwarder);
}

test "app forward: udp forwarder init/deinit no leak" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(2, 0);
    const target_port = testTargetPort(2, 0);

    var handle = try makeSinglePortHandle(alloc, 2, .udp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    var runtime = loop_manager.LoopRuntime.init(alloc);
    try runtime.start();
    defer runtime.deinit();

    const forwarder = try createUdpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port);
    defer destroyUdpForwarderOnRuntime(&runtime, forwarder);
}

test "app forward: tcp forwarder reports invalid target address" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(20, 0);
    const target_port = testTargetPort(20, 0);

    var handle = try makeSinglePortHandleWithOptions(alloc, 20, .tcp, listen_port, "not-an-ip", target_port, false);
    defer cleanupProjectHandle(&handle);

    var runtime = loop_manager.LoopRuntime.init(alloc);
    try runtime.start();
    defer runtime.deinit();

    try testing.expectError(app_forward.ForwardError.ListenFailed, createTcpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port));
    try testing.expectEqual(project_status.StartupStatus.failed, handle.startup_status);
    try testing.expectEqual(@as(i32, -5), handle.error_code);
}

test "app forward: udp forwarder reports invalid target address" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(21, 0);
    const target_port = testTargetPort(21, 0);

    var handle = try makeSinglePortHandleWithOptions(alloc, 21, .udp, listen_port, "not-an-ip", target_port, false);
    defer cleanupProjectHandle(&handle);

    var runtime = loop_manager.LoopRuntime.init(alloc);
    try runtime.start();
    defer runtime.deinit();

    try testing.expectError(app_forward.ForwardError.ListenFailed, createUdpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port));
    try testing.expectEqual(project_status.StartupStatus.failed, handle.startup_status);
    try testing.expectEqual(@as(i32, -5), handle.error_code);
}

test "app forward: forwarder stats preserve listen port and start at zero" {
    const alloc = testing.allocator;
    const tcp_listen_port = testListenPort(22, 0);
    const tcp_target_port = testTargetPort(22, 0);
    const udp_listen_port = testListenPort(23, 0);
    const udp_target_port = testTargetPort(23, 0);

    var tcp_handle = try makeSinglePortHandleWithOptions(alloc, 22, .tcp, tcp_listen_port, "127.0.0.1", tcp_target_port, true);
    defer cleanupProjectHandle(&tcp_handle);
    var runtime = loop_manager.LoopRuntime.init(alloc);
    try runtime.start();
    defer runtime.deinit();

    const tcp_forwarder = try createTcpForwarderOnRuntime(alloc, &tcp_handle, &runtime, tcp_listen_port, tcp_target_port);
    defer destroyTcpForwarderOnRuntime(&runtime, tcp_forwarder);

    const tcp_stats = tcp_forwarder.getStats();
    try testing.expectEqual(@as(u64, 0), tcp_stats.bytes_in);
    try testing.expectEqual(@as(u64, 0), tcp_stats.bytes_out);
    try testing.expectEqual(tcp_listen_port, tcp_stats.listen_port);

    var udp_handle = try makeSinglePortHandleWithOptions(alloc, 23, .udp, udp_listen_port, "127.0.0.1", udp_target_port, true);
    defer cleanupProjectHandle(&udp_handle);
    const udp_forwarder = try createUdpForwarderOnRuntime(alloc, &udp_handle, &runtime, udp_listen_port, udp_target_port);
    defer destroyUdpForwarderOnRuntime(&runtime, udp_forwarder);

    const udp_stats = udp_forwarder.getStats();
    try testing.expectEqual(@as(u64, 0), udp_stats.bytes_in);
    try testing.expectEqual(@as(u64, 0), udp_stats.bytes_out);
    try testing.expectEqual(udp_listen_port, udp_stats.listen_port);
}

test "app forward: tcp init returns OutOfMemory when wrapper allocation fails" {
    const base_alloc = testing.allocator;
    const listen_port = testListenPort(24, 0);
    const target_port = testTargetPort(24, 0);

    var handle = try makeSinglePortHandle(base_alloc, 24, .tcp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    var failing_allocator = testing.FailingAllocator.init(base_alloc, .{ .fail_index = 1 });
    const alloc = failing_allocator.allocator();

    var runtime = loop_manager.LoopRuntime.init(base_alloc);
    try runtime.start();
    defer runtime.deinit();

    try testing.expectError(error.OutOfMemory, createTcpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port));
    try testing.expect(failing_allocator.has_induced_failure);
}

test "app forward: udp init returns OutOfMemory when wrapper allocation fails" {
    const base_alloc = testing.allocator;
    const listen_port = testListenPort(25, 0);
    const target_port = testTargetPort(25, 0);

    var handle = try makeSinglePortHandle(base_alloc, 25, .udp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    var failing_allocator = testing.FailingAllocator.init(base_alloc, .{ .fail_index = 1 });
    const alloc = failing_allocator.allocator();

    var runtime = loop_manager.LoopRuntime.init(base_alloc);
    try runtime.start();
    defer runtime.deinit();

    try testing.expectError(error.OutOfMemory, createUdpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port));
    try testing.expect(failing_allocator.has_induced_failure);
}

test "app forward: tcp init cleans up C allocations on malloc failure" {
    try expectForwarderInitMallocFailure(.tcp, 26, 2);
    try expectForwarderInitMallocFailure(.tcp, 27, 3);
    try expectForwarderInitMallocFailure(.tcp, 28, 4);
}

test "app forward: udp init cleans up C allocations on malloc failure" {
    try expectForwarderInitMallocFailure(.udp, 29, 2);
    try expectForwarderInitMallocFailure(.udp, 30, 3);
    try expectForwarderInitMallocFailure(.udp, 31, 4);
}

test "app forward: tcp forwarder runs for 3s then exits cleanly" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(3, 0);
    const target_port = testTargetPort(3, 0);

    var handle = try makeSinglePortHandle(alloc, 3, .tcp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    var runtime = loop_manager.LoopRuntime.init(alloc);
    try runtime.start();
    defer runtime.deinit();

    const forwarder = try createTcpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port);
    defer destroyTcpForwarderOnRuntime(&runtime, forwarder);

    var ctx = TcpRunContext{ .handle = &handle, .runtime = &runtime, .forwarder = forwarder };
    const thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpStartThread, .{&ctx});

    compat.sleepNanos(run_duration_ns);
    forwarder.requestStop();
    thread.join();

    try testing.expect(ctx.start_error == null);
}

test "app forward: udp forwarder runs for 3s then exits cleanly" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(4, 0);
    const target_port = testTargetPort(4, 0);

    var handle = try makeSinglePortHandle(alloc, 4, .udp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    var runtime = loop_manager.LoopRuntime.init(alloc);
    try runtime.start();
    defer runtime.deinit();

    const forwarder = try createUdpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port);
    defer destroyUdpForwarderOnRuntime(&runtime, forwarder);

    var ctx = UdpRunContext{ .handle = &handle, .runtime = &runtime, .forwarder = forwarder };
    const thread = try std.Thread.spawn(app_forward.getThreadConfig(), udpStartThread, .{&ctx});

    compat.sleepNanos(run_duration_ns);
    forwarder.requestStop();
    thread.join();

    try testing.expect(ctx.start_error == null);
}

test "app forward: project single-port tcp runs for 3s then stops" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(5, 0);
    const target_port = testTargetPort(5, 0);

    var handle = try makeSinglePortHandle(alloc, 5, .tcp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    try app_forward.startForwarding(alloc, &handle);
    compat.sleepNanos(run_duration_ns);
}

test "app forward: project single-port udp runs for 3s then stops" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(6, 0);
    const target_port = testTargetPort(6, 0);

    var handle = try makeSinglePortHandle(alloc, 6, .udp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    try app_forward.startForwarding(alloc, &handle);
    compat.sleepNanos(run_duration_ns);
}

test "app forward: project range both runs for 3s then stops" {
    const alloc = testing.allocator;
    const listen_start = testListenPort(7, 0);
    const target_start = testTargetPort(7, 0);
    const listen_range = try std.fmt.allocPrint(alloc, "{d}-{d}", .{ listen_start, listen_start + 1 });
    defer alloc.free(listen_range);
    const target_range = try std.fmt.allocPrint(alloc, "{d}-{d}", .{ target_start, target_start + 1 });
    defer alloc.free(target_range);

    var handle = try makeRangeMappingHandle(alloc, 7, .both, listen_range, target_range);
    defer cleanupProjectHandle(&handle);

    try app_forward.startForwarding(alloc, &handle);
    compat.sleepNanos(run_duration_ns);
}

test "app forward: per_project shared loop hosts two tcp listeners" {
    const alloc = testing.allocator;
    const listen_start = testListenPort(40, 0);
    const target_start = testTargetPort(40, 0);
    const listen_range = try std.fmt.allocPrint(alloc, "{d}-{d}", .{ listen_start, listen_start + 1 });
    defer alloc.free(listen_range);
    const target_range = try std.fmt.allocPrint(alloc, "{d}-{d}", .{ target_start, target_start + 1 });
    defer alloc.free(target_range);

    var handle = try makeRangeMappingHandle(alloc, 40, .tcp, listen_range, target_range);
    handle.cfg.app_forward_loop_mode = .per_project;

    var runtime_manager = try loop_manager.LoopManager.init(alloc);
    defer runtime_manager.deinit();
    defer handle.cfg.deinit(handle.allocator);
    defer handle.deinit();
    defer runtime_manager.releaseProjectRuntime(&handle) catch |err| {
        std.log.err("failed to release shared loop runtime for project {d}: {}", .{ handle.id, err });
    };

    var first_echo = TcpSizedEchoServerContext{ .port = target_start, .max_connections = 1 };
    var second_echo = TcpSizedEchoServerContext{ .port = target_start + 1, .max_connections = 1 };
    const first_echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpSizedEchoServerThread, .{&first_echo});
    defer first_echo_thread.join();
    const second_echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpSizedEchoServerThread, .{&second_echo});
    defer second_echo_thread.join();

    try app_forward.startForwardingWithLoopManager(alloc, &handle, &runtime_manager);
    compat.sleepNanos(forwarder_ready_ns);

    try testing.expectEqual(project_status.StartupStatus.success, handle.startup_status);
    try testing.expectEqual(@as(u32, 2), handle.active_ports);
    try testing.expectEqual(@as(usize, 1), runtime_manager.debugRuntimeCount(.per_project));

    const first_response = try tcpClientTest(listen_start, "first shared tcp", std.time.ns_per_s);
    defer alloc.free(first_response);
    const second_response = try tcpClientTest(listen_start + 1, "second shared tcp", std.time.ns_per_s);
    defer alloc.free(second_response);

    try testing.expectEqualStrings("first shared tcp", first_response);
    try testing.expectEqualStrings("second shared tcp", second_response);
    try testing.expect(first_echo.start_error == null);
    try testing.expect(second_echo.start_error == null);
}

test "app forward: per_project shared loop hosts mixed tcp and udp listeners" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(41, 0);
    const target_port = testTargetPort(41, 0);

    var handle = try makeSinglePortHandle(alloc, 41, .both, listen_port, target_port);
    handle.cfg.app_forward_loop_mode = .per_project;

    var runtime_manager = try loop_manager.LoopManager.init(alloc);
    defer runtime_manager.deinit();
    defer handle.cfg.deinit(handle.allocator);
    defer handle.deinit();
    defer runtime_manager.releaseProjectRuntime(&handle) catch |err| {
        std.log.err("failed to release shared loop runtime for project {d}: {}", .{ handle.id, err });
    };

    var tcp_echo = TcpSizedEchoServerContext{ .port = target_port, .max_connections = 1 };
    const tcp_echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpSizedEchoServerThread, .{&tcp_echo});
    defer tcp_echo_thread.join();
    var udp_echo = UdpEchoServerContext{ .port = target_port, .max_messages = 1 };
    const udp_echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), udpEchoServerThread, .{&udp_echo});
    defer udp_echo_thread.join();

    try app_forward.startForwardingWithLoopManager(alloc, &handle, &runtime_manager);
    compat.sleepNanos(forwarder_ready_ns);

    try testing.expectEqual(project_status.StartupStatus.success, handle.startup_status);
    try testing.expectEqual(@as(u32, 2), handle.active_ports);
    try testing.expectEqual(@as(usize, 1), runtime_manager.debugRuntimeCount(.per_project));

    const tcp_response = try tcpClientTest(listen_port, "mixed tcp", std.time.ns_per_s);
    defer alloc.free(tcp_response);
    const udp_response = try udpClientTest(listen_port, "mixed udp", std.time.ns_per_s);
    defer alloc.free(udp_response);

    try testing.expectEqualStrings("mixed tcp", tcp_response);
    try testing.expectEqualStrings("mixed udp", udp_response);
    try testing.expect(tcp_echo.start_error == null);
    try testing.expect(udp_echo.start_error == null);
}

test "app forward: per_listener compatibility keeps listeners isolated" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(42, 0);
    const target_port = testTargetPort(42, 0);

    var handle = try makeSinglePortHandle(alloc, 42, .both, listen_port, target_port);
    handle.cfg.app_forward_loop_mode = .per_listener;

    var runtime_manager = try loop_manager.LoopManager.init(alloc);
    defer runtime_manager.deinit();
    defer handle.cfg.deinit(handle.allocator);
    defer handle.deinit();
    defer runtime_manager.releaseProjectRuntime(&handle) catch |err| {
        std.log.err("failed to release shared loop runtime for project {d}: {}", .{ handle.id, err });
    };

    var tcp_echo = TcpSizedEchoServerContext{ .port = target_port, .max_connections = 1 };
    const tcp_echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpSizedEchoServerThread, .{&tcp_echo});
    defer tcp_echo_thread.join();
    var udp_echo = UdpEchoServerContext{ .port = target_port, .max_messages = 1 };
    const udp_echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), udpEchoServerThread, .{&udp_echo});
    defer udp_echo_thread.join();

    try app_forward.startForwardingWithLoopManager(alloc, &handle, &runtime_manager);
    compat.sleepNanos(forwarder_ready_ns);

    try testing.expectEqual(project_status.StartupStatus.success, handle.startup_status);
    try testing.expectEqual(@as(u32, 2), handle.active_ports);
    try testing.expectEqual(@as(usize, 2), runtime_manager.debugRuntimeCount(.per_listener));

    const tcp_response = try tcpClientTest(listen_port, "isolated tcp", std.time.ns_per_s);
    defer alloc.free(tcp_response);
    const udp_response = try udpClientTest(listen_port, "isolated udp", std.time.ns_per_s);
    defer alloc.free(udp_response);

    try testing.expectEqualStrings("isolated tcp", tcp_response);
    try testing.expectEqualStrings("isolated udp", udp_response);
    try testing.expect(tcp_echo.start_error == null);
    try testing.expect(udp_echo.start_error == null);
}

test "app forward: shared loop shutdown releases runtime and bind failure is isolated" {
    const alloc = testing.allocator;

    var runtime_manager = try loop_manager.LoopManager.init(alloc);
    defer runtime_manager.deinit();

    const conflict_listen_port = testListenPort(43, 0);
    const conflict_target_port = testTargetPort(43, 0);
    var occupied_handle = try makeSinglePortHandle(alloc, 43, .tcp, conflict_listen_port, conflict_target_port);
    occupied_handle.cfg.app_forward_loop_mode = .global;
    var occupied_released = false;
    defer occupied_handle.cfg.deinit(occupied_handle.allocator);
    defer if (!occupied_released) occupied_handle.deinit();
    defer if (!occupied_released) runtime_manager.releaseProjectRuntime(&occupied_handle) catch |err| {
        std.log.err("failed to release occupied shared loop runtime for project {d}: {}", .{ occupied_handle.id, err });
    };
    try app_forward.startForwardingWithLoopManager(alloc, &occupied_handle, &runtime_manager);

    var conflict_handle = try makeSinglePortHandle(alloc, 45, .tcp, conflict_listen_port, conflict_target_port);
    conflict_handle.cfg.app_forward_loop_mode = .global;
    defer cleanupProjectHandle(&conflict_handle);
    try testing.expectError(app_forward.ForwardError.ListenFailed, app_forward.startForwardingWithLoopManager(alloc, &conflict_handle, &runtime_manager));
    try testing.expectEqual(project_status.StartupStatus.failed, conflict_handle.startup_status);

    try runtime_manager.releaseProjectRuntime(&occupied_handle);
    occupied_handle.deinit();
    occupied_released = true;

    const healthy_listen_port = testListenPort(44, 0);
    const healthy_target_port = testTargetPort(44, 0);
    var healthy_handle = try makeSinglePortHandle(alloc, 44, .tcp, healthy_listen_port, healthy_target_port);
    healthy_handle.cfg.app_forward_loop_mode = .global;
    try app_forward.startForwardingWithLoopManager(alloc, &healthy_handle, &runtime_manager);
    compat.sleepNanos(forwarder_ready_ns);
    try testing.expectEqual(project_status.StartupStatus.success, healthy_handle.startup_status);
    try testing.expectEqual(@as(usize, 1), runtime_manager.debugRuntimeCount(.global));

    try runtime_manager.releaseProjectRuntime(&healthy_handle);
    healthy_handle.deinit();
    try testing.expectEqual(@as(usize, 0), runtime_manager.debugRuntimeCount(.global));
    healthy_handle.cfg.deinit(healthy_handle.allocator);
}

test "app forward: architecture test with three concurrent loop modes" {
    const alloc = testing.allocator;

    const base_id = 60;
    const listen_port_a = testListenPort(base_id, 0);
    const target_port_a = testTargetPort(base_id, 0);

    const listen_port_b = testListenPort(base_id, 1);
    const target_port_b = testTargetPort(base_id, 1);

    const listen_port_c = testListenPort(base_id, 2);
    const target_port_c = testTargetPort(base_id, 2);

    // Initialize the shared LoopManager
    var runtime_manager = try loop_manager.LoopManager.init(alloc);
    defer runtime_manager.deinit();

    // 1. Project A: global mode (TCP)
    var handle_a = try makeSinglePortHandle(alloc, base_id, .tcp, listen_port_a, target_port_a);
    handle_a.cfg.app_forward_loop_mode = .global;
    defer handle_a.cfg.deinit(handle_a.allocator);
    defer handle_a.deinit();
    defer runtime_manager.releaseProjectRuntime(&handle_a) catch {};

    // 2. Project B: per_project mode (UDP)
    var handle_b = try makeSinglePortHandle(alloc, base_id + 1, .udp, listen_port_b, target_port_b);
    handle_b.cfg.app_forward_loop_mode = .per_project;
    defer handle_b.cfg.deinit(handle_b.allocator);
    defer handle_b.deinit();
    defer runtime_manager.releaseProjectRuntime(&handle_b) catch {};

    // 3. Project C: per_listener mode (both TCP & UDP)
    var handle_c = try makeSinglePortHandle(alloc, base_id + 2, .both, listen_port_c, target_port_c);
    handle_c.cfg.app_forward_loop_mode = .per_listener;
    defer handle_c.cfg.deinit(handle_c.allocator);
    defer handle_c.deinit();
    defer runtime_manager.releaseProjectRuntime(&handle_c) catch {};

    // Spawn echo servers for targets
    var tcp_echo_a = TcpSizedEchoServerContext{ .port = target_port_a, .max_connections = 1 };
    const tcp_thread_a = try std.Thread.spawn(app_forward.getThreadConfig(), tcpSizedEchoServerThread, .{&tcp_echo_a});
    defer tcp_thread_a.join();

    var udp_echo_b = UdpEchoServerContext{ .port = target_port_b, .max_messages = 1 };
    const udp_thread_b = try std.Thread.spawn(app_forward.getThreadConfig(), udpEchoServerThread, .{&udp_echo_b});
    defer udp_thread_b.join();

    var tcp_echo_c = TcpSizedEchoServerContext{ .port = target_port_c, .max_connections = 1 };
    const tcp_thread_c = try std.Thread.spawn(app_forward.getThreadConfig(), tcpSizedEchoServerThread, .{&tcp_echo_c});
    defer tcp_thread_c.join();

    var udp_echo_c = UdpEchoServerContext{ .port = target_port_c, .max_messages = 1 };
    const udp_thread_c = try std.Thread.spawn(app_forward.getThreadConfig(), udpEchoServerThread, .{&udp_echo_c});
    defer udp_thread_c.join();

    // Start forwarding for all three projects
    try app_forward.startForwardingWithLoopManager(alloc, &handle_a, &runtime_manager);
    try app_forward.startForwardingWithLoopManager(alloc, &handle_b, &runtime_manager);
    try app_forward.startForwardingWithLoopManager(alloc, &handle_c, &runtime_manager);

    compat.sleepNanos(forwarder_ready_ns);

    // Verify successful startup and active ports counts
    try testing.expectEqual(project_status.StartupStatus.success, handle_a.startup_status);
    try testing.expectEqual(project_status.StartupStatus.success, handle_b.startup_status);
    try testing.expectEqual(project_status.StartupStatus.success, handle_c.startup_status);

    try testing.expectEqual(@as(u32, 1), handle_a.active_ports);
    try testing.expectEqual(@as(u32, 1), handle_b.active_ports);
    try testing.expectEqual(@as(u32, 2), handle_c.active_ports);

    // Verify LoopManager runtime counts:
    // Global: 1
    // Per-project: 1
    // Per-listener: 2
    try testing.expectEqual(@as(usize, 1), runtime_manager.debugRuntimeCount(.global));
    try testing.expectEqual(@as(usize, 1), runtime_manager.debugRuntimeCount(.per_project));
    try testing.expectEqual(@as(usize, 2), runtime_manager.debugRuntimeCount(.per_listener));

    // Perform concurrent data transfers to verify all portforwarders work fine
    const response_a = try tcpClientTest(listen_port_a, "global tcp msg", std.time.ns_per_s);
    defer alloc.free(response_a);
    try testing.expectEqualStrings("global tcp msg", response_a);

    const response_b = try udpClientTest(listen_port_b, "per-project udp msg", std.time.ns_per_s);
    defer alloc.free(response_b);
    try testing.expectEqualStrings("per-project udp msg", response_b);

    const response_c_tcp = try tcpClientTest(listen_port_c, "per-listener tcp msg", std.time.ns_per_s);
    defer alloc.free(response_c_tcp);
    try testing.expectEqualStrings("per-listener tcp msg", response_c_tcp);

    const response_c_udp = try udpClientTest(listen_port_c, "per-listener udp msg", std.time.ns_per_s);
    defer alloc.free(response_c_udp);
    try testing.expectEqualStrings("per-listener udp msg", response_c_udp);

    try testing.expect(tcp_echo_a.start_error == null);
    try testing.expect(udp_echo_b.start_error == null);
    try testing.expect(tcp_echo_c.start_error == null);
    try testing.expect(udp_echo_c.start_error == null);

    // Clean stop and release runtimes
    try runtime_manager.releaseProjectRuntime(&handle_a);
    try runtime_manager.releaseProjectRuntime(&handle_b);
    try runtime_manager.releaseProjectRuntime(&handle_c);

    // Verify all loop runtimes are completely released and cleaned up (no leaks)
    try testing.expectEqual(@as(usize, 0), runtime_manager.debugRuntimeCount(.global));
    try testing.expectEqual(@as(usize, 0), runtime_manager.debugRuntimeCount(.per_project));
    try testing.expectEqual(@as(usize, 0), runtime_manager.debugRuntimeCount(.per_listener));
}

test "app forward: tcp single connection with data transfer" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(8, 0);
    const target_port = testTargetPort(8, 0);

    var handle = try makeSinglePortHandle(alloc, 8, .tcp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    var runtime = loop_manager.LoopRuntime.init(alloc);
    try runtime.start();
    defer runtime.deinit();

    const forwarder = try createTcpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port);
    defer destroyTcpForwarderOnRuntime(&runtime, forwarder);

    const echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpEchoServerThread, .{target_port});
    defer echo_thread.join();

    var forwarder_ctx = TcpRunContext{ .handle = &handle, .runtime = &runtime, .forwarder = forwarder };
    const forwarder_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpStartThread, .{&forwarder_ctx});
    defer forwarder_thread.join();

    compat.sleepNanos(forwarder_ready_ns);
    try testing.expect(forwarder_ctx.start_error == null);

    const message = "Hello, PortWeaver!";
    const response = try tcpClientTest(listen_port, message, std.time.ns_per_s);
    defer alloc.free(response);

    try testing.expectEqualStrings(message, response);

    forwarder.requestStop();
}

test "app forward: udp single datagram with data transfer" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(32, 0);
    const target_port = testTargetPort(32, 0);

    var handle = try makeSinglePortHandle(alloc, 32, .udp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    var runtime = loop_manager.LoopRuntime.init(alloc);
    try runtime.start();
    defer runtime.deinit();

    const forwarder = try createUdpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port);
    defer destroyUdpForwarderOnRuntime(&runtime, forwarder);

    var echo_ctx = UdpEchoServerContext{ .port = target_port, .max_messages = 1 };
    const echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), udpEchoServerThread, .{&echo_ctx});
    defer echo_thread.join();

    var forwarder_ctx = UdpRunContext{ .handle = &handle, .runtime = &runtime, .forwarder = forwarder };
    const forwarder_thread = try std.Thread.spawn(app_forward.getThreadConfig(), udpStartThread, .{&forwarder_ctx});
    defer forwarder_thread.join();
    defer forwarder.requestStop();

    compat.sleepNanos(forwarder_ready_ns);
    try testing.expect(forwarder_ctx.start_error == null);

    const message = "UDP says hello through PortWeaver";
    const response = try udpClientTest(listen_port, message, std.time.ns_per_s);
    defer alloc.free(response);

    try testing.expectEqualStrings(message, response);

    try testing.expect(echo_ctx.start_error == null);
}

test "app forward: udp 10 packets from same client" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(35, 0);
    const target_port = testTargetPort(35, 0);

    var handle = try makeSinglePortHandle(alloc, 35, .udp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    var runtime = loop_manager.LoopRuntime.init(alloc);
    try runtime.start();
    defer runtime.deinit();

    const forwarder = try createUdpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port);
    defer destroyUdpForwarderOnRuntime(&runtime, forwarder);

    var echo_ctx = UdpEchoServerContext{ .port = target_port, .max_messages = 10 };
    const echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), udpEchoServerThread, .{&echo_ctx});
    defer echo_thread.join();

    var forwarder_ctx = UdpRunContext{ .handle = &handle, .runtime = &runtime, .forwarder = forwarder };
    const forwarder_thread = try std.Thread.spawn(app_forward.getThreadConfig(), udpStartThread, .{&forwarder_ctx});
    defer forwarder_thread.join();
    defer forwarder.requestStop();

    compat.sleepNanos(forwarder_ready_ns);
    try testing.expect(forwarder_ctx.start_error == null);

    for (1..11) |i| {
        var buf: [64]u8 = undefined;
        const message = std.fmt.bufPrint(&buf, "udp packet {d}", .{i}) catch unreachable;
        const response = try udpClientTest(listen_port, message, std.time.ns_per_s);
        defer alloc.free(response);
        try testing.expectEqualStrings(message, response);
    }

    try testing.expect(echo_ctx.start_error == null);
}

test "app forward: udp client sends and closes immediately" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(36, 0);
    const target_port = testTargetPort(36, 0);

    var handle = try makeSinglePortHandle(alloc, 36, .udp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    var runtime = loop_manager.LoopRuntime.init(alloc);
    try runtime.start();
    defer runtime.deinit();

    const forwarder = try createUdpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port);
    defer destroyUdpForwarderOnRuntime(&runtime, forwarder);

    var echo_ctx = UdpEchoServerContext{ .port = target_port, .max_messages = 1 };
    const echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), udpEchoServerThread, .{&echo_ctx});
    defer echo_thread.join();

    var forwarder_ctx = UdpRunContext{ .handle = &handle, .runtime = &runtime, .forwarder = forwarder };
    const forwarder_thread = try std.Thread.spawn(app_forward.getThreadConfig(), udpStartThread, .{&forwarder_ctx});
    defer forwarder_thread.join();
    defer forwarder.requestStop();

    compat.sleepNanos(forwarder_ready_ns);
    try testing.expect(forwarder_ctx.start_error == null);

    try udpSendOnly(listen_port, "send and forget");
    // Give the echo server a moment to process
    compat.sleepNanos(forwarder_ready_ns);

    try testing.expect(echo_ctx.start_error == null);
}

test "app forward: tcp 64KB data transfer" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(37, 0);
    const target_port = testTargetPort(37, 0);

    var handle = try makeSinglePortHandle(alloc, 37, .tcp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    var runtime = loop_manager.LoopRuntime.init(alloc);
    try runtime.start();
    defer runtime.deinit();

    const forwarder = try createTcpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port);
    defer destroyTcpForwarderOnRuntime(&runtime, forwarder);

    var echo_ctx = TcpSizedEchoServerContext{ .port = target_port, .max_connections = 1 };
    const echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpSizedEchoServerThread, .{&echo_ctx});
    defer echo_thread.join();

    var forwarder_ctx = TcpRunContext{ .handle = &handle, .runtime = &runtime, .forwarder = forwarder };
    const forwarder_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpStartThread, .{&forwarder_ctx});
    defer forwarder_thread.join();
    defer forwarder.requestStop();

    compat.sleepNanos(forwarder_ready_ns);
    try testing.expect(forwarder_ctx.start_error == null);

    // Build 64KB payload: 'a' + (idx % 26)
    const data_len = 65536;
    const payload = try alloc.alloc(u8, data_len);
    defer alloc.free(payload);
    for (payload, 0..) |*byte, idx| {
        byte.* = @intCast('a' + (idx % 26));
    }

    const response = try tcpClientTest(listen_port, payload, std.time.ns_per_s);
    defer alloc.free(response);

    try testing.expectEqual(data_len, response.len);
    try testing.expectEqualSlices(u8, payload, response);

    try testing.expect(echo_ctx.start_error == null);
}

test "app forward: udp session timeout and garbage collection" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(70, 0);
    const target_port = testTargetPort(70, 0);

    var handle = try makeSinglePortHandle(alloc, 70, .udp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    var runtime = loop_manager.LoopRuntime.init(alloc);
    try runtime.start();
    defer runtime.deinit();

    const forwarder = try createUdpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port);
    defer destroyUdpForwarderOnRuntime(&runtime, forwarder);

    var echo_ctx = UdpEchoServerContext{ .port = target_port, .max_messages = 2 };
    const echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), udpEchoServerThread, .{&echo_ctx});
    defer echo_thread.join();

    var forwarder_ctx = UdpRunContext{ .handle = &handle, .runtime = &runtime, .forwarder = forwarder };
    const forwarder_thread = try std.Thread.spawn(app_forward.getThreadConfig(), udpStartThread, .{&forwarder_ctx});
    defer forwarder_thread.join();
    defer forwarder.requestStop();

    compat.sleepNanos(forwarder_ready_ns);
    try testing.expect(forwarder_ctx.start_error == null);

    // 1. Send first packet to establish a session
    const msg1 = "packet 1";
    const resp1 = try udpClientTest(listen_port, msg1, std.time.ns_per_s);
    defer alloc.free(resp1);
    try testing.expectEqualStrings(msg1, resp1);

    // Verify stats show 1 active session
    const stats1 = forwarder.getStats();
    try testing.expectEqual(@as(u32, 1), stats1.active_sessions);

    // 2. Sleep for 6 seconds (timeout in DEBUG is 5 seconds) to trigger GC
    compat.sleepNanos(6 * std.time.ns_per_s);

    // Verify stats show 0 active sessions after GC
    const stats2 = forwarder.getStats();
    try testing.expectEqual(@as(u32, 0), stats2.active_sessions);

    // 3. Send second packet to establish a new session
    const msg2 = "packet 2";
    const resp2 = try udpClientTest(listen_port, msg2, std.time.ns_per_s);
    defer alloc.free(resp2);
    try testing.expectEqualStrings(msg2, resp2);

    // Verify stats show 1 active session again
    const stats3 = forwarder.getStats();
    try testing.expectEqual(@as(u32, 1), stats3.active_sessions);

    try testing.expect(echo_ctx.start_error == null);
}

test "app forward: tcp 5 sequential clients" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(9, 0);
    const target_port = testTargetPort(9, 0);

    var handle = try makeSinglePortHandle(alloc, 9, .tcp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    const EchoServer = struct {
        fn tcpEchoServerThread(port: u16) void {
            const io = compat.io();
            var address = std.Io.net.IpAddress.parseIp4("127.0.0.1", port) catch return;
            var server = address.listen(io, .{ .reuse_address = true, .mode = .stream, .protocol = .tcp }) catch return;
            defer server.deinit(io);

            var connections: usize = 0;
            while (connections < 5) {
                const connection = server.accept(io) catch return;
                defer connection.close(io);

                var read_buffer: [4096]u8 = undefined;
                var write_buffer: [4096]u8 = undefined;
                var reader = connection.reader(io, &read_buffer);
                var writer = connection.writer(io, &write_buffer);

                while (true) {
                    var chunk: [4096]u8 = undefined;
                    const read_len = reader.interface.readSliceShort(&chunk) catch return;
                    if (read_len == 0) break;
                    writer.interface.writeAll(chunk[0..read_len]) catch return;
                    writer.interface.flush() catch return;
                }

                connections += 1;
            }
        }
    };

    var runtime = loop_manager.LoopRuntime.init(alloc);
    try runtime.start();
    defer runtime.deinit();

    const forwarder = try createTcpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port);
    defer destroyTcpForwarderOnRuntime(&runtime, forwarder);

    const echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), EchoServer.tcpEchoServerThread, .{target_port});
    defer echo_thread.join();

    var forwarder_ctx = TcpRunContext{ .handle = &handle, .runtime = &runtime, .forwarder = forwarder };
    const forwarder_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpStartThread, .{&forwarder_ctx});
    defer forwarder_thread.join();
    defer forwarder.requestStop();

    compat.sleepNanos(forwarder_ready_ns);
    try testing.expect(forwarder_ctx.start_error == null);

    for (0..5) |idx| {
        var message_buffer: [32]u8 = undefined;
        const message = try std.fmt.bufPrint(&message_buffer, "client {}", .{idx + 1});

        const response = try tcpClientTest(listen_port, message, std.time.ns_per_s);
        defer alloc.free(response);

        try testing.expectEqualStrings(message, response);
        compat.sleepNanos(50 * std.time.ns_per_ms);
    }

    forwarder.requestStop();
}

test "app forward: tcp target can disconnect abruptly" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(33, 0);
    const target_port = testTargetPort(33, 0);

    var handle = try makeSinglePortHandle(alloc, 33, .tcp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    var runtime = loop_manager.LoopRuntime.init(alloc);
    try runtime.start();
    defer runtime.deinit();

    const forwarder = try createTcpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port);
    defer destroyTcpForwarderOnRuntime(&runtime, forwarder);

    var close_ctx = TcpCloseServerContext{ .port = target_port };
    const close_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpCloseServerThread, .{&close_ctx});
    defer close_thread.join();

    var forwarder_ctx = TcpRunContext{ .handle = &handle, .runtime = &runtime, .forwarder = forwarder };
    const forwarder_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpStartThread, .{&forwarder_ctx});
    defer forwarder_thread.join();

    compat.sleepNanos(forwarder_ready_ns);
    try testing.expect(forwarder_ctx.start_error == null);

    var client_ctx = TcpPeerCloseClientContext{ .port = listen_port };
    const client_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpPeerCloseClientThread, .{&client_ctx});
    compat.sleepNanos(forwarder_ready_ns);
    forwarder.requestStop();
    client_thread.join();

    try testing.expect(client_ctx.completed);
    try testing.expect(client_ctx.err == null);
    try testing.expect(close_ctx.start_error == null);
}

test "app forward: tcp concurrent clients with large payload" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(34, 0);
    const target_port = testTargetPort(34, 0);
    const client_count = 10;
    const payload_len = 8192;

    var handle = try makeSinglePortHandle(alloc, 34, .tcp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    var runtime = loop_manager.LoopRuntime.init(alloc);
    try runtime.start();
    defer runtime.deinit();

    const forwarder = try createTcpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port);
    defer destroyTcpForwarderOnRuntime(&runtime, forwarder);

    var echo_ctx = TcpSizedEchoServerContext{ .port = target_port, .max_connections = client_count };
    const echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpSizedEchoServerThread, .{&echo_ctx});
    defer echo_thread.join();

    var forwarder_ctx = TcpRunContext{ .handle = &handle, .runtime = &runtime, .forwarder = forwarder };
    const forwarder_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpStartThread, .{&forwarder_ctx});
    defer forwarder_thread.join();
    defer forwarder.requestStop();

    compat.sleepNanos(forwarder_ready_ns);
    try testing.expect(forwarder_ctx.start_error == null);

    var payload: [payload_len]u8 = undefined;
    for (&payload, 0..) |*byte, idx| {
        byte.* = @intCast('a' + (idx % 26));
    }

    var client_threads: [client_count]std.Thread = undefined;
    var client_contexts: [client_count]TcpClientContext = undefined;
    for (&client_contexts, 0..) |*ctx, idx| {
        ctx.* = .{ .port = listen_port, .message = payload[0..], .client_index = idx };
        client_threads[idx] = try std.Thread.spawn(app_forward.getThreadConfig(), tcpClientThread, .{ctx});
    }

    for (&client_threads) |thread| {
        thread.join();
    }

    for (&client_contexts) |ctx| {
        try testing.expect(ctx.err == null);
    }

    try testing.expect(echo_ctx.start_error == null);
}

const TcpClientContext = struct {
    port: u16,
    message: []const u8,
    client_index: usize,
    err: ?anyerror = null,
};

fn expectForwarderInitMallocFailure(kind: ForwarderKind, id: usize, fail_index: usize) !void {
    const base_alloc = testing.allocator;
    const listen_port = testListenPort(@intCast(id), 0);
    const target_port = testTargetPort(@intCast(id), 0);
    const protocol: types.Protocol = switch (kind) {
        .tcp => .tcp,
        .udp => .udp,
    };

    var handle = try makeSinglePortHandle(base_alloc, id, protocol, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    var failing_allocator = ThreadSafeFailingAllocator.init(base_alloc, fail_index);
    const alloc = failing_allocator.allocator();

    var runtime = loop_manager.LoopRuntime.init(base_alloc);
    try runtime.start();
    defer runtime.deinit();

    runtime.allocator = alloc;

    switch (kind) {
        .tcp => {
            if (createTcpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port)) |fwd| {
                destroyTcpForwarderOnRuntime(&runtime, fwd);
                return error.TestUnexpectedSuccess;
            } else |err| {
                try testing.expect(err == app_forward.ForwardError.ListenFailed or err == error.OutOfMemory);
                if (err == app_forward.ForwardError.ListenFailed) {
                    try testing.expectEqual(project_status.StartupStatus.failed, handle.startup_status);
                    try testing.expectEqual(@as(i32, -1), handle.error_code);
                }
            }
        },
        .udp => {
            if (createUdpForwarderOnRuntime(alloc, &handle, &runtime, listen_port, target_port)) |fwd| {
                destroyUdpForwarderOnRuntime(&runtime, fwd);
                return error.TestUnexpectedSuccess;
            } else |err| {
                try testing.expect(err == app_forward.ForwardError.ListenFailed or err == error.OutOfMemory);
                if (err == app_forward.ForwardError.ListenFailed) {
                    try testing.expectEqual(project_status.StartupStatus.failed, handle.startup_status);
                    try testing.expectEqual(@as(i32, -1), handle.error_code);
                }
            }
        },
    }

    try testing.expect(failing_allocator.has_induced_failure);
}

fn tcpClientThread(ctx: *TcpClientContext) void {
    const response = tcpClientTest(ctx.port, ctx.message, std.time.ns_per_s) catch |err| {
        ctx.err = err;
        return;
    };
    defer testing.allocator.free(response);

    testing.expectEqualSlices(u8, ctx.message, response) catch |err| {
        ctx.err = err;
        return;
    };

    ctx.err = null;
}

fn tcpPeerCloseClientThread(ctx: *TcpPeerCloseClientContext) void {
    tcpClientExpectPeerClose(ctx.port) catch |err| {
        std.debug.print("\n=== tcpClientExpectPeerClose error: {any} ===\n", .{err});
        ctx.err = err;
    };
    ctx.completed = true;
}

fn tcpEchoServerThread(port: u16) void {
    const io = compat.io();
    var address = std.Io.net.IpAddress.parseIp4("127.0.0.1", port) catch return;
    var server = address.listen(io, .{ .reuse_address = true, .mode = .stream, .protocol = .tcp }) catch return;
    defer server.deinit(io);

    const connection = server.accept(io) catch return;
    defer connection.close(io);

    var read_buffer: [4096]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
    var reader = connection.reader(io, &read_buffer);
    var writer = connection.writer(io, &write_buffer);

    const expected_len = "Hello, PortWeaver!".len;
    var echoed: usize = 0;
    while (true) {
        var chunk: [4096]u8 = undefined;
        const read_len = reader.interface.readSliceShort(&chunk) catch return;

        if (read_len == 0) break;

        writer.interface.writeAll(chunk[0..read_len]) catch return;
        writer.interface.flush() catch return;
        echoed += read_len;
        if (echoed >= expected_len) break;
    }
}

fn tcpSizedEchoServerThread(ctx: *TcpSizedEchoServerContext) void {
    const io = compat.io();
    var address = std.Io.net.IpAddress.parseIp4("127.0.0.1", ctx.port) catch |err| {
        ctx.start_error = err;
        return;
    };
    var server = address.listen(io, .{ .reuse_address = true, .mode = .stream, .protocol = .tcp }) catch |err| {
        ctx.start_error = err;
        return;
    };
    defer server.deinit(io);

    var connections: usize = 0;
    while (connections < ctx.max_connections) {
        const connection = server.accept(io) catch |err| {
            ctx.start_error = err;
            return;
        };
        defer connection.close(io);

        var read_buffer: [4096]u8 = undefined;
        var write_buffer: [4096]u8 = undefined;
        var reader = connection.reader(io, &read_buffer);
        var writer = connection.writer(io, &write_buffer);

        while (true) {
            var chunk: [4096]u8 = undefined;
            const read_len = reader.interface.readSliceShort(&chunk) catch |err| {
                ctx.start_error = err;
                return;
            };
            if (read_len == 0) break;
            writer.interface.writeAll(chunk[0..read_len]) catch |err| {
                ctx.start_error = err;
                return;
            };
            writer.interface.flush() catch |err| {
                ctx.start_error = err;
                return;
            };
        }

        connections += 1;
    }

    ctx.start_error = null;
}

fn tcpCloseServerThread(ctx: *TcpCloseServerContext) void {
    const io = compat.io();
    var address = std.Io.net.IpAddress.parseIp4("127.0.0.1", ctx.port) catch |err| {
        ctx.start_error = err;
        return;
    };
    var server = address.listen(io, .{ .reuse_address = true, .mode = .stream, .protocol = .tcp }) catch |err| {
        ctx.start_error = err;
        return;
    };
    defer server.deinit(io);

    const connection = server.accept(io) catch |err| {
        ctx.start_error = err;
        return;
    };
    connection.close(io);
    ctx.start_error = null;
}

fn tcpClientTest(port: u16, message: []const u8, timeout_ns: u64) ![]const u8 {
    const allocator = testing.allocator;

    const io = compat.io();
    var address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    const timeout = std.Io.Timeout{
        .duration = .{
            .raw = std.Io.Duration.fromNanoseconds(timeout_ns),
            .clock = .real,
        },
    };
    const stream = try address.connect(io, .{
        .mode = .stream,
        .protocol = .tcp,
    });
    defer stream.close(io);

    var write_buf: [1024]u8 = undefined;
    var writer = stream.writer(io, &write_buf);
    try writer.interface.writeAll(message);
    try writer.interface.flush();

    stream.shutdown(io, .send) catch return error.ConnectionResetByPeer;

    var response = try allocator.alloc(u8, message.len);
    errdefer allocator.free(response);
    var response_len: usize = 0;
    while (response_len < response.len) {
        const remaining = response[response_len..];
        const result = try io.operateTimeout(.{ .file_read_streaming = .{
            .file = .{ .handle = stream.socket.handle, .flags = .{ .nonblocking = true } },
            .data = &[_][]u8{remaining},
        } }, timeout);

        const read_len = result.file_read_streaming catch |err| switch (err) {
            error.EndOfStream => @as(usize, 0),
            else => return err,
        };
        if (read_len == 0) break;
        response_len += read_len;
    }

    if (response_len != response.len) {
        return allocator.realloc(response, response_len);
    }
    return response;
}

fn tcpClientExpectPeerClose(port: u16) !void {
    const io = compat.io();
    var address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    const timeout = std.Io.Timeout{
        .duration = .{
            .raw = std.Io.Duration.fromSeconds(2),
            .clock = .real,
        },
    };
    const stream = try address.connect(io, .{
        .mode = .stream,
        .protocol = .tcp,
    });
    defer stream.close(io);

    var write_buf: [64]u8 = undefined;
    var writer = stream.writer(io, &write_buf);
    try writer.interface.writeAll("peer-close");
    try writer.interface.flush();

    var chunk: [64]u8 = undefined;
    const result = try io.operateTimeout(.{ .file_read_streaming = .{
        .file = .{ .handle = stream.socket.handle, .flags = .{ .nonblocking = true } },
        .data = &[_][]u8{chunk[0..]},
    } }, timeout);

    const read_len = result.file_read_streaming catch |err| switch (err) {
        error.EndOfStream, error.ConnectionResetByPeer => @as(usize, 0),
        else => return err,
    };
    try testing.expectEqual(@as(usize, 0), read_len);
}

fn udpEchoServerThread(ctx: *UdpEchoServerContext) void {
    const io = compat.io();
    var address = std.Io.net.IpAddress.parseIp4("127.0.0.1", ctx.port) catch |err| {
        ctx.start_error = err;
        return;
    };
    const socket = address.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch |err| {
        ctx.start_error = err;
        return;
    };
    defer socket.close(io);

    var buffer: [65507]u8 = undefined;
    var messages: usize = 0;

    const timeout = std.Io.Timeout{
        .duration = .{
            .raw = std.Io.Duration.fromSeconds(10),
            .clock = .real,
        },
    };

    while (messages < ctx.max_messages) {
        const incoming = socket.receiveTimeout(io, buffer[0..], timeout) catch |err| {
            ctx.start_error = err;
            return;
        };
        if (incoming.data.len == 0) continue;

        socket.send(io, &incoming.from, incoming.data) catch |err| {
            ctx.start_error = err;
            return;
        };
        messages += 1;
    }

    ctx.start_error = null;
}

fn udpSendOnly(port: u16, message: []const u8) !void {
    const io = compat.io();
    var server_addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    var local_addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    const socket = try local_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);

    try socket.send(io, &server_addr, message);
}

fn udpClientTest(port: u16, message: []const u8, timeout_ns: u64) ![]const u8 {
    const allocator = testing.allocator;
    const io = compat.io();
    var server_addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    var local_addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    const socket = try local_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);

    try socket.send(io, &server_addr, message);

    var response: [1024]u8 = undefined;
    const timeout = std.Io.Timeout{
        .duration = .{
            .raw = std.Io.Duration.fromNanoseconds(timeout_ns),
            .clock = .real,
        },
    };
    const incoming = try socket.receiveTimeout(io, response[0..], timeout);

    return try allocator.dupe(u8, incoming.data);
}

