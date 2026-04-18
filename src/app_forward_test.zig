const std = @import("std");
const testing = std.testing;

const types = @import("./config/types.zig");
const app_forward = @import("./impl/app_forward.zig");
const project_status = @import("./impl/project_status.zig");
const compat = @import("./compat.zig");

const run_duration_ns = 3 * std.time.ns_per_s;

fn testListenPort(id: u16, offset: u16) u16 {
    const pid_component: u16 = @intCast(@mod(std.c.getpid(), 1000));
    return 40000 + pid_component * 20 + id * 4 + offset;
}

fn testTargetPort(id: u16, offset: u16) u16 {
    return 50000 + id * 4 + offset;
}

const TcpRunContext = struct {
    handle: *project_status.ProjectHandle,
    forwarder: *app_forward.TcpForwarder,
    start_error: ?anyerror = null,
};

const UdpRunContext = struct {
    handle: *project_status.ProjectHandle,
    forwarder: *app_forward.UdpForwarder,
    start_error: ?anyerror = null,
};

fn cleanupProjectHandle(handle: *project_status.ProjectHandle) void {
    handle.deinit();
    handle.cfg.deinit(handle.allocator);
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
    enable_stats: bool,
) !project_status.ProjectHandle {
    const remark = try allocator.dupe(u8, "forwarder leak test");
    errdefer allocator.free(remark);

    const target_address = try allocator.dupe(u8, target_address_input);
    errdefer allocator.free(target_address);

    return project_status.ProjectHandle.init(allocator, id, .{
        .remark = remark,
        .protocol = protocol,
        .listen_port = listen_port,
        .target_address = target_address,
        .target_port = target_port,
        .enable_app_forward = true,
        .enable_stats = enable_stats,
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
        .listen_port = 0,
        .target_address = target_address,
        .target_port = 0,
        .port_mappings = mappings,
        .enable_app_forward = true,
        .enable_stats = false,
        .reuseaddr = true,
    });
}

fn tcpStartThread(ctx: *TcpRunContext) void {
    ctx.forwarder.start(ctx.handle) catch |err| {
        ctx.start_error = err;
        return;
    };

    ctx.start_error = null;
}

fn udpStartThread(ctx: *UdpRunContext) void {
    ctx.forwarder.start(ctx.handle) catch |err| {
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

    const forwarder = try app_forward.TcpForwarder.init(alloc, &handle, listen_port, target_port);
    defer forwarder.deinit();
}

test "app forward: udp forwarder init/deinit no leak" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(2, 0);
    const target_port = testTargetPort(2, 0);

    var handle = try makeSinglePortHandle(alloc, 2, .udp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    const forwarder = try app_forward.UdpForwarder.init(alloc, &handle, listen_port, target_port);
    defer forwarder.deinit();
}

test "app forward: tcp forwarder reports invalid target address" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(20, 0);
    const target_port = testTargetPort(20, 0);

    var handle = try makeSinglePortHandleWithOptions(alloc, 20, .tcp, listen_port, "not-an-ip", target_port, false);
    defer cleanupProjectHandle(&handle);

    try testing.expectError(app_forward.ForwardError.ListenFailed, app_forward.TcpForwarder.init(alloc, &handle, listen_port, target_port));
    try testing.expectEqual(project_status.StartupStatus.failed, handle.startup_status);
    try testing.expectEqual(@as(i32, -5), handle.error_code);
}

test "app forward: udp forwarder reports invalid target address" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(21, 0);
    const target_port = testTargetPort(21, 0);

    var handle = try makeSinglePortHandleWithOptions(alloc, 21, .udp, listen_port, "not-an-ip", target_port, false);
    defer cleanupProjectHandle(&handle);

    try testing.expectError(app_forward.ForwardError.ListenFailed, app_forward.UdpForwarder.init(alloc, &handle, listen_port, target_port));
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
    const tcp_forwarder = try app_forward.TcpForwarder.init(alloc, &tcp_handle, tcp_listen_port, tcp_target_port);
    defer tcp_forwarder.deinit();

    const tcp_stats = tcp_forwarder.getStats();
    try testing.expectEqual(@as(u64, 0), tcp_stats.bytes_in);
    try testing.expectEqual(@as(u64, 0), tcp_stats.bytes_out);
    try testing.expectEqual(tcp_listen_port, tcp_stats.listen_port);

    var udp_handle = try makeSinglePortHandleWithOptions(alloc, 23, .udp, udp_listen_port, "127.0.0.1", udp_target_port, true);
    defer cleanupProjectHandle(&udp_handle);
    const udp_forwarder = try app_forward.UdpForwarder.init(alloc, &udp_handle, udp_listen_port, udp_target_port);
    defer udp_forwarder.deinit();

    const udp_stats = udp_forwarder.getStats();
    try testing.expectEqual(@as(u64, 0), udp_stats.bytes_in);
    try testing.expectEqual(@as(u64, 0), udp_stats.bytes_out);
    try testing.expectEqual(udp_listen_port, udp_stats.listen_port);
}

test "app forward: tcp forwarder runs for 3s then exits cleanly" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(3, 0);
    const target_port = testTargetPort(3, 0);

    var handle = try makeSinglePortHandle(alloc, 3, .tcp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    const forwarder = try app_forward.TcpForwarder.init(alloc, &handle, listen_port, target_port);
    defer forwarder.deinit();

    var ctx = TcpRunContext{ .handle = &handle, .forwarder = forwarder };
    const thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpStartThread, .{&ctx});

    compat.sleepNanos(run_duration_ns);
    forwarder.stop();
    thread.join();

    try testing.expect(ctx.start_error == null);
}

test "app forward: udp forwarder runs for 3s then exits cleanly" {
    const alloc = testing.allocator;
    const listen_port = testListenPort(4, 0);
    const target_port = testTargetPort(4, 0);

    var handle = try makeSinglePortHandle(alloc, 4, .udp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    const forwarder = try app_forward.UdpForwarder.init(alloc, &handle, listen_port, target_port);
    defer forwarder.deinit();

    var ctx = UdpRunContext{ .handle = &handle, .forwarder = forwarder };
    const thread = try std.Thread.spawn(app_forward.getThreadConfig(), udpStartThread, .{&ctx});

    compat.sleepNanos(run_duration_ns);
    forwarder.stop();
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
