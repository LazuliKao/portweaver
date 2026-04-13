const std = @import("std");
const testing = std.testing;

const types = @import("./config/types.zig");
const app_forward = @import("./impl/app_forward.zig");
const project_status = @import("./impl/project_status.zig");

const run_duration_ns = 3 * std.time.ns_per_s;

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
    const remark = try allocator.dupe(u8, "forwarder leak test");
    errdefer allocator.free(remark);

    const target_address = try allocator.dupe(u8, "127.0.0.1");
    errdefer allocator.free(target_address);

    return project_status.ProjectHandle.init(allocator, id, .{
        .remark = remark,
        .protocol = protocol,
        .listen_port = listen_port,
        .target_address = target_address,
        .target_port = target_port,
        .enable_app_forward = true,
        .enable_stats = false,
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

    var handle = try makeSinglePortHandle(alloc, 1, .tcp, 43110, 53110);
    defer cleanupProjectHandle(&handle);

    const forwarder = try app_forward.TcpForwarder.init(alloc, &handle, 43110, 53110);
    defer forwarder.deinit();
}

test "app forward: udp forwarder init/deinit no leak" {
    const alloc = testing.allocator;

    var handle = try makeSinglePortHandle(alloc, 2, .udp, 43111, 53111);
    defer cleanupProjectHandle(&handle);

    const forwarder = try app_forward.UdpForwarder.init(alloc, &handle, 43111, 53111);
    defer forwarder.deinit();
}

test "app forward: tcp forwarder runs for 3s then exits cleanly" {
    const alloc = testing.allocator;

    var handle = try makeSinglePortHandle(alloc, 3, .tcp, 43120, 53120);
    defer cleanupProjectHandle(&handle);

    const forwarder = try app_forward.TcpForwarder.init(alloc, &handle, 43120, 53120);
    defer forwarder.deinit();

    var ctx = TcpRunContext{ .handle = &handle, .forwarder = forwarder };
    const thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpStartThread, .{&ctx});

    std.Thread.sleep(run_duration_ns);
    forwarder.stop();
    thread.join();

    try testing.expect(ctx.start_error == null);
}

test "app forward: udp forwarder runs for 3s then exits cleanly" {
    const alloc = testing.allocator;

    var handle = try makeSinglePortHandle(alloc, 4, .udp, 43121, 53121);
    defer cleanupProjectHandle(&handle);

    const forwarder = try app_forward.UdpForwarder.init(alloc, &handle, 43121, 53121);
    defer forwarder.deinit();

    var ctx = UdpRunContext{ .handle = &handle, .forwarder = forwarder };
    const thread = try std.Thread.spawn(app_forward.getThreadConfig(), udpStartThread, .{&ctx});

    std.Thread.sleep(run_duration_ns);
    forwarder.stop();
    thread.join();

    try testing.expect(ctx.start_error == null);
}

test "app forward: project single-port tcp runs for 3s then stops" {
    const alloc = testing.allocator;

    var handle = try makeSinglePortHandle(alloc, 5, .tcp, 43130, 53130);
    defer cleanupProjectHandle(&handle);

    try app_forward.startForwarding(alloc, &handle);
    std.Thread.sleep(run_duration_ns);
}

test "app forward: project single-port udp runs for 3s then stops" {
    const alloc = testing.allocator;

    var handle = try makeSinglePortHandle(alloc, 6, .udp, 43131, 53131);
    defer cleanupProjectHandle(&handle);

    try app_forward.startForwarding(alloc, &handle);
    std.Thread.sleep(run_duration_ns);
}

test "app forward: project range both runs for 3s then stops" {
    const alloc = testing.allocator;

    var handle = try makeRangeMappingHandle(alloc, 7, .both, "43140-43141", "53140-53141");
    defer cleanupProjectHandle(&handle);

    try app_forward.startForwarding(alloc, &handle);
    std.Thread.sleep(run_duration_ns);
}
