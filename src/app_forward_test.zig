const std = @import("std");
const testing = std.testing;

const types = @import("./config/types.zig");
const app_forward = @import("./impl/app_forward.zig");
const project_status = @import("./impl/project_status.zig");
const compat = @import("./compat.zig");

const run_duration_ns = 1 * std.time.ns_per_s;
const forwarder_ready_ns = 100 * std.time.ns_per_ms;
const ForwarderKind = enum { tcp, udp };

fn testListenPort(id: u16, offset: u16) u16 {
    return 40000 + id * 4 + offset;
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
        .family = .ipv4,
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
        .family = .ipv4,
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

test "app forward: tcp init returns OutOfMemory when wrapper allocation fails" {
    const base_alloc = testing.allocator;
    const listen_port = testListenPort(24, 0);
    const target_port = testTargetPort(24, 0);

    var handle = try makeSinglePortHandle(base_alloc, 24, .tcp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    var failing_allocator = testing.FailingAllocator.init(base_alloc, .{ .fail_index = 1 });
    const alloc = failing_allocator.allocator();

    try testing.expectError(error.OutOfMemory, app_forward.TcpForwarder.init(alloc, &handle, listen_port, target_port));
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

    try testing.expectError(error.OutOfMemory, app_forward.UdpForwarder.init(alloc, &handle, listen_port, target_port));
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

test "app forward: tcp single connection with data transfer" {
    const alloc = testing.allocator;

    var handle = try makeSinglePortHandle(alloc, 8, .tcp, 43150, 53150);
    defer cleanupProjectHandle(&handle);

    const forwarder = try app_forward.TcpForwarder.init(alloc, &handle, 43150, 53150);
    defer forwarder.deinit();

    const echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpEchoServerThread, .{53150});
    defer echo_thread.join();

    var forwarder_ctx = TcpRunContext{ .handle = &handle, .forwarder = forwarder };
    const forwarder_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpStartThread, .{&forwarder_ctx});
    defer forwarder_thread.join();

    try testing.expect(forwarder_ctx.start_error == null);

    const message = "Hello, PortWeaver!";
    const response = try tcpClientTest(43150, message, std.time.ns_per_s);
    defer alloc.free(response);

    try testing.expectEqualStrings(message, response);

    forwarder.stop();
}

test "app forward: udp single datagram with data transfer" {
    const alloc = testing.allocator;
    const listen_port: u16 = 43160;
    const target_port: u16 = 53160;

    var handle = try makeSinglePortHandle(alloc, 32, .udp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    const forwarder = try app_forward.UdpForwarder.init(alloc, &handle, listen_port, target_port);
    defer forwarder.deinit();

    var echo_ctx = UdpEchoServerContext{ .port = target_port, .max_messages = 1 };
    const echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), udpEchoServerThread, .{&echo_ctx});
    defer echo_thread.join();

    var forwarder_ctx = UdpRunContext{ .handle = &handle, .forwarder = forwarder };
    const forwarder_thread = try std.Thread.spawn(app_forward.getThreadConfig(), udpStartThread, .{&forwarder_ctx});
    defer forwarder_thread.join();
    defer forwarder.stop();

    compat.sleepNanos(forwarder_ready_ns);
    try testing.expect(forwarder_ctx.start_error == null);

    const message = "UDP says hello through PortWeaver";
    const response = try udpClientTest(listen_port, message, std.time.ns_per_s);
    defer alloc.free(response);

    try testing.expectEqualStrings(message, response);

    try testing.expect(echo_ctx.start_error == null);
}

test "app forward: tcp 5 sequential clients" {
    const alloc = testing.allocator;

    var handle = try makeSinglePortHandle(alloc, 9, .tcp, 43151, 53151);
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

    const forwarder = try app_forward.TcpForwarder.init(alloc, &handle, 43151, 53151);
    defer forwarder.deinit();

    const echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), EchoServer.tcpEchoServerThread, .{53151});
    defer echo_thread.join();

    var forwarder_ctx = TcpRunContext{ .handle = &handle, .forwarder = forwarder };
    const forwarder_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpStartThread, .{&forwarder_ctx});
    defer forwarder_thread.join();
    defer forwarder.stop();

    try testing.expect(forwarder_ctx.start_error == null);

    for (0..5) |idx| {
        var message_buffer: [32]u8 = undefined;
        const message = try std.fmt.bufPrint(&message_buffer, "client {}", .{idx + 1});

        const response = try tcpClientTest(43151, message, std.time.ns_per_s);
        defer alloc.free(response);

        try testing.expectEqualStrings(message, response);
    }

    forwarder.stop();
}

test "app forward: tcp target can disconnect abruptly" {
    const alloc = testing.allocator;
    const listen_port: u16 = 43152;
    const target_port: u16 = 53152;

    var handle = try makeSinglePortHandle(alloc, 33, .tcp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    const forwarder = try app_forward.TcpForwarder.init(alloc, &handle, listen_port, target_port);
    defer forwarder.deinit();

    var close_ctx = TcpCloseServerContext{ .port = target_port };
    const close_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpCloseServerThread, .{&close_ctx});
    defer close_thread.join();

    var forwarder_ctx = TcpRunContext{ .handle = &handle, .forwarder = forwarder };
    const forwarder_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpStartThread, .{&forwarder_ctx});
    defer forwarder_thread.join();

    compat.sleepNanos(forwarder_ready_ns);
    try testing.expect(forwarder_ctx.start_error == null);

    var client_ctx = TcpPeerCloseClientContext{ .port = listen_port };
    const client_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpPeerCloseClientThread, .{&client_ctx});
    compat.sleepNanos(forwarder_ready_ns);
    forwarder.stop();
    client_thread.join();

    try testing.expect(client_ctx.completed);
    try testing.expect(client_ctx.err == null);
    try testing.expect(close_ctx.start_error == null);
}

test "app forward: tcp concurrent clients with large payload" {
    const alloc = testing.allocator;
    const listen_port: u16 = 43153;
    const target_port: u16 = 53153;
    const client_count = 8;
    const payload_len = 8192;

    var handle = try makeSinglePortHandle(alloc, 34, .tcp, listen_port, target_port);
    defer cleanupProjectHandle(&handle);

    const forwarder = try app_forward.TcpForwarder.init(alloc, &handle, listen_port, target_port);
    defer forwarder.deinit();

    var echo_ctx = TcpSizedEchoServerContext{ .port = target_port, .max_connections = client_count };
    const echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpSizedEchoServerThread, .{&echo_ctx});
    defer echo_thread.join();

    var forwarder_ctx = TcpRunContext{ .handle = &handle, .forwarder = forwarder };
    const forwarder_thread = try std.Thread.spawn(app_forward.getThreadConfig(), tcpStartThread, .{&forwarder_ctx});
    defer forwarder_thread.join();
    defer forwarder.stop();

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

    var failing_allocator = testing.FailingAllocator.init(base_alloc, .{ .fail_index = fail_index });
    const alloc = failing_allocator.allocator();

    switch (kind) {
        .tcp => try testing.expectError(app_forward.ForwardError.ListenFailed, app_forward.TcpForwarder.init(alloc, &handle, listen_port, target_port)),
        .udp => try testing.expectError(app_forward.ForwardError.ListenFailed, app_forward.UdpForwarder.init(alloc, &handle, listen_port, target_port)),
    }

    try testing.expect(failing_allocator.has_induced_failure);
    try testing.expectEqual(project_status.StartupStatus.failed, handle.startup_status);
    try testing.expectEqual(@as(i32, -1), handle.error_code);
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
    _ = timeout_ns;

    const io = compat.io();
    var address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    const stream = try address.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var write_buf: [1024]u8 = undefined;
    var writer = stream.writer(io, &write_buf);
    try writer.interface.writeAll(message);
    try writer.interface.flush();

    stream.shutdown(io, .send) catch return error.ConnectionResetByPeer;

    var read_buf: [1024]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    var response = try allocator.alloc(u8, message.len);
    errdefer allocator.free(response);
    var response_len: usize = 0;
    while (true) {
        var chunk: [1024]u8 = undefined;
        const read_len = try reader.interface.readSliceShort(&chunk);

        if (read_len == 0) break;
        const end = response_len + read_len;
        if (end > response.len) return error.MessageTooBig;
        @memcpy(response[response_len..end], chunk[0..read_len]);
        response_len = end;

        if (response_len >= message.len) break;
    }

    if (response_len != response.len) {
        return allocator.realloc(response, response_len);
    }
    return response;
}

fn tcpClientExpectPeerClose(port: u16) !void {
    const io = compat.io();
    var address = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    const stream = try address.connect(io, .{ .mode = .stream, .protocol = .tcp });
    defer stream.close(io);

    var write_buf: [64]u8 = undefined;
    var writer = stream.writer(io, &write_buf);
    try writer.interface.writeAll("peer-close");
    try writer.interface.flush();

    var read_buf: [64]u8 = undefined;
    var reader = stream.reader(io, &read_buf);
    var chunk: [64]u8 = undefined;
    const read_len = try reader.interface.readSliceShort(&chunk);
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

    while (messages < ctx.max_messages) {
        const incoming = socket.receive(io, buffer[0..]) catch |err| {
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

fn udpClientTest(port: u16, message: []const u8, timeout_ns: u64) ![]const u8 {
    const allocator = testing.allocator;
    const io = compat.io();
    var server_addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", port);
    var local_addr = try std.Io.net.IpAddress.parseIp4("127.0.0.1", 0);
    const socket = try local_addr.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);

    try socket.send(io, &server_addr, message);

    var response: [1024]u8 = undefined;
    _ = timeout_ns;
    const incoming = try socket.receive(io, response[0..]);

    return try allocator.dupe(u8, incoming.data);
}
