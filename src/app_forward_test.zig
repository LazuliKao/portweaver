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

test "app forward: tcp single connection with data transfer" {
    const alloc = testing.allocator;

    var handle = try makeSinglePortHandle(alloc, 8, .tcp, 43150, 53150);
    defer cleanupProjectHandle(&handle);

    const EchoServer = struct {
        fn tcpEchoServerThread(port: u16) void {
            const address = std.net.Address.parseIp4("127.0.0.1", port) catch return;

            const sockfd = std.posix.socket(address.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP) catch return;
            defer std.posix.close(sockfd);

            const reuse_addr = std.mem.toBytes(@as(c_int, 1));
            std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, reuse_addr[0..]) catch return;

            const socklen = address.getOsSockLen();
            std.posix.bind(sockfd, &address.any, socklen) catch return;
            std.posix.listen(sockfd, 128) catch return;

            const connection_fd = std.posix.accept(sockfd, null, null, std.posix.SOCK.CLOEXEC) catch return;
            defer std.posix.close(connection_fd);

            const connection = std.net.Stream{ .handle = connection_fd };

            var buffer: [4096]u8 = undefined;
            while (true) {
                const read_len = connection.read(&buffer) catch return;

                if (read_len == 0) break;
                connection.writeAll(buffer[0..read_len]) catch return;
            }
        }
    };

    const forwarder = try app_forward.TcpForwarder.init(alloc, &handle, 43150, 53150);
    defer forwarder.deinit();

    const echo_thread = try std.Thread.spawn(app_forward.getThreadConfig(), EchoServer.tcpEchoServerThread, .{53150});
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

test "app forward: tcp 5 sequential clients" {
    const alloc = testing.allocator;

    var handle = try makeSinglePortHandle(alloc, 9, .tcp, 43151, 53151);
    defer cleanupProjectHandle(&handle);

    const EchoServer = struct {
        fn tcpEchoServerThread(port: u16) void {
            const address = std.net.Address.parseIp4("127.0.0.1", port) catch return;

            const sockfd = std.posix.socket(address.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP) catch return;
            defer std.posix.close(sockfd);

            const reuse_addr = std.mem.toBytes(@as(c_int, 1));
            std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, reuse_addr[0..]) catch return;

            const socklen = address.getOsSockLen();
            std.posix.bind(sockfd, &address.any, socklen) catch return;
            std.posix.listen(sockfd, 128) catch return;

            var connections: usize = 0;
            while (connections < 5) {
                const connection_fd = std.posix.accept(sockfd, null, null, std.posix.SOCK.CLOEXEC) catch return;
                defer std.posix.close(connection_fd);

                const connection = std.net.Stream{ .handle = connection_fd };

                var buffer: [4096]u8 = undefined;
                while (true) {
                    const read_len = connection.read(&buffer) catch return;
                    if (read_len == 0) break;
                    connection.writeAll(buffer[0..read_len]) catch return;
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

fn tcpEchoServerThread(port: u16) void {
    const address = std.net.Address.parseIp4("127.0.0.1", port) catch return;

    const sockfd = std.posix.socket(address.any.family, std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC, std.posix.IPPROTO.TCP) catch return;
    defer std.posix.close(sockfd);

    const reuse_addr = std.mem.toBytes(@as(c_int, 1));
    std.posix.setsockopt(sockfd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, reuse_addr[0..]) catch return;

    const socklen = address.getOsSockLen();
    std.posix.bind(sockfd, &address.any, socklen) catch return;
    std.posix.listen(sockfd, 128) catch return;

    var poll_fds = [_]std.posix.pollfd{.{
        .fd = sockfd,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const deadline = std.time.nanoTimestamp() + std.time.ns_per_s;

    while (true) {
        const now = std.time.nanoTimestamp();
        if (now >= deadline) return;

        const remaining_ns: u64 = @intCast(deadline - now);
        const remaining_ms: i32 = @intCast(@max(@as(u64, 1), (remaining_ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms));
        const poll_result = std.posix.poll(poll_fds[0..], remaining_ms) catch return;
        if (poll_result == 0) return;
        if ((poll_fds[0].revents & std.posix.POLL.IN) != 0) break;
    }

    const connection_fd = std.posix.accept(sockfd, null, null, std.posix.SOCK.CLOEXEC) catch return;
    defer std.posix.close(connection_fd);

    const connection = std.net.Stream{ .handle = connection_fd };

    const expected_len = "Hello, PortWeaver!".len;
    var echoed: usize = 0;
    var buffer: [4096]u8 = undefined;
    while (true) {
        const read_len = connection.read(&buffer) catch return;

        if (read_len == 0) break;

        connection.writeAll(buffer[0..read_len]) catch return;
        echoed += read_len;
        if (echoed >= expected_len) break;
    }
}

fn tcpClientTest(port: u16, message: []const u8, timeout_ns: u64) ![]const u8 {
    const allocator = testing.allocator;
    const address = try std.net.Address.parseIp4("127.0.0.1", port);

    const sockfd = try std.posix.socket(
        address.any.family,
        std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC | std.posix.SOCK.NONBLOCK,
        std.posix.IPPROTO.TCP,
    );
    defer std.posix.close(sockfd);

    std.posix.connect(sockfd, &address.any, address.getOsSockLen()) catch |err| switch (err) {
        error.WouldBlock, error.ConnectionPending => {},
        else => return err,
    };

    const deadline = std.time.nanoTimestamp() + @as(i128, @intCast(timeout_ns));
    while (true) {
        const now = std.time.nanoTimestamp();
        if (now >= deadline) return error.Timeout;

        const remaining_ns: u64 = @intCast(deadline - now);
        const remaining_ms: i32 = @intCast(@max(@as(u64, 1), (remaining_ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms));

        var poll_fds = [_]std.posix.pollfd{.{
            .fd = sockfd,
            .events = std.posix.POLL.OUT,
            .revents = 0,
        }};
        const poll_result = std.posix.poll(poll_fds[0..], remaining_ms) catch |err| return err;
        if (poll_result == 0) return error.Timeout;
        if ((poll_fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL)) != 0) {
            return error.ConnectionResetByPeer;
        }

        std.posix.getsockoptError(sockfd) catch |err| switch (err) {
            error.WouldBlock, error.ConnectionPending => continue,
            else => return err,
        };
        break;
    }

    var stream = std.net.Stream{ .handle = sockfd };
    defer stream.close();

    try stream.writeAll(message);
    std.posix.shutdown(stream.handle, .send) catch return error.ConnectionResetByPeer;
    var response: [1024]u8 = undefined;
    var response_len: usize = 0;

    var buffer: [1024]u8 = undefined;
    while (true) {
        const read_len = stream.read(&buffer) catch |err| return err;

        if (read_len == 0) break;
        const end = response_len + read_len;
        if (end > response.len) return error.MessageTooBig;
        @memcpy(response[response_len..end], buffer[0..read_len]);
        response_len = end;

        if (response_len >= message.len) break;
    }

    return try allocator.dupe(u8, response[0..response_len]);
}

fn udpEchoServerThread(port: u16) void {
    const address = std.net.Address.parseIp4("127.0.0.1", port) catch return;

    var socket = std.net.UdpSocket.init(address) catch return;
    defer socket.deinit();

    var buffer: [65507]u8 = undefined;
    var peer_addr: std.net.Address = undefined;
    var peer_addr_len: usize = @sizeOf(std.net.Address);

    while (true) {
        const recv_len = socket.receiveFrom(buffer[0..], &peer_addr, &peer_addr_len) catch return;
        if (recv_len == 0) continue;

        socket.sendTo(peer_addr, buffer[0..recv_len]) catch return;
    }
}

fn udpClientTest(port: u16, message: []const u8, timeout_ns: u64) ![]const u8 {
    const allocator = testing.allocator;
    const address = try std.net.Address.parseIp4("127.0.0.1", port);

    var socket = try std.net.UdpSocket.init(address);
    defer socket.deinit();

    const deadline = std.time.nanoTimestamp() + @as(i128, @intCast(timeout_ns));
    try socket.send(message);

    var response: [1024]u8 = undefined;
    while (true) {
        const now = std.time.nanoTimestamp();
        if (now >= deadline) return error.Timeout;

        const remaining_ns: u64 = @intCast(deadline - now);
        const remaining_ms: i32 = @intCast(@max(@as(u64, 1), (remaining_ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms));

        var poll_fds = [_]std.posix.pollfd{.{
            .fd = socket.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};

        const poll_result = std.posix.poll(poll_fds[0..], remaining_ms) catch |err| return err;
        if (poll_result == 0) return error.Timeout;
        if ((poll_fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL)) != 0) {
            return error.ConnectionResetByPeer;
        }

        const recv_len = socket.receive(response[0..]) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };

        return try allocator.dupe(u8, response[0..recv_len]);
    }
}
