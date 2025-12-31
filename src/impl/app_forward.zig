const std = @import("std");
const Io = std.Io;
const types = @import("../config/types.zig");
const tcp = @import("forwarders/tcp.zig");
const udp = @import("forwarders/udp.zig");

pub const ForwardError = error{
    ListenFailed,
    ConnectFailed,
    AcceptFailed,
    TransferFailed,
    InvalidAddress,
};

const THREAD_STACK_SIZE = 64 * 1024;

pub inline fn getThreadConfig() std.Thread.SpawnConfig {
    return std.Thread.SpawnConfig{
        .stack_size = THREAD_STACK_SIZE,
    };
}

// /// UDP 转发器
// pub const UdpForwarder = struct {
//     allocator: std.mem.Allocator,
//     listen_port: u16,
//     target_address: []const u8,
//     target_port: u16,
//     family: types.AddressFamily,
//     socket: ?posix.socket_t,
//     running: std.atomic.Value(bool),
//     // 优化：删除了造成内存泄漏且未被使用的 clients HashMap

//     pub fn init(
//         allocator: std.mem.Allocator,
//         listen_port: u16,
//         target_address: []const u8,
//         target_port: u16,
//         family: types.AddressFamily,
//     ) UdpForwarder {
//         return .{
//             .allocator = allocator,
//             .listen_port = listen_port,
//             .target_address = target_address,
//             .target_port = target_port,
//             .family = family,
//             .socket = null,
//             .running = std.atomic.Value(bool).init(false),
//         };
//     }

//     pub fn deinit(self: *UdpForwarder) void {
//         // 无需清理 clients map
//         _ = self;
//     }

//     pub fn start(self: *UdpForwarder) !void {
//         self.running.store(true, .seq_cst);

//         const bind_address = switch (self.family) {
//             .ipv4 => net.IpAddress.parseIp4("0.0.0.0", self.listen_port) catch return ForwardError.ListenFailed,
//             .ipv6 => net.IpAddress.parseIp6("::", self.listen_port) catch return ForwardError.ListenFailed,
//             .any => net.IpAddress.parseIp6("::", self.listen_port) catch
//                 net.IpAddress.parseIp4("0.0.0.0", self.listen_port) catch return ForwardError.ListenFailed,
//         };
//         const sock = try posix.socket(
//             bind_address.any.family,
//             posix.SOCK.DGRAM,
//             posix.IPPROTO.UDP,
//         );
//         errdefer posix.close(sock);

//         try posix.setsockopt(
//             sock,
//             posix.SOL.SOCKET,
//             posix.SO.REUSEADDR,
//             &std.mem.toBytes(@as(c_int, 1)),
//         );

//         try posix.bind(sock, &bind_address.any, bind_address.getOsSockLen());

//         self.socket = sock;

//         std.debug.print("[UDP] Listening on port {d}, forwarding to {s}:{d}\n", .{
//             self.listen_port,
//             self.target_address,
//             self.target_port,
//         });

//         const target_list = try net.getAddressList(self.allocator, self.target_address, self.target_port);
//         defer target_list.deinit();

//         if (target_list.addrs.len == 0) {
//             return ForwardError.InvalidAddress;
//         }

//         const target_addr = target_list.addrs[0];

//         var buffer: [BUFFER_SIZE]u8 = undefined;

//         while (self.running.load(.seq_cst)) {
//             var src_addr: net.Address = undefined;
//             var src_addr_len: posix.socklen_t = @sizeOf(net.Address);

//             const n = posix.recvfrom(
//                 sock,
//                 &buffer,
//                 0,
//                 &src_addr.any,
//                 &src_addr_len,
//             ) catch |err| {
//                 if (self.running.load(.seq_cst)) {
//                     std.debug.print("[UDP] Receive error: {any}\n", .{err});
//                 }
//                 continue;
//             };

//             if (n == 0) continue;

//             // 转发到目标服务器
//             _ = posix.sendto(
//                 sock,
//                 buffer[0..n],
//                 0,
//                 &target_addr.any,
//                 target_addr.getOsSockLen(),
//             ) catch |err| {
//                 std.debug.print("[UDP] Send to target error: {any}\n", .{err});
//                 continue;
//             };

//             // 优化：移除了 put client 到 hashmap 的逻辑，避免内存泄漏
//             // 注意：当前的 UDP 逻辑仅支持 "Client -> Target" 的单向盲转发。
//             // 如果需要支持 Target 回包给 Client，需要实现 NAT 映射表和双向监听，
//             // 且必须带有超时清理机制 (TTL)，否则内存必然泄露。
//             // 鉴于原代码逻辑并未处理回包，这里仅做内存清理。

//             std.debug.print("[UDP] Forwarded {d} bytes from {any} to {s}:{d}\n", .{
//                 n,
//                 src_addr,
//                 self.target_address,
//                 self.target_port,
//             });
//         }
//     }

//     pub fn stop(self: *UdpForwarder) void {
//         self.running.store(false, .seq_cst);
//         if (self.socket) |sock| {
//             posix.close(sock);
//             self.socket = null;
//         }
//     }
// };
/// 启动一个端口转发项目
pub fn startForwarding(io: Io, allocator: std.mem.Allocator, project: types.Project) !void {
    if (!project.enable_app_forward) {
        std.debug.print("[Forward] Application-layer forwarding is disabled for this project\n", .{});
        return;
    }

    std.debug.print("[Forward] Starting application-layer forwarding for: {s}\n", .{project.remark});

    // 检查是单端口模式还是多端口模式
    if (project.port_mappings.len > 0) {
        // 多端口模式：为每个映射启动转发
        for (project.port_mappings) |mapping| {
            try startForwardingForMapping(io, allocator, project, mapping);
        }

        // 主线程等待
        while (true) {
            io.sleep(std.Io.Duration.fromSeconds(365 * 24 * 60 * 60), .awake) catch {};
        }
    } else {
        // 单端口模式：使用原有逻辑
        switch (project.protocol) {
            .tcp => {
                var tcp_forwarder = tcp.TcpForwarder.init(
                    allocator,
                    project.listen_port,
                    project.target_address,
                    project.target_port,
                    project.family,
                );
                try tcp_forwarder.start(io);
            },
            .udp => {

                // var udp_forwarder = udp.UdpForwarder.init(
                //     allocator,
                //     project.listen_port,
                //     project.target_address,
                //     project.target_port,
                //     project.family,
                // );
                // defer udp_forwarder.stop();
                // try udp_forwarder.start();
            },
            .both => {
                // 同时启动 TCP 和 UDP 转发
                const tcp_thread = try std.Thread.spawn(getThreadConfig(), startTcpForward, .{
                    io,
                    allocator,
                    project.listen_port,
                    project.target_address,
                    project.target_port,
                    project.family,
                });
                tcp_thread.detach();

                const udp_thread = try std.Thread.spawn(getThreadConfig(), startUdpForward, .{
                    allocator,
                    project.listen_port,
                    project.target_address,
                    project.target_port,
                    project.family,
                });
                udp_thread.detach();

                // 主线程等待
                while (true) {
                    io.sleep(std.Io.Duration.fromSeconds(365 * 24 * 60 * 60), .awake) catch {};
                }
            },
        }
    }
}

/// 解析端口范围字符串，返回起始和结束端口
fn parsePortRange(port_str: []const u8) !struct { start: u16, end: u16 } {
    const trimmed = std.mem.trim(u8, port_str, " \t\r\n");

    if (std.mem.indexOf(u8, trimmed, "-")) |dash_pos| {
        // 端口范围
        const start_str = trimmed[0..dash_pos];
        const end_str = trimmed[dash_pos + 1 ..];

        const start_port = try types.parsePort(start_str);
        const end_port = try types.parsePort(end_str);

        return .{ .start = start_port, .end = end_port };
    } else {
        // 单个端口
        const port = try types.parsePort(trimmed);
        return .{ .start = port, .end = port };
    }
}

/// 为单个端口映射启动转发
fn startForwardingForMapping(
    io: Io,
    allocator: std.mem.Allocator,
    project: types.Project,
    mapping: types.PortMapping,
) !void {
    const listen_range = try parsePortRange(mapping.listen_port);
    const target_range = try parsePortRange(mapping.target_port);

    // 验证端口范围长度一致
    const listen_count = listen_range.end - listen_range.start + 1;
    const target_count = target_range.end - target_range.start + 1;

    if (listen_count != target_count) {
        std.debug.print("[Forward] Error: Port range mismatch - listen {d} ports, target {d} ports\n", .{
            listen_count,
            target_count,
        });
        return ForwardError.InvalidAddress;
    }

    // 为范围内的每个端口启动转发
    var i: u16 = 0;
    while (i < listen_count) : (i += 1) {
        const listen_port = listen_range.start + i;
        const target_port = target_range.start + i;

        switch (mapping.protocol) {
            .tcp => {
                const tcp_thread = try std.Thread.spawn(getThreadConfig(), startTcpForward, .{
                    io,
                    allocator,
                    listen_port,
                    project.target_address,
                    target_port,
                    project.family,
                });
                tcp_thread.detach();
            },
            .udp => {
                const udp_thread = try std.Thread.spawn(getThreadConfig(), startUdpForward, .{
                    allocator,
                    listen_port,
                    project.target_address,
                    target_port,
                    project.family,
                });
                udp_thread.detach();
            },
            .both => {
                const tcp_thread = try std.Thread.spawn(getThreadConfig(), startTcpForward, .{
                    io,
                    allocator,
                    listen_port,
                    project.target_address,
                    target_port,
                    project.family,
                });
                tcp_thread.detach();

                const udp_thread = try std.Thread.spawn(getThreadConfig(), startUdpForward, .{
                    allocator,
                    listen_port,
                    project.target_address,
                    target_port,
                    project.family,
                });
                udp_thread.detach();
            },
        }
    }
}

fn startTcpForward(
    io: Io,
    allocator: std.mem.Allocator,
    listen_port: u16,
    target_address: []const u8,
    target_port: u16,
    family: types.AddressFamily,
) void {
    // 这是一个长时间运行的线程，栈大小保持默认或者稍微减小均可
    var tcp_forwarder = tcp.TcpForwarder.init(allocator, listen_port, target_address, target_port, family);
    tcp_forwarder.start(io) catch |err| {
        std.debug.print("[TCP] Forward error: {any}\n", .{err});
    };
}

fn startUdpForward(
    allocator: std.mem.Allocator,
    listen_port: u16,
    target_address: []const u8,
    target_port: u16,
    family: types.AddressFamily,
) void {
    _ = allocator;
    _ = listen_port;
    _ = target_address;
    _ = target_port;
    _ = family;
    // var udp_forwarder = udp.UdpForwarder.init(allocator, listen_port, target_address, target_port, family);
    // udp_forwarder.start() catch |err| {
    //     std.debug.print("[UDP] Forward error: {any}\n", .{err});
    // };
}
