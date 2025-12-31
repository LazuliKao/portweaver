const network = @import("network");

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const posix = std.posix;
const builtin = @import("builtin");
const types = @import("../../config/types.zig");
const ForwardError = @import("../app_forward.zig").ForwardError;
const BUFFER_SIZE = 1 * 1024;
/// UDP 转发器
pub const UdpForwarder = struct {
    allocator: std.mem.Allocator,
    listen_port: u16,
    target_address: []const u8,
    target_port: u16,
    family: types.AddressFamily,
    socket: ?posix.socket_t,
    running: std.atomic.Value(bool),
    // 优化：删除了造成内存泄漏且未被使用的 clients HashMap

    pub fn init(
        allocator: std.mem.Allocator,
        listen_port: u16,
        target_address: []const u8,
        target_port: u16,
        family: types.AddressFamily,
    ) UdpForwarder {
        return .{
            .allocator = allocator,
            .listen_port = listen_port,
            .target_address = target_address,
            .target_port = target_port,
            .family = family,
            .socket = null,
            .running = std.atomic.Value(bool).init(false),
        };
    }

    pub fn deinit(self: *UdpForwarder) void {
        // 无需清理 clients map
        _ = self;
    }

    pub fn start(self: *UdpForwarder) !void {
        self.running.store(true, .seq_cst);

        // const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
        // defer std.posix.close(sock);

        // const addr = try std.net.Address.parseIp("127.0.0.1", 55555);
        // try std.posix.bind(sock, &addr.any, addr.getOsSockLen());

        // var buf: [1024]u8 = undefined;
        // const len = try std.posix.recvfrom(sock, &buf, 0, null, null);
        // std.debug.print("recv: {s}\n", .{buf[0..len]});

        // const server = address.listen(io, .{});

        const family = switch (self.family) {
            .ipv4 => posix.AF.INET,
            .ipv6 => posix.AF.INET6,
            .any => posix.AF.INET6,
        };

        const sock = try posix.socket(
            family,
            posix.SOCK.DGRAM,
            posix.IPPROTO.UDP,
        );
        errdefer posix.close(sock);

        try posix.setsockopt(
            sock,
            posix.SOL.SOCKET,
            posix.SO.REUSEADDR,
            &std.mem.toBytes(@as(c_int, 1)),
        );
        try posix.bind(
            sock,
        );

        self.socket = sock;

        std.debug.print("[UDP] Listening on port {d}, forwarding to {s}:{d}\n", .{
            self.listen_port,
            self.target_address,
            self.target_port,
        });

        const target_list = try net.getAddressList(self.allocator, self.target_address, self.target_port);
        defer target_list.deinit();

        if (target_list.addrs.len == 0) {
            return ForwardError.InvalidAddress;
        }

        const target_addr = target_list.addrs[0];

        var buffer: [BUFFER_SIZE]u8 = undefined;

        while (self.running.load(.seq_cst)) {
            var src_addr: net.Address = undefined;
            var src_addr_len: posix.socklen_t = @sizeOf(net.Address);

            const n = posix.recvfrom(
                sock,
                &buffer,
                0,
                &src_addr.any,
                &src_addr_len,
            ) catch |err| {
                if (self.running.load(.seq_cst)) {
                    std.debug.print("[UDP] Receive error: {any}\n", .{err});
                }
                continue;
            };

            if (n == 0) continue;

            // 转发到目标服务器
            _ = posix.sendto(
                sock,
                buffer[0..n],
                0,
                &target_addr.any,
                target_addr.getOsSockLen(),
            ) catch |err| {
                std.debug.print("[UDP] Send to target error: {any}\n", .{err});
                continue;
            };

            // 优化：移除了 put client 到 hashmap 的逻辑，避免内存泄漏
            // 注意：当前的 UDP 逻辑仅支持 "Client -> Target" 的单向盲转发。
            // 如果需要支持 Target 回包给 Client，需要实现 NAT 映射表和双向监听，
            // 且必须带有超时清理机制 (TTL)，否则内存必然泄露。
            // 鉴于原代码逻辑并未处理回包，这里仅做内存清理。

            std.debug.print("[UDP] Forwarded {d} bytes from {any} to {s}:{d}\n", .{
                n,
                src_addr,
                self.target_address,
                self.target_port,
            });
        }
    }

    pub fn stop(self: *UdpForwarder) void {
        self.running.store(false, .seq_cst);
        if (self.socket) |sock| {
            posix.close(sock);
            self.socket = null;
        }
    }
};
