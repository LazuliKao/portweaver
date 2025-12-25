const std = @import("std");
const net = std.net;
const posix = std.posix;
const types = @import("../config/types.zig");

pub const ForwardError = error{
    ListenFailed,
    ConnectFailed,
    AcceptFailed,
    TransferFailed,
    InvalidAddress,
};

const BUFFER_SIZE = 8192;

/// TCP 转发器
pub const TcpForwarder = struct {
    allocator: std.mem.Allocator,
    listen_port: u16,
    target_address: []const u8,
    target_port: u16,
    family: types.AddressFamily,
    server: ?net.Server,
    running: std.atomic.Value(bool),

    pub fn init(
        allocator: std.mem.Allocator,
        listen_port: u16,
        target_address: []const u8,
        target_port: u16,
        family: types.AddressFamily,
    ) TcpForwarder {
        return .{
            .allocator = allocator,
            .listen_port = listen_port,
            .target_address = target_address,
            .target_port = target_port,
            .family = family,
            .server = null,
            .running = std.atomic.Value(bool).init(false),
        };
    }

    pub fn start(self: *TcpForwarder) !void {
        self.running.store(true, .seq_cst);

        const address = switch (self.family) {
            .ipv4 => net.Address.parseIp4("0.0.0.0", self.listen_port) catch return ForwardError.ListenFailed,
            .ipv6 => net.Address.parseIp6("::", self.listen_port) catch return ForwardError.ListenFailed,
            .any => net.Address.parseIp6("::", self.listen_port) catch
                net.Address.parseIp4("0.0.0.0", self.listen_port) catch return ForwardError.ListenFailed,
        };

        var server = try address.listen(.{
            .reuse_address = true,
            .reuse_port = false,
        });

        self.server = server;

        std.debug.print("[TCP] Listening on port {d}, forwarding to {s}:{d}\n", .{
            self.listen_port,
            self.target_address,
            self.target_port,
        });

        while (self.running.load(.seq_cst)) {
            // 接受连接
            const connection = server.accept() catch |err| {
                if (self.running.load(.seq_cst)) {
                    std.debug.print("[TCP] Accept error: {}\n", .{err});
                }
                continue;
            };

            // 为每个连接创建新线程
            const thread = std.Thread.spawn(.{}, handleTcpConnection, .{
                self.allocator,
                connection,
                self.target_address,
                self.target_port,
            }) catch |err| {
                std.debug.print("[TCP] Failed to spawn thread: {}\n", .{err});
                connection.stream.close();
                continue;
            };
            thread.detach();
        }
    }

    pub fn stop(self: *TcpForwarder) void {
        self.running.store(false, .seq_cst);
        if (self.server) |*server| {
            server.deinit();
            self.server = null;
        }
    }

    fn handleTcpConnection(
        allocator: std.mem.Allocator,
        client: net.Server.Connection,
        target_address: []const u8,
        target_port: u16,
    ) void {
        defer client.stream.close();

        const client_addr = client.address;
        std.debug.print("[TCP] New connection from {}\n", .{client_addr});

        // 连接到目标服务器
        const target = net.tcpConnectToHost(allocator, target_address, target_port) catch |err| {
            std.debug.print("[TCP] Failed to connect to target {s}:{d}: {}\n", .{ target_address, target_port, err });
            return;
        };
        defer target.close();

        std.debug.print("[TCP] Connected to target {s}:{d}\n", .{ target_address, target_port });

        // 创建两个线程分别处理双向转发
        const forward_thread = std.Thread.spawn(.{}, forwardData, .{ &client.stream, &target, "client->target" }) catch |err| {
            std.debug.print("[TCP] Failed to spawn forward thread: {}\n", .{err});
            return;
        };
        defer forward_thread.join();

        const backward_thread = std.Thread.spawn(.{}, forwardData, .{ &target, &client.stream, "target->client" }) catch |err| {
            std.debug.print("[TCP] Failed to spawn backward thread: {}\n", .{err});
            return;
        };
        defer backward_thread.join();
    }

    fn forwardData(src: *net.Stream, dst: *net.Stream, direction: []const u8) void {
        var buffer: [BUFFER_SIZE]u8 = undefined;

        while (true) {
            const n = src.read(&buffer) catch |err| {
                if (err != error.EndOfStream) {
                    std.debug.print("[TCP] Read error ({s}): {}\n", .{ direction, err });
                }
                break;
            };

            if (n == 0) break;

            dst.writeAll(buffer[0..n]) catch |err| {
                std.debug.print("[TCP] Write error ({s}): {}\n", .{ direction, err });
                break;
            };
        }
    }
};

/// UDP 转发器
pub const UdpForwarder = struct {
    allocator: std.mem.Allocator,
    listen_port: u16,
    target_address: []const u8,
    target_port: u16,
    family: types.AddressFamily,
    socket: ?posix.socket_t,
    running: std.atomic.Value(bool),
    // 客户端地址映射表，用于记住每个客户端的地址
    clients: std.AutoHashMap(u64, net.Address),

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
            .clients = std.AutoHashMap(u64, net.Address).init(allocator),
        };
    }

    pub fn deinit(self: *UdpForwarder) void {
        self.clients.deinit();
    }

    pub fn start(self: *UdpForwarder) !void {
        self.running.store(true, .seq_cst);

        const bind_address = switch (self.family) {
            .ipv4 => net.Address.parseIp4("0.0.0.0", self.listen_port) catch return ForwardError.ListenFailed,
            .ipv6 => net.Address.parseIp6("::", self.listen_port) catch return ForwardError.ListenFailed,
            .any => net.Address.parseIp6("::", self.listen_port) catch
                net.Address.parseIp4("0.0.0.0", self.listen_port) catch return ForwardError.ListenFailed,
        };

        const sock = try posix.socket(
            bind_address.any.family,
            posix.SOCK.DGRAM,
            posix.IPPROTO.UDP,
        );
        errdefer posix.close(sock);

        // 设置 SO_REUSEADDR
        try posix.setsockopt(
            sock,
            posix.SOL.SOCKET,
            posix.SO.REUSEADDR,
            &std.mem.toBytes(@as(c_int, 1)),
        );

        try posix.bind(sock, &bind_address.any, bind_address.getOsSockLen());

        self.socket = sock;

        std.debug.print("[UDP] Listening on port {d}, forwarding to {s}:{d}\n", .{
            self.listen_port,
            self.target_address,
            self.target_port,
        });

        // 解析目标地址
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
                    std.debug.print("[UDP] Receive error: {}\n", .{err});
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
                std.debug.print("[UDP] Send to target error: {}\n", .{err});
                continue;
            };

            // 保存客户端地址以便回复
            const client_hash = hashAddress(src_addr);
            try self.clients.put(client_hash, src_addr);

            std.debug.print("[UDP] Forwarded {d} bytes from {} to {s}:{d}\n", .{
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

    fn hashAddress(addr: net.Address) u64 {
        var hasher = std.hash.Wyhash.init(0);
        const bytes = std.mem.asBytes(&addr.any);
        hasher.update(bytes);
        return hasher.final();
    }
};

/// 启动一个端口转发项目
pub fn startForwarding(allocator: std.mem.Allocator, project: types.Project) !void {
    if (!project.enable_app_forward) {
        std.debug.print("[Forward] Application-layer forwarding is disabled for this project\n", .{});
        return;
    }

    std.debug.print("[Forward] Starting application-layer forwarding for: {s}\n", .{project.remark});

    // 根据协议启动相应的转发器
    switch (project.protocol) {
        .tcp => {
            var tcp_forwarder = TcpForwarder.init(
                allocator,
                project.listen_port,
                project.target_address,
                project.target_port,
                project.family,
            );
            try tcp_forwarder.start();
        },
        .udp => {
            var udp_forwarder = UdpForwarder.init(
                allocator,
                project.listen_port,
                project.target_address,
                project.target_port,
                project.family,
            );
            defer udp_forwarder.deinit();
            try udp_forwarder.start();
        },
        .both => {
            // 同时启动 TCP 和 UDP 转发
            const tcp_thread = try std.Thread.spawn(.{}, startTcpForward, .{
                allocator,
                project.listen_port,
                project.target_address,
                project.target_port,
                project.family,
            });
            tcp_thread.detach();

            const udp_thread = try std.Thread.spawn(.{}, startUdpForward, .{
                allocator,
                project.listen_port,
                project.target_address,
                project.target_port,
                project.family,
            });
            udp_thread.detach();

            // 主线程等待
            std.time.sleep(std.time.ns_per_s * 365 * 24 * 60 * 60); // 1 year
        },
    }
}

fn startTcpForward(
    allocator: std.mem.Allocator,
    listen_port: u16,
    target_address: []const u8,
    target_port: u16,
    family: types.AddressFamily,
) void {
    var tcp_forwarder = TcpForwarder.init(allocator, listen_port, target_address, target_port, family);
    tcp_forwarder.start() catch |err| {
        std.debug.print("[TCP] Forward error: {}\n", .{err});
    };
}

fn startUdpForward(
    allocator: std.mem.Allocator,
    listen_port: u16,
    target_address: []const u8,
    target_port: u16,
    family: types.AddressFamily,
) void {
    var udp_forwarder = UdpForwarder.init(allocator, listen_port, target_address, target_port, family);
    defer udp_forwarder.deinit();
    udp_forwarder.start() catch |err| {
        std.debug.print("[UDP] Forward error: {}\n", .{err});
    };
}
