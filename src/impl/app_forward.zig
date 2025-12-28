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
                    std.debug.print("[TCP] Accept error: {any}\n", .{err});
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
                std.debug.print("[TCP] Failed to spawn thread: {any}\n", .{err});
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
        std.debug.print("[TCP] New connection from {any}\n", .{client_addr});

        // 连接到目标服务器
        const target = net.tcpConnectToHost(allocator, target_address, target_port) catch |err| {
            std.debug.print("[TCP] Failed to connect to target {s}:{d}: {any}\n", .{ target_address, target_port, err });
            return;
        };
        defer target.close();

        std.debug.print("[TCP] Connected to target {s}:{d}\n", .{ target_address, target_port });

        // 创建两个线程分别处理双向转发
        var client_stream = client.stream;
        var target_stream = target;

        const forward_thread = std.Thread.spawn(.{}, forwardData, .{ &client_stream, &target_stream, "client->target" }) catch |err| {
            std.debug.print("[TCP] Failed to spawn forward thread: {any}\n", .{err});
            return;
        };
        defer forward_thread.join();

        const backward_thread = std.Thread.spawn(.{}, forwardData, .{ &target_stream, &client_stream, "target->client" }) catch |err| {
            std.debug.print("[TCP] Failed to spawn backward thread: {any}\n", .{err});
            return;
        };
        defer backward_thread.join();
    }

    fn forwardData(src: *net.Stream, dst: *net.Stream, direction: []const u8) void {
        var buffer: [BUFFER_SIZE]u8 = undefined;

        while (true) {
            const n = src.read(&buffer) catch |err| {
                if (err != error.EndOfStream) {
                    std.debug.print("[TCP] Read error ({s}): {any}\n", .{ direction, err });
                }
                break;
            };

            if (n == 0) break;

            dst.writeAll(buffer[0..n]) catch |err| {
                std.debug.print("[TCP] Write error ({s}): {any}\n", .{ direction, err });
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

            // 保存客户端地址以便回复
            const client_hash = hashAddress(src_addr);
            try self.clients.put(client_hash, src_addr);

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

    // 检查是单端口模式还是多端口模式
    if (project.port_mappings.len > 0) {
        // 多端口模式：为每个映射启动转发
        for (project.port_mappings) |mapping| {
            try startForwardingForMapping(allocator, project, mapping);
        }
        
        // 主线程等待
        std.Thread.sleep(std.time.ns_per_s * 365 * 24 * 60 * 60); // 1 year
    } else {
        // 单端口模式：使用原有逻辑
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
                std.Thread.sleep(std.time.ns_per_s * 365 * 24 * 60 * 60); // 1 year
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
        const end_str = trimmed[dash_pos + 1..];
        
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
                const tcp_thread = try std.Thread.spawn(.{}, startTcpForward, .{
                    allocator,
                    listen_port,
                    project.target_address,
                    target_port,
                    project.family,
                });
                tcp_thread.detach();
            },
            .udp => {
                const udp_thread = try std.Thread.spawn(.{}, startUdpForward, .{
                    allocator,
                    listen_port,
                    project.target_address,
                    target_port,
                    project.family,
                });
                udp_thread.detach();
            },
            .both => {
                const tcp_thread = try std.Thread.spawn(.{}, startTcpForward, .{
                    allocator,
                    listen_port,
                    project.target_address,
                    target_port,
                    project.family,
                });
                tcp_thread.detach();

                const udp_thread = try std.Thread.spawn(.{}, startUdpForward, .{
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
    allocator: std.mem.Allocator,
    listen_port: u16,
    target_address: []const u8,
    target_port: u16,
    family: types.AddressFamily,
) void {
    var tcp_forwarder = TcpForwarder.init(allocator, listen_port, target_address, target_port, family);
    tcp_forwarder.start() catch |err| {
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
    var udp_forwarder = UdpForwarder.init(allocator, listen_port, target_address, target_port, family);
    defer udp_forwarder.deinit();
    udp_forwarder.start() catch |err| {
        std.debug.print("[UDP] Forward error: {any}\n", .{err});
    };
}
