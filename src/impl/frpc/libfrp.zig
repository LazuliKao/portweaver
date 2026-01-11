const std = @import("std");

// C 函数声明
extern "c" fn FrpInit() c_int;
extern "c" fn FrpCreateClient(serverAddr: [*:0]const u8, serverPort: c_int, token: ?[*:0]const u8) c_int;
extern "c" fn FrpAddTcpProxy(clientID: c_int, proxyName: [*:0]const u8, localIP: [*:0]const u8, localPort: c_int, remotePort: c_int) c_int;
extern "c" fn FrpAddUdpProxy(clientID: c_int, proxyName: [*:0]const u8, localIP: [*:0]const u8, localPort: c_int, remotePort: c_int) c_int;
extern "c" fn FrpStartClient(clientID: c_int) c_int;
extern "c" fn FrpStopClient(clientID: c_int) c_int;
extern "c" fn FrpDestroyClient(clientID: c_int) c_int;
extern "c" fn FrpGetVersion() [*:0]u8;
extern "c" fn FrpFreeString(str: [*:0]u8) void;
extern "c" fn FrpCleanup() void;

pub const FrpError = error{
    InitFailed,
    CreateClientFailed,
    AddProxyFailed,
    StartFailed,
    StopFailed,
    DestroyFailed,
    InvalidClientID,
};

pub const ProxyType = enum {
    tcp,
    udp,
};

pub const FrpClient = struct {
    id: c_int,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, server_addr: []const u8, server_port: u16, token: ?[]const u8) !FrpClient {
        // 初始化 FRP 库（只需要调用一次）
        _ = FrpInit();

        // 将 Zig 字符串转换为 C 字符串
        const c_addr = try allocator.dupeZ(u8, server_addr);
        defer allocator.free(c_addr);

        var c_token: ?[*:0]const u8 = null;
        var token_buf: ?[:0]u8 = null;
        if (token) |t| {
            token_buf = try allocator.dupeZ(u8, t);
            c_token = token_buf.?;
        }
        defer if (token_buf) |tb| allocator.free(tb);

        const client_id = FrpCreateClient(c_addr.ptr, @intCast(server_port), c_token);
        if (client_id < 0) {
            return FrpError.CreateClientFailed;
        }

        return FrpClient{
            .id = client_id,
            .allocator = allocator,
        };
    }

    pub fn addTcpProxy(self: *FrpClient, proxy_name: []const u8, local_ip: []const u8, local_port: u16, remote_port: u16) !void {
        const c_name = try self.allocator.dupeZ(u8, proxy_name);
        defer self.allocator.free(c_name);

        const c_ip = try self.allocator.dupeZ(u8, local_ip);
        defer self.allocator.free(c_ip);

        const result = FrpAddTcpProxy(self.id, c_name.ptr, c_ip.ptr, @intCast(local_port), @intCast(remote_port));
        if (result < 0) {
            return FrpError.AddProxyFailed;
        }
    }

    pub fn addUdpProxy(self: *FrpClient, proxy_name: []const u8, local_ip: []const u8, local_port: u16, remote_port: u16) !void {
        const c_name = try self.allocator.dupeZ(u8, proxy_name);
        defer self.allocator.free(c_name);

        const c_ip = try self.allocator.dupeZ(u8, local_ip);
        defer self.allocator.free(c_ip);

        const result = FrpAddUdpProxy(self.id, c_name.ptr, c_ip.ptr, @intCast(local_port), @intCast(remote_port));
        if (result < 0) {
            return FrpError.AddProxyFailed;
        }
    }

    pub fn start(self: *FrpClient) !void {
        const result = FrpStartClient(self.id);
        if (result < 0) {
            return FrpError.StartFailed;
        }
    }

    pub fn stop(self: *FrpClient) !void {
        const result = FrpStopClient(self.id);
        if (result < 0) {
            return FrpError.StopFailed;
        }
    }

    pub fn deinit(self: *FrpClient) void {
        _ = FrpDestroyClient(self.id);
    }
};

pub fn getVersion(allocator: std.mem.Allocator) ![]const u8 {
    const c_version = FrpGetVersion();
    defer FrpFreeString(c_version);

    const len = std.mem.len(c_version);
    return try allocator.dupe(u8, c_version[0..len]);
}

pub fn cleanup() void {
    FrpCleanup();
}

// 测试用例
test "frp client basic usage" {
    const allocator = std.testing.allocator;

    // 获取版本
    const version = try getVersion(allocator);
    defer allocator.free(version);
    std.debug.print("FRP Version: {s}\n", .{version});

    // 创建客户端
    var client = try FrpClient.init(allocator, "127.0.0.1", 7000, null);
    defer client.deinit();

    // 添加代理
    try client.addTcpProxy("ssh", "127.0.0.1", 22, 6000);
    try client.addUdpProxy("dns", "127.0.0.1", 53, 6053);

    // 注意：这里不真正启动客户端，因为需要真实的 FRP 服务器
    // try client.start();
    // std.time.sleep(2 * std.time.ns_per_s);
    // try client.stop();
}
