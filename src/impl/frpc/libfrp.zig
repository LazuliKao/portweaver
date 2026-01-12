const std = @import("std");
const c = @cImport({
    @cInclude("libfrp.h");
});

pub const FrpError = error{
    InitFailed,
    CreateClientFailed,
    AddProxyFailed,
    FlushFailed,
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
        _ = c.FrpInit();

        // 将 Zig 字符串转换为 C 字符串
        const c_addr = try allocator.dupeZ(u8, server_addr);
        defer allocator.free(c_addr);

        var token_buf: ?[:0]u8 = null;
        if (token) |t| {
            token_buf = try allocator.dupeZ(u8, t);
        }
        defer if (token_buf) |tb| allocator.free(tb);

        const client_id = c.FrpCreateClient(c_addr.ptr, @intCast(server_port), if (token_buf) |tb| tb.ptr else null);
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

        const result = c.FrpAddTcpProxy(self.id, c_name.ptr, c_ip.ptr, @intCast(local_port), @intCast(remote_port));
        if (result < 0) {
            return FrpError.AddProxyFailed;
        }
    }

    pub fn addUdpProxy(self: *FrpClient, proxy_name: []const u8, local_ip: []const u8, local_port: u16, remote_port: u16) !void {
        const c_name = try self.allocator.dupeZ(u8, proxy_name);
        defer self.allocator.free(c_name);

        const c_ip = try self.allocator.dupeZ(u8, local_ip);
        defer self.allocator.free(c_ip);

        const result = c.FrpAddUdpProxy(self.id, c_name.ptr, c_ip.ptr, @intCast(local_port), @intCast(remote_port));
        if (result < 0) {
            return FrpError.AddProxyFailed;
        }
    }

    pub fn flush(self: *FrpClient) !void {
        const result = c.FrpFlushClient(self.id);
        if (result < 0) return FrpError.FlushFailed;
    }

    pub fn start(self: *FrpClient) !void {
        const result = c.FrpStartClient(self.id);
        if (result < 0) {
            return FrpError.StartFailed;
        }
    }

    pub fn stop(self: *FrpClient) !void {
        const result = c.FrpStopClient(self.id);
        if (result < 0) {
            return FrpError.StopFailed;
        }
    }

    pub fn deinit(self: *FrpClient) void {
        _ = c.FrpDestroyClient(self.id);
    }
};

pub fn getVersion(allocator: std.mem.Allocator) ![]const u8 {
    const c_version = c.FrpGetVersion();
    defer c.FrpFreeString(c_version);

    const len = std.mem.len(c_version);
    return try allocator.dupe(u8, c_version[0..len]);
}

pub fn cleanup() void {
    c.FrpCleanup();
}
