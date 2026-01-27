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

// C declarations for new FRP functions
extern "c" fn FrpGetStatus(clientID: c_int) [*c]u8;
extern "c" fn FrpGetLogs(clientID: c_int) [*c]u8;
extern "c" fn FrpClearLogs(clientID: c_int) void;

pub const ProxyType = enum {
    tcp,
    udp,
};

var frp_initialized: bool = false;
var frp_init_lock: std.Thread.Mutex = .{};

fn ensureFrpInit() !void {
    frp_init_lock.lock();
    defer frp_init_lock.unlock();

    if (frp_initialized) return;

    std.debug.print("==== [FRP] Calling FrpInit()...\n", .{});
    _ = c.FrpInit();
    std.debug.print("==== [FRP] FrpInit() completed.\n", .{});
    frp_initialized = true;
}

pub const FrpClient = struct {
    id: c_int,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, server_addr: []const u8, server_port: u16, token: ?[]const u8) !FrpClient {
        std.debug.print("==== Initializing FRP client with server_addr={s}, server_port={d}\n", .{ server_addr, server_port });
        const frp_Version = c.FrpGetVersion();
        std.debug.print("==== FRP library version: {s}\n", .{frp_Version});

        // 延迟初始化 FRP 库，避免在应用启动早期导致 Go 运行时初始化失败
        try ensureFrpInit();
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

    pub fn getStatus(self: *FrpClient, allocator: std.mem.Allocator) ![]const u8 {
        const c_status = c.FrpGetStatus(self.id);
        defer c.FrpFreeString(c_status);

        const len = std.mem.len(c_status);
        return try allocator.dupe(u8, c_status[0..len]);
    }

    pub fn getLogs(self: *FrpClient, allocator: std.mem.Allocator) ![]const u8 {
        const c_logs = c.FrpGetLogs(self.id);
        defer c.FrpFreeString(c_logs);

        const len = std.mem.len(c_logs);
        return try allocator.dupe(u8, c_logs[0..len]);
    }

    pub fn clearLogs(self: *FrpClient) void {
        c.FrpClearLogs(self.id);
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
