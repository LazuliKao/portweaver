const std = @import("std");
const c = @cImport({
    @cInclude("libgolibs.h");
});

pub const FrpcError = error{
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

var frpc_initialized: bool = false;
var frpc_init_lock: std.Thread.Mutex = .{};

fn ensureFrpcInit() !void {
    frpc_init_lock.lock();
    defer frpc_init_lock.unlock();

    if (frpc_initialized) return;

    _ = c.FrpcInit();
    frpc_initialized = true;
}

pub const FrpcClient = struct {
    id: c_int,
    allocator: std.mem.Allocator,
    use_encryption: bool,
    use_compression: bool,

    pub fn init(allocator: std.mem.Allocator, server_addr: []const u8, server_port: u16, token: ?[]const u8, log_level: ?[]const u8, client_name: ?[]const u8, use_encryption: bool, use_compression: bool) !FrpcClient {
        try ensureFrpcInit();
        const c_addr = try allocator.dupeZ(u8, server_addr);
        defer allocator.free(c_addr);

        var token_buf: ?[:0]u8 = null;
        if (token) |t| {
            token_buf = try allocator.dupeZ(u8, t);
        }
        defer if (token_buf) |tb| allocator.free(tb);

        var log_level_buf: ?[:0]u8 = null;
        if (log_level) |ll| {
            log_level_buf = try allocator.dupeZ(u8, ll);
        }
        defer if (log_level_buf) |llb| allocator.free(llb);

        var client_name_buf: ?[:0]u8 = null;
        if (client_name) |cn| {
            client_name_buf = try allocator.dupeZ(u8, cn);
        }
        defer if (client_name_buf) |cnb| allocator.free(cnb);

        const client_id = c.FrpcCreateClient(
            c_addr.ptr,
            @intCast(server_port),
            if (token_buf) |tb| tb.ptr else null,
            if (log_level_buf) |llb| llb.ptr else null,
            if (client_name_buf) |cnb| cnb.ptr else null,
            if (use_encryption) @as(c_int, 1) else @as(c_int, 0),
            if (use_compression) @as(c_int, 1) else @as(c_int, 0),
        );
        if (client_id < 0) {
            return FrpcError.CreateClientFailed;
        }

        return FrpcClient{
            .id = client_id,
            .allocator = allocator,
            .use_encryption = use_encryption,
            .use_compression = use_compression,
        };
    }

    pub fn addTcpProxy(self: *FrpcClient, proxy_name: []const u8, local_ip: []const u8, local_port: u16, remote_port: u16) !void {
        const c_name = try self.allocator.dupeZ(u8, proxy_name);
        defer self.allocator.free(c_name);

        const c_ip = try self.allocator.dupeZ(u8, local_ip);
        defer self.allocator.free(c_ip);

        const result = c.FrpcAddTcpProxy(self.id, c_name.ptr, c_ip.ptr, @intCast(local_port), @intCast(remote_port), if (self.use_encryption) @as(c_int, 1) else @as(c_int, 0), if (self.use_compression) @as(c_int, 1) else @as(c_int, 0));
        if (result < 0) {
            return FrpcError.AddProxyFailed;
        }
    }

    pub fn addUdpProxy(self: *FrpcClient, proxy_name: []const u8, local_ip: []const u8, local_port: u16, remote_port: u16) !void {
        const c_name = try self.allocator.dupeZ(u8, proxy_name);
        defer self.allocator.free(c_name);

        const c_ip = try self.allocator.dupeZ(u8, local_ip);
        defer self.allocator.free(c_ip);

        const result = c.FrpcAddUdpProxy(self.id, c_name.ptr, c_ip.ptr, @intCast(local_port), @intCast(remote_port), if (self.use_encryption) @as(c_int, 1) else @as(c_int, 0), if (self.use_compression) @as(c_int, 1) else @as(c_int, 0));
        if (result < 0) {
            return FrpcError.AddProxyFailed;
        }
    }

    pub fn flush(self: *FrpcClient) !void {
        const result = c.FrpcFlushClient(self.id);
        if (result < 0) return FrpcError.FlushFailed;
    }

    pub fn start(self: *FrpcClient) !void {
        const result = c.FrpcStartClient(self.id);
        if (result < 0) {
            return FrpcError.StartFailed;
        }
    }

    pub fn stop(self: *FrpcClient) !void {
        const result = c.FrpcStopClient(self.id);
        if (result < 0) {
            return FrpcError.StopFailed;
        }
    }

    pub fn deinit(self: *FrpcClient) void {
        _ = c.FrpcDestroyClient(self.id);
    }

    pub fn getStatus(self: *FrpcClient, allocator: std.mem.Allocator) ![]const u8 {
        const c_status = c.FrpcGetStatus(self.id);
        defer c.FrpcFreeString(c_status);

        const len = std.mem.len(c_status);
        return try allocator.dupe(u8, c_status[0..len]);
    }

    pub fn getLogs(self: *FrpcClient, allocator: std.mem.Allocator) ![]const u8 {
        const c_logs = c.FrpcGetLogs(self.id);
        defer c.FrpcFreeString(c_logs);

        const len = std.mem.len(c_logs);
        return try allocator.dupe(u8, c_logs[0..len]);
    }

    pub fn clearLogs(self: *FrpcClient) void {
        c.FrpcClearLogs(self.id);
    }

    pub fn getProxyTrafficStats(self: *FrpcClient, allocator: std.mem.Allocator) ![]const u8 {
        const c_result = c.FrpcGetProxyTrafficStats(self.id);
        if (c_result == null) return error.InvalidResponse;
        defer c.FrpcFreeString(c_result);

        const len = std.mem.len(c_result);
        return try allocator.dupe(u8, c_result[0..len]);
    }
};

pub fn getVersion(allocator: std.mem.Allocator) ![]const u8 {
    const c_version = c.FrpcGetVersion();
    defer c.FrpcFreeString(c_version);

    const len = std.mem.len(c_version);
    return try allocator.dupe(u8, c_version[0..len]);
}

pub fn cleanup() void {
    c.FrpcCleanup();
}
