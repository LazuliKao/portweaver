const std = @import("std");
const c = @cImport({
    @cInclude(if (@import("builtin").os.tag == .windows) "golibs.h" else "libgolibs.h");
});

pub const FrpsError = error{
    InitFailed,
    CreateServerFailed,
    StartFailed,
    StopFailed,
    DestroyFailed,
    InvalidServerError,
};

var frps_initialized: bool = false;
var frps_init_lock: std.Thread.Mutex = .{};

fn ensureFrpsInit() !void {
    frps_init_lock.lock();
    defer frps_init_lock.unlock();

    if (frps_initialized) return;

    c.FrpsInit();
    frps_initialized = true;
}

pub const FrpsServer = struct {
    id: c_int,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, config_json: []const u8, server_name: ?[]const u8) !FrpsServer {
        try ensureFrpsInit();
        const c_config = try allocator.dupeZ(u8, config_json);
        defer allocator.free(c_config);

        var server_name_buf: ?[:0]u8 = null;
        if (server_name) |sn| {
            server_name_buf = try allocator.dupeZ(u8, sn);
        }
        defer if (server_name_buf) |snb| allocator.free(snb);

        const server_id = c.FrpsCreateServer(
            c_config.ptr,
            if (server_name_buf) |snb| snb.ptr else null,
        );
        if (server_id < 0) {
            return FrpsError.CreateServerFailed;
        }

        return FrpsServer{
            .id = server_id,
            .allocator = allocator,
        };
    }

    pub fn start(self: *FrpsServer) !void {
        const result = c.FrpsStartServer(self.id);
        if (result < 0) {
            return FrpsError.StartFailed;
        }
    }

    pub fn stop(self: *FrpsServer) !void {
        const result = c.FrpsStopServer(self.id);
        if (result < 0) {
            return FrpsError.StopFailed;
        }
    }

    pub fn deinit(self: *FrpsServer) void {
        _ = c.FrpsDestroyServer(self.id);
    }

    pub fn getStatus(self: *FrpsServer, allocator: std.mem.Allocator) ![]const u8 {
        const c_status = c.FrpsGetStatus(self.id);
        defer c.FrpsFreeString(c_status);

        const len = std.mem.len(c_status);
        return try allocator.dupe(u8, c_status[0..len]);
    }

    pub fn getLogs(self: *FrpsServer, allocator: std.mem.Allocator) ![]const u8 {
        const c_logs = c.FrpsGetLogs(self.id);
        defer c.FrpsFreeString(c_logs);

        const len = std.mem.len(c_logs);
        return try allocator.dupe(u8, c_logs[0..len]);
    }

    pub fn clearLogs(self: *FrpsServer) void {
        c.FrpsClearLogs(self.id);
    }
};

pub fn getVersion(allocator: std.mem.Allocator) ![]const u8 {
    const c_version = c.FrpsGetVersion();
    defer c.FrpsFreeString(c_version);

    const len = std.mem.len(c_version);
    return try allocator.dupe(u8, c_version[0..len]);
}

pub const ServerStats = struct {
    status: []const u8,
    last_error: []const u8,
    client_count: usize,
    proxy_count: usize,
    server_count: usize,
};

pub fn getServerStats(allocator: std.mem.Allocator) !ServerStats {
    const c_stats = c.FrpsGetServerStats();
    defer c.FrpsFreeString(c_stats);

    const len = std.mem.len(c_stats);
    const json_str = c_stats[0..len];

    return parseServerStatsJson(allocator, json_str);
}

fn parseServerStatsJson(allocator: std.mem.Allocator, json: []const u8) !ServerStats {
    var status: []const u8 = "unknown";
    var last_error: []const u8 = "";
    var client_count: usize = 0;
    var proxy_count: usize = 0;
    var server_count: usize = 0;

    if (std.mem.indexOf(u8, json, "\"status\":\"")) |start| {
        const value_start = start + 10;
        if (std.mem.indexOfPos(u8, json, value_start, "\"")) |end| {
            status = json[value_start..end];
        }
    }

    if (std.mem.indexOf(u8, json, "\"last_error\":\"")) |start| {
        const value_start = start + 14;
        if (std.mem.indexOfPos(u8, json, value_start, "\"")) |end| {
            last_error = json[value_start..end];
        }
    }

    if (std.mem.indexOf(u8, json, "\"client_count\":")) |start| {
        const value_start = start + 15;
        if (std.mem.indexOfPos(u8, json, value_start, ",")) |end| {
            const num_str = json[value_start..end];
            client_count = std.fmt.parseInt(usize, num_str, 10) catch 0;
        } else if (std.mem.indexOfPos(u8, json, value_start, "}")) |end| {
            const num_str = json[value_start..end];
            client_count = std.fmt.parseInt(usize, num_str, 10) catch 0;
        }
    }

    if (std.mem.indexOf(u8, json, "\"proxy_count\":")) |start| {
        const value_start = start + 14;
        if (std.mem.indexOfPos(u8, json, value_start, ",")) |end| {
            const num_str = json[value_start..end];
            proxy_count = std.fmt.parseInt(usize, num_str, 10) catch 0;
        } else if (std.mem.indexOfPos(u8, json, value_start, "}")) |end| {
            const num_str = json[value_start..end];
            proxy_count = std.fmt.parseInt(usize, num_str, 10) catch 0;
        }
    }

    if (std.mem.indexOf(u8, json, "\"server_count\":")) |start| {
        const value_start = start + 15;
        if (std.mem.indexOfPos(u8, json, value_start, ",")) |end| {
            const num_str = json[value_start..end];
            server_count = std.fmt.parseInt(usize, num_str, 10) catch 0;
        } else if (std.mem.indexOfPos(u8, json, value_start, "}")) |end| {
            const num_str = json[value_start..end];
            server_count = std.fmt.parseInt(usize, num_str, 10) catch 0;
        }
    }

    return ServerStats{
        .status = try allocator.dupe(u8, status),
        .last_error = try allocator.dupe(u8, last_error),
        .client_count = client_count,
        .proxy_count = proxy_count,
        .server_count = server_count,
    };
}

pub fn cleanup() void {
    c.FrpsCleanup();
}
