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

pub fn cleanup() void {
    c.FrpsCleanup();
}
