const std = @import("std");
const compat = @import("../compat.zig");
const c = @cImport({
    @cInclude("rathole.h");
});

pub const RatholeError = error{
    InitFailed,
    CreateInstanceFailed,
    StartFailed,
    StopFailed,
    DestroyFailed,
    InvalidInstance,
    InvalidResponse,
};

var initialized = false;
var init_lock: std.Io.Mutex = .init;

fn ensureInit() !void {
    init_lock.lockUncancelable(compat.io());
    defer init_lock.unlock(compat.io());
    if (initialized) return;
    if (c.RatholeInit() != 0) return RatholeError.InitFailed;
    initialized = true;
}

pub const Instance = struct {
    id: c_int,
    allocator: std.mem.Allocator,

    pub fn initClient(allocator: std.mem.Allocator, toml: []const u8, name: []const u8) !Instance {
        try ensureInit();
        const c_toml = try allocator.dupeZ(u8, toml);
        defer allocator.free(c_toml);
        const c_name = try allocator.dupeZ(u8, name);
        defer allocator.free(c_name);
        const id = c.RatholeCreateClientFromToml(c_toml.ptr, c_name.ptr);
        if (id < 0) return RatholeError.CreateInstanceFailed;
        return .{ .id = id, .allocator = allocator };
    }

    pub fn initServer(allocator: std.mem.Allocator, toml: []const u8, name: []const u8) !Instance {
        try ensureInit();
        const c_toml = try allocator.dupeZ(u8, toml);
        defer allocator.free(c_toml);
        const c_name = try allocator.dupeZ(u8, name);
        defer allocator.free(c_name);
        const id = c.RatholeCreateServerFromToml(c_toml.ptr, c_name.ptr);
        if (id < 0) return RatholeError.CreateInstanceFailed;
        return .{ .id = id, .allocator = allocator };
    }

    pub fn start(self: *Instance) !void {
        if (c.RatholeStart(self.id) != 0) return RatholeError.StartFailed;
    }

    pub fn stop(self: *Instance) !void {
        if (c.RatholeStop(self.id) != 0) return RatholeError.StopFailed;
    }

    pub fn deinit(self: *Instance) void {
        _ = c.RatholeDestroy(self.id);
    }

    pub fn getStatus(self: *Instance, allocator: std.mem.Allocator) ![]const u8 {
        const response = c.RatholeGetStatus(self.id) orelse return RatholeError.InvalidResponse;
        defer c.RatholeFreeString(response);
        return try allocator.dupe(u8, std.mem.span(response));
    }

    pub fn getLogs(self: *Instance, allocator: std.mem.Allocator) ![]const u8 {
        const response = c.RatholeGetLogs(self.id) orelse return RatholeError.InvalidResponse;
        defer c.RatholeFreeString(response);
        return try allocator.dupe(u8, std.mem.span(response));
    }

    pub fn clearLogs(self: *Instance) void {
        c.RatholeClearLogs(self.id);
    }
};

pub fn getVersion(allocator: std.mem.Allocator) ![]const u8 {
    try ensureInit();
    const response = c.RatholeGetVersion() orelse return RatholeError.InvalidResponse;
    defer c.RatholeFreeString(response);
    return try allocator.dupe(u8, std.mem.span(response));
}

pub fn cleanup() void {
    c.RatholeCleanup();
    init_lock.lockUncancelable(compat.io());
    defer init_lock.unlock(compat.io());
    initialized = false;
}
