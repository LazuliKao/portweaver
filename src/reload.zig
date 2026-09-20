const std = @import("std");
const build_options = @import("build_options");
const config = @import("config/mod.zig");
const RuntimeController = @import("runtime_controller.zig").RuntimeController;
const process_lock = @import("process_lock.zig");

/// UCI or JSON config source. The reload manager owns source metadata only;
/// RuntimeController owns the live configuration and project lifecycle.
pub const ConfigSource = enum {
    uci,
    json,
};

var allocator: ?std.mem.Allocator = null;
var controller: ?*RuntimeController = null;
var config_source: ConfigSource = .uci;
var config_path: ?[]const u8 = null;

extern "c" fn file_watcher_start(path: [*:0]const u8, callback: *const fn (?*anyopaque) callconv(.c) void, user_data: ?*anyopaque) ?*anyopaque;
extern "c" fn file_watcher_stop(handle: ?*anyopaque) void;

var watcher_handle: ?*anyopaque = null;

fn onFileChanged(user_data: ?*anyopaque) callconv(.c) void {
    _ = user_data;
    std.log.info("Config file changed, triggering reload...", .{});
    process_lock.requestReload();
}

fn startWatcher() void {
    if (config_source != .json) return;
    const runtime = controller orelse return;
    if (!runtime.watchEnabled()) return;
    const path = config_path orelse return;
    const alloc = allocator orelse return;

    const c_path = alloc.dupeZ(u8, path) catch |err| {
        std.log.warn("Failed to allocate watcher path: {any}", .{err});
        return;
    };
    defer alloc.free(c_path);

    watcher_handle = file_watcher_start(c_path.ptr, onFileChanged, null);
    if (watcher_handle != null) {
        std.log.info("Config file watcher started for: {s} (event-driven)", .{path});
    } else {
        std.log.warn("Failed to start config file watcher for: {s}", .{path});
    }
}

fn stopWatcher() void {
    if (watcher_handle) |handle| {
        file_watcher_stop(handle);
        watcher_handle = null;
    }
}

/// Initializes source metadata. The controller must outlive this module.
pub fn init(
    alloc: std.mem.Allocator,
    runtime: *RuntimeController,
    source: ConfigSource,
    path: ?[]const u8,
) void {
    allocator = alloc;
    controller = runtime;
    config_source = source;
    config_path = path;
    startWatcher();
}

pub fn deinit() void {
    stopWatcher();
    controller = null;
    allocator = null;
    config_path = null;
}

/// Loads and validates a candidate config outside the control-plane lock, then
/// transfers it to RuntimeController for the serialized lifecycle transition.
pub fn apply() void {
    const alloc = allocator orelse {
        std.log.err("Reload: module not initialized", .{});
        return;
    };
    const runtime = controller orelse {
        std.log.err("Reload: runtime controller not initialized", .{});
        return;
    };

    std.log.info("Reload: reading configuration...", .{});
    var new_cfg = loadConfigFromSource(alloc) catch |err| {
        std.log.err("Reload: failed to load new config: {any}", .{err});
        return;
    };

    const watched_before = runtime.watchEnabled();
    runtime.applyConfig(&new_cfg);
    const watched_after = runtime.watchEnabled();
    if (watched_before != watched_after) {
        stopWatcher();
        startWatcher();
    }
}

fn loadConfigFromSource(alloc: std.mem.Allocator) !config.Config {
    if (build_options.uci_mode and config_source == .uci) {
        const uci = @import("uci/mod.zig");
        var uci_ctx = try uci.UciContext.alloc();
        defer uci_ctx.free();
        return config.loadFromUci(alloc, uci_ctx, "portweaver");
    }
    if (config_source == .json) {
        return config.loadFromJsonFile(alloc, config_path orelse "config.json");
    }
    return config.ConfigError.UnsupportedFeature;
}

test "ConfigSource enum values" {
    try std.testing.expectEqual(ConfigSource.uci, ConfigSource.uci);
    try std.testing.expectEqual(ConfigSource.json, ConfigSource.json);
    try std.testing.expect(ConfigSource.uci != ConfigSource.json);
}

test "file watcher callback requests reload" {
    onFileChanged(null);
}
