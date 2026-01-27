const std = @import("std");
const types = @import("../config/types.zig");
const libddns = @import("ddns/libddns.zig");
const main = @import("../main.zig");
const event_log = main.event_log;

pub const DdnsStatus = struct {
    section: []const u8,
    name: []const u8,
    provider: []const u8,
    status: []const u8, // "ok", "error", "disabled", "starting"
    last_update: i64, // Unix timestamp
    last_ip: []const u8,
    message: []const u8,

    pub fn deinit(self: *DdnsStatus, allocator: std.mem.Allocator) void {
        allocator.free(self.section);
        allocator.free(self.name);
        allocator.free(self.provider);
        allocator.free(self.status);
        allocator.free(self.last_ip);
        allocator.free(self.message);
        self.* = undefined;
    }
};

const InstanceHolder = struct {
    instance: libddns.DdnsInstance,
    config: types.DdnsConfig,
    thread: ?std.Thread = null,
    should_stop: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    lock: std.Thread.Mutex = .{},
    last_status: []const u8 = "starting",
    last_update: i64 = 0,
    last_ip: []const u8 = "",
    last_message: []const u8 = "",

    pub fn deinit(self: *InstanceHolder, allocator: std.mem.Allocator) void {
        self.should_stop.store(true, .seq_cst);
        if (self.thread) |t| {
            t.join();
        }
        self.instance.deinit();
        self.config.deinit(allocator);
        if (self.last_ip.len > 0) allocator.free(self.last_ip);
        if (self.last_message.len > 0) allocator.free(self.last_message);
        self.* = undefined;
    }
};

var instances: ?std.StringHashMap(*InstanceHolder) = null;
var instances_allocator: ?std.mem.Allocator = null;
var instances_lock: std.Thread.Mutex = .{};

fn ddnsUpdateThread(holder: *InstanceHolder) void {
    std.log.debug("[DDNS] Update thread started for {s}", .{holder.config.name});

    while (!holder.should_stop.load(.seq_cst)) {
        holder.lock.lock();
        holder.last_status = "running";
        holder.lock.unlock();

        holder.instance.startAutoUpdate() catch |err| {
            std.log.warn("[DDNS] Auto-update failed for {s}: {any}", .{ holder.config.name, err });
            holder.lock.lock();
            holder.last_status = "error";
            holder.last_message = "Update failed";
            holder.lock.unlock();
        };

        // Sleep for a while before next update check
        std.time.sleep(60 * std.time.ns_per_s); // 60 seconds
    }

    std.log.debug("[DDNS] Update thread stopped for {s}", .{holder.config.name});
}

fn getInstanceMap(allocator: std.mem.Allocator) !*std.StringHashMap(*InstanceHolder) {
    if (instances == null) {
        instances = std.StringHashMap(*InstanceHolder).init(allocator);
        instances_allocator = allocator;
    }
    return &instances.?;
}

fn createInstance(
    allocator: std.mem.Allocator,
    config: types.DdnsConfig,
) !*InstanceHolder {
    const holder = try allocator.create(InstanceHolder);
    errdefer allocator.destroy(holder);

    // Convert DdnsConfig to libddns types
    const provider = try libddns.DnsProvider.fromString(config.dns_provider);
    const credentials = libddns.DnsCredentials{
        .id = if (config.dns_id.len > 0) config.dns_id else null,
        .secret = if (config.dns_secret.len > 0) config.dns_secret else null,
        .ext_param = if (config.dns_ext_param.len > 0) config.dns_ext_param else null,
    };

    holder.* = .{
        .instance = try libddns.DdnsInstance.init(allocator, provider, credentials),
        .config = config,
    };

    return holder;
}

pub fn applyConfig(allocator: std.mem.Allocator, configs: []types.DdnsConfig) !void {
    instances_lock.lock();
    defer instances_lock.unlock();

    var map = try getInstanceMap(allocator);

    // Build a set of new config names
    var new_names = std.StringHashMap(void).init(allocator);
    defer new_names.deinit();
    for (configs) |cfg| {
        try new_names.put(cfg.name, {});
    }

    // Remove instances not in new config
    var it = map.iterator();
    var to_remove = std.array_list.Managed([]const u8).init(allocator);
    defer to_remove.deinit();

    while (it.next()) |entry| {
        if (!new_names.contains(entry.key_ptr.*)) {
            try to_remove.append(entry.key_ptr.*);
        }
    }

    for (to_remove.items) |name| {
        if (map.fetchRemove(name)) |kv| {
            std.log.info("[DDNS] Removing instance: {s}", .{name});
            kv.value.deinit(allocator);
            allocator.destroy(kv.value);
            allocator.free(kv.key);
        }
    }

    // Add or update instances
    for (configs) |cfg| {
        if (map.get(cfg.name)) |_| {
            // TODO: Check if config changed and restart if needed
            std.log.debug("[DDNS] Instance {s} already exists", .{cfg.name});
        } else {
            std.log.info("[DDNS] Creating new instance: {s}", .{cfg.name});
            const holder = try createInstance(allocator, cfg);
            const key = try allocator.dupe(u8, cfg.name);
            try map.put(key, holder);

            // Start update thread
            holder.thread = try std.Thread.spawn(.{}, ddnsUpdateThread, .{holder});
        }
    }
}

pub fn getStatuses(allocator: std.mem.Allocator) ![]DdnsStatus {
    instances_lock.lock();
    defer instances_lock.unlock();

    if (instances == null) {
        return &[_]DdnsStatus{};
    }

    var list = std.array_list.Managed(DdnsStatus).init(allocator);
    errdefer {
        for (list.items) |*s| s.deinit(allocator);
        list.deinit();
    }

    var it = instances.?.iterator();
    while (it.next()) |entry| {
        const holder = entry.value_ptr.*;
        holder.lock.lock();
        defer holder.lock.unlock();

        try list.append(.{
            .section = try allocator.dupe(u8, entry.key_ptr.*),
            .name = try allocator.dupe(u8, holder.config.name),
            .provider = try allocator.dupe(u8, holder.config.dns_provider),
            .status = try allocator.dupe(u8, holder.last_status),
            .last_update = holder.last_update,
            .last_ip = try allocator.dupe(u8, holder.last_ip),
            .message = try allocator.dupe(u8, holder.last_message),
        });
    }

    return try list.toOwnedSlice();
}

pub fn deinit(allocator: std.mem.Allocator) void {
    instances_lock.lock();
    defer instances_lock.unlock();

    if (instances) |*map| {
        var it = map.iterator();
        while (it.next()) |entry| {
            entry.value.deinit(allocator);
            allocator.destroy(entry.value);
            allocator.free(entry.key_ptr.*);
        }
        map.deinit();
        instances = null;
    }
}
