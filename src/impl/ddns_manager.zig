const std = @import("std");
const types = @import("../config/types.zig");
const libddns = @import("ddns/libddns.zig");
const main = @import("../main.zig");
const event_log = main.event_log;

pub const DdnsStatus = struct {
    name: []const u8,
    provider: []const u8,
    status: []const u8, // "ok", "error", "disabled", "starting"
    last_update: i64, // Unix timestamp
    last_ip: []const u8,
    message: []const u8,

    pub fn deinit(self: *DdnsStatus, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.provider);
        allocator.free(self.status);
        allocator.free(self.last_ip);
        allocator.free(self.message);
        self.* = undefined;
    }
};

pub const DdnsInfo = struct {
    status: []const u8,
    last_error: []const u8,
    logs: std.array_list.Managed([]const u8),

    pub fn deinit(self: *DdnsInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.status);
        allocator.free(self.last_error);
        for (self.logs.items) |log| {
            allocator.free(log);
        }
        self.logs.deinit();
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

    // Use TTL as update interval (convert to seconds, default 300 if TTL is too small)
    const interval_seconds: u32 = if (holder.config.ttl >= 60) holder.config.ttl else 300;

    holder.lock.lock();
    holder.last_status = "success";
    holder.lock.unlock();

    holder.instance.startAutoUpdate(interval_seconds) catch |err| {
        std.log.warn("[DDNS] Auto-update failed for {s}: {any}", .{ holder.config.name, err });
        holder.lock.lock();
        holder.last_status = "error";
        holder.last_message = "Failed to start auto-update";
        holder.lock.unlock();
        return;
    };

    // Wait until stop signal
    while (!holder.should_stop.load(.seq_cst)) {
        std.Thread.sleep(1 * std.time.ns_per_s); // Check every second
    }

    // Stop auto-update when thread is stopping
    holder.instance.stopAutoUpdate() catch |err| {
        std.log.warn("[DDNS] Failed to stop auto-update for {s}: {any}", .{ holder.config.name, err });
    };

    std.log.debug("[DDNS] Update thread stopped for {s}", .{holder.config.name});
}

fn getInstanceMap(allocator: std.mem.Allocator) !*std.StringHashMap(*InstanceHolder) {
    if (instances == null) {
        instances = std.StringHashMap(*InstanceHolder).init(allocator);
        instances_allocator = allocator;
    }
    return &instances.?;
}

fn parseDomains(allocator: std.mem.Allocator, domains_str: []const u8) ![][]const u8 {
    if (domains_str.len == 0) return &[_][]const u8{};

    var list = std.array_list.Managed([]const u8).init(allocator);
    errdefer {
        for (list.items) |item| allocator.free(item);
        list.deinit();
    }

    var iter = std.mem.splitScalar(u8, domains_str, ',');
    while (iter.next()) |domain| {
        const trimmed = std.mem.trim(u8, domain, " \t\r\n");
        if (trimmed.len > 0) {
            try list.append(try allocator.dupe(u8, trimmed));
        }
    }

    return try list.toOwnedSlice();
}

fn createInstance(
    allocator: std.mem.Allocator,
    config: types.DdnsConfig,
) !*InstanceHolder {
    const holder = try allocator.create(InstanceHolder);
    errdefer allocator.destroy(holder);

    // Convert DdnsConfig to libddns types
    const provider = try libddns.DnsProvider.fromString(config.dns_provider);

    // Create instance with provider only
    var instance = try libddns.DdnsInstance.init(allocator, provider);
    errdefer instance.deinit();

    // Set credentials
    try instance.setCredentials(
        if (config.dns_id.len > 0) config.dns_id else null,
        if (config.dns_secret.len > 0) config.dns_secret else null,
    );

    // Set extended parameters
    try instance.setExtParam(
        if (config.dns_ext_param.len > 0) config.dns_ext_param else null,
    );

    // Configure IPv4 if enabled
    if (config.ipv4.enable) {
        // Set IPv4 get type
        const ipv4_get_type = config.ipv4.get_type.toString();
        try instance.setIPv4GetType(ipv4_get_type);

        // Set IPv4 address/url/interface/cmd based on get_type
        switch (config.ipv4.get_type) {
            .url => {
                if (config.ipv4.url.len > 0) {
                    try instance.setIPv4Address(config.ipv4.url);
                }
            },
            .net_interface => {
                if (config.ipv4.net_interface.len > 0) {
                    try instance.setIPv4Address(config.ipv4.net_interface);
                }
            },
            .cmd => {
                if (config.ipv4.cmd.len > 0) {
                    try instance.setIPv4Address(config.ipv4.cmd);
                }
            },
        }

        // Parse and add IPv4 domains
        if (config.ipv4.domains.len > 0) {
            const domains = try parseDomains(allocator, config.ipv4.domains);
            defer {
                for (domains) |d| allocator.free(d);
                allocator.free(domains);
            }

            for (domains) |domain_str| {
                // Split domain and subdomain by '@' or use whole string as domain
                var domain_parts = std.mem.splitScalar(u8, domain_str, '@');
                const subdomain = domain_parts.next() orelse "";
                const domain = domain_parts.next() orelse domain_str;

                try instance.addDomain(.{
                    .domain_name = domain,
                    .sub_domain = if (subdomain.len > 0 and !std.mem.eql(u8, subdomain, domain_str)) subdomain else null,
                    .ipv4_enabled = true,
                    .ipv6_enabled = false,
                });
            }
        }
    }

    // Configure IPv6 if enabled
    if (config.ipv6.enable) {
        // Set IPv6 get type
        const ipv6_get_type = config.ipv6.get_type.toString();
        try instance.setIPv6GetType(ipv6_get_type);

        // Set IPv6 address/url/interface/cmd based on get_type
        switch (config.ipv6.get_type) {
            .url => {
                if (config.ipv6.url.len > 0) {
                    try instance.setIPv6Address(config.ipv6.url);
                }
            },
            .net_interface => {
                if (config.ipv6.net_interface.len > 0) {
                    try instance.setIPv6Address(config.ipv6.net_interface);
                }
            },
            .cmd => {
                if (config.ipv6.cmd.len > 0) {
                    try instance.setIPv6Address(config.ipv6.cmd);
                }
            },
        }

        // Parse and add IPv6 domains
        if (config.ipv6.domains.len > 0) {
            const domains = try parseDomains(allocator, config.ipv6.domains);
            defer {
                for (domains) |d| allocator.free(d);
                allocator.free(domains);
            }

            for (domains) |domain_str| {
                // Split domain and subdomain by '@' or use whole string as domain
                var domain_parts = std.mem.splitScalar(u8, domain_str, '@');
                const subdomain = domain_parts.next() orelse "";
                const domain = domain_parts.next() orelse domain_str;

                try instance.addDomain(.{
                    .domain_name = domain,
                    .sub_domain = if (subdomain.len > 0 and !std.mem.eql(u8, subdomain, domain_str)) subdomain else null,
                    .ipv4_enabled = false,
                    .ipv6_enabled = true,
                });
            }
        }
    }

    holder.* = .{
        .instance = instance,
        .config = config,
    };

    return holder;
}

pub fn applyConfig(allocator: std.mem.Allocator, configs: []types.DdnsConfig) !void {
    instances_lock.lock();
    defer instances_lock.unlock();

    var map = try getInstanceMap(allocator);

    // Build a set of ALL new config names (regardless of enabled status)
    var new_names = std.StringHashMap(void).init(allocator);
    defer new_names.deinit();
    for (configs) |cfg| {
        try new_names.put(cfg.name, {});
    }

    // Remove instances not in new config or disabled in new config
    var to_remove = std.array_list.Managed([]const u8).init(allocator);
    defer to_remove.deinit();

    var it = map.iterator();
    while (it.next()) |entry| {
        const instance_name = entry.key_ptr.*;

        // Check if the config is not in new config set OR if it's now disabled
        var should_remove = true;
        for (configs) |cfg| {
            if (std.mem.eql(u8, cfg.name, instance_name)) {
                // Found matching config - remove only if it's disabled
                should_remove = !cfg.enabled;
                break;
            }
        }

        if (should_remove) {
            try to_remove.append(instance_name);
        }
    }

    for (to_remove.items) |name| {
        if (map.fetchRemove(name)) |kv| {
            std.log.info("[DDNS] Removing instance: {s} (config disabled or removed)", .{name});
            kv.value.deinit(allocator);
            allocator.destroy(kv.value);
            allocator.free(kv.key);
        }
    }

    // Add or update instances (only for enabled configs)
    for (configs) |cfg| {
        if (!cfg.enabled) {
            std.log.debug("[DDNS] Skipping disabled config: {s}", .{cfg.name});
            continue;
        }

        if (map.get(cfg.name)) |_| {
            // Check if config changed and restart if needed
            std.log.debug("[DDNS] Instance {s} already exists", .{cfg.name});
            // TODO: Check if config changed and restart if needed
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

pub fn getInstanceStatus(allocator: std.mem.Allocator, name: []const u8) !DdnsInfo {
    instances_lock.lock();
    defer instances_lock.unlock();

    if (instances == null) {
        return error.NoInstances;
    }

    const holder = instances.?.get(name) orelse return error.InstanceNotFound;

    const response = try holder.instance.getStatusAndLogs();
    defer {
        allocator.free(response.status);
        allocator.free(response.last_error);
        for (response.logs) |log| {
            allocator.free(log);
        }
        allocator.free(response.logs);
    }

    var logs_list = std.array_list.Managed([]const u8).init(allocator);
    errdefer logs_list.deinit();

    for (response.logs) |log| {
        try logs_list.append(try allocator.dupe(u8, log));
    }

    return .{
        .status = try allocator.dupe(u8, response.status),
        .last_error = try allocator.dupe(u8, response.last_error),
        .logs = logs_list,
    };
}

pub fn clearInstanceLogs(name: []const u8) !void {
    instances_lock.lock();
    defer instances_lock.unlock();

    if (instances == null) {
        return error.NoInstances;
    }

    const holder = instances.?.get(name) orelse return error.InstanceNotFound;
    holder.instance.clearLogs();
}

pub fn deinit(allocator: std.mem.Allocator) void {
    instances_lock.lock();
    defer instances_lock.unlock();

    if (instances) |*map| {
        var it = map.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit(allocator);
            allocator.destroy(entry.value_ptr.*);
            allocator.free(entry.key_ptr.*);
        }
        map.deinit();
        instances = null;
    }
}

const build_options = @import("build_options");

test "ddns_manager: skip disabled configs" {
    if (!build_options.ddns_mode) return;

    const allocator = std.testing.allocator;

    // Create a disabled DDNS config
    var disabled_config = types.DdnsConfig{
        .name = try allocator.dupe(u8, "test-disabled"),
        .enabled = false,
        .dns_provider = try allocator.dupe(u8, "cloudflare"),
        .dns_id = try allocator.dupe(u8, "test-id"),
        .dns_secret = try allocator.dupe(u8, "test-secret"),
        .ipv4 = .{
            .enable = true,
            .get_type = .url,
            .domains = try allocator.dupe(u8, "test.example.com"),
        },
        .ipv6 = .{
            .enable = false,
            .get_type = .url,
            .domains = "",
        },
    };
    defer disabled_config.deinit(allocator);

    // Create an enabled DDNS config
    var enabled_config = types.DdnsConfig{
        .name = try allocator.dupe(u8, "test-enabled"),
        .enabled = true,
        .dns_provider = try allocator.dupe(u8, "cloudflare"),
        .dns_id = try allocator.dupe(u8, "test-id"),
        .dns_secret = try allocator.dupe(u8, "test-secret"),
        .ipv4 = .{
            .enable = true,
            .get_type = .url,
            .domains = try allocator.dupe(u8, "test2.example.com"),
        },
        .ipv6 = .{
            .enable = false,
            .get_type = .url,
            .domains = "",
        },
    };
    defer enabled_config.deinit(allocator);

    var configs = std.ArrayList(types.DdnsConfig).init(allocator);
    defer configs.deinit();
    try configs.append(disabled_config);
    try configs.append(enabled_config);

    // Apply configs - disabled config should be skipped
    try applyConfig(allocator, configs.items);
    defer deinit(allocator);

    // Check that only the enabled config has an instance
    const instances_map = try getInstanceMap(allocator);
    try std.testing.expectEqual(@as(usize, 1), instances_map.count());
    try std.testing.expect(instances_map.get("test-enabled") != null);
    try std.testing.expect(instances_map.get("test-disabled") == null);
}
