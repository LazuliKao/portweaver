const std = @import("std");
const types = @import("../config/types.zig");
const project_status = @import("project_status.zig");
const libfrps = @import("frps/libfrps.zig");
const common = @import("app_forward/common.zig");
const main = @import("../main.zig");
const event_log = main.event_log;
const build_options = @import("build_options");

const ServerHolder = struct {
    server: libfrps.FrpsServer,
    started: bool = false,
    lock: std.Thread.Mutex = .{},
};

var servers: ?std.StringHashMap(*ServerHolder) = null;
var servers_allocator: ?std.mem.Allocator = null;
var servers_lock: std.Thread.Mutex = .{};

fn startFrpsServer(holder: *ServerHolder, node_name: []const u8) void {
    if (holder.started) {
        std.log.debug("[FRPS] Server {s} already started", .{node_name});
        return;
    }

    std.log.info("[FRPS] Initializing server {s}...", .{node_name});
    holder.*.server.start() catch |err| {
        std.log.err("[FRPS] Failed to start server {s}: {any}", .{ node_name, err });
        return;
    };
    holder.started = true;
    std.log.info("[FRPS] Server {s} started successfully", .{node_name});
}

fn getServerMap(allocator: std.mem.Allocator) !*std.StringHashMap(*ServerHolder) {
    if (servers == null) {
        std.log.debug("[FRPS] Initializing server map", .{});
        servers = std.StringHashMap(*ServerHolder).init(allocator);
        servers_allocator = allocator;
    }
    return &servers.?;
}

fn getOrCreateServer(
    allocator: std.mem.Allocator,
    node_name: []const u8,
    node: types.FrpsNode,
) !*ServerHolder {
    servers_lock.lock();
    var map = try getServerMap(allocator);
    if (map.get(node_name)) |holder_ptr| {
        servers_lock.unlock();
        std.log.debug("[FRPS] Server {s} already exists in map", .{node_name});
        return holder_ptr;
    }
    servers_lock.unlock();

    std.log.debug("[FRPS] Creating new server instance for {s}", .{node_name});
    const holder = try allocator.create(ServerHolder);
    errdefer allocator.destroy(holder);

    const config = libfrps.FrpsServer.Config{
        .bind_port = node.bind_port,
        .bind_addr = node.bind_addr,
        .auth_token = node.auth_token,
        .dashboard_addr = node.dashboard_addr,
        .dashboard_port = node.dashboard_port,
        .dashboard_user = node.dashboard_user,
        .dashboard_pwd = node.dashboard_pwd,
        .log_level = node.log_level,
        .max_pool_count = node.max_pool_count,
        .max_ports_per_client = node.max_ports_per_client,
        .tcp_mux = node.tcp_mux,
        .allow_ports = node.allow_ports,
    };

    holder.* = .{
        .server = try libfrps.FrpsServer.init(
            allocator,
            config,
            node_name,
        ),
        .started = false,
        .lock = .{},
    };

    servers_lock.lock();
    defer servers_lock.unlock();
    map = try getServerMap(allocator);
    if (map.get(node_name)) |existing| {
        std.log.debug("[FRPS] Server {s} was created by another thread, using existing instance", .{node_name});
        holder.server.deinit();
        allocator.destroy(holder);
        return existing;
    }

    const key = try allocator.dupe(u8, node_name);
    try map.put(key, holder);
    std.log.debug("[FRPS] Server {s} added to server map", .{node_name});
    return holder;
}

pub fn startServer(
    allocator: std.mem.Allocator,
    node_name: []const u8,
    node: types.FrpsNode,
) !void {
    std.log.info("[FRPS] Loading configuration for server {s}...", .{node_name});
    std.log.debug("[FRPS] Server config - bind_port: {any}, max_pool_count: {any}, tcp_mux: {any}", .{
        node.bind_port,
        node.max_pool_count,
        node.tcp_mux,
    });

    const holder = try getOrCreateServer(allocator, node_name, node);

    holder.lock.lock();
    defer holder.lock.unlock();

    startFrpsServer(holder, node_name);
}

pub fn stopServer(node_name: []const u8) void {
    std.log.info("[FRPS] Stopping server {s}...", .{node_name});
    servers_lock.lock();
    defer servers_lock.unlock();

    if (servers) |*map| {
        if (map.get(node_name)) |holder| {
            holder.lock.lock();
            defer holder.lock.unlock();

            if (holder.started) {
                holder.server.stop() catch |err| {
                    std.log.err("[FRPS] Failed to stop server {s}: {any}", .{ node_name, err });
                };
                holder.started = false;
                std.log.info("[FRPS] Server {s} stopped", .{node_name});
            }
        }
    }
}

pub fn stopAll() void {
    if (servers == null) return;
    servers_lock.lock();
    defer servers_lock.unlock();

    var map = servers.?;
    const allocator = servers_allocator orelse std.heap.c_allocator;

    var it = map.iterator();
    var count: usize = 0;
    while (it.next()) |entry| {
        if (entry.value_ptr.*.started) {
            entry.value_ptr.*.server.stop() catch {};
            count += 1;
        }
        entry.value_ptr.*.server.deinit();
        allocator.free(entry.key_ptr.*);
        allocator.destroy(entry.value_ptr.*);
    }
    map.deinit();
    servers = null;
    servers_allocator = null;
    std.log.info("[FRPS] All {d} FRPS servers stopped and cleaned up", .{count});
}

/// FRPS server status
pub const FrpsServerStatus = struct {
    status: []const u8,
    last_error: []const u8,
    node_name: []const u8,
};

/// Get the status of a specific FRPS server by node name
/// Caller owns all returned strings and must free them
pub fn getServerStatus(allocator: std.mem.Allocator, node_name: []const u8) !struct {
    status: []const u8,
    last_error: []const u8,
    logs: []const u8,
} {
    servers_lock.lock();
    defer servers_lock.unlock();

    // No servers initialized
    if (servers == null) {
        std.log.debug("[FRPS] No servers initialized, returning stopped status for {s}", .{node_name});
        return .{
            .status = try allocator.dupe(u8, "stopped"),
            .last_error = try allocator.dupe(u8, ""),
            .logs = try allocator.dupe(u8, ""),
        };
    }
    const map = servers.?;

    const holder = map.get(node_name) orelse {
        // Node not found
        std.log.debug("[FRPS] Server {s} not found in map", .{node_name});
        return .{
            .status = try allocator.dupe(u8, "stopped"),
            .last_error = try allocator.dupe(u8, ""),
            .logs = try allocator.dupe(u8, ""),
        };
    };

    // Server exists but not started
    if (!holder.started) {
        std.log.debug("[FRPS] Server {s} exists but not started", .{node_name});
        return .{
            .status = try allocator.dupe(u8, "stopped"),
            .last_error = try allocator.dupe(u8, ""),
            .logs = try allocator.dupe(u8, ""),
        };
    }

    // Server is started - get actual status and logs
    const status_json = try holder.server.getStatus(allocator);
    defer allocator.free(status_json);
    const logs = try holder.server.getLogs(allocator);
    errdefer allocator.free(logs);

    const parsed = try parseStatusJson(allocator, status_json);
    // Note: logs is already owned by caller, parsed.status and parsed.last_error also owned

    return .{
        .status = parsed.status,
        .last_error = parsed.last_error,
        .logs = logs,
    };
}

/// Get all proxy statistics for an FRPS server
/// Returns JSON string: [{"name":"...","type":"...","status":"...",...}]
pub fn getProxyStats(allocator: std.mem.Allocator, node_name: []const u8) ![]const u8 {
    servers_lock.lock();
    defer servers_lock.unlock();

    // No servers initialized
    if (servers == null) {
        std.log.debug("[FRPS] No servers initialized, returning empty stats for {s}", .{node_name});
        // Return empty array
        return std.fmt.allocPrint(allocator, "[]", .{});
    }

    const map = servers.?;
    const holder = map.get(node_name) orelse {
        // Node not found - return empty array
        std.log.debug("[FRPS] Server {s} not found, returning empty stats", .{node_name});
        return std.fmt.allocPrint(allocator, "[]", .{});
    };

    // Server exists but not started
    if (!holder.started) {
        std.log.debug("[FRPS] Server {s} not started, returning empty stats", .{node_name});
        return std.fmt.allocPrint(allocator, "[]", .{});
    }

    // Server is started - return empty array since FRPS doesn't support detailed proxy stats
    return std.fmt.allocPrint(allocator, "[]", .{});
}

/// Clear the logs of a specific FRP server by node name
/// This is idempotent - returns success if node not found or not started
pub fn clearServerLogs(node_name: []const u8) void {
    servers_lock.lock();
    defer servers_lock.unlock();

    if (servers == null) {
        std.log.debug("[FRPS] No servers to clear logs for {s}", .{node_name});
        return;
    }

    const map = servers.?;
    const holder = map.get(node_name) orelse {
        std.log.debug("[FRPS] Server {s} not found, skipping log clear", .{node_name});
        return;
    };

    if (!holder.started) {
        std.log.debug("[FRPS] Server {s} not started, skipping log clear", .{node_name});
        return;
    }

    holder.server.clearLogs();
    std.log.debug("[FRPS] Logs cleared for server {s}", .{node_name});
}

/// Parse the status JSON from FrpsGetStatus
fn parseStatusJson(allocator: std.mem.Allocator, json: []const u8) !struct {
    status: []const u8,
    last_error: []const u8,
} {
    // Simple JSON parsing for {"status":"...","last_error":"..."}
    // We use a basic approach since std.json might not be available in all builds

    var status: []const u8 = "unknown";
    var last_error: []const u8 = "";

    // Find "status":"..."
    if (std.mem.indexOf(u8, json, "\"status\":\"")) |start| {
        const value_start = start + 10; // length of "status":"
        if (std.mem.indexOfPos(u8, json, value_start, "\"")) |end| {
            status = json[value_start..end];
        }
    }

    // Find "last_error":"..."
    if (std.mem.indexOf(u8, json, "\"last_error\":\"")) |start| {
        const value_start = start + 14; // length of "last_error":"
        if (std.mem.indexOfPos(u8, json, value_start, "\"")) |end| {
            last_error = json[value_start..end];
        }
    }

    return .{
        .status = try allocator.dupe(u8, status),
        .last_error = try allocator.dupe(u8, last_error),
    };
}

pub const ServerSummary = struct {
    name: []const u8,
    status: []const u8,
    client_count: usize,
    proxy_count: usize,
    server_count: usize,
    last_error: []const u8,
};

pub fn freeServerSummaries(allocator: std.mem.Allocator, items: []ServerSummary) void {
    for (items) |item| {
        allocator.free(item.name);
        allocator.free(item.status);
        allocator.free(item.last_error);
    }
    allocator.free(items);
}

/// Returns a slice of per-node server summaries. Caller must call freeServerSummaries.
pub fn getAllServerSummaries(allocator: std.mem.Allocator) ![]ServerSummary {
    var node_names = std.array_list.Managed([]const u8).init(allocator);
    defer {
        for (node_names.items) |n| allocator.free(n);
        node_names.deinit();
    }
    {
        servers_lock.lock();
        defer servers_lock.unlock();
        if (servers) |map| {
            var it = map.iterator();
            while (it.next()) |entry| {
                try node_names.append(try allocator.dupe(u8, entry.key_ptr.*));
            }
        }
    }

    var list = std.array_list.Managed(ServerSummary).init(allocator);
    errdefer {
        for (list.items) |item| {
            allocator.free(item.name);
            allocator.free(item.status);
            allocator.free(item.last_error);
        }
        list.deinit();
    }

    // Get aggregate counts once (global stats across all FRPS instances)
    var agg_client_count: usize = 0;
    var agg_proxy_count: usize = 0;
    var agg_server_count: usize = 0;
    if (libfrps.getServerStats(allocator)) |stats| {
        defer allocator.free(stats.status);
        defer allocator.free(stats.last_error);
        agg_client_count = stats.client_count;
        agg_proxy_count = stats.proxy_count;
        agg_server_count = stats.server_count;
    } else |_| {}

    for (node_names.items) |name| {
        const result = getServerStatus(allocator, name) catch |err| {
            std.log.warn("[FRPS] getAllServerSummaries: getServerStatus failed for {s}: {any}", .{ name, err });
            continue;
        };
        defer allocator.free(result.logs);
        errdefer allocator.free(result.status);
        errdefer allocator.free(result.last_error);
        const name_copy = try allocator.dupe(u8, name);
        errdefer allocator.free(name_copy);
        try list.append(ServerSummary{
            .name = name_copy,
            .status = result.status,
            .client_count = agg_client_count,
            .proxy_count = agg_proxy_count,
            .server_count = agg_server_count,
            .last_error = result.last_error,
        });
    }

    return list.toOwnedSlice();
}

test "getProxyStats: returns empty array for unknown node" {
    const result = try getProxyStats(std.testing.allocator, "no_such_node");
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("[]", result);
}
