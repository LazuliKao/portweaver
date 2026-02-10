const std = @import("std");
const types = @import("../config/types.zig");
const project_status = @import("project_status.zig");
const libfrp = @import("frpc/libfrp.zig");
const common = @import("app_forward/common.zig");
const main = @import("../main.zig");
const event_log = main.event_log;
const build_options = @import("build_options");

const ClientHolder = struct {
    client: libfrp.FrpClient,
    started: bool = false,
    lock: std.Thread.Mutex = .{},
};

var clients: ?std.StringHashMap(*ClientHolder) = null;
var clients_allocator: ?std.mem.Allocator = null;
var clients_lock: std.Thread.Mutex = .{};
var pending_starts: std.ArrayList([]const u8) = undefined;
var pending_starts_lock: std.Thread.Mutex = .{};

fn flushFrpClient(holder: *ClientHolder, node_name: []const u8) void {
    if (holder.started) {
        std.log.debug("[FRP] Client {s} already started, flushing changes", .{node_name});
        std.log.debug("[FRP] About to call flush for node {s}", .{node_name});
        holder.client.flush() catch |err| {
            std.log.warn("[FRP] Failed to flush client {s}: {any}", .{ node_name, err });
        };
        std.log.debug("[FRP] Flush completed for node {s}", .{node_name});
    } else {
        holder.started = true;
        holder.*.client.start() catch |err| {
            std.log.warn("[FRP] Failed to start client {s}: {any}", .{ node_name, err });
            return;
        };
        std.log.info("[FRP] Client {s} started successfully", .{node_name});
    }
}

fn getClientMap(allocator: std.mem.Allocator) !*std.StringHashMap(*ClientHolder) {
    if (clients == null) {
        clients = std.StringHashMap(*ClientHolder).init(allocator);
        clients_allocator = allocator;
    }
    return &clients.?;
}

fn getOrCreateClient(
    allocator: std.mem.Allocator,
    node_name: []const u8,
    node: types.FrpNode,
) !*ClientHolder {
    // Fast path: check under lock if client already exists
    std.log.debug("[FRP] getOrCreateClient: acquiring clients_lock for node {s}", .{node_name});
    clients_lock.lock();
    var map = try getClientMap(allocator);
    if (map.get(node_name)) |holder_ptr| {
        clients_lock.unlock();
        std.log.debug("[FRP] getOrCreateClient: found existing holder for node {s}", .{node_name});
        return holder_ptr;
    }
    // No holder yet; release lock before the potentially blocking init
    clients_lock.unlock();
    std.log.debug("[FRP] getOrCreateClient: lock released; creating new holder for node {s}, server={s}, port={d}", .{ node_name, node.server, node.port });

    const token_opt: ?[]const u8 = if (node.token.len == 0) null else node.token;
    const log_level_opt: ?[]const u8 = if (node.log_level.len == 0) null else node.log_level;
    const holder = try allocator.create(ClientHolder);
    errdefer allocator.destroy(holder);

    std.log.debug("[FRP] getOrCreateClient: initializing FrpClient for node {s}", .{node_name});
    holder.* = .{
        .client = try libfrp.FrpClient.init(allocator, node.server, node.port, token_opt, log_level_opt, node_name, node.use_encryption, node.use_compression),
        .started = false,
        .lock = .{},
    };
    std.log.debug("[FRP] getOrCreateClient: FrpClient initialized successfully", .{});

    // Re-acquire lock to insert, double-checking if another thread won the race
    std.log.debug("[FRP] getOrCreateClient: re-acquiring clients_lock to insert holder for node {s}", .{node_name});
    clients_lock.lock();
    defer clients_lock.unlock();
    map = try getClientMap(allocator);
    if (map.get(node_name)) |existing| {
        std.log.debug("[FRP] getOrCreateClient: another thread already registered holder for node {s}, discarding newly created", .{node_name});
        holder.client.deinit();
        allocator.destroy(holder);
        return existing;
    }

    const key = try allocator.dupe(u8, node_name);
    try map.put(key, holder);
    std.log.debug("[FRP] getOrCreateClient: holder registered in map for node {s}", .{node_name});
    return holder;
}

fn addProxyForPorts(
    allocator: std.mem.Allocator,
    holder: *ClientHolder,
    mapping: types.PortMapping,
    local_ip: []const u8,
    local_port: u16,
    remote_port: u16,
    project_id: usize,
    remark: []const u8,
) !void {
    switch (mapping.protocol) {
        .tcp => {
            const proxy_name = try std.fmt.allocPrint(allocator, "proj{d}_{s}_{d}_{s}", .{ project_id + 1, remark, remote_port, @tagName(mapping.protocol) });
            defer allocator.free(proxy_name);
            try holder.client.addTcpProxy(proxy_name, local_ip, local_port, remote_port);
        },
        .udp => {
            const proxy_name = try std.fmt.allocPrint(allocator, "proj{d}_{s}_{d}_{s}", .{ project_id + 1, remark, remote_port, @tagName(mapping.protocol) });
            defer allocator.free(proxy_name);
            try holder.client.addUdpProxy(proxy_name, local_ip, local_port, remote_port);
        },
        .both => {
            const proxy_name_tcp = try std.fmt.allocPrint(allocator, "proj{d}_{s}_{d}_{s}_tcp", .{ project_id + 1, remark, remote_port, @tagName(mapping.protocol) });
            defer allocator.free(proxy_name_tcp);
            try holder.client.addTcpProxy(proxy_name_tcp, local_ip, local_port, remote_port);

            const proxy_name_udp = try std.fmt.allocPrint(allocator, "proj{d}_{s}_{d}_{s}_udp", .{ project_id + 1, remark, remote_port, @tagName(mapping.protocol) });
            defer allocator.free(proxy_name_udp);
            try holder.client.addUdpProxy(proxy_name_udp, local_ip, local_port, remote_port);
        },
    }
}

fn applyFrpForMapping(
    allocator: std.mem.Allocator,
    handle: *project_status.ProjectHandle,
    frp_nodes: *const std.StringHashMap(types.FrpNode),
    mapping: types.PortMapping,
) !void {
    std.log.debug("[FRP] applyFrpForMapping started for project {d}, mapping listen_port={s}, target_port={s}", .{ handle.id + 1, mapping.listen_port, mapping.target_port });

    if (mapping.frp.len == 0) {
        std.log.debug("[FRP] applyFrpForMapping: no FRP entries for this mapping, skipping", .{});
        return;
    }

    const listen_range = try common.parsePortRange(mapping.listen_port);
    const target_range = try common.parsePortRange(mapping.target_port);

    const listen_count: u32 = listen_range.end - listen_range.start + 1;
    const target_count: u32 = target_range.end - target_range.start + 1;
    if (listen_count != target_count) {
        std.log.warn("[FRP] Port range mismatch listen={d}-{d} target={d}-{d}", .{ listen_range.start, listen_range.end, target_range.start, target_range.end });
        return;
    }

    for (mapping.frp) |fwd| {
        std.log.debug("[FRP] Processing FRP entry: node_name={s}, remote_port={d}", .{ fwd.node_name, fwd.remote_port });

        const node = frp_nodes.get(fwd.node_name) orelse {
            std.log.warn("[FRP] Node '{s}' not found in configuration", .{fwd.node_name});
            continue;
        };

        const remote_start: u16 = if (fwd.remote_port != 0) fwd.remote_port else target_range.start;
        if (@as(u32, remote_start) + (listen_count - 1) > 65535) {
            std.log.warn("[FRP] Remote port range overflow starting at {d} (count {d})", .{ remote_start, listen_count });
            continue;
        }

        std.log.debug("[FRP] About to call getOrCreateClient for node {s}", .{fwd.node_name});
        const holder = try getOrCreateClient(allocator, fwd.node_name, node);
        std.log.debug("[FRP] Client holder created/retrieved for node {s}, started={}", .{ fwd.node_name, holder.started });

        std.log.debug("[FRP] About to acquire holder lock for node {s}", .{fwd.node_name});
        holder.lock.lock();
        defer holder.lock.unlock();
        std.log.debug("[FRP] Holder lock acquired for node {s}", .{fwd.node_name});

        var idx: u32 = 0;
        while (idx < listen_count) : (idx += 1) {
            const offset: u16 = @as(u16, @intCast(idx));
            const local_port: u16 = target_range.start + offset;
            const remote_port: u16 = remote_start + offset;
            std.log.debug("[FRP] Adding proxy: local_port={d}, remote_port={d}, node={s}", .{ local_port, remote_port, fwd.node_name });

            addProxyForPorts(allocator, holder, mapping, handle.cfg.target_address, local_port, remote_port, handle.id, handle.cfg.remark) catch |err| {
                std.log.warn("[FRP] Failed to add proxy for node {s} port {d}: {any}", .{ fwd.node_name, remote_port, err });
                continue;
            };
        }
        flushFrpClient(holder, fwd.node_name);
    }

    std.log.debug("[FRP] applyFrpForMapping completed for project {d}", .{handle.id + 1});
}

pub fn startForwarding(
    allocator: std.mem.Allocator,
    handle: *project_status.ProjectHandle,
    frp_nodes: *const std.StringHashMap(types.FrpNode),
) !void {
    for (handle.cfg.port_mappings) |mapping| {
        applyFrpForMapping(allocator, handle, frp_nodes, mapping) catch |err| {
            std.log.warn("[FRP] Failed to apply mapping: {any}", .{err});
        };
    }
}

pub fn stopAll() void {
    if (clients == null) return;
    clients_lock.lock();
    defer clients_lock.unlock();

    var map = clients.?;
    const allocator = clients_allocator orelse std.heap.c_allocator;

    var it = map.iterator();
    while (it.next()) |entry| {
        if (entry.value_ptr.*.started) {
            entry.value_ptr.*.client.stop() catch {};
        }
        entry.value_ptr.*.client.deinit();
        allocator.free(entry.key_ptr.*);
        allocator.destroy(entry.value_ptr.*);
    }
    map.deinit();
    clients = null;
    clients_allocator = null;
}

/// Aggregated FRP client status
pub const FrpClientStatus = struct {
    status: []const u8,
    last_error: []const u8,
    node_name: []const u8,
};

/// Get the aggregated status of all FRP clients
/// Returns the "worst" status and the latest error if any
pub fn getAggregatedStatus(allocator: std.mem.Allocator) !struct {
    status: []const u8,
    last_error: []const u8,
    client_count: usize,
} {
    clients_lock.lock();
    defer clients_lock.unlock();

    if (clients == null) {
        return .{
            .status = try allocator.dupe(u8, "stopped"),
            .last_error = try allocator.dupe(u8, ""),
            .client_count = 0,
        };
    }

    var map = clients.?;
    var has_error = false;
    var has_connecting = false;
    var has_connected = false;
    var last_error_msg: []const u8 = "";
    var client_count: usize = 0;

    var it = map.iterator();
    while (it.next()) |entry| {
        client_count += 1;
        const holder = entry.value_ptr.*;

        if (!holder.started) continue;

        // Get status from the FRP client
        const status_json = holder.client.getStatus(allocator) catch |err| {
            std.log.warn("[FRP] Failed to get status for client: {any}", .{err});
            continue;
        };
        defer allocator.free(status_json);

        // Parse the status JSON to extract status and last_error
        // Format: {"status":"...","last_error":"..."}
        const parsed = parseStatusJson(allocator, status_json) catch |err| {
            std.log.warn("[FRP] Failed to parse status JSON: {any}", .{err});
            continue;
        };
        defer allocator.free(parsed.status);
        defer allocator.free(parsed.last_error);

        // Track the worst status
        if (std.mem.eql(u8, parsed.status, "error")) {
            has_error = true;
            if (parsed.last_error.len > 0) {
                // Log the error to the event log
                event_log.logEvent(.frp_error, parsed.last_error, -1);
                // Keep the latest non-empty error
                if (last_error_msg.len > 0) allocator.free(last_error_msg);
                last_error_msg = allocator.dupe(u8, parsed.last_error) catch "";
            }
        } else if (std.mem.eql(u8, parsed.status, "connecting")) {
            has_connecting = true;
        } else if (std.mem.eql(u8, parsed.status, "connected")) {
            has_connected = true;
        }
    }

    // Determine overall status
    const overall_status = if (has_error)
        "error"
    else if (has_connecting)
        "connecting"
    else if (has_connected)
        "connected"
    else
        "stopped";

    return .{
        .status = try allocator.dupe(u8, overall_status),
        .last_error = if (last_error_msg.len > 0) last_error_msg else try allocator.dupe(u8, ""),
        .client_count = client_count,
    };
}

/// Get the status of a specific FRP client by node name
/// Caller owns all returned strings and must free them
pub fn getClientStatus(allocator: std.mem.Allocator, node_name: []const u8) !struct {
    status: []const u8,
    last_error: []const u8,
    logs: []const u8,
} {
    clients_lock.lock();
    defer clients_lock.unlock();

    // No clients initialized
    if (clients == null) {
        return .{
            .status = try allocator.dupe(u8, "stopped"),
            .last_error = try allocator.dupe(u8, ""),
            .logs = try allocator.dupe(u8, ""),
        };
    }
    const map = clients.?;

    const holder = map.get(node_name) orelse {
        // Node not found
        return .{
            .status = try allocator.dupe(u8, "stopped"),
            .last_error = try allocator.dupe(u8, ""),
            .logs = try allocator.dupe(u8, ""),
        };
    };

    // Client exists but not started
    if (!holder.started) {
        return .{
            .status = try allocator.dupe(u8, "stopped"),
            .last_error = try allocator.dupe(u8, ""),
            .logs = try allocator.dupe(u8, ""),
        };
    }

    // Client is started - get actual status and logs
    const status_json = try holder.client.getStatus(allocator);
    defer allocator.free(status_json);
    const logs = try holder.client.getLogs(allocator);
    errdefer allocator.free(logs);

    const parsed = try parseStatusJson(allocator, status_json);
    // Note: logs is already owned by caller, parsed.status and parsed.last_error also owned

    return .{
        .status = parsed.status,
        .last_error = parsed.last_error,
        .logs = logs,
    };
}

/// Clear the logs of a specific FRP client by node name
/// This is idempotent - returns success if node not found or not started
pub fn clearClientLogs(node_name: []const u8) void {
    clients_lock.lock();
    defer clients_lock.unlock();

    if (clients == null) return;

    const map = clients.?;
    const holder = map.get(node_name) orelse return;

    if (!holder.started) return;

    holder.client.clearLogs();
}

/// Get all proxy statistics for an FRP client
/// Returns JSON string: [{"name":"...","type":"...","status":"...",...}]
pub fn getProxyStats(allocator: std.mem.Allocator, node_name: []const u8) ![]const u8 {
    clients_lock.lock();
    defer clients_lock.unlock();

    // No clients initialized
    if (clients == null) {
        // Return empty array
        return std.fmt.allocPrint(allocator, "{{\"error\":\"no clients\"}}", .{});
    }

    const map = clients.?;
    const holder = map.get(node_name) orelse {
        // Node not found - return empty array
        return std.fmt.allocPrint(allocator, "{{\"error\":\"node {s} not found\"}}", .{node_name});
    };

    // Client exists but not started
    if (!holder.started) {
        return std.fmt.allocPrint(allocator, "{{\"error\":\"node {s} not started\"}}", .{node_name});
    }

    // Client is started - get all proxy stats
    return holder.client.getProxyTrafficStats(allocator);
}

/// Parse the status JSON from FrpGetStatus
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
