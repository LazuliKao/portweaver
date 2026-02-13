const std = @import("std");
const types = @import("../config/types.zig");
const project_status = @import("project_status.zig");
const libfrps = @import("frps/libfrps.zig");
const common = @import("app_forward/common.zig");
const main = @import("../main.zig");
const event_log = main.event_log;
const build_options = @import("build_options");
const uci_firewall = @import("uci_firewall.zig");
const uci = @import("../uci/mod.zig");

/// Tracks firewall rules for a single FRPS server
const ServerFirewallManager = struct {
    allocator: std.mem.Allocator,
    ctx: uci.UciContext,
    /// Map: port -> protocol string ("tcp" or "udp")
    active_ports: std.AutoHashMap(u16, []const u8),
    lock: std.Thread.Mutex = .{},

    fn init(allocator: std.mem.Allocator) !ServerFirewallManager {
        const ctx = try uci.UciContext.init();
        return .{
            .allocator = allocator,
            .ctx = ctx,
            .active_ports = std.AutoHashMap(u16, []const u8).init(allocator),
        };
    }

    fn deinit(self: *ServerFirewallManager) void {
        self.lock.lock();
        defer self.lock.unlock();

        var it = self.active_ports.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.value_ptr.*);
        }
        self.active_ports.deinit();
        self.ctx.deinit();
    }

    /// Add firewall rule for a new proxy
    fn addProxyRule(self: *ServerFirewallManager, port: u16, proxy_type: []const u8) !void {
        self.lock.lock();
        defer self.lock.unlock();

        // Determine protocol from proxy type
        const protocol = if (std.mem.eql(u8, proxy_type, "tcp")) "tcp" else "udp";

        // Check if rule already exists
        if (self.active_ports.get(port)) |existing_protocol| {
            if (std.mem.eql(u8, existing_protocol, protocol)) {
                // Rule already exists
                return;
            }
            // Different protocol on same port - remove old rule first
            self.allocator.free(existing_protocol);
            _ = self.active_ports.remove(port);
        }

        // Add firewall rule
        const port_str = try std.fmt.allocPrint(self.allocator, "{d}", .{port});
        defer self.allocator.free(port_str);

        const remark = try std.fmt.allocPrint(
            self.allocator,
            "PORTWEAVER_FRPS_{s}_PORT_{d}",
            .{ std.ascii.upperStringAlloc(self.allocator, proxy_type), port },
        );
        defer self.allocator.free(remark);

        try uci_firewall.addFirewallAcceptRule(self.ctx, self.allocator, protocol, port_str, remark, "any");

        // Track this port
        const protocol_copy = try self.allocator.dupe(u8, protocol);
        try self.active_ports.put(port, protocol_copy);

        std.log.info("[FRPS Firewall] Added {s} rule for port {d} ({s})", .{ protocol, port, proxy_type });
    }

    /// Remove firewall rule for a removed proxy
    fn removeProxyRule(self: *ServerFirewallManager, port: u16, proxy_type: []const u8) void {
        self.lock.lock();
        defer self.lock.unlock();

        // Determine protocol from proxy type
        const protocol = if (std.mem.eql(u8, proxy_type, "tcp")) "tcp" else "udp";

        // Check if we have this port tracked
        if (self.active_ports.get(port)) |existing_protocol| {
            if (!std.mem.eql(u8, existing_protocol, protocol)) {
                // Different protocol - don't remove
                return;
            }

            // Remove from tracking
            self.allocator.free(existing_protocol);
            _ = self.active_ports.remove(port);

            // Remove firewall rule
            const port_str = std.fmt.allocPrint(self.allocator, "{d}", .{port}) catch return;
            defer self.allocator.free(port_str);

            const remark = std.fmt.allocPrint(
                self.allocator,
                "PORTWEAVER_FRPS_{s}_PORT_{d}",
                .{ std.ascii.upperStringAlloc(self.allocator, proxy_type), port },
            );
            defer self.allocator.free(remark);

            uci_firewall.removeFirewallRule(self.ctx, self.allocator, protocol, port_str, remark) catch |err| {
                std.log.warn("[FRPS Firewall] Failed to remove rule: {any}", .{err});
            };

            std.log.info("[FRPS Firewall] Removed {s} rule for port {d} ({s})", .{ protocol, port, proxy_type });
        }

        // Reload firewall to apply changes
        uci_firewall.reloadFirewall(self.allocator) catch |err| {
            std.log.warn("[FRPS Firewall] Failed to reload firewall: {any}", .{err});
        };
    }

    /// Clear all firewall rules for this server
    fn clearAllRules(self: *ServerFirewallManager) void {
        self.lock.lock();
        defer self.lock.unlock();

        var it = self.active_ports.iterator();
        while (it.next()) |entry| {
            const port = entry.key_ptr.*;
            const protocol = entry.value_ptr.*;

            const port_str = std.fmt.allocPrint(self.allocator, "{d}", .{port}) catch continue;
            defer self.allocator.free(port_str);

            const remark = std.fmt.allocPrint(
                self.allocator,
                "PORTWEAVER_FRPS_PORT_{d}",
                .{port},
            );
            defer self.allocator.free(remark);

            uci_firewall.removeFirewallRule(self.ctx, self.allocator, protocol, port_str, remark) catch |err| {
                std.log.warn("[FRPS Firewall] Failed to remove rule: {any}", .{err});
            };

            self.allocator.free(protocol);
        }
        self.active_ports.clearRetaining();

        // Reload firewall to apply changes
        uci_firewall.reloadFirewall(self.allocator) catch |err| {
            std.log.warn("[FRPS Firewall] Failed to reload firewall: {any}", .{err});
        };
    }
};

const ServerHolder = struct {
    server: libfrps.FrpsServer,
    firewall_manager: ServerFirewallManager,
    started: bool = false,
    lock: std.Thread.Mutex = .{},
};

var servers: ?std.StringHashMap(*ServerHolder) = null;
var servers_allocator: ?std.mem.Allocator = null;
var servers_lock: std.Thread.Mutex = .{};

/// Global map for Go callbacks to find firewall managers by server ID
/// This is needed because the Go callback only provides the server ID
var firewall_managers: ?std.AutoHashMap(c_int, *ServerFirewallManager) = null;
var firewall_managers_allocator: ?std.mem.Allocator = null;
var firewall_managers_lock: std.Thread.Mutex = .{};

fn startFrpsServer(holder: *ServerHolder, node_name: []const u8) void {
    if (holder.started) {
        std.log.debug("[FRPS] Server {s} already started", .{node_name});
        return;
    }

    holder.*.server.start() catch |err| {
        std.log.warn("[FRPS] Failed to start server {s}: {any}", .{ node_name, err });
        return;
    };
    holder.started = true;
    std.log.info("[FRPS] Server {s} started successfully", .{node_name});
}

fn getServerMap(allocator: std.mem.Allocator) !*std.StringHashMap(*ServerHolder) {
    if (servers == null) {
        servers = std.StringHashMap(*ServerHolder).init(allocator);
        servers_allocator = allocator;
    }
    return &servers.?;
}

/// Get or create the firewall managers map
fn getFirewallManagersMap(allocator: std.mem.Allocator) !*std.AutoHashMap(c_int, *ServerFirewallManager) {
    if (firewall_managers == null) {
        firewall_managers = std.AutoHashMap(c_int, *ServerFirewallManager).init(allocator);
        firewall_managers_allocator = allocator;
    }
    return &firewall_managers.?;
}

/// Callback function called from Go when proxy events occur
fn proxyEventCallback(
    event_type: libfrps.ProxyEventType,
    proxy_name: [*:0]const u8,
    proxy_type: [*:0]const u8,
    bind_port: u16,
    server_id: c_int,
) callconv(.C) void {
    _ = proxy_name; // Not currently used

    firewall_managers_lock.lock();
    defer firewall_managers_lock.unlock();

    if (firewall_managers == null) return;

    const map = &firewall_managers.?;
    const manager = map.get(server_id) orelse {
        std.log.warn("[FRPS Callback] Server ID {d} not found in firewall managers", .{server_id});
        return;
    };

    const proxy_type_slice = std.mem.sliceTo(proxy_type, 0);

    switch (event_type) {
        .added => {
            manager.addProxyRule(bind_port, proxy_type_slice) catch |err| {
                std.log.err("[FRPS Callback] Failed to add firewall rule: {any}", .{err});
            };
        },
        .removed => {
            manager.removeProxyRule(bind_port, proxy_type_slice);
        },
    }
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
        return holder_ptr;
    }
    servers_lock.unlock();

    const holder = try allocator.create(ServerHolder);
    errdefer allocator.destroy(holder);

    // Convert FrpsNode to JSON configuration for the server
    const config_json = try createFrpsConfigJson(allocator, node, node_name);
    defer allocator.free(config_json);

    // Initialize firewall manager
    const firewall_manager = ServerFirewallManager.init(allocator);

    // Create server with callback
    holder.* = .{
        .server = try libfrps.FrpsServer.initWithCallback(
            allocator,
            config_json,
            node_name,
            &proxyEventCallback,
        ),
        .firewall_manager = firewall_manager,
        .started = false,
        .lock = .{},
    };

    // Register firewall manager in global map
    firewall_managers_lock.lock();
    defer firewall_managers_lock.unlock();
    const fw_map = try getFirewallManagersMap(allocator);
    try fw_map.put(holder.server.id, &holder.firewall_manager);

    servers_lock.lock();
    defer servers_lock.unlock();
    map = try getServerMap(allocator);
    if (map.get(node_name)) |existing| {
        holder.server.deinit();
        holder.firewall_manager.deinit();
        allocator.destroy(holder);
        return existing;
    }

    const key = try allocator.dupe(u8, node_name);
    try map.put(key, holder);
    return holder;
}

pub fn startServer(
    allocator: std.mem.Allocator,
    node_name: []const u8,
    node: types.FrpsNode,
) !void {
    const holder = try getOrCreateServer(allocator, node_name, node);

    holder.lock.lock();
    defer holder.lock.unlock();

    startFrpsServer(holder, node_name);
}

pub fn stopServer(node_name: []const u8) void {
    servers_lock.lock();
    defer servers_lock.unlock();

    if (servers) |*map| {
        if (map.get(node_name)) |holder| {
            holder.lock.lock();
            defer holder.lock.unlock();

            if (holder.started) {
                holder.server.stop() catch |err| {
                    std.log.warn("[FRPS] Failed to stop server {s}: {any}", .{ node_name, err });
                };
                holder.started = false;
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
    while (it.next()) |entry| {
        if (entry.value_ptr.*.started) {
            entry.value_ptr.*.server.stop() catch {};
        }
        entry.value_ptr.*.server.deinit();
        allocator.free(entry.key_ptr.*);
        allocator.destroy(entry.value_ptr.*);
    }
    map.deinit();
    servers = null;
    servers_allocator = null;

    // Clean up firewall managers map
    firewall_managers_lock.lock();
    defer firewall_managers_lock.unlock();
    if (firewall_managers) |*fw_map| {
        var fw_it = fw_map.iterator();
        while (fw_it.next()) |fw_entry| {
            fw_entry.value_ptr.*.deinit();
        }
        fw_map.deinit();
        firewall_managers = null;
        firewall_managers_allocator = null;
    }
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
        return .{
            .status = try allocator.dupe(u8, "stopped"),
            .last_error = try allocator.dupe(u8, ""),
            .logs = try allocator.dupe(u8, ""),
        };
    }
    const map = servers.?;

    const holder = map.get(node_name) orelse {
        // Node not found
        return .{
            .status = try allocator.dupe(u8, "stopped"),
            .last_error = try allocator.dupe(u8, ""),
            .logs = try allocator.dupe(u8, ""),
        };
    };

    // Server exists but not started
    if (!holder.started) {
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
        // Return empty array
        return std.fmt.allocPrint(allocator, "[]", .{});
    }

    const map = servers.?;
    const holder = map.get(node_name) orelse {
        // Node not found - return empty array
        return std.fmt.allocPrint(allocator, "[]", .{});
    };

    // Server exists but not started
    if (!holder.started) {
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

    if (servers == null) return;

    const map = servers.?;
    const holder = map.get(node_name) orelse return;

    if (!holder.started) return;

    holder.server.clearLogs();
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

/// Create FRPS configuration JSON from FrpsNode
fn createFrpsConfigJson(allocator: std.mem.Allocator, node: types.FrpsNode, server_name: []const u8) ![]const u8 {
    _ = server_name; // unused parameter

    // Calculate the maximum possible JSON size
    const max_size = 1024 +
        node.token.len +
        node.log_level.len +
        node.allow_ports.len +
        node.bind_addr.len +
        node.dashboard_addr.len +
        node.dashboard_user.len +
        node.dashboard_pwd.len;

    var buffer = try allocator.alloc(u8, max_size);
    defer allocator.free(buffer);

    var written: usize = 0;

    // Start with opening brace and first field
    {
        const result = try std.fmt.bufPrint(buffer[written..], "{{\"bindPort\":{d}", .{node.port});
        written += result.len;
    }
    {
        const result = try std.fmt.bufPrint(buffer[written..], ",\"maxPoolCount\":{d}", .{node.max_pool_count});
        written += result.len;
    }
    {
        const result = try std.fmt.bufPrint(buffer[written..], ",\"maxPortsPerClient\":{d}", .{node.max_ports_per_client});
        written += result.len;
    }
    {
        const result = try std.fmt.bufPrint(buffer[written..], ",\"tcpMux\":{}", .{if (node.tcp_mux) true else false});
        written += result.len;
    }
    {
        const result = try std.fmt.bufPrint(buffer[written..], ",\"udpMux\":{}", .{if (node.udp_mux) true else false});
        written += result.len;
    }
    {
        const result = try std.fmt.bufPrint(buffer[written..], ",\"kcpMux\":{}", .{if (node.kcp_mux) true else false});
        written += result.len;
    }

    // Optional fields
    if (node.token.len > 0) {
        const result = try std.fmt.bufPrint(buffer[written..], ",\"token\":\"{s}\"", .{node.token});
        written += result.len;
    }
    if (node.log_level.len > 0) {
        const result = try std.fmt.bufPrint(buffer[written..], ",\"logLevel\":\"{s}\"", .{node.log_level});
        written += result.len;
    }
    if (node.allow_ports.len > 0) {
        const result = try std.fmt.bufPrint(buffer[written..], ",\"allowPorts\":\"{s}\"", .{node.allow_ports});
        written += result.len;
    }
    if (node.bind_addr.len > 0) {
        const result = try std.fmt.bufPrint(buffer[written..], ",\"bindAddr\":\"{s}\"", .{node.bind_addr});
        written += result.len;
    }
    if (node.dashboard_addr.len > 0) {
        const result = try std.fmt.bufPrint(buffer[written..], ",\"dashboardAddr\":\"{s}\"", .{node.dashboard_addr});
        written += result.len;
    }
    if (node.dashboard_user.len > 0) {
        const result = try std.fmt.bufPrint(buffer[written..], ",\"dashboardUser\":\"{s}\"", .{node.dashboard_user});
        written += result.len;
    }
    if (node.dashboard_pwd.len > 0) {
        const result = try std.fmt.bufPrint(buffer[written..], ",\"dashboardPwd\":\"{s}\"", .{node.dashboard_pwd});
        written += result.len;
    }

    // Close the JSON object
    {
        const result = try std.fmt.bufPrint(buffer[written..], "}}", .{});
        written += result.len;
    }

    return allocator.dupe(u8, buffer[0..written]);
}
