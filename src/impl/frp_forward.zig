const std = @import("std");
const types = @import("../config/types.zig");
const project_status = @import("project_status.zig");
const libfrp = @import("frpc/libfrp.zig");
const common = @import("app_forward/common.zig");

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

fn frpClientStartThread(node_name: []const u8) void {
    std.log.debug("[FRP] Background start thread initiated for node {s}", .{node_name});

    clients_lock.lock();
    defer clients_lock.unlock();

    if (clients == null) {
        std.log.warn("[FRP] Clients map is null in start thread", .{});
        return;
    }

    if (clients.?.get(node_name)) |holder_ptr| {
        std.log.debug("[FRP] Background thread: calling start() for node {s}", .{node_name});
        holder_ptr.*.client.start() catch |err| {
            std.log.warn("[FRP] Failed to start client {s}: {any}", .{ node_name, err });
            return;
        };
        std.log.info("[FRP] Client {s} started successfully in background thread", .{node_name});
    } else {
        std.log.warn("[FRP] Client holder not found for node {s}", .{node_name});
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
    const holder = try allocator.create(ClientHolder);
    errdefer allocator.destroy(holder);

    std.log.debug("[FRP] getOrCreateClient: initializing FrpClient for node {s}", .{node_name});
    holder.* = .{
        .client = try libfrp.FrpClient.init(allocator, node.server, node.port, token_opt),
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
    const proxy_name = try std.fmt.allocPrint(allocator, "proj{d}_{s}_{d}_{s}", .{ project_id + 1, remark, remote_port, @tagName(mapping.protocol) });
    defer allocator.free(proxy_name);

    switch (mapping.protocol) {
        .tcp => try holder.client.addTcpProxy(proxy_name, local_ip, local_port, remote_port),
        .udp => try holder.client.addUdpProxy(proxy_name, local_ip, local_port, remote_port),
        .both => {
            try holder.client.addTcpProxy(proxy_name, local_ip, local_port, remote_port);
            try holder.client.addUdpProxy(proxy_name, local_ip, local_port, remote_port);
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

        if (holder.started) {
            std.log.debug("[FRP] Client {s} already started, flushing changes", .{fwd.node_name});
            std.log.debug("[FRP] About to call flush for node {s}", .{fwd.node_name});
            holder.client.flush() catch |err| {
                std.log.warn("[FRP] Failed to flush client {s}: {any}", .{ fwd.node_name, err });
            };
            std.log.debug("[FRP] Flush completed for node {s}", .{fwd.node_name});
        } else {
            std.log.debug("[FRP] Spawning background thread to start client {s}", .{fwd.node_name});
            std.log.debug("[FRP] Marking client {s} as started to prevent duplicate start attempts", .{fwd.node_name});
            holder.started = true;

            // Spawn background thread for start (avoid blocking with lock held)
            const thread = std.Thread.spawn(.{}, frpClientStartThread, .{fwd.node_name}) catch |err| {
                std.log.warn("[FRP] Failed to spawn start thread for node {s}: {any}", .{ fwd.node_name, err });
                holder.started = false;
                continue;
            };
            thread.detach();
            std.log.debug("[FRP] Background thread spawned for node {s}", .{fwd.node_name});
        }
    }

    std.log.debug("[FRP] applyFrpForMapping completed for project {d}", .{handle.id + 1});
}

pub fn startForwarding(
    allocator: std.mem.Allocator,
    handle: *project_status.ProjectHandle,
    frp_nodes: *const std.StringHashMap(types.FrpNode),
) !void {
    // 仅在存在 FRP 转发配置时执行
    var has_frp = false;
    for (handle.cfg.port_mappings, 1..) |mapping, idx| {
        if (mapping.frp.len != 0) {
            has_frp = true;
            std.log.debug("[FRP] project {d} mapping {d}/{d} frp entry(ies)", .{ handle.id + 1, idx, mapping.frp.len });
        }
    }
    if (!has_frp) {
        std.log.debug("[FRP] project {d} has no frp mappings, skip", .{handle.id + 1});
        return;
    }

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
