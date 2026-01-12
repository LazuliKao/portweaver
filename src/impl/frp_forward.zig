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
    clients_lock.lock();
    defer clients_lock.unlock();

    var map = try getClientMap(allocator);
    if (map.get(node_name)) |holder_ptr| return holder_ptr;

    const token_opt: ?[]const u8 = if (node.token.len == 0) null else node.token;
    const holder = try allocator.create(ClientHolder);
    errdefer allocator.destroy(holder);
    holder.* = .{
        .client = try libfrp.FrpClient.init(allocator, node.server, node.port, token_opt),
        .started = false,
        .lock = .{},
    };

    const key = try allocator.dupe(u8, node_name);
    try map.put(key, holder);
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
    if (mapping.frp.len == 0) return;

    const listen_range = try common.parsePortRange(mapping.listen_port);
    const target_range = try common.parsePortRange(mapping.target_port);

    const listen_count: u32 = listen_range.end - listen_range.start + 1;
    const target_count: u32 = target_range.end - target_range.start + 1;
    if (listen_count != target_count) {
        std.log.warn("[FRP] Port range mismatch listen={d}-{d} target={d}-{d}", .{ listen_range.start, listen_range.end, target_range.start, target_range.end });
        return;
    }

    for (mapping.frp) |fwd| {
        const node = frp_nodes.get(fwd.node_name) orelse {
            std.log.warn("[FRP] Node '{s}' not found in configuration", .{fwd.node_name});
            continue;
        };

        const remote_start: u16 = if (fwd.remote_port != 0) fwd.remote_port else target_range.start;
        if (@as(u32, remote_start) + (listen_count - 1) > 65535) {
            std.log.warn("[FRP] Remote port range overflow starting at {d} (count {d})", .{ remote_start, listen_count });
            continue;
        }

        const holder = try getOrCreateClient(allocator, fwd.node_name, node);
        holder.lock.lock();
        defer holder.lock.unlock();

        var idx: u32 = 0;
        while (idx < listen_count) : (idx += 1) {
            const offset: u16 = @as(u16, @intCast(idx));
            const local_port: u16 = target_range.start + offset;
            const remote_port: u16 = remote_start + offset;
            addProxyForPorts(allocator, holder, mapping, handle.cfg.target_address, local_port, remote_port, handle.id, handle.cfg.remark) catch |err| {
                std.log.warn("[FRP] Failed to add proxy for node {s} port {d}: {any}", .{ fwd.node_name, remote_port, err });
                continue;
            };
        }

        if (holder.started) {
            holder.client.flush() catch |err| {
                std.log.warn("[FRP] Failed to flush client {s}: {any}", .{ fwd.node_name, err });
            };
        } else {
            holder.client.start() catch |err| {
                std.log.warn("[FRP] Failed to start client {s}: {any}", .{ fwd.node_name, err });
                continue;
            };
            holder.started = true;
        }
    }
}

pub fn startForwarding(
    allocator: std.mem.Allocator,
    handle: *project_status.ProjectHandle,
    frp_nodes: *const std.StringHashMap(types.FrpNode),
) !void {
    // 仅在存在 FRP 转发配置时执行
    var has_frp = false;
    for (handle.cfg.port_mappings) |mapping| {
        if (mapping.frp.len != 0) {
            has_frp = true;
            break;
        }
    }
    if (!has_frp) return;

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
