const std = @import("std");
const types = @import("../config/types.zig");
const server = @import("../ubus/server.zig");

const common = @import("app_forward/common.zig");
const tcp_uv = @import("app_forward/tcp_forwarder_uv.zig");
const udp_uv = @import("app_forward/udp_forwarder_uv.zig");
const c = @import("app_forward/uv.zig").c;

pub const ForwardError = common.ForwardError;

pub inline fn getThreadConfig() std.Thread.SpawnConfig {
    return common.getThreadConfig();
}

pub const TcpForwarder = tcp_uv.TcpForwarder;
pub const UdpForwarder = udp_uv.UdpForwarder;

const ProjectHandles = struct {
    tcp: ?*c.tcp_forwarder_t = null,
    udp: ?*c.udp_forwarder_t = null,
};

var g_handles: std.array_list.Aligned(ProjectHandles, null) = std.array_list.Aligned(ProjectHandles, null).empty;
var g_handles_mutex: std.Thread.Mutex = .{};

fn ensureHandles(allocator: std.mem.Allocator, project_id: usize) !void {
    if (project_id + 1 > g_handles.items.len) {
        // ensure the structure is initialized with a small initial capacity
        if (g_handles.capacity == 0) {
            g_handles = try std.array_list.Aligned(ProjectHandles, null).initCapacity(allocator, 4);
        }
        const need: usize = project_id + 1 - g_handles.items.len;
        var i: usize = 0;
        while (i < need) : (i += 1) {
            try g_handles.append(allocator, .{});
        }
    }
}

fn setHandles(allocator: std.mem.Allocator, project_id: usize, tcp: ?*c.tcp_forwarder_t, udp: ?*c.udp_forwarder_t) !void {
    g_handles_mutex.lock();
    defer g_handles_mutex.unlock();
    try ensureHandles(allocator, project_id);
    g_handles.items[project_id].tcp = tcp;
    g_handles.items[project_id].udp = udp;
}

pub fn getProjectStats(project_id: usize) common.TrafficStats {
    g_handles_mutex.lock();
    defer g_handles_mutex.unlock();
    if (project_id >= g_handles.items.len) {
        return .{ .bytes_in = 0, .bytes_out = 0 };
    }
    const h = g_handles.items[project_id];
    var stats = common.TrafficStats{ .bytes_in = 0, .bytes_out = 0 };
    if (h.tcp) |t| {
        const s = tcp_uv.getStatsRaw(t);
        stats.bytes_in += s.bytes_in;
        stats.bytes_out += s.bytes_out;
    }
    if (h.udp) |u| {
        const s = udp_uv.getStatsRaw(u);
        stats.bytes_in += s.bytes_in;
        stats.bytes_out += s.bytes_out;
    }
    return stats;
}

/// Start a port forwarding project
pub fn startForwarding(allocator: std.mem.Allocator, project_id: usize, project: types.Project) !void {
    try ensureHandles(allocator, project_id);

    if (!project.enable_app_forward) {
        return;
    }

    if (project.port_mappings.len > 0) {
        for (project.port_mappings) |mapping| {
            try startForwardingForMapping(allocator, project, mapping);
        }
        return;
    }

    // Single-port mode
    switch (project.protocol) {
        .tcp => {
            var tcp_forwarder = try TcpForwarder.init(
                allocator,
                project.listen_port,
                project.target_address,
                project.target_port,
                project.family,
                project.enable_stats,
            );
            try setHandles(allocator, project_id, tcp_forwarder.getHandle(), null);
            server.updateProjectMetrics(project_id, 1, 0, 0);
            try tcp_forwarder.start();
        },
        .udp => {
            var udp_forwarder = UdpForwarder.init(
                allocator,
                project.listen_port,
                project.target_address,
                project.target_port,
                project.family,
                project.enable_stats,
            );
            try setHandles(allocator, project_id, null, udp_forwarder.getHandle());
            server.updateProjectMetrics(project_id, 1, 0, 0);
            try udp_forwarder.start();
        },
        .both => {
            var tcp_forwarder = try TcpForwarder.init(
                allocator,
                project.listen_port,
                project.target_address,
                project.target_port,
                project.family,
                project.enable_stats,
            );

            var udp_forwarder = UdpForwarder.init(
                allocator,
                project.listen_port,
                project.target_address,
                project.target_port,
                project.family,
                project.enable_stats,
            );

            try setHandles(allocator, project_id, tcp_forwarder.getHandle(), udp_forwarder.getHandle());
            server.updateProjectMetrics(project_id, 2, 0, 0);
            try tcp_forwarder.start();
        },
    }
}

/// 解析端口范围字符串，返回起始和结束端口
fn parsePortRange(port_str: []const u8) !common.PortRange {
    return common.parsePortRange(port_str);
}

/// 为单个端口映射启动转发
fn startForwardingForMapping(
    allocator: std.mem.Allocator,
    project: types.Project,
    mapping: types.PortMapping,
) !void {
    const listen_range = try parsePortRange(mapping.listen_port);
    const target_range = try parsePortRange(mapping.target_port);

    // 验证端口范围长度一致
    const listen_count = listen_range.end - listen_range.start + 1;
    const target_count = target_range.end - target_range.start + 1;

    if (listen_count != target_count) {
        std.debug.print("[Forward] Port range mismatch: {d} listen ports vs {d} target ports\n", .{ listen_count, target_count });
        return ForwardError.InvalidAddress;
    }

    // 为范围内的每个端口启动转发
    var i: u16 = 0;
    while (i < listen_count) : (i += 1) {
        const listen_port = listen_range.start + i;
        const target_port = target_range.start + i;

        switch (mapping.protocol) {
            .tcp => {
                const tcp_thread = try std.Thread.spawn(getThreadConfig(), startTcpForward, .{
                    allocator,
                    listen_port,
                    project.target_address,
                    target_port,
                    project.family,
                    project.enable_stats,
                });
                tcp_thread.detach();
            },
            .udp => {
                const udp_thread = try std.Thread.spawn(getThreadConfig(), startUdpForward, .{
                    allocator,
                    listen_port,
                    project.target_address,
                    target_port,
                    project.family,
                    project.enable_stats,
                });
                udp_thread.detach();
            },
            .both => {
                const tcp_thread = try std.Thread.spawn(getThreadConfig(), startTcpForward, .{
                    allocator,
                    listen_port,
                    project.target_address,
                    target_port,
                    project.family,
                    project.enable_stats,
                });
                tcp_thread.detach();

                const udp_thread = try std.Thread.spawn(getThreadConfig(), startUdpForward, .{
                    allocator,
                    listen_port,
                    project.target_address,
                    target_port,
                    project.family,
                    project.enable_stats,
                });
                udp_thread.detach();
            },
        }
    }
}

fn startTcpForward(
    allocator: std.mem.Allocator,
    listen_port: u16,
    target_address: []const u8,
    target_port: u16,
    family: types.AddressFamily,
    enable_stats: bool,
) void {
    var tcp_forwarder = TcpForwarder.init(allocator, listen_port, target_address, target_port, family, enable_stats) catch |err| {
        std.debug.print("[TCP] Failed to create forwarder on port {d}: {any}\n", .{ listen_port, err });
        return;
    };
    tcp_forwarder.start() catch |err| {
        std.debug.print("[TCP] Failed to start forwarder on port {d}: {any}\n", .{ listen_port, err });
        return;
    };
}

fn startUdpForward(
    allocator: std.mem.Allocator,
    listen_port: u16,
    target_address: []const u8,
    target_port: u16,
    family: types.AddressFamily,
    enable_stats: bool,
) void {
    var udp_forwarder = UdpForwarder.init(allocator, listen_port, target_address, target_port, family, enable_stats);
    defer udp_forwarder.deinit();
    udp_forwarder.start() catch |err| {
        std.debug.print("[UDP] Failed to start forwarder on port {d}: {any}\n", .{ listen_port, err });
        return;
    };
}
