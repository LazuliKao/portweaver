const std = @import("std");
const types = @import("../config/types.zig");
const server = @import("../ubus/server.zig");
const project_status = @import("project_status.zig");
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

// Helper: create and initialize a TCP forwarder. If fatal_on_fail is true, it will set startup status on failure.
fn createTcpForwarder(
    allocator: std.mem.Allocator,
    projectHandle: *project_status.ProjectHandles,
    listen_port: u16,
    target_address: []const u8,
    target_port: u16,
    family: types.AddressFamily,
    enable_stats: bool,
) !*TcpForwarder {
    var error_code: i32 = 0;
    const fwd = try allocator.create(TcpForwarder);
    fwd.* = TcpForwarder.init(allocator, listen_port, target_address, target_port, family, enable_stats, &error_code) catch |err| {
        allocator.destroy(fwd);
        projectHandle.setStartupFailed(error_code);
        return err;
    };
    return fwd;
}

fn createUdpForwarder(
    allocator: std.mem.Allocator,
    projectHandle: *project_status.ProjectHandles,
    listen_port: u16,
    target_address: []const u8,
    target_port: u16,
    family: types.AddressFamily,
    enable_stats: bool,
) !*UdpForwarder {
    var error_code: i32 = 0;
    const fwd = try allocator.create(UdpForwarder);
    fwd.* = UdpForwarder.init(allocator, listen_port, target_address, target_port, family, enable_stats, &error_code) catch |err| {
        allocator.destroy(fwd);
        projectHandle.setStartupFailed(error_code);
        return err;
    };
    return fwd;
}

fn startAndRegisterTcp(projectHandle: *project_status.ProjectHandles, fwd: *TcpForwarder) !void {
    try projectHandle.registerTcpHandle(fwd);
    const tcp_thread = try std.Thread.spawn(getThreadConfig(), startTcpForward, .{fwd});
    tcp_thread.detach();
}

fn startAndRegisterUdp(projectHandle: *project_status.ProjectHandles, fwd: *UdpForwarder) !void {
    try projectHandle.registerUdpHandle(fwd);
    const udp_thread = try std.Thread.spawn(getThreadConfig(), startUdpForward, .{fwd});
    udp_thread.detach();
}

// pub fn getProjectStats(project_id: usize) common.TrafficStats {
//     g_handles_mutex.lock();
//     defer g_handles_mutex.unlock();
//     if (project_id >= g_handles.items.len) {
//         return .{ .bytes_in = 0, .bytes_out = 0 };
//     }
//     const h = g_handles.items[project_id];
//     var stats = common.TrafficStats{ .bytes_in = 0, .bytes_out = 0 };
//     if (h.tcp_handles) |tcp_list| {
//         for (tcp_list.items) |t| {
//             const s = tcp_uv.getStatsRaw(t);
//             stats.bytes_in += s.bytes_in;
//             stats.bytes_out += s.bytes_out;
//         }
//     }
//     if (h.udp_handles) |udp_list| {
//         for (udp_list.items) |u| {
//             const s = udp_uv.getStatsRaw(u);
//             stats.bytes_in += s.bytes_in;
//             stats.bytes_out += s.bytes_out;
//         }
//     }
//     return stats;
// }

// pub fn getProjectRuntimeInfo(project_id: usize) project_status.ProjectRuntimeInfo {
//     const h = g_handles.items[project_id];
//     var bytes_in: u64 = 0;
//     var bytes_out: u64 = 0;
//     if (h.tcp_handles) |tcp_list| {
//         for (tcp_list.items) |t| {
//             const s = tcp_uv.getStatsRaw(t);
//             bytes_in += s.bytes_in;
//             bytes_out += s.bytes_out;
//         }
//     }
//     if (h.udp_handles) |udp_list| {
//         for (udp_list.items) |u| {
//             const s = udp_uv.getStatsRaw(u);
//             bytes_in += s.bytes_in;
//             bytes_out += s.bytes_out;
//         }
//     }
//     return .{
//         .active_ports = h.active_ports,
//         .bytes_in = bytes_in,
//         .bytes_out = bytes_out,
//         .startup_status = h.startup_status,
//         .error_code = h.error_code,
//     };
// }

/// Start a port forwarding project
pub fn startForwarding(allocator: std.mem.Allocator, projectHandle: *project_status.ProjectHandles) !void {
    if (!projectHandle.cfg.enable_app_forward) {
        return;
    }
    // Multi-port mode
    if (projectHandle.cfg.port_mappings.len > 0) {
        for (projectHandle.cfg.port_mappings) |mapping| {
            try startForwardingForMapping(allocator, projectHandle, mapping);
        }
        projectHandle.setStartupSuccess();
        return;
    }
    // Single-port mode
    const listen_port_str = try common.portToString(projectHandle.cfg.listen_port, allocator);
    defer allocator.free(listen_port_str);
    const target_port_str = try common.portToString(projectHandle.cfg.target_port, allocator);
    defer allocator.free(target_port_str);

    try startForwardingForMapping(allocator, projectHandle, .{ // convert to mapping
        .protocol = projectHandle.cfg.protocol,
        .listen_port = listen_port_str,
        .target_port = target_port_str,
    });
    projectHandle.setStartupSuccess();
}

/// 解析端口范围字符串，返回起始和结束端口
fn parsePortRange(port_str: []const u8) !common.PortRange {
    return common.parsePortRange(port_str);
}

/// 为单个端口映射启动转发
fn startForwardingForMapping(
    allocator: std.mem.Allocator,
    projectHandle: *project_status.ProjectHandles,
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
                const fwd = createTcpForwarder(allocator, projectHandle, listen_port, projectHandle.cfg.target_address, target_port, projectHandle.cfg.family, projectHandle.cfg.enable_stats) catch |err| {
                    std.debug.print("[TCP] Failed to create forwarder on port {d}: {any}\n", .{ listen_port, err });
                    continue;
                };
                // mapping: start inside thread and non-fatal
                try startAndRegisterTcp(projectHandle, fwd);
            },
            .udp => {
                const fwd = createUdpForwarder(allocator, projectHandle, listen_port, projectHandle.cfg.target_address, target_port, projectHandle.cfg.family, projectHandle.cfg.enable_stats) catch |err| {
                    std.debug.print("[UDP] Failed to create forwarder on port {d}: {any}\n", .{ listen_port, err });
                    continue;
                };
                try startAndRegisterUdp(projectHandle, fwd);
            },
            .both => {
                const tcp_fwd = createTcpForwarder(allocator, projectHandle, listen_port, projectHandle.cfg.target_address, target_port, projectHandle.cfg.family, projectHandle.cfg.enable_stats) catch |err| {
                    std.debug.print("[TCP] Failed to create forwarder on port {d}: {any}\n", .{ listen_port, err });
                    continue;
                };
                const udp_fwd = createUdpForwarder(allocator, projectHandle, listen_port, projectHandle.cfg.target_address, target_port, projectHandle.cfg.family, projectHandle.cfg.enable_stats) catch |err| {
                    std.debug.print("[UDP] Failed to create forwarder on port {d}: {any}\n", .{ listen_port, err });
                    continue;
                };
                try startAndRegisterTcp(projectHandle, tcp_fwd);
                try startAndRegisterUdp(projectHandle, udp_fwd);
            },
        }
    }
}

fn startTcpForward(tcp_forwarder: *TcpForwarder) void {
    defer tcp_forwarder.deinit();
    tcp_forwarder.start() catch |err| {
        std.debug.print("[TCP] Failed to start forwarder: {any}\n", .{err});
        return;
    };
}

fn startUdpForward(udp_forwarder: *UdpForwarder) void {
    defer udp_forwarder.deinit();
    udp_forwarder.start() catch |err| {
        std.debug.print("[UDP] Failed to start forwarder: {any}\n", .{err});
        return;
    };
}
