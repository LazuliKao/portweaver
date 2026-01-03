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

/// Start a port forwarding project
pub fn startForwarding(allocator: std.mem.Allocator, projectHandle: *project_status.ProjectHandle) !void {
    errdefer {
        projectHandle.setStartupFailed();
    }
    std.log.debug("[startForwarding] Entry - project {d}", .{projectHandle.id});
    if (!projectHandle.cfg.enable_app_forward) {
        std.log.debug("[startForwarding] App forward disabled, returning", .{});
        return;
    }
    // Multi-port mode
    if (projectHandle.cfg.port_mappings.len > 0) {
        std.log.debug("[startForwarding] Multi-port mode - {d} mappings", .{projectHandle.cfg.port_mappings.len});
        for (projectHandle.cfg.port_mappings) |mapping| {
            try startForwardingForMapping(allocator, projectHandle, mapping);
        }
        projectHandle.setStartupSuccess();
        return;
    }
    // Single-port mode
    std.log.debug("[startForwarding] Single-port mode - port {d}", .{projectHandle.cfg.listen_port});
    const listen_port_str = try common.portToString(projectHandle.cfg.listen_port, allocator);
    defer allocator.free(listen_port_str);
    const target_port_str = try common.portToString(projectHandle.cfg.target_port, allocator);
    defer allocator.free(target_port_str);

    std.log.debug("[startForwarding] Calling startForwardingForMapping...", .{});
    try startForwardingForMapping(allocator, projectHandle, .{ // convert to mapping
        .protocol = projectHandle.cfg.protocol,
        .listen_port = listen_port_str,
        .target_port = target_port_str,
    });
    std.log.debug("[startForwarding] Setting startup success...", .{});
    projectHandle.setStartupSuccess();
    std.log.debug("[startForwarding] Done", .{});
}

/// 解析端口范围字符串，返回起始和结束端口
fn parsePortRange(port_str: []const u8) !common.PortRange {
    return common.parsePortRange(port_str);
}

/// 为单个端口映射启动转发
fn startForwardingForMapping(
    allocator: std.mem.Allocator,
    projectHandle: *project_status.ProjectHandle,
    mapping: types.PortMapping,
) !void {
    std.log.debug("[startForwardingForMapping] Entry - parsing port ranges", .{});
    const listen_range = try parsePortRange(mapping.listen_port);
    const target_range = try parsePortRange(mapping.target_port);

    std.log.debug("[startForwardingForMapping] Listen range: {d}-{d}, Target range: {d}-{d}", .{ listen_range.start, listen_range.end, target_range.start, target_range.end });

    // 验证端口范围长度一致
    const listen_count = listen_range.end - listen_range.start + 1;
    const target_count = target_range.end - target_range.start + 1;

    if (listen_count != target_count) {
        std.log.debug("[Forward] Port range mismatch: {d} listen ports vs {d} target ports", .{ listen_count, target_count });
        return ForwardError.InvalidAddress;
    }

    std.log.debug("[startForwardingForMapping] Starting {d} port forwarder(s), protocol={s}", .{ listen_count, @tagName(mapping.protocol) });
    // 为范围内的每个端口启动转发
    var i: u16 = 0;
    while (i < listen_count) : (i += 1) {
        const listen_port = listen_range.start + i;
        const target_port = target_range.start + i;

        std.log.debug("[startForwardingForMapping] Creating forwarder {d}/{d} on port {d}", .{ i + 1, listen_count, listen_port });

        switch (mapping.protocol) {
            .tcp => {
                try startAndRegisterTcp(projectHandle, allocator, listen_port, target_port);
            },
            .udp => {
                try startAndRegisterUdp(projectHandle, allocator, listen_port, target_port);
            },
            .both => {
                try startAndRegisterTcp(projectHandle, allocator, listen_port, target_port);
                try startAndRegisterUdp(projectHandle, allocator, listen_port, target_port);
            },
        }
    }
    std.log.debug("[startForwardingForMapping] All forwarders created and registered", .{});
}

fn startAndRegisterTcp(projectHandle: *project_status.ProjectHandle, allocator: std.mem.Allocator, listen_port: u16, target_port: u16) !void {
    const fwd = TcpForwarder.init(allocator, projectHandle, listen_port, target_port) catch |err| {
        std.log.debug("[TCP] Failed to create forwarder on port {d}: {any}", .{ listen_port, err });
        return;
    };

    const tcp_thread = try std.Thread.spawn(getThreadConfig(), loopTcpForward, .{ projectHandle, fwd });
    tcp_thread.detach();
}

fn startAndRegisterUdp(projectHandle: *project_status.ProjectHandle, allocator: std.mem.Allocator, listen_port: u16, target_port: u16) !void {
    const fwd = UdpForwarder.init(allocator, projectHandle, listen_port, target_port) catch |err| {
        std.log.debug("[UDP] Failed to create forwarder on port {d}: {any}", .{ listen_port, err });
        return;
    };

    const udp_thread = try std.Thread.spawn(getThreadConfig(), loopUdpForward, .{ projectHandle, fwd });
    udp_thread.detach();
}

fn loopTcpForward(projectHandle: *project_status.ProjectHandle, tcp_forwarder: *TcpForwarder) void {
    std.log.debug("[TcpForward] Thread started", .{});
    defer {
        projectHandle.deregisterTcpHandle(tcp_forwarder) catch {};
        tcp_forwarder.deinit();
    }
    projectHandle.registerTcpHandle(tcp_forwarder) catch |err| {
        std.log.debug("[TCP] Failed to register forwarder: {any}", .{err});
        projectHandle.setStartupFailed();
        return;
    };
    tcp_forwarder.start(projectHandle) catch |err| {
        std.log.debug("[TCP] Failed to start forwarder: {any}", .{err});
        projectHandle.setStartupFailed();
        return;
    };
    std.log.debug("[TcpForward] Thread done.", .{});
}

fn loopUdpForward(projectHandle: *project_status.ProjectHandle, udp_forwarder: *UdpForwarder) void {
    std.log.debug("[UdpForward] Thread started", .{});
    defer {
        projectHandle.deregisterUdpHandle(udp_forwarder) catch {};
        udp_forwarder.deinit();
    }
    projectHandle.registerUdpHandle(udp_forwarder) catch |err| {
        std.log.debug("[UDP] Failed to register forwarder: {any}", .{err});
        projectHandle.setStartupFailed();
        return;
    };
    udp_forwarder.start(projectHandle) catch |err| {
        std.log.debug("[UDP] Failed to start forwarder: {any}", .{err});
        projectHandle.setStartupFailed();
        return;
    };
    std.log.debug("[UdpForward] Thread done.", .{});
}
