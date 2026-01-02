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
    projectHandle: *project_status.ProjectHandle,
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
        projectHandle.setStartupFailedCode(error_code);
        return err;
    };
    return fwd;
}

fn createUdpForwarder(
    allocator: std.mem.Allocator,
    projectHandle: *project_status.ProjectHandle,
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
        projectHandle.setStartupFailedCode(error_code);
        return err;
    };
    return fwd;
}

fn startAndRegisterTcp(projectHandle: *project_status.ProjectHandle, fwd: *TcpForwarder) !void {
    std.log.debug("[startAndRegisterTcp] Entry - registering handle...", .{});
    try projectHandle.registerTcpHandle(fwd);
    std.log.debug("[startAndRegisterTcp] Handle registered, spawning thread...", .{});
    const tcp_thread = try std.Thread.spawn(getThreadConfig(), startTcpForward, .{ projectHandle, fwd });
    std.log.debug("[startAndRegisterTcp] Thread spawned, detaching...", .{});
    tcp_thread.detach();
    std.log.debug("[startAndRegisterTcp] Done", .{});
}

fn startAndRegisterUdp(projectHandle: *project_status.ProjectHandle, fwd: *UdpForwarder) !void {
    try projectHandle.registerUdpHandle(fwd);
    const udp_thread = try std.Thread.spawn(getThreadConfig(), startUdpForward, .{ projectHandle, fwd });
    udp_thread.detach();
}

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
                const fwd = createTcpForwarder(allocator, projectHandle, listen_port, projectHandle.cfg.target_address, target_port, projectHandle.cfg.family, projectHandle.cfg.enable_stats) catch |err| {
                    std.log.debug("[TCP] Failed to create forwarder on port {d}: {any}", .{ listen_port, err });
                    continue;
                };
                std.log.debug("[startForwardingForMapping] Starting TCP forwarder on port {d}", .{listen_port});
                // mapping: start inside thread and non-fatal
                try startAndRegisterTcp(projectHandle, fwd);
            },
            .udp => {
                const fwd = createUdpForwarder(allocator, projectHandle, listen_port, projectHandle.cfg.target_address, target_port, projectHandle.cfg.family, projectHandle.cfg.enable_stats) catch |err| {
                    std.log.debug("[UDP] Failed to create forwarder on port {d}: {any}", .{ listen_port, err });
                    continue;
                };
                try startAndRegisterUdp(projectHandle, fwd);
            },
            .both => {
                const tcp_fwd = createTcpForwarder(allocator, projectHandle, listen_port, projectHandle.cfg.target_address, target_port, projectHandle.cfg.family, projectHandle.cfg.enable_stats) catch |err| {
                    std.log.debug("[TCP] Failed to create forwarder on port {d}: {any}", .{ listen_port, err });
                    continue;
                };
                const udp_fwd = createUdpForwarder(allocator, projectHandle, listen_port, projectHandle.cfg.target_address, target_port, projectHandle.cfg.family, projectHandle.cfg.enable_stats) catch |err| {
                    std.log.debug("[UDP] Failed to create forwarder on port {d}: {any}", .{ listen_port, err });
                    continue;
                };
                try startAndRegisterTcp(projectHandle, tcp_fwd);
                try startAndRegisterUdp(projectHandle, udp_fwd);
            },
        }
    }
    std.log.debug("[startForwardingForMapping] All forwarders created and registered", .{});
}

fn startTcpForward(projectHandle: *project_status.ProjectHandle, tcp_forwarder: *TcpForwarder) void {
    std.log.debug("[startTcpForward] Thread started", .{});
    defer tcp_forwarder.deinit();
    std.log.debug("[startTcpForward] Calling tcp_forwarder.start()...", .{});
    tcp_forwarder.start(projectHandle) catch |err| {
        std.log.debug("[TCP] Failed to start forwarder: {any}", .{err});
        projectHandle.setStartupFailed();
        return;
    };
    std.log.debug("[startTcpForward] Forwarder started successfully, entering event loop", .{});
}

fn startUdpForward(projectHandle: *project_status.ProjectHandle, udp_forwarder: *UdpForwarder) void {
    defer udp_forwarder.deinit();
    udp_forwarder.start(projectHandle) catch |err| {
        std.log.debug("[UDP] Failed to start forwarder: {any}", .{err});
        projectHandle.setStartupFailed();
        return;
    };
}
