const std = @import("std");
const types = @import("../config/types.zig");
const project_status = @import("project_status.zig");
const common = @import("app_forward/common.zig");
const tcp_uv = @import("app_forward/tcp_forwarder_uv.zig");
const udp_uv = @import("app_forward/udp_forwarder_uv.zig");
const loop_manager = @import("app_forward/loop_manager.zig");
const forwarder_runtime = @import("app_forward/forwarder_runtime.zig");
const first_packet_hook = @import("first_packet_hook.zig");

pub const ForwardError = common.ForwardError;

pub inline fn getThreadConfig() std.Thread.SpawnConfig {
    return common.getThreadConfig();
}

pub const TcpForwarder = tcp_uv.TcpForwarder;
pub const UdpForwarder = udp_uv.UdpForwarder;

const SharedTcpStartContext = struct {
    allocator: std.mem.Allocator,
    projectHandle: *project_status.ProjectHandle,
    runtime: *loop_manager.LoopRuntime,
    listen_port: u16,
    target_port: u16,

    fn run(ptr: *anyopaque) !void {
        const ctx: *@This() = @ptrCast(@alignCast(ptr));
        const token = forwarder_runtime.runtimeToken(ctx.runtime.ctx.?);
        const fwd = try TcpForwarder.createOnRuntimeThread(ctx.allocator, ctx.projectHandle, token, ctx.listen_port, ctx.target_port);
        try ctx.projectHandle.registerTcpHandle(fwd);
        errdefer {
            ctx.projectHandle.deregisterTcpHandle(fwd) catch |err| {
                std.log.warn("Failed to deregister TCP forwarder after start failure: {}", .{err});
            };
            fwd.destroyOnRuntimeThread(token);
            fwd.destroyWrapper();
        }
        // Register first-packet callback if WoL or protocol filter is enabled.
        if (ctx.projectHandle.cfg.enable_wol or ctx.projectHandle.cfg.enable_protocol_filter) {
            try first_packet_hook.registerCallback(fwd.forwarder, ctx.allocator, &ctx.projectHandle.cfg, ctx.projectHandle.id);
        }
        try fwd.startOnRuntimeThread(token, ctx.projectHandle);
    }
};

const SharedUdpStartContext = struct {
    allocator: std.mem.Allocator,
    projectHandle: *project_status.ProjectHandle,
    runtime: *loop_manager.LoopRuntime,
    listen_port: u16,
    target_port: u16,

    fn run(ptr: *anyopaque) !void {
        const ctx: *@This() = @ptrCast(@alignCast(ptr));
        const token = forwarder_runtime.runtimeToken(ctx.runtime.ctx.?);
        const fwd = try UdpForwarder.createOnRuntimeThread(ctx.allocator, ctx.projectHandle, token, ctx.listen_port, ctx.target_port);
        try ctx.projectHandle.registerUdpHandle(fwd);
        errdefer {
            ctx.projectHandle.deregisterUdpHandle(fwd) catch |err| {
                std.log.warn("Failed to deregister UDP forwarder after start failure: {}", .{err});
            };
            fwd.destroyOnRuntimeThread(token);
            fwd.destroyWrapper();
        }
        try fwd.startOnRuntimeThread(token, ctx.projectHandle);
    }
};

/// Start a port forwarding project.
/// All persistent listener and runtime allocations use `projectHandle.allocator`.
/// The handle allocator must outlive `ProjectHandle.deinit` or `teardownForwarders`.
pub fn startForwarding(projectHandle: *project_status.ProjectHandle) !void {
    const allocator = projectHandle.allocator;
    projectHandle.beginStartup();
    if (!projectHandle.cfg.enable_app_forward) return;

    const mode = projectHandle.cfg.effectiveAppForwardLoopMode(.per_project);

    // Create LoopManager if not already present
    if (projectHandle.runtime_manager == null) {
        projectHandle.runtime_manager = loop_manager.LoopManager.init(allocator) catch |err| {
            projectHandle.recordStartupFailure("unknown", 0, -99);
            projectHandle.finishStartup();
            return err;
        };
    }
    const rm = &projectHandle.runtime_manager.?;

    if (projectHandle.cfg.port_mappings.len > 0) {
        for (projectHandle.cfg.port_mappings) |mapping| {
            _ = startForwardingForMappingBestEffort(allocator, projectHandle, mapping, rm, mode);
        }
        projectHandle.finishStartup();
        return;
    }

    // Single-port mode
    var listen_port_buf: [5]u8 = undefined;
    const listen_port_str = common.portToString(projectHandle.cfg.listen_port, &listen_port_buf);
    var target_port_buf: [5]u8 = undefined;
    const target_port_str = common.portToString(projectHandle.cfg.target_port, &target_port_buf);

    _ = startForwardingForMappingBestEffort(allocator, projectHandle, .{
        .protocol = projectHandle.cfg.protocol,
        .listen_port = listen_port_str,
        .target_port = target_port_str,
    }, rm, mode);
    projectHandle.finishStartup();
}

/// Start a project using an externally owned loop manager.
/// Listener and callback allocations still belong to `projectHandle.allocator`.
pub fn startForwardingWithLoopManager(projectHandle: *project_status.ProjectHandle, runtime_manager: *loop_manager.LoopManager) !void {
    const allocator = projectHandle.allocator;
    projectHandle.beginStartup();
    if (!projectHandle.cfg.enable_app_forward) return;

    const mode = projectHandle.cfg.effectiveAppForwardLoopMode(.per_project);
    var had_failure = false;
    if (projectHandle.cfg.port_mappings.len > 0) {
        for (projectHandle.cfg.port_mappings) |mapping| {
            had_failure = startForwardingForMappingBestEffort(allocator, projectHandle, mapping, runtime_manager, mode) or had_failure;
        }
    } else {
        var listen_port_buf: [5]u8 = undefined;
        const listen_port_str = common.portToString(projectHandle.cfg.listen_port, &listen_port_buf);
        var target_port_buf: [5]u8 = undefined;
        const target_port_str = common.portToString(projectHandle.cfg.target_port, &target_port_buf);
        had_failure = startForwardingForMappingBestEffort(allocator, projectHandle, .{
            .protocol = projectHandle.cfg.protocol,
            .listen_port = listen_port_str,
            .target_port = target_port_str,
        }, runtime_manager, mode);
    }
    projectHandle.finishStartup();
    if (had_failure) return ForwardError.ListenFailed;
}

/// 解析端口范围字符串，返回起始和结束端口
fn parsePortRange(port_str: []const u8) !common.PortRange {
    return common.parsePortRange(port_str);
}

/// 为单个端口映射启动转发 (shared-loop path)
/// Attempts every listener in a mapping so a failed port does not suppress the
/// remaining ports in a range. Returns whether at least one attempt failed.
fn startForwardingForMappingBestEffort(
    allocator: std.mem.Allocator,
    projectHandle: *project_status.ProjectHandle,
    mapping: types.PortMapping,
    runtime_manager: *loop_manager.LoopManager,
    mode: types.LoopMode,
) bool {
    const listen_range = parsePortRange(mapping.listen_port) catch |err| {
        std.log.err("Invalid listen port mapping {s}: {}", .{ mapping.listen_port, err });
        projectHandle.recordStartupFailure("unknown", 0, -5);
        return true;
    };
    const target_range = parsePortRange(mapping.target_port) catch |err| {
        std.log.err("Invalid target port mapping {s}: {}", .{ mapping.target_port, err });
        projectHandle.recordStartupFailure("unknown", 0, -5);
        return true;
    };
    const listen_count = listen_range.end - listen_range.start + 1;
    const target_count = target_range.end - target_range.start + 1;
    if (listen_count != target_count) {
        projectHandle.recordStartupFailure("unknown", listen_range.start, -5);
        return true;
    }

    var shared_lease: ?loop_manager.RuntimeLease = null;
    if (mode != .per_listener) {
        shared_lease = runtime_manager.acquire(mode, projectHandle) catch |err| {
            std.log.err("Failed to acquire forwarding runtime: {}", .{err});
            projectHandle.recordStartupFailure("unknown", listen_range.start, -99);
            return true;
        };
    }
    const active_ports_before = projectHandle.getProjectRuntimeInfo().active_ports;
    var had_failure = false;

    var i: u16 = 0;
    while (i < listen_count) : (i += 1) {
        const listen_port = listen_range.start + i;
        const target_port = target_range.start + i;
        switch (mapping.protocol) {
            .tcp => startAndRegisterSharedTcp(projectHandle, allocator, listen_port, target_port, runtime_manager, mode, shared_lease) catch |err| {
                logUnexpectedStartupFailure(projectHandle, "tcp", listen_port, err);
                had_failure = true;
            },
            .udp => startAndRegisterSharedUdp(projectHandle, allocator, listen_port, target_port, runtime_manager, mode, shared_lease) catch |err| {
                logUnexpectedStartupFailure(projectHandle, "udp", listen_port, err);
                had_failure = true;
            },
            .both => {
                startAndRegisterSharedTcp(projectHandle, allocator, listen_port, target_port, runtime_manager, mode, shared_lease) catch |err| {
                    logUnexpectedStartupFailure(projectHandle, "tcp", listen_port, err);
                    had_failure = true;
                };
                startAndRegisterSharedUdp(projectHandle, allocator, listen_port, target_port, runtime_manager, mode, shared_lease) catch |err| {
                    logUnexpectedStartupFailure(projectHandle, "udp", listen_port, err);
                    had_failure = true;
                };
            },
        }
    }
    if (had_failure and shared_lease != null and projectHandle.getProjectRuntimeInfo().active_ports == active_ports_before) {
        runtime_manager.release(shared_lease.?);
    }
    return had_failure;
}

fn logUnexpectedStartupFailure(projectHandle: *project_status.ProjectHandle, protocol: []const u8, listen_port: u16, err: anyerror) void {
    std.log.warn("Failed to start {s} forwarding on port {d}: {}", .{ protocol, listen_port, err });
    if (err != ForwardError.ListenFailed) {
        projectHandle.recordStartupFailure(protocol, listen_port, -99);
    }
}

fn startAndRegisterSharedTcp(
    projectHandle: *project_status.ProjectHandle,
    allocator: std.mem.Allocator,
    listen_port: u16,
    target_port: u16,
    runtime_manager: *loop_manager.LoopManager,
    mode: types.LoopMode,
    shared_lease: ?loop_manager.RuntimeLease,
) !void {
    var owned_lease: ?loop_manager.RuntimeLease = null;
    const lease = shared_lease orelse blk: {
        owned_lease = try runtime_manager.acquire(mode, projectHandle);
        break :blk owned_lease.?;
    };
    errdefer if (owned_lease) |owned| runtime_manager.release(owned);

    var ctx = SharedTcpStartContext{
        .allocator = allocator,
        .projectHandle = projectHandle,
        .runtime = lease.runtime,
        .listen_port = listen_port,
        .target_port = target_port,
    };
    try lease.runtime.marshal(.{ .callback = SharedTcpStartContext.run, .context = &ctx });
}

fn startAndRegisterSharedUdp(
    projectHandle: *project_status.ProjectHandle,
    allocator: std.mem.Allocator,
    listen_port: u16,
    target_port: u16,
    runtime_manager: *loop_manager.LoopManager,
    mode: types.LoopMode,
    shared_lease: ?loop_manager.RuntimeLease,
) !void {
    var owned_lease: ?loop_manager.RuntimeLease = null;
    const lease = shared_lease orelse blk: {
        owned_lease = try runtime_manager.acquire(mode, projectHandle);
        break :blk owned_lease.?;
    };
    errdefer if (owned_lease) |owned| runtime_manager.release(owned);

    var ctx = SharedUdpStartContext{
        .allocator = allocator,
        .projectHandle = projectHandle,
        .runtime = lease.runtime,
        .listen_port = listen_port,
        .target_port = target_port,
    };
    try lease.runtime.marshal(.{ .callback = SharedUdpStartContext.run, .context = &ctx });
}
