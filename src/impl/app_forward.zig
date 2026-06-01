const std = @import("std");
const types = @import("../config/types.zig");
const project_status = @import("project_status.zig");
const common = @import("app_forward/common.zig");
const tcp_uv = @import("app_forward/tcp_forwarder_uv.zig");
const udp_uv = @import("app_forward/udp_forwarder_uv.zig");
const loop_manager = @import("app_forward/loop_manager.zig");
const forwarder_runtime = @import("app_forward/forwarder_runtime.zig");

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
/// Creates a LoopManager on the project if one does not already exist,
/// then delegates to the shared-loop code path.
pub fn startForwarding(allocator: std.mem.Allocator, projectHandle: *project_status.ProjectHandle) !void {
    errdefer projectHandle.setStartupFailed();
    if (!projectHandle.cfg.enable_app_forward) return;

    const mode = projectHandle.cfg.effectiveAppForwardLoopMode(.per_project);

    // Create LoopManager if not already present
    if (projectHandle.runtime_manager == null) {
        projectHandle.runtime_manager = try loop_manager.LoopManager.init(allocator);
    }
    const rm = &projectHandle.runtime_manager.?;

    if (projectHandle.cfg.port_mappings.len > 0) {
        for (projectHandle.cfg.port_mappings) |mapping| {
            startForwardingForMappingWithLoopManager(allocator, projectHandle, mapping, rm, mode) catch |err| {
                std.log.err("Failed to start forwarding: {}", .{err});
            };
        }
        projectHandle.setStartupSuccess();
        return;
    }

    // Single-port mode
    var listen_port_buf: [5]u8 = undefined;
    const listen_port_str = common.portToString(projectHandle.cfg.listen_port, &listen_port_buf);
    var target_port_buf: [5]u8 = undefined;
    const target_port_str = common.portToString(projectHandle.cfg.target_port, &target_port_buf);

    startForwardingForMappingWithLoopManager(allocator, projectHandle, .{
        .protocol = projectHandle.cfg.protocol,
        .listen_port = listen_port_str,
        .target_port = target_port_str,
    }, rm, mode) catch |err| {
        std.log.err("Failed to start forwarding: {}", .{err});
    };
    projectHandle.setStartupSuccess();
}

pub fn startForwardingWithLoopManager(allocator: std.mem.Allocator, projectHandle: *project_status.ProjectHandle, runtime_manager: *loop_manager.LoopManager) !void {
    errdefer projectHandle.setStartupFailed();
    if (!projectHandle.cfg.enable_app_forward) return;

    const mode = projectHandle.cfg.effectiveAppForwardLoopMode(.per_project);
    if (projectHandle.cfg.port_mappings.len > 0) {
        for (projectHandle.cfg.port_mappings) |mapping| {
            try startForwardingForMappingWithLoopManager(allocator, projectHandle, mapping, runtime_manager, mode);
        }
        projectHandle.setStartupSuccess();
        return;
    }

    var listen_port_buf: [5]u8 = undefined;
    const listen_port_str = common.portToString(projectHandle.cfg.listen_port, &listen_port_buf);
    var target_port_buf: [5]u8 = undefined;
    const target_port_str = common.portToString(projectHandle.cfg.target_port, &target_port_buf);
    try startForwardingForMappingWithLoopManager(allocator, projectHandle, .{
        .protocol = projectHandle.cfg.protocol,
        .listen_port = listen_port_str,
        .target_port = target_port_str,
    }, runtime_manager, mode);
    projectHandle.setStartupSuccess();
}

/// 解析端口范围字符串，返回起始和结束端口
fn parsePortRange(port_str: []const u8) !common.PortRange {
    return common.parsePortRange(port_str);
}

/// 为单个端口映射启动转发 (shared-loop path)
fn startForwardingForMappingWithLoopManager(
    allocator: std.mem.Allocator,
    projectHandle: *project_status.ProjectHandle,
    mapping: types.PortMapping,
    runtime_manager: *loop_manager.LoopManager,
    mode: types.LoopMode,
) !void {
    const listen_range = try parsePortRange(mapping.listen_port);
    const target_range = try parsePortRange(mapping.target_port);
    const listen_count = listen_range.end - listen_range.start + 1;
    const target_count = target_range.end - target_range.start + 1;
    if (listen_count != target_count) return ForwardError.InvalidAddress;

    var shared_lease: ?loop_manager.RuntimeLease = null;
    if (mode != .per_listener) {
        shared_lease = try runtime_manager.acquire(mode, projectHandle);
    }
    errdefer if (shared_lease) |lease| {
        if (projectHandle.getProjectRuntimeInfo().active_ports > 0) {
            runtime_manager.releaseProjectRuntime(projectHandle) catch |err| {
                std.log.err("Failed to roll back partially started shared runtime: {}", .{err});
                runtime_manager.release(lease);
            };
        } else {
            runtime_manager.release(lease);
        }
    };

    var i: u16 = 0;
    while (i < listen_count) : (i += 1) {
        const listen_port = listen_range.start + i;
        const target_port = target_range.start + i;
        switch (mapping.protocol) {
            .tcp => try startAndRegisterSharedTcp(projectHandle, allocator, listen_port, target_port, runtime_manager, mode, shared_lease),
            .udp => try startAndRegisterSharedUdp(projectHandle, allocator, listen_port, target_port, runtime_manager, mode, shared_lease),
            .both => {
                try startAndRegisterSharedTcp(projectHandle, allocator, listen_port, target_port, runtime_manager, mode, shared_lease);
                try startAndRegisterSharedUdp(projectHandle, allocator, listen_port, target_port, runtime_manager, mode, shared_lease);
            },
        }
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
