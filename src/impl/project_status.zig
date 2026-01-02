const std = @import("std");
const types = @import("../config/types.zig");
const tcp_uv = @import("app_forward/tcp_forwarder_uv.zig");
const udp_uv = @import("app_forward/udp_forwarder_uv.zig");
pub const TcpForwarder = tcp_uv.TcpForwarder;
pub const UdpForwarder = udp_uv.UdpForwarder;

/// 项目启动状态
pub const StartupStatus = enum(u8) {
    /// 项目未启用（正常）
    disabled = 0,
    /// 启动成功，正在运行
    success = 1,
    /// 启动失败，有错误信息
    failed = 2,

    pub fn toString(self: StartupStatus) [:0]const u8 {
        return switch (self) {
            .disabled => "disabled",
            .success => "success",
            .failed => "failed",
        };
    }
};
pub const ProjectRuntimeInfo = struct {
    active_ports: u32,
    bytes_in: u64,
    bytes_out: u64,
    startup_status: StartupStatus,
    error_code: i32,
};
pub const ProjectHandle = struct {
    allocator: std.mem.Allocator,
    startup_status: StartupStatus = .disabled,
    tcp_forwarders: std.array_list.Managed(*TcpForwarder),
    udp_forwarders: std.array_list.Managed(*UdpForwarder),
    cfg: types.Project,
    error_code: i32 = 0,
    active_ports: u32 = 0,
    id: usize,
    pub fn init(allocator: std.mem.Allocator, id: usize, cfg: types.Project) ProjectHandle {
        return ProjectHandle{
            .tcp_forwarders = std.array_list.Managed(*TcpForwarder).init(allocator),
            .udp_forwarders = std.array_list.Managed(*UdpForwarder).init(allocator),
            .allocator = allocator,
            .id = id,
            .startup_status = .disabled,
            .cfg = cfg,
            .error_code = 0,
            .active_ports = 0,
        };
    }
    pub fn deinit(self: *ProjectHandle) void {
        for (self.tcp_forwarders.items) |fwd| {
            fwd.deinit();
            self.allocator.destroy(fwd);
        }
        for (self.udp_forwarders.items) |fwd| {
            fwd.deinit();
            self.allocator.destroy(fwd);
        }
        self.tcp_forwarders.deinit();
        self.udp_forwarders.deinit();
    }
    pub inline fn setStartupFailed(self: *ProjectHandle, err_code: i32) void {
        self.startup_status = .failed;
        self.error_code = err_code;
    }
    pub inline fn setStartupSuccess(self: *ProjectHandle) void {
        self.startup_status = .success;
        self.error_code = 0;
    }
    pub inline fn registerTcpHandle(self: *ProjectHandle, fwd: *TcpForwarder) !void {
        self.active_ports += 1;
        try self.tcp_forwarders.append(fwd);
    }
    pub inline fn registerUdpHandle(self: *ProjectHandle, fwd: *UdpForwarder) !void {
        self.active_ports += 1;
        try self.udp_forwarders.append(fwd);
    }
};
pub fn stopAll(handles: *std.array_list.Managed(ProjectHandle)) void {
    for (handles.items) |*handle| {
        handle.deinit();
    }
    handles.clearAndFree();
}
