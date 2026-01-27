const std = @import("std");
const types = @import("../config/types.zig");
const tcp_uv = @import("app_forward/tcp_forwarder_uv.zig");
const udp_uv = @import("app_forward/udp_forwarder_uv.zig");
const app_forward = @import("app_forward.zig");
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

pub const TrafficStats = struct {
    bytes_in: u64,
    bytes_out: u64,
};

/// Statistics for a single forwarder (port)
pub const ForwarderStats = struct {
    protocol: []const u8, // "tcp" or "udp"
    local_port: u16,
    bytes_in: u64,
    bytes_out: u64,
};

pub const ProjectHandle = struct {
    allocator: std.mem.Allocator,
    startup_status: StartupStatus = .disabled,
    tcp_forwarders: std.array_list.Managed(*TcpForwarder),
    udp_forwarders: std.array_list.Managed(*UdpForwarder),
    lock: std.Thread.Mutex = .{},
    cfg: types.Project,
    error_code: i32 = 0,
    active_ports: u32 = 0,
    id: usize,
    runtime_enabled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    runtime_enabled_lock: std.Thread.Mutex = .{},

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
            fwd.stop();
        }
        for (self.udp_forwarders.items) |fwd| {
            fwd.stop();
        }
        // up to 5s
        const rate = 10;
        for (0..10 * rate) |_| {
            if (self.tcp_forwarders.items.len == 0 and self.udp_forwarders.items.len == 0) {
                break;
            }
            std.Thread.sleep(std.time.ns_per_s / rate);
        }
        self.tcp_forwarders.deinit();
        self.udp_forwarders.deinit();
    }
    pub inline fn setStartupFailedCode(self: *ProjectHandle, err_code: i32) void {
        self.startup_status = .failed;
        self.error_code = err_code;
    }
    pub inline fn setDisabled(self: *ProjectHandle) void {
        self.startup_status = .disabled;
    }
    pub inline fn setStartupFailed(self: *ProjectHandle) void {
        self.startup_status = .failed;
    }
    pub inline fn setStartupSuccess(self: *ProjectHandle) void {
        self.startup_status = .success;
        self.error_code = 0;
    }
    inline fn updateRuntimeStatus(self: *ProjectHandle) void {
        if (self.active_ports > 0) {
            self.runtime_enabled.store(true, .seq_cst);
        } else {
            self.runtime_enabled.store(false, .seq_cst);
        }
    }
    inline fn findIndexOfTcpForwarder(self: *ProjectHandle, fwd: *TcpForwarder) !usize {
        for (self.tcp_forwarders.items, 0..) |item, index| {
            if (item == fwd) {
                return index;
            }
        }
        return error.NotFound;
    }
    inline fn findIndexOfUdpForwarder(self: *ProjectHandle, fwd: *UdpForwarder) !usize {
        for (self.udp_forwarders.items, 0..) |item, index| {
            if (item == fwd) {
                return index;
            }
        }
        return error.NotFound;
    }
    pub inline fn deregisterTcpHandle(self: *ProjectHandle, fwd: *TcpForwarder) !void {
        self.lock.lock();
        defer self.lock.unlock();
        defer self.updateRuntimeStatus();
        self.active_ports -= 1;
        const index = try self.findIndexOfTcpForwarder(fwd);
        _ = self.tcp_forwarders.swapRemove(index);
    }
    pub inline fn registerTcpHandle(self: *ProjectHandle, fwd: *TcpForwarder) !void {
        self.lock.lock();
        defer self.lock.unlock();
        defer self.updateRuntimeStatus();
        self.active_ports += 1;
        try self.tcp_forwarders.append(fwd);
    }
    pub inline fn deregisterUdpHandle(self: *ProjectHandle, fwd: *UdpForwarder) !void {
        self.lock.lock();
        defer self.lock.unlock();
        defer self.updateRuntimeStatus();
        self.active_ports -= 1;
        const index = try self.findIndexOfUdpForwarder(fwd);
        _ = self.udp_forwarders.swapRemove(index);
    }
    pub inline fn registerUdpHandle(self: *ProjectHandle, fwd: *UdpForwarder) !void {
        self.lock.lock();
        defer self.lock.unlock();
        defer self.updateRuntimeStatus();
        self.active_ports += 1;
        try self.udp_forwarders.append(fwd);
    }

    pub fn getProjectStats(self: *ProjectHandle) TrafficStats {
        var stats = TrafficStats{ .bytes_in = 0, .bytes_out = 0 };
        // Sum stats from all TCP forwarders
        for (self.tcp_forwarders.items) |fwd| {
            const s = fwd.getStats();
            stats.bytes_in += s.bytes_in;
            stats.bytes_out += s.bytes_out;
        }
        // Sum stats from all UDP forwarders
        for (self.udp_forwarders.items) |fwd| {
            const s = fwd.getStats();
            stats.bytes_in += s.bytes_in;
            stats.bytes_out += s.bytes_out;
        }
        return stats;
    }

    pub fn getProjectRuntimeInfo(self: *ProjectHandle) ProjectRuntimeInfo {
        const s = self.getProjectStats();
        return .{
            .active_ports = self.active_ports,
            .bytes_in = s.bytes_in,
            .bytes_out = s.bytes_out,
            .startup_status = self.startup_status,
            .error_code = self.error_code,
        };
    }

    /// Get statistics for each individual forwarder (port)
    /// Note: Since forwarders don't store port info, we use the project config
    pub fn getForwarderStats(self: *ProjectHandle, allocator: std.mem.Allocator) ![]ForwarderStats {
        self.lock.lock();
        defer self.lock.unlock();

        const total_count = self.tcp_forwarders.items.len + self.udp_forwarders.items.len;
        if (total_count == 0) {
            return &[_]ForwarderStats{};
        }

        const stats = try allocator.alloc(ForwarderStats, total_count);
        errdefer allocator.free(stats);

        var idx: usize = 0;

        // Get stats from TCP forwarders
        for (self.tcp_forwarders.items) |fwd| {
            const s = fwd.getStats();
            stats[idx] = ForwarderStats{
                .protocol = "tcp",
                .local_port = self.cfg.listen_port,
                .bytes_in = s.bytes_in,
                .bytes_out = s.bytes_out,
            };
            idx += 1;
        }

        // Get stats from UDP forwarders
        for (self.udp_forwarders.items) |fwd| {
            const s = fwd.getStats();
            stats[idx] = ForwarderStats{
                .protocol = "udp",
                .local_port = self.cfg.listen_port,
                .bytes_in = s.bytes_in,
                .bytes_out = s.bytes_out,
            };
            idx += 1;
        }

        return stats;
    }

    /// Set runtime enabled state (controls forwarding without restarting threads)
    pub fn setRuntimeEnabled(self: *ProjectHandle, enabled: bool) void {
        self.runtime_enabled_lock.lock();
        defer self.runtime_enabled_lock.unlock();
        const old = self.isRuntimeEnabled();
        // const old = self.runtime_enabled.swap(enabled, .seq_cst);
        std.log.debug("Project {d} ({s}) runtime enabled set to {} (was {})", .{ self.id, self.cfg.remark, enabled, old });
        if (old != enabled) {
            if (enabled) {
                std.log.info("Project {d} ({s}) runtime enabled", .{ self.id, self.cfg.remark });
                // Start all forwarders
                app_forward.startForwarding(self.allocator, self) catch {
                    std.log.err("Failed to start forwarding for project {d} ({s})", .{ self.id, self.cfg.remark });
                };
            } else {
                std.log.info("Project {d} ({s}) runtime disabled - stopping forwarders", .{ self.id, self.cfg.remark });
                // Stop all forwarders
                for (self.tcp_forwarders.items) |fwd| {
                    fwd.stop();
                }
                for (self.udp_forwarders.items) |fwd| {
                    fwd.stop();
                }
            }
        }
    }

    /// Get current runtime enabled state
    pub fn isRuntimeEnabled(self: *ProjectHandle) bool {
        return self.runtime_enabled.load(.seq_cst);
    }
};
pub fn stopAll(handles: *std.array_list.Managed(ProjectHandle)) void {
    for (handles.items) |*handle| {
        handle.deinit();
    }
    handles.clearAndFree();
}
