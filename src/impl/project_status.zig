const std = @import("std");
const types = @import("../config/types.zig");
const tcp_uv = @import("app_forward/tcp_forwarder_uv.zig");
const udp_uv = @import("app_forward/udp_forwarder_uv.zig");
const app_forward = @import("app_forward.zig");
const loop_manager = @import("app_forward/loop_manager.zig");
const uv = @import("app_forward/uv.zig");
const c = uv.c;
const compat = @import("../compat.zig");
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
    listen_port: u16,
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
    lock: std.Io.Mutex = .init,
    cfg: types.Project,
    error_code: i32 = 0,
    active_ports: u32 = 0,
    id: usize,
    runtime_enabled: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    shutting_down: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    runtime_enabled_lock: std.Io.Mutex = .init,
    runtime_manager: ?loop_manager.LoopManager = null,

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
        self.shutting_down.store(true, .seq_cst);

        if (self.runtime_manager) |*manager| {
            manager.releaseProjectRuntime(self) catch |err| {
                std.log.err("Failed to release runtimes for project {d}: {}", .{ self.id, err });
                self.stopSharedForwarders() catch |stop_err| {
                    std.log.err("Failed to stop forwarders for project {d}: {}", .{ self.id, stop_err });
                };
            };
            manager.deinit();
            self.runtime_manager = null;
        } else {
            self.stopSharedForwarders() catch |err| {
                std.log.err("Failed to stop forwarders for project {d}: {}", .{ self.id, err });
            };
        }

        self.destroySharedForwardersAfterRuntimeStop() catch |err| {
            std.log.err("Failed to free forwarder wrappers for project {d}: {}", .{ self.id, err });
        };

        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());
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
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());
        defer self.updateRuntimeStatus();
        const index = try self.findIndexOfTcpForwarder(fwd);
        _ = self.tcp_forwarders.swapRemove(index);
        if (self.active_ports > 0) {
            self.active_ports -= 1;
        }
    }
    pub inline fn registerTcpHandle(self: *ProjectHandle, fwd: *TcpForwarder) !void {
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());
        if (self.shutting_down.load(.seq_cst)) return error.ProjectStopping;
        defer self.updateRuntimeStatus();
        self.active_ports += 1;
        try self.tcp_forwarders.append(fwd);
    }
    pub inline fn deregisterUdpHandle(self: *ProjectHandle, fwd: *UdpForwarder) !void {
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());
        defer self.updateRuntimeStatus();
        const index = try self.findIndexOfUdpForwarder(fwd);
        _ = self.udp_forwarders.swapRemove(index);
        if (self.active_ports > 0) {
            self.active_ports -= 1;
        }
    }
    pub inline fn registerUdpHandle(self: *ProjectHandle, fwd: *UdpForwarder) !void {
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());
        if (self.shutting_down.load(.seq_cst)) return error.ProjectStopping;
        defer self.updateRuntimeStatus();
        self.active_ports += 1;
        try self.udp_forwarders.append(fwd);
    }

    /// Frees shared-loop forwarder wrappers after their owning loop runtime has
    /// destroyed the C resources on the runtime thread.
    pub fn destroySharedForwardersAfterRuntimeStop(self: *ProjectHandle) !void {
        self.lock.lockUncancelable(compat.io());
        const tcp_forwarders = self.allocator.dupe(*TcpForwarder, self.tcp_forwarders.items) catch |err| {
            self.lock.unlock(compat.io());
            return err;
        };
        errdefer self.allocator.free(tcp_forwarders);
        const udp_forwarders = self.allocator.dupe(*UdpForwarder, self.udp_forwarders.items) catch |err| {
            self.lock.unlock(compat.io());
            return err;
        };
        self.lock.unlock(compat.io());
        defer self.allocator.free(tcp_forwarders);
        defer self.allocator.free(udp_forwarders);

        for (tcp_forwarders) |fwd| {
            self.deregisterTcpHandle(fwd) catch |err| {
                std.log.warn("Failed to deregister TCP forwarder for project {d}: {}", .{ self.id, err });
            };
            fwd.destroyWrapper();
        }
        for (udp_forwarders) |fwd| {
            self.deregisterUdpHandle(fwd) catch |err| {
                std.log.warn("Failed to deregister UDP forwarder for project {d}: {}", .{ self.id, err });
            };
            fwd.destroyWrapper();
        }
    }

    /// Runs on the owning runtime thread during runtime shutdown, after backend
    /// close callbacks have drained and before the runtime itself is closed.
    pub fn destroySharedForwarderCResourcesForRuntime(self: *ProjectHandle, runtime: *c.forwarder_runtime_t) void {
        const token = uv.runtimeToken(runtime);
        self.lock.lockUncancelable(compat.io());
        const tcp_forwarders = self.allocator.dupe(*TcpForwarder, self.tcp_forwarders.items) catch |err| {
            self.lock.unlock(compat.io());
            std.log.err("Failed to snapshot TCP forwarders for C destroy in project {d}: {}", .{ self.id, err });
            return;
        };
        const udp_forwarders = self.allocator.dupe(*UdpForwarder, self.udp_forwarders.items) catch |err| {
            self.lock.unlock(compat.io());
            self.allocator.free(tcp_forwarders);
            std.log.err("Failed to snapshot UDP forwarders for C destroy in project {d}: {}", .{ self.id, err });
            return;
        };
        self.lock.unlock(compat.io());
        defer self.allocator.free(tcp_forwarders);
        defer self.allocator.free(udp_forwarders);

        for (tcp_forwarders) |fwd| {
            if (fwd.belongsToRuntime(runtime)) {
                fwd.destroyOnRuntimeThread(token);
            }
        }
        for (udp_forwarders) |fwd| {
            if (fwd.belongsToRuntime(runtime)) {
                fwd.destroyOnRuntimeThread(token);
            }
        }
    }

    /// Requests loop-thread closure for shared-loop forwarders. The loop manager
    /// calls this before stopping the runtime so C close callbacks can release
    /// per-listener/session allocations while the libuv loop is still alive.
    pub fn stopSharedForwarders(self: *ProjectHandle) !void {
        self.lock.lockUncancelable(compat.io());
        const tcp_forwarders = self.allocator.dupe(*TcpForwarder, self.tcp_forwarders.items) catch |err| {
            self.lock.unlock(compat.io());
            return err;
        };
        errdefer self.allocator.free(tcp_forwarders);
        const udp_forwarders = self.allocator.dupe(*UdpForwarder, self.udp_forwarders.items) catch |err| {
            self.lock.unlock(compat.io());
            return err;
        };
        self.lock.unlock(compat.io());
        defer self.allocator.free(tcp_forwarders);
        defer self.allocator.free(udp_forwarders);

        for (tcp_forwarders) |fwd| {
            fwd.requestStop();
        }
        for (udp_forwarders) |fwd| {
            fwd.requestStop();
        }
    }

    fn collectProjectStatsLocked(self: *ProjectHandle) TrafficStats {
        var stats = TrafficStats{ .bytes_in = 0, .bytes_out = 0, .listen_port = 0 };
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

    pub fn getProjectStats(self: *ProjectHandle) TrafficStats {
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());

        return self.collectProjectStatsLocked();
    }

    pub fn getProjectRuntimeInfo(self: *ProjectHandle) ProjectRuntimeInfo {
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());

        const s = self.collectProjectStatsLocked();
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
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());

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
                .local_port = s.listen_port,
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
                .local_port = s.listen_port,
                .bytes_in = s.bytes_in,
                .bytes_out = s.bytes_out,
            };
            idx += 1;
        }

        return stats;
    }

    /// Set runtime enabled state (controls forwarding without restarting threads)
    pub fn setRuntimeEnabled(self: *ProjectHandle, enabled: bool) void {
        self.runtime_enabled_lock.lockUncancelable(compat.io());
        defer self.runtime_enabled_lock.unlock(compat.io());
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
                if (self.runtime_manager) |*manager| {
                    manager.releaseProjectRuntime(self) catch |err| {
                        std.log.err("Failed to release runtimes for project {d}: {}", .{ self.id, err });
                    };
                    manager.deinit();
                    self.runtime_manager = null;
                } else {
                    self.stopSharedForwarders() catch |err| {
                        std.log.err("Failed to stop forwarders for project {d}: {}", .{ self.id, err });
                    };
                    self.destroySharedForwardersAfterRuntimeStop() catch |err| {
                        std.log.err("Failed to free forwarders for project {d}: {}", .{ self.id, err });
                    };
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

test "project status: init yields empty runtime info" {
    const allocator = std.testing.allocator;

    var cfg = types.Project{
        .listen_port = 8080,
        .target_address = try allocator.dupe(u8, "127.0.0.1"),
        .target_port = 80,
    };
    defer cfg.deinit(allocator);

    var handle = ProjectHandle.init(allocator, 7, cfg);
    defer handle.deinit();

    const runtime = handle.getProjectRuntimeInfo();
    try std.testing.expectEqual(@as(u32, 0), runtime.active_ports);
    try std.testing.expectEqual(@as(u64, 0), runtime.bytes_in);
    try std.testing.expectEqual(@as(u64, 0), runtime.bytes_out);
    try std.testing.expectEqual(StartupStatus.disabled, runtime.startup_status);
    try std.testing.expectEqual(@as(i32, 0), runtime.error_code);
    try std.testing.expect(!handle.isRuntimeEnabled());
}

test "project status: startup status transitions update error code" {
    const allocator = std.testing.allocator;

    var cfg = types.Project{
        .listen_port = 8080,
        .target_address = try allocator.dupe(u8, "127.0.0.1"),
        .target_port = 80,
    };
    defer cfg.deinit(allocator);

    var handle = ProjectHandle.init(allocator, 0, cfg);
    defer handle.deinit();

    handle.setStartupFailedCode(-5);
    try std.testing.expectEqual(StartupStatus.failed, handle.startup_status);
    try std.testing.expectEqual(@as(i32, -5), handle.error_code);

    handle.setStartupSuccess();
    try std.testing.expectEqual(StartupStatus.success, handle.startup_status);
    try std.testing.expectEqual(@as(i32, 0), handle.error_code);

    handle.setDisabled();
    try std.testing.expectEqual(StartupStatus.disabled, handle.startup_status);
}
