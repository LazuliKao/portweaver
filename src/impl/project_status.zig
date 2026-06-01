const std = @import("std");
const types = @import("../config/types.zig");
const tcp_uv = @import("app_forward/tcp_forwarder_uv.zig");
const udp_uv = @import("app_forward/udp_forwarder_uv.zig");
const app_forward = @import("app_forward.zig");
const loop_manager = @import("app_forward/loop_manager.zig");
const uv = @import("app_forward/uv.zig");
const c = uv.c;
const compat = @import("../compat.zig");
const build_options = @import("build_options");
const nft_fw = if (build_options.nftables_mode) @import("nft_firewall.zig") else void;
const nft_mod = if (build_options.nftables_mode) @import("../nftables/mod.zig") else void;
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
    active_sessions: u32,
    startup_status: StartupStatus,
    error_code: i32,
};

pub const TrafficStats = struct {
    bytes_in: u64,
    bytes_out: u64,
    listen_port: u16,
    active_sessions: u32 = 0,
};

/// Statistics for a single forwarder (port)
pub const ForwarderStats = struct {
    protocol: []const u8, // "tcp" or "udp"
    local_port: u16,
    bytes_in: u64,
    bytes_out: u64,
    active_sessions: u32,
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
        var stats = TrafficStats{ .bytes_in = 0, .bytes_out = 0, .listen_port = 0, .active_sessions = 0 };
        // Sum stats from all TCP forwarders
        for (self.tcp_forwarders.items) |fwd| {
            const s = fwd.getStats();
            stats.bytes_in += s.bytes_in;
            stats.bytes_out += s.bytes_out;
            stats.active_sessions += s.active_sessions;
        }
        // Sum stats from all UDP forwarders
        for (self.udp_forwarders.items) |fwd| {
            const s = fwd.getStats();
            stats.bytes_in += s.bytes_in;
            stats.bytes_out += s.bytes_out;
            stats.active_sessions += s.active_sessions;
        }
        return stats;
    }

    pub fn getProjectStats(self: *ProjectHandle) TrafficStats {
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());

        var stats = self.collectProjectStatsLocked();

        // Add nftables firewall stats when enabled
        if (build_options.nftables_mode and self.shouldUseNftStats()) {
            if (self.collectNftStatsLocked()) |nft| {
                stats.bytes_in += nft.bytes_in;
                stats.bytes_out += nft.bytes_out;
            } else |_| {}
        }

        return stats;
    }

    pub fn getProjectRuntimeInfo(self: *ProjectHandle) ProjectRuntimeInfo {
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());

        var s = self.collectProjectStatsLocked();

        // Add nftables firewall stats when enabled
        if (build_options.nftables_mode and self.shouldUseNftStats()) {
            if (self.collectNftStatsLocked()) |nft| {
                s.bytes_in += nft.bytes_in;
                s.bytes_out += nft.bytes_out;
            } else |_| {}
        }

        return .{
            .active_ports = self.active_ports,
            .bytes_in = s.bytes_in,
            .bytes_out = s.bytes_out,
            .active_sessions = s.active_sessions,
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
            // No app-layer forwarders — try nftables counters for pure firewall mode
            if (self.shouldUseNftStats()) {
                return self.collectNftForwarderStats(allocator);
            }
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
                .active_sessions = s.active_sessions,
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
                .active_sessions = s.active_sessions,
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

    /// Whether this project should collect nftables counter stats.
    /// Requires: nftables build, enable_firewall_stats flag, and add_firewall_forward flag.
    fn shouldUseNftStats(self: *const ProjectHandle) bool {
        if (!build_options.nftables_mode) return false;
        if (!self.cfg.enable_firewall_stats) return false;
        return self.cfg.add_firewall_forward;
    }

    /// Collect nftables counter stats by running a single batch `reset counters`
    /// command. This avoids output buffer accumulation bugs from sequential reads.
    /// Must be called while lock is held.
    fn collectNftStatsLocked(self: *ProjectHandle) !TrafficStats {
        var stats = TrafficStats{ .bytes_in = 0, .bytes_out = 0, .listen_port = 0, .active_sessions = 0 };
        if (build_options.nftables_mode) {
            var ctx = try nft_mod.NftablesContext.init(self.allocator);
            defer ctx.deinit();
            try ctx.setJsonOutput();

            // Batch reset ALL counters in one command — single kernel round-trip,
            // no output buffer accumulation between reads.
            const cmd: [*:0]const u8 = "reset counters table inet portweaver";
            ctx.runCommand(cmd) catch return stats;
            const batch_output = ctx.getOutputMsg() orelse return stats;

            if (self.cfg.port_mappings.len > 0) {
                for (self.cfg.port_mappings) |mapping| {
                    collectNftCountersFromBatch(batch_output, mapping.listen_port, mapping.protocol, &stats);
                }
            } else {
                var port_buf: [5]u8 = undefined;
                const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{self.cfg.listen_port}) catch unreachable;
                collectNftCountersFromBatch(batch_output, port_str, self.cfg.protocol, &stats);
            }
        }
        return stats;
    }

    /// Generate per-port ForwarderStats from nftables counters when no app-layer
    /// forwarders exist (pure firewall mode). Must be called while lock is held.
    fn collectNftForwarderStats(self: *ProjectHandle, allocator: std.mem.Allocator) ![]ForwarderStats {
        if (!build_options.nftables_mode) return &[_]ForwarderStats{};

        var ctx = try nft_mod.NftablesContext.init(allocator);
        defer ctx.deinit();
        try ctx.setJsonOutput();
        const cmd: [*:0]const u8 = "reset counters table inet portweaver";
        ctx.runCommand(cmd) catch return &[_]ForwarderStats{};
        const batch = ctx.getOutputMsg() orelse return &[_]ForwarderStats{};

        var stats_list: std.ArrayList(ForwarderStats) = .empty;
        errdefer stats_list.deinit(allocator);

        if (self.cfg.port_mappings.len > 0) {
            for (self.cfg.port_mappings) |mapping| {
                const port = parsePortPrefix(mapping.listen_port);
                for (protocolNames(mapping.protocol)) |proto| {
                    const entry = try buildNftForwarderStats(allocator, batch, mapping.listen_port, proto, port);
                    try stats_list.append(allocator, entry);
                }
            }
        } else {
            var port_buf: [5]u8 = undefined;
            const port_str = std.fmt.bufPrint(&port_buf, "{d}", .{self.cfg.listen_port}) catch unreachable;
            for (protocolNames(self.cfg.protocol)) |proto| {
                const entry = try buildNftForwarderStats(allocator, batch, port_str, proto, self.cfg.listen_port);
                try stats_list.append(allocator, entry);
            }
        }

        return stats_list.toOwnedSlice(allocator);
    }
};

/// Reads nftables counter stats from a batch JSON output for a given port+protocol.
/// dstnat counter → bytes_in (inbound traffic), srcnat counter → bytes_out (outbound traffic).
/// No allocations — counter names are constructed on the stack.
fn collectNftCountersFromBatch(
    batch_json: []const u8,
    port_str: []const u8,
    protocol: types.Protocol,
    stats: *TrafficStats,
) void {
    if (!build_options.nftables_mode) return;

    for (protocolNames(protocol)) |proto| {
        // dstnat counter → bytes_in
        var dstnat_buf: [64]u8 = undefined;
        const dstnat_name = std.fmt.bufPrint(&dstnat_buf, "pw_{s}_{s}_dstnat", .{ port_str, proto }) catch continue;
        if (nft_fw.parseNamedCounter(batch_json, dstnat_name)) |cnt| {
            stats.bytes_in += cnt.bytes;
        }

        // srcnat counter → bytes_out
        var srcnat_buf: [64]u8 = undefined;
        const srcnat_name = std.fmt.bufPrint(&srcnat_buf, "pw_{s}_{s}_srcnat", .{ port_str, proto }) catch continue;
        if (nft_fw.parseNamedCounter(batch_json, srcnat_name)) |cnt| {
            stats.bytes_out += cnt.bytes;
        }
    }
}

/// Build a single ForwarderStats entry from nftables counters.
fn buildNftForwarderStats(
    allocator: std.mem.Allocator,
    batch_json: []const u8,
    port_str: []const u8,
    proto: []const u8,
    local_port: u16,
) !ForwarderStats {
    var entry = ForwarderStats{
        .protocol = proto,
        .local_port = local_port,
        .bytes_in = 0,
        .bytes_out = 0,
        .active_sessions = 0,
    };
    const dstnat_name = try std.fmt.allocPrint(allocator, "pw_{s}_{s}_dstnat", .{ port_str, proto });
    defer allocator.free(dstnat_name);
    if (nft_fw.parseNamedCounter(batch_json, dstnat_name)) |cnt| entry.bytes_in = cnt.bytes;

    const srcnat_name = try std.fmt.allocPrint(allocator, "pw_{s}_{s}_srcnat", .{ port_str, proto });
    defer allocator.free(srcnat_name);
    if (nft_fw.parseNamedCounter(batch_json, srcnat_name)) |cnt| entry.bytes_out = cnt.bytes;

    return entry;
}

/// Returns the protocol name strings for a Protocol enum value.
fn protocolNames(protocol: types.Protocol) []const []const u8 {
    return switch (protocol) {
        .tcp => &[_][]const u8{"tcp"},
        .udp => &[_][]const u8{"udp"},
        .both => &[_][]const u8{ "tcp", "udp" },
    };
}

/// Parses the first port number from a port string (e.g. "8080-8090" → 8080, "80" → 80).
fn parsePortPrefix(port_str: []const u8) u16 {
    if (std.mem.indexOf(u8, port_str, "-")) |dash| {
        return std.fmt.parseInt(u16, port_str[0..dash], 10) catch 0;
    }
    return std.fmt.parseInt(u16, port_str, 10) catch 0;
}

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
