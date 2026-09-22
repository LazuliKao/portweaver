const std = @import("std");
const build_options = @import("build_options");
const config = @import("config/mod.zig");
const config_types = @import("config/types.zig");
const project_status = @import("impl/project_status.zig");
const app_forward = @import("impl/app_forward.zig");
const loop_manager = @import("impl/app_forward/loop_manager.zig");
const event_log = @import("event_log.zig");
const file_log = @import("file_log.zig");
const compat = @import("compat.zig");

const frpc_forward = if (build_options.frpc_mode) @import("impl/frpc_forward.zig") else struct {};
const frps_forward = if (build_options.frps_mode) @import("impl/frps_forward.zig") else struct {};
const ddns_manager = if (build_options.ddns_mode) @import("impl/ddns_manager.zig") else struct {};
const rathole_enabled = build_options.rathole_client_mode or build_options.rathole_server_mode;
const rathole_forward = if (rathole_enabled) @import("impl/rathole_forward.zig") else struct {};
const StringSet = std.StringHashMap(void);

const STATUS_RUNNING: [:0]const u8 = "running";
const STATUS_STOPPED: [:0]const u8 = "stopped";
const STATUS_DEGRADED: [:0]const u8 = "degraded";

pub const ForwarderSnapshot = struct {
    protocol: []const u8,
    local_port: u16,
    bytes_in: u64,
    bytes_out: u64,
    active_sessions: u32,
};

pub const ForwarderFailureSnapshot = struct {
    protocol: []const u8,
    local_port: u16,
    error_code: i32,
};

/// An allocator-owned, self-contained project status record. All strings and
/// slices which originate in Config are copied into the caller's allocator.
pub const ProjectSnapshot = struct {
    id: u32,
    section_name: []const u8,
    enabled: bool,
    status: [:0]const u8,
    startup_status: [:0]const u8,
    active_ports: u32,
    bytes_in: u64,
    bytes_out: u64,
    active_sessions: u32,
    last_changed: u64,
    error_code: ?i32,
    enable_app_stats: bool,
    enable_firewall_stats: bool,
    forwarders: []const ForwarderSnapshot,
    failures: []const ForwarderFailureSnapshot,

    pub fn deinit(self: *ProjectSnapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.section_name);
        allocator.free(self.forwarders);
        allocator.free(self.failures);
        self.* = undefined;
    }
};

/// An allocator-owned view of one complete control-plane generation.
pub const Snapshot = struct {
    generation: u64,
    apply_status: []const u8,
    changed_projects: u32,
    failed_projects: u32,
    failed_components: u32,
    status: [:0]const u8,
    total_projects: u32,
    active_ports: u32,
    total_bytes_in: u64,
    total_bytes_out: u64,
    uptime: u64,
    projects: []const ProjectSnapshot,

    /// Releases data produced by Guard.snapshot when its allocator is not a
    /// request arena. UBUS uses a request arena and releases it as a whole.
    pub fn deinit(self: *Snapshot, allocator: std.mem.Allocator) void {
        for (self.projects) |*project| project.deinit(allocator);
        allocator.free(self.projects);
        self.* = undefined;
    }
};

pub const LoopTopologyListener = project_status.RuntimeListener;

pub const LoopTopologyProject = struct {
    id: u32,
    section_name: []const u8,
    listeners: []const LoopTopologyListener,

    fn deinit(self: *LoopTopologyProject, allocator: std.mem.Allocator) void {
        allocator.free(self.section_name);
        allocator.free(self.listeners);
        self.* = undefined;
    }
};

pub const LoopTopologyRuntime = struct {
    runtime_id: u64,
    mode: []const u8,
    state: []const u8,
    reference_count: u32,
    listener_count: u32,
    project_count: u32,
    projects: []const LoopTopologyProject,

    fn deinit(self: *LoopTopologyRuntime, allocator: std.mem.Allocator) void {
        for (self.projects) |project_value| {
            var project = project_value;
            project.deinit(allocator);
        }
        allocator.free(self.projects);
        self.* = undefined;
    }
};

/// Allocator-owned topology of the actual runtime instances and listeners.
/// Runtime IDs are process-local identities, not operating-system thread IDs.
pub const LoopTopology = struct {
    generation: u64,
    backend: []const u8,
    runtime_count: u32,
    project_count: u32,
    listener_count: u32,
    runtimes: []const LoopTopologyRuntime,

    pub fn deinit(self: *LoopTopology, allocator: std.mem.Allocator) void {
        for (self.runtimes) |runtime_value| {
            var runtime = runtime_value;
            runtime.deinit(allocator);
        }
        allocator.free(self.runtimes);
        self.* = undefined;
    }
};

pub const ProjectEnabledResult = struct {
    id: u32,
    enabled: bool,
    status: [:0]const u8,
    last_changed: u64,
};

pub const WolSnapshot = struct {
    project_id: i32,
    enabled: bool,
    mac_addresses: []const []const u8,
    cooldown_ms: u64,
    log_enabled: bool,
    detect_protocols: []const []const u8,
};

pub const ApplyStatus = enum {
    success,
    degraded,
    rejected,

    pub fn toString(self: ApplyStatus) []const u8 {
        return @tagName(self);
    }
};

pub const ApplyReport = struct {
    generation: u64,
    status: ApplyStatus,
    changed_projects: u32,
    failed_projects: u32,
    failed_components: u32,
};

/// Owns the active configuration, project handles and all operations that can
/// replace or destroy them. A Guard is the only capability that exposes
/// control-plane commands to adapters such as UBUS.
pub const RuntimeController = struct {
    allocator: std.mem.Allocator,
    current_config: config.Config,
    handles: project_status.ProjectHandleList,
    app_loop_manager: loop_manager.LoopManager,
    generation: u64 = 1,
    last_apply: ApplyReport = .{
        .generation = 1,
        .status = .success,
        .changed_projects = 0,
        .failed_projects = 0,
        .failed_components = 0,
    },
    log_config_applied: bool = true,
    frpc_config_applied: bool = true,
    firewall_config_applied: bool = true,
    start_ts: u64,
    mutex: std.Io.Mutex = .init,

    /// Takes ownership of cfg. Call deinit exactly once after all request
    /// adapters have stopped using the controller.
    pub fn init(allocator: std.mem.Allocator, cfg: config.Config) !RuntimeController {
        var owned_config = cfg;
        errdefer owned_config.deinit(allocator);
        var app_loop_manager = try loop_manager.LoopManager.init(allocator);
        errdefer app_loop_manager.deinit();
        const handles = try project_status.ProjectHandleList.initCapacity(allocator, owned_config.projects.len);
        return .{
            .allocator = allocator,
            .current_config = owned_config,
            .handles = handles,
            .app_loop_manager = app_loop_manager,
            .start_ts = currentTs(),
        };
    }

    /// Stops owned services and releases project handles before releasing their
    /// borrowed configuration. The caller must stop UBUS before calling this.
    pub fn deinit(self: *RuntimeController) void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        project_status.stopAll(&self.handles);
        self.app_loop_manager.deinit();
        if (rathole_enabled) {
            rathole_forward.stop_all();
            @import("impl/librathole.zig").cleanup();
        }
        if (build_options.frpc_mode) {
            frpc_forward.stopAll();
            @import("impl/frpc/libfrpc.zig").cleanup();
        }
        if (build_options.ddns_mode) ddns_manager.deinit(self.allocator);
        if (build_options.frps_mode) {
            frps_forward.stopAll();
            @import("impl/frps/libfrps.zig").cleanup();
        }
        self.current_config.deinit(self.allocator);
    }

    /// Creates initial project handles and starts configured runtime services.
    pub fn start(self: *RuntimeController) !bool {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        file_log.replaceGlobalFileLogger(self.allocator, self.current_config.log_config) catch |err| {
            self.log_config_applied = false;
            std.log.warn("Failed to apply file logger configuration: {any}", .{err});
        };
        try self.createInitialHandlesLocked();
        if (rathole_enabled) try rathole_forward.apply_config(self.allocator, &self.current_config);
        self.firewall_config_applied = refreshFirewallRules(self.allocator, &self.current_config);
        if (build_options.ddns_mode) {
            ddns_manager.applyConfig(self.allocator, self.current_config.ddns_configs) catch |err| {
                std.log.warn("Failed to apply DDNS configuration: {any}", .{err});
            };
        }
        if (build_options.frps_mode) {
            frps_forward.startConfiguredServers(self.allocator, &self.current_config.frps_nodes) catch |err| {
                std.log.warn("Failed to start configured FRPS servers: {any}", .{err});
            };
        }
        return self.startForwardingLocked();
    }

    /// Applies a validated candidate config. It always consumes new_cfg: on
    /// preparation failure it deinitializes it and preserves the live state.
    pub fn applyConfig(self: *RuntimeController, new_cfg: *config.Config) ApplyReport {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        return self.applyConfigLocked(new_cfg);
    }

    pub fn projectCount(self: *RuntimeController) usize {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        return self.handles.items.len;
    }

    pub fn watchEnabled(self: *RuntimeController) bool {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        return self.current_config.watch;
    }

    pub fn acquire(self: *RuntimeController) Guard {
        self.mutex.lockUncancelable(compat.io());
        return .{ .controller = self };
    }

    pub const Guard = struct {
        controller: *RuntimeController,

        pub fn release(self: *Guard) void {
            self.controller.mutex.unlock(compat.io());
        }

        pub fn snapshot(self: *Guard, allocator: std.mem.Allocator) !Snapshot {
            return self.controller.snapshotLocked(allocator);
        }

        pub fn loopTopology(self: *Guard, allocator: std.mem.Allocator) !LoopTopology {
            return self.controller.loopTopologyLocked(allocator);
        }

        pub fn setProjectEnabled(self: *Guard, id: u32, enabled: bool) !ProjectEnabledResult {
            const idx: usize = @intCast(id);
            if (idx >= self.controller.handles.items.len) return error.InvalidArgument;

            const project = self.controller.handles.items[idx];
            const old_enabled = project.cfg.enabled;
            project.cfg.enabled = enabled;
            project.last_changed = currentTs();
            project.setRuntimeEnabled(enabled, &self.controller.app_loop_manager);

            if (old_enabled != enabled) {
                if (enabled) {
                    event_log.logEventFmt(.project_started, @intCast(idx), "Project {d} enabled via UBUS", .{idx + 1});
                } else {
                    event_log.logEventFmt(.project_stopped, @intCast(idx), "Project {d} disabled via UBUS", .{idx + 1});
                }
            }

            return .{
                .id = id,
                .enabled = enabled,
                .status = if (enabled) STATUS_RUNNING else STATUS_STOPPED,
                .last_changed = project.last_changed,
            };
        }

        pub fn restartProject(self: *Guard, id: u32) !void {
            const idx: usize = @intCast(id);
            if (idx >= self.controller.handles.items.len) return error.InvalidArgument;

            const project = self.controller.handles.items[idx];
            if (!project.cfg.enabled) return error.InvalidArgument;

            project.teardownForwarders();
            if (project.cfg.enable_app_forward) {
                app_forward.startForwardingWithLoopManager(project, &self.controller.app_loop_manager) catch |err| {
                    std.log.warn("ubus: failed to restart project {d}: {any}", .{ id, err });
                };
            }
            if (build_options.frpc_mode) {
                frpc_forward.startForwarding(project, &self.controller.current_config.frpc_nodes) catch |err| {
                    std.log.warn("ubus: failed to restart FRPC for project {d}: {any}", .{ id, err });
                };
            }
            project.last_changed = currentTs();
            event_log.logEventFmt(.project_started, @intCast(id), "Project {d} restarted via UBUS", .{id + 1});
        }

        /// Returns a request-owned root path, so filesystem work may outlive the
        /// guard without borrowing the active Config.
        pub fn copyFrpConfigRoot(self: *Guard, allocator: std.mem.Allocator) ![]const u8 {
            return allocator.dupe(u8, self.controller.current_config.frpConfigRoot());
        }

        pub fn useNftables(self: *Guard) bool {
            return self.controller.current_config.use_nftables;
        }

        pub fn wakeWolTarget(self: *Guard, name: []const u8) !WolSnapshot {
            const target = self.controller.current_config.wol_targets.get(name) orelse return error.NotFound;
            return .{
                .project_id = -1,
                .enabled = target.enabled,
                .mac_addresses = target.mac_addresses,
                .cooldown_ms = target.cooldown_ms,
                .log_enabled = target.log_enabled,
                .detect_protocols = &.{},
            };
        }

        pub fn wakeWolProject(self: *Guard, name: []const u8) !WolSnapshot {
            const project = self.controller.findProjectLocked(name) orelse return error.NotFound;
            return .{
                .project_id = @intCast(project.id),
                .enabled = project.cfg.enable_wol,
                .mac_addresses = project.cfg.resolved_wol_macs,
                .cooldown_ms = project.cfg.resolved_wol_cooldown_ms,
                .log_enabled = project.cfg.resolved_wol_log_enabled,
                .detect_protocols = project.cfg.detect_protocols,
            };
        }
    };

    fn createInitialHandlesLocked(self: *RuntimeController) !void {
        try self.handles.ensureTotalCapacity(self.current_config.projects.len);
        errdefer project_status.stopAll(&self.handles);
        for (self.current_config.projects, 0..) |project, id| {
            const handle = try self.allocator.create(project_status.ProjectHandle);
            errdefer self.allocator.destroy(handle);
            handle.* = project_status.ProjectHandle.init(self.allocator, id, project, self.current_config.use_nftables);
            handle.app_forward_loop_mode = self.current_config.app_forward_loop_mode;
            handle.last_changed = self.start_ts;
            self.handles.appendAssumeCapacity(handle);
        }
    }

    fn startForwardingLocked(self: *RuntimeController) !bool {
        var has_app_forward = false;
        var frpc_failed = false;
        if (build_options.frpc_mode) frpc_forward.initialize(self.allocator);

        for (self.handles.items) |handle| {
            if (!handle.cfg.enabled) {
                handle.setDisabled();
                continue;
            }
            if (handle.cfg.enable_app_forward) has_app_forward = true;
            startForwardingForHandle(handle, &self.app_loop_manager);
            if (build_options.frpc_mode) {
                frpc_forward.startForwarding(handle, &self.current_config.frpc_nodes) catch |err| {
                    frpc_failed = true;
                    std.log.err("Failed to start FRPC forwarding for project {d} ({s}): {any}", .{ handle.id + 1, handle.cfg.remark, err });
                };
            }
        }
        if (build_options.frpc_mode) {
            frpc_forward.startConfiguredClients(&self.current_config.frpc_nodes) catch |err| {
                frpc_failed = true;
                std.log.warn("Failed to start configured FRPC clients: {any}", .{err});
            };
            self.frpc_config_applied = !frpc_failed;
        }
        return has_app_forward;
    }

    fn applyConfigLocked(self: *RuntimeController, new_cfg: *config.Config) ApplyReport {
        const old_cfg = &self.current_config;
        var plan = ProjectReloadPlan.init(self.allocator, self, new_cfg) catch |err| {
            std.log.warn("Reload: unable to prepare project changes, keeping current config: {any}", .{err});
            new_cfg.deinit(self.allocator);
            self.last_apply = .{
                .generation = self.generation,
                .status = .rejected,
                .changed_projects = 0,
                .failed_projects = 0,
                .failed_components = 0,
            };
            return self.last_apply;
        };
        defer plan.deinit();

        // Release every conflicting listener before starting any replacement.
        // This makes port hand-off independent of project ordering.
        for (self.handles.items, 0..) |handle, old_index| {
            if (!plan.stop_old[old_index]) continue;
            std.log.info("Reload: stopping project {d} ({s})", .{ old_index + 1, handle.cfg.remark });
            handle.teardownForwarders();
        }
        var frpc_failed = false;
        var frps_failed = false;
        var rathole_failed = false;
        var ddns_failed = false;
        var logger_failed = false;
        if (build_options.frpc_mode) frpc_failed = frpc_forward.removeClients(&plan.frpc_affected) != 0;
        if (build_options.frps_mode) frps_failed = releaseFrpsNodes(old_cfg, new_cfg) != 0;
        if (rathole_enabled) rathole_forward.stop_changed(old_cfg, new_cfg);

        const firewall_released = !self.firewall_config_applied or
            releaseFirewallRules(self.allocator, old_cfg, new_cfg, &plan.firewall_affected);
        var firewall_failed = !firewall_released;

        for (self.handles.items, 0..) |handle, old_index| {
            if (plan.old_matched[old_index]) continue;
            std.log.info("Reload: removing project {d} ({s})", .{ old_index + 1, handle.cfg.remark });
            handle.deinit();
            self.allocator.destroy(handle);
            event_log.logEventFmt(.project_stopped, @intCast(old_index), "Project {d} removed", .{old_index + 1});
        }

        const changed_at = currentTs();
        for (plan.new_handles.items, 0..) |handle, new_index| {
            const old_enabled = handle.cfg.enabled;
            handle.cfg = new_cfg.projects[new_index];
            handle.app_forward_loop_mode = new_cfg.app_forward_loop_mode;
            handle.use_nftables = new_cfg.use_nftables;
            handle.id = new_index;
            if (plan.changed_new[new_index]) handle.last_changed = changed_at;
            if (old_enabled != handle.cfg.enabled) {
                if (handle.cfg.enabled) {
                    event_log.logEventFmt(.project_started, @intCast(new_index), "Project {d} enabled via reload", .{new_index + 1});
                } else {
                    event_log.logEventFmt(.project_stopped, @intCast(new_index), "Project {d} disabled via reload", .{new_index + 1});
                }
            }
        }

        var old_handles = self.handles;
        self.handles = plan.takeHandles();
        old_handles.deinit();

        var failed_projects: u32 = 0;
        for (self.handles.items, 0..) |handle, new_index| {
            if (!handle.cfg.enabled) {
                handle.setDisabled();
                continue;
            }
            if (!plan.start_new[new_index]) continue;
            startForwardingForHandle(handle, &self.app_loop_manager);
            if (handle.startup_status == .failed or handle.startup_status == .partial) failed_projects += 1;
        }

        if (build_options.frpc_mode) {
            for (self.handles.items) |handle| {
                if (!handle.cfg.enabled) continue;
                frpc_forward.startForwardingForNodes(handle, &new_cfg.frpc_nodes, &plan.frpc_affected) catch |err| {
                    frpc_failed = true;
                    std.log.warn("Reload: failed to rebuild affected FRPC proxies for project {d}: {any}", .{ handle.id + 1, err });
                };
            }
            frpc_forward.startConfiguredClientsForNodes(&new_cfg.frpc_nodes, &plan.frpc_affected) catch |err| {
                frpc_failed = true;
                std.log.warn("Reload: failed to start affected FRPC clients: {any}", .{err});
            };
            self.frpc_config_applied = !frpc_failed;
        }

        if (build_options.frps_mode) frps_failed = activateFrpsNodes(self.allocator, old_cfg, new_cfg) != 0 or frps_failed;
        if (rathole_enabled) rathole_failed = rathole_forward.start_changed(self.allocator, new_cfg) != 0;
        const firewall_applied = if (!self.firewall_config_applied)
            refreshFirewallRules(self.allocator, new_cfg)
        else
            firewall_released and activateFirewallRules(self.allocator, old_cfg, new_cfg, &plan.firewall_affected);
        if (!firewall_applied) {
            firewall_failed = true;
        }
        self.firewall_config_applied = firewall_applied;
        if (build_options.ddns_mode) {
            ddns_manager.applyConfig(self.allocator, new_cfg.ddns_configs) catch |err| {
                ddns_failed = true;
                std.log.warn("Reload: failed to apply DDNS config: {any}", .{err});
            };
        }
        if (!self.log_config_applied or !old_cfg.log_config.eql(new_cfg.log_config)) {
            if (file_log.replaceGlobalFileLogger(self.allocator, new_cfg.log_config)) |_| {
                self.log_config_applied = true;
            } else |err| {
                self.log_config_applied = false;
                logger_failed = true;
                std.log.warn("Reload: failed to replace file logger, keeping previous logger: {any}", .{err});
            }
        }

        const failed_components: u32 = @intFromBool(frpc_failed) +
            @intFromBool(frps_failed) +
            @intFromBool(rathole_failed) +
            @intFromBool(firewall_failed) +
            @intFromBool(ddns_failed) +
            @intFromBool(logger_failed);

        old_cfg.deinit(self.allocator);
        self.current_config = new_cfg.*;
        self.generation +%= 1;
        self.last_apply = .{
            .generation = self.generation,
            .status = if (failed_projects == 0 and failed_components == 0) .success else .degraded,
            .changed_projects = plan.changed_count,
            .failed_projects = failed_projects,
            .failed_components = failed_components,
        };
        event_log.logEventFmt(.info, -1, "Config reloaded: {d} project(s) changed, {d} project(s) and {d} component(s) failed", .{ plan.changed_count, failed_projects, failed_components });
        std.log.info("Reload complete: {d} project(s) changed, {d} project(s) and {d} component(s) failed", .{ plan.changed_count, failed_projects, failed_components });
        return self.last_apply;
    }

    fn snapshotLocked(self: *RuntimeController, allocator: std.mem.Allocator) !Snapshot {
        var projects = std.ArrayList(ProjectSnapshot).empty;
        errdefer {
            for (projects.items) |*project| project.deinit(allocator);
            projects.deinit(allocator);
        }

        var enabled_projects: u32 = 0;
        var successful_projects: u32 = 0;
        var active_ports: u32 = 0;
        var bytes_in: u64 = 0;
        var bytes_out: u64 = 0;

        for (self.handles.items) |project| {
            const info = project.getProjectRuntimeInfo();
            if (project.cfg.enabled) {
                enabled_projects += 1;
                if (info.startup_status == .success) successful_projects += 1;
            }
            active_ports += info.active_ports;
            bytes_in += info.bytes_in;
            bytes_out += info.bytes_out;

            const forwarder_stats = try project.getForwarderStats(allocator);
            defer if (forwarder_stats.len > 0) allocator.free(forwarder_stats);
            var forwarders = std.ArrayList(ForwarderSnapshot).empty;
            errdefer forwarders.deinit(allocator);
            for (forwarder_stats) |stat| {
                try forwarders.append(allocator, .{
                    .protocol = stat.protocol,
                    .local_port = stat.local_port,
                    .bytes_in = stat.bytes_in,
                    .bytes_out = stat.bytes_out,
                    .active_sessions = stat.active_sessions,
                });
            }

            const failures = try project.getStartupFailures(allocator);
            defer if (failures.len > 0) allocator.free(failures);
            var startup_failures = std.ArrayList(ForwarderFailureSnapshot).empty;
            errdefer startup_failures.deinit(allocator);
            for (failures) |failure| {
                try startup_failures.append(allocator, .{
                    .protocol = failure.protocol,
                    .local_port = failure.local_port,
                    .error_code = failure.error_code,
                });
            }

            const section_name = try allocator.dupe(u8, project.cfg.section_name);
            errdefer allocator.free(section_name);
            const forwarders_slice = try forwarders.toOwnedSlice(allocator);
            errdefer allocator.free(forwarders_slice);
            const failures_slice = try startup_failures.toOwnedSlice(allocator);
            errdefer allocator.free(failures_slice);
            const project_snapshot = ProjectSnapshot{
                .id = @intCast(project.id),
                .section_name = section_name,
                .enabled = project.cfg.enabled,
                .status = if (project.cfg.enabled) STATUS_RUNNING else STATUS_STOPPED,
                .startup_status = info.startup_status.toString(),
                .active_ports = info.active_ports,
                .bytes_in = info.bytes_in,
                .bytes_out = info.bytes_out,
                .active_sessions = info.active_sessions,
                .last_changed = project.last_changed,
                .error_code = if ((info.startup_status == .failed or info.startup_status == .partial) and info.error_code != 0) info.error_code else null,
                .enable_app_stats = project.cfg.enable_app_stats,
                .enable_firewall_stats = project.cfg.enable_firewall_stats,
                .forwarders = forwarders_slice,
                .failures = failures_slice,
            };
            try projects.append(allocator, project_snapshot);
        }

        return .{
            .generation = self.generation,
            .apply_status = self.last_apply.status.toString(),
            .changed_projects = self.last_apply.changed_projects,
            .failed_projects = self.last_apply.failed_projects,
            .failed_components = self.last_apply.failed_components,
            .status = if (enabled_projects == 0)
                STATUS_STOPPED
            else if (enabled_projects == successful_projects)
                STATUS_RUNNING
            else
                STATUS_DEGRADED,
            .total_projects = @intCast(self.handles.items.len),
            .active_ports = active_ports,
            .total_bytes_in = bytes_in,
            .total_bytes_out = bytes_out,
            .uptime = currentTs() - self.start_ts,
            .projects = try projects.toOwnedSlice(allocator),
        };
    }

    fn loopTopologyLocked(self: *RuntimeController, allocator: std.mem.Allocator) !LoopTopology {
        const descriptors = try self.app_loop_manager.snapshotRuntimes(allocator);
        defer allocator.free(descriptors);

        var runtimes = std.ArrayList(LoopTopologyRuntime).empty;
        errdefer {
            for (runtimes.items) |*runtime| runtime.deinit(allocator);
            runtimes.deinit(allocator);
        }
        var total_projects: u32 = 0;
        var total_listeners: u32 = 0;

        for (descriptors) |descriptor| {
            var projects = std.ArrayList(LoopTopologyProject).empty;
            errdefer {
                for (projects.items) |*project| project.deinit(allocator);
                projects.deinit(allocator);
            }
            var runtime_listener_count: u32 = 0;

            if (descriptor.runtime_context) |runtime_context| {
                for (self.handles.items) |handle| {
                    const listeners = try handle.getRuntimeListeners(allocator, runtime_context);
                    if (listeners.len == 0) {
                        allocator.free(listeners);
                        continue;
                    }
                    errdefer allocator.free(listeners);
                    const section_name = try allocator.dupe(u8, handle.cfg.section_name);
                    errdefer allocator.free(section_name);
                    try projects.append(allocator, .{
                        .id = @intCast(handle.id),
                        .section_name = section_name,
                        .listeners = listeners,
                    });
                    runtime_listener_count += @intCast(listeners.len);
                }
            }

            const project_count: u32 = @intCast(projects.items.len);
            const project_slice = try projects.toOwnedSlice(allocator);
            errdefer {
                for (project_slice) |*project| project.deinit(allocator);
                allocator.free(project_slice);
            }
            try runtimes.append(allocator, .{
                .runtime_id = descriptor.runtime_id,
                .mode = @tagName(descriptor.mode),
                .state = @tagName(descriptor.state),
                .reference_count = @intCast(descriptor.reference_count),
                .listener_count = runtime_listener_count,
                .project_count = project_count,
                .projects = project_slice,
            });
            total_projects += project_count;
            total_listeners += runtime_listener_count;
        }

        return .{
            .generation = self.generation,
            .backend = @tagName(build_options.forward_backend),
            .runtime_count = @intCast(runtimes.items.len),
            .project_count = total_projects,
            .listener_count = total_listeners,
            .runtimes = try runtimes.toOwnedSlice(allocator),
        };
    }

    fn findProjectLocked(self: *RuntimeController, name: []const u8) ?*project_status.ProjectHandle {
        for (self.handles.items) |project| {
            if (std.mem.eql(u8, project.cfg.section_name, name)) return project;
        }
        const index = std.fmt.parseUnsigned(usize, name, 10) catch return null;
        if (index < self.handles.items.len) return self.handles.items[index];
        return null;
    }
};

const ProjectReloadPlan = struct {
    allocator: std.mem.Allocator,
    new_handles: project_status.ProjectHandleList,
    old_matched: []bool,
    stop_old: []bool,
    start_new: []bool,
    changed_new: []bool,
    added_new: []bool,
    frpc_affected: StringSet,
    firewall_affected: StringSet,
    changed_count: u32,
    handles_transferred: bool = false,

    fn init(
        allocator: std.mem.Allocator,
        controller: *RuntimeController,
        new_cfg: *const config.Config,
    ) !ProjectReloadPlan {
        var old_by_name = std.StringHashMap(usize).init(allocator);
        defer old_by_name.deinit();
        for (controller.handles.items, 0..) |handle, index| {
            if (handle.cfg.section_name.len == 0 or old_by_name.contains(handle.cfg.section_name)) {
                return error.DuplicateProjectSection;
            }
            try old_by_name.put(handle.cfg.section_name, index);
        }

        var new_names = std.StringHashMap(void).init(allocator);
        defer new_names.deinit();
        for (new_cfg.projects) |project| {
            if (project.section_name.len == 0 or new_names.contains(project.section_name)) {
                return error.DuplicateProjectSection;
            }
            try new_names.put(project.section_name, {});
        }

        var new_handles = try project_status.ProjectHandleList.initCapacity(allocator, new_cfg.projects.len);
        errdefer new_handles.deinit();
        const old_matched = try allocator.alloc(bool, controller.handles.items.len);
        errdefer allocator.free(old_matched);
        @memset(old_matched, false);
        const stop_old = try allocator.alloc(bool, controller.handles.items.len);
        errdefer allocator.free(stop_old);
        @memset(stop_old, false);
        const start_new = try allocator.alloc(bool, new_cfg.projects.len);
        errdefer allocator.free(start_new);
        @memset(start_new, false);
        const changed_new = try allocator.alloc(bool, new_cfg.projects.len);
        errdefer allocator.free(changed_new);
        @memset(changed_new, false);
        const added_new = try allocator.alloc(bool, new_cfg.projects.len);
        errdefer allocator.free(added_new);
        @memset(added_new, false);
        var frpc_affected = StringSet.init(allocator);
        errdefer frpc_affected.deinit();
        var firewall_affected = StringSet.init(allocator);
        errdefer firewall_affected.deinit();

        errdefer {
            for (new_handles.items, 0..) |handle, index| {
                if (added_new[index]) {
                    handle.deinit();
                    allocator.destroy(handle);
                }
            }
        }

        var changed_count: u32 = 0;
        for (new_cfg.projects, 0..) |new_project, new_index| {
            if (old_by_name.get(new_project.section_name)) |old_index| {
                const handle = controller.handles.items[old_index];
                old_matched[old_index] = true;
                const app_changed = !appForwardConfigEql(
                    handle.cfg,
                    controller.current_config.app_forward_loop_mode,
                    new_project,
                    new_cfg.app_forward_loop_mode,
                );
                const old_active = handle.cfg.enabled and handle.cfg.enable_app_forward;
                const new_active = new_project.enabled and new_project.enable_app_forward;
                const app_needs_retry = old_active and new_active and
                    (handle.startup_status == .failed or handle.startup_status == .partial);
                stop_old[old_index] = old_active and (!new_active or app_changed or app_needs_retry);
                start_new[new_index] = new_active and (!old_active or app_changed or app_needs_retry);
                changed_new[new_index] = app_needs_retry or app_changed or !projectConfigEql(handle.cfg, new_project);
                if (changed_new[new_index]) changed_count += 1;
                if (!frpcProjectConfigEql(handle.cfg, new_project)) {
                    try collectProjectFrpcNodes(&frpc_affected, handle.cfg);
                    try collectProjectFrpcNodes(&frpc_affected, new_project);
                }
                if (!firewallProjectConfigEql(handle.cfg, new_project)) {
                    try firewall_affected.put(new_project.section_name, {});
                }
                new_handles.appendAssumeCapacity(handle);
            } else {
                try collectProjectFrpcNodes(&frpc_affected, new_project);
                try firewall_affected.put(new_project.section_name, {});
                const handle = blk: {
                    const created = try allocator.create(project_status.ProjectHandle);
                    errdefer allocator.destroy(created);
                    created.* = project_status.ProjectHandle.init(allocator, new_index, new_project, new_cfg.use_nftables);
                    created.app_forward_loop_mode = new_cfg.app_forward_loop_mode;
                    break :blk created;
                };
                handle.last_changed = currentTs();
                added_new[new_index] = true;
                changed_new[new_index] = true;
                start_new[new_index] = new_project.enabled and new_project.enable_app_forward;
                changed_count += 1;
                new_handles.appendAssumeCapacity(handle);
            }
        }

        for (controller.handles.items, 0..) |handle, old_index| {
            if (old_matched[old_index]) continue;
            stop_old[old_index] = handle.cfg.enabled and handle.cfg.enable_app_forward;
            changed_count += 1;
            try collectProjectFrpcNodes(&frpc_affected, handle.cfg);
            try firewall_affected.put(handle.cfg.section_name, {});
        }

        try collectChangedFrpcNodes(&frpc_affected, &controller.current_config, new_cfg);
        if (build_options.frpc_mode and !controller.frpc_config_applied) {
            try collectAllFrpcNodes(&frpc_affected, &controller.current_config);
            try collectAllFrpcNodes(&frpc_affected, new_cfg);
        }

        return .{
            .allocator = allocator,
            .new_handles = new_handles,
            .old_matched = old_matched,
            .stop_old = stop_old,
            .start_new = start_new,
            .changed_new = changed_new,
            .added_new = added_new,
            .frpc_affected = frpc_affected,
            .firewall_affected = firewall_affected,
            .changed_count = changed_count,
        };
    }

    fn takeHandles(self: *ProjectReloadPlan) project_status.ProjectHandleList {
        self.handles_transferred = true;
        return self.new_handles;
    }

    fn deinit(self: *ProjectReloadPlan) void {
        if (!self.handles_transferred) {
            for (self.new_handles.items, 0..) |handle, index| {
                if (!self.added_new[index]) continue;
                handle.deinit();
                self.allocator.destroy(handle);
            }
            self.new_handles.deinit();
        }
        self.allocator.free(self.old_matched);
        self.allocator.free(self.stop_old);
        self.allocator.free(self.start_new);
        self.allocator.free(self.changed_new);
        self.allocator.free(self.added_new);
        self.frpc_affected.deinit();
        self.firewall_affected.deinit();
        self.* = undefined;
    }
};

fn collectProjectFrpcNodes(node_names: *StringSet, project: config.Project) !void {
    for (project.port_mappings) |mapping| {
        for (mapping.frpc) |forward| try node_names.put(forward.node_name, {});
    }
}

fn collectChangedFrpcNodes(
    node_names: *StringSet,
    old_cfg: *const config.Config,
    new_cfg: *const config.Config,
) !void {
    const old_nodes = &old_cfg.frpc_nodes;
    const new_nodes = &new_cfg.frpc_nodes;
    const root_changed = !frpConfigRootEql(old_cfg, new_cfg);
    var old_it = old_nodes.iterator();
    while (old_it.next()) |entry| {
        const replacement = new_nodes.get(entry.key_ptr.*);
        if (replacement == null or !entry.value_ptr.eql(replacement.?) or
            (root_changed and entry.value_ptr.source.mode == .external_file))
        {
            try node_names.put(entry.key_ptr.*, {});
        }
    }
    var new_it = new_nodes.iterator();
    while (new_it.next()) |entry| {
        if (!old_nodes.contains(entry.key_ptr.*) or
            (root_changed and entry.value_ptr.source.mode == .external_file))
        {
            try node_names.put(entry.key_ptr.*, {});
        }
    }
}

fn collectAllFrpcNodes(node_names: *StringSet, cfg: *const config.Config) !void {
    var node_it = cfg.frpc_nodes.iterator();
    while (node_it.next()) |entry| try node_names.put(entry.key_ptr.*, {});
    for (cfg.projects) |project| try collectProjectFrpcNodes(node_names, project);
}

fn frpConfigRootEql(old_cfg: *const config.Config, new_cfg: *const config.Config) bool {
    return std.mem.eql(u8, old_cfg.frpConfigRoot(), new_cfg.frpConfigRoot());
}

fn appForwardConfigEql(a: config.Project, a_default_mode: config_types.LoopMode, b: config.Project, b_default_mode: config_types.LoopMode) bool {
    return a.enable_app_forward == b.enable_app_forward and
        a.family == b.family and
        a.protocol == b.protocol and
        a.listen_port == b.listen_port and
        std.mem.eql(u8, a.target_address, b.target_address) and
        a.target_port == b.target_port and
        portMappingsEql(a.port_mappings, b.port_mappings) and
        a.reuseaddr == b.reuseaddr and
        a.enable_app_stats == b.enable_app_stats and
        a.effectiveAppForwardLoopMode(a_default_mode) == b.effectiveAppForwardLoopMode(b_default_mode) and
        a.connect_timeout_ms == b.connect_timeout_ms and
        a.max_connections == b.max_connections and
        a.enable_wol == b.enable_wol and
        a.wol_trigger_mode == b.wol_trigger_mode and
        stringSlicesEql(a.detect_protocols, b.detect_protocols) and
        stringSlicesEql(a.resolved_wol_macs, b.resolved_wol_macs) and
        a.resolved_wol_cooldown_ms == b.resolved_wol_cooldown_ms and
        a.resolved_wol_wake_delay_ms == b.resolved_wol_wake_delay_ms and
        a.resolved_wol_retry_interval_ms == b.resolved_wol_retry_interval_ms and
        a.resolved_wol_retry_window_ms == b.resolved_wol_retry_window_ms and
        a.resolved_wol_log_enabled == b.resolved_wol_log_enabled and
        a.enable_protocol_filter == b.enable_protocol_filter and
        stringSlicesEql(a.allowed_protocols, b.allowed_protocols) and
        stringSlicesEql(a.tls_allowed_snis, b.tls_allowed_snis);
}

fn frpcProjectConfigEql(a: config.Project, b: config.Project) bool {
    return a.enabled == b.enabled and
        std.mem.eql(u8, a.target_address, b.target_address) and
        portMappingsEql(a.port_mappings, b.port_mappings);
}

fn firewallProjectConfigEql(a: config.Project, b: config.Project) bool {
    return a.enabled == b.enabled and
        std.mem.eql(u8, a.remark, b.remark) and
        stringSlicesEql(a.src_zones, b.src_zones) and
        stringSlicesEql(a.dest_zones, b.dest_zones) and
        a.family == b.family and
        a.protocol == b.protocol and
        a.listen_port == b.listen_port and
        std.mem.eql(u8, a.target_address, b.target_address) and
        a.target_port == b.target_port and
        firewallPortMappingsEql(a.port_mappings, b.port_mappings) and
        a.open_firewall_port == b.open_firewall_port and
        a.add_firewall_forward == b.add_firewall_forward and
        a.preserve_source_ip == b.preserve_source_ip;
}

fn firewallPortMappingsEql(a: []const config.PortMapping, b: []const config.PortMapping) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (!std.mem.eql(u8, left.listen_port, right.listen_port) or
            !std.mem.eql(u8, left.target_port, right.target_port) or
            left.protocol != right.protocol)
        {
            return false;
        }
    }
    return true;
}

fn portMappingsEql(a: []const config.PortMapping, b: []const config.PortMapping) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (!left.eql(right)) return false;
    }
    return true;
}

fn projectConfigEql(a: config.Project, b: config.Project) bool {
    return a.eql(b) and
        std.mem.eql(u8, a.remark, b.remark) and
        stringSlicesEql(a.resolved_wol_macs, b.resolved_wol_macs) and
        a.resolved_wol_cooldown_ms == b.resolved_wol_cooldown_ms and
        a.resolved_wol_wake_delay_ms == b.resolved_wol_wake_delay_ms and
        a.resolved_wol_retry_interval_ms == b.resolved_wol_retry_interval_ms and
        a.resolved_wol_retry_window_ms == b.resolved_wol_retry_window_ms and
        a.resolved_wol_log_enabled == b.resolved_wol_log_enabled;
}

fn stringSlicesEql(a: []const []const u8, b: []const []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| {
        if (!std.mem.eql(u8, left, right)) return false;
    }
    return true;
}

fn startForwardingForHandle(handle: *project_status.ProjectHandle, runtime_manager: *loop_manager.LoopManager) void {
    if (!handle.cfg.enable_app_forward) return;
    app_forward.startForwardingWithLoopManager(handle, runtime_manager) catch |err| {
        std.log.err("Reload: failed to start forwarding for project {d} ({s}): {any}", .{ handle.id + 1, handle.cfg.remark, err });
    };
}

fn refreshFirewallRules(allocator: std.mem.Allocator, cfg: *const config.Config) bool {
    var success = true;
    if (build_options.nftables_mode and cfg.use_nftables) {
        const nftables = @import("nftables/mod.zig");
        const nft_firewall = @import("impl/nft_firewall.zig");
        if (!nftables.isLoaded()) {
            std.log.warn("Reload: libnftables not available, skipping nftables rules", .{});
            return false;
        }
        var ctx = nftables.NftablesContext.init(allocator) catch |err| {
            std.log.warn("Reload: failed to init nftables context: {any}", .{err});
            return false;
        };
        defer ctx.deinit();
        nft_firewall.setupTable(&ctx, allocator) catch |err| {
            std.log.warn("Reload: failed to setup nftables table: {any}", .{err});
            return false;
        };
        nft_firewall.clearRules(&ctx) catch |err| {
            success = false;
            std.log.warn("Reload: failed to clear nftables rules: {any}", .{err});
        };
        for (cfg.projects) |project| {
            if (!project.enabled) continue;
            nft_firewall.applyRulesForProject(&ctx, allocator, project) catch |err| {
                success = false;
                std.log.warn("Reload: failed to apply nftables rules for project: {any}", .{err});
            };
        }
        return success;
    }
    if (build_options.uci_mode) {
        const firewall = @import("impl/uci_firewall.zig");
        const uci = @import("uci/mod.zig");
        var uci_ctx = uci.UciContext.alloc() catch |err| {
            std.log.warn("Reload: failed to alloc UCI context: {any}", .{err});
            return false;
        };
        defer uci_ctx.free();
        firewall.clearFirewallRules(uci_ctx, allocator) catch |err| {
            success = false;
            std.log.warn("Reload: failed to clear firewall rules: {any}", .{err});
        };
        for (cfg.projects) |project| {
            if (!project.enabled) continue;
            firewall.applyFirewallRulesForProject(uci_ctx, allocator, project) catch |err| {
                success = false;
                std.log.warn("Reload: failed to apply firewall rules: {any}", .{err});
            };
        }
        firewall.reloadFirewall(allocator) catch |err| {
            success = false;
            std.log.warn("Reload: failed to reload firewall: {any}", .{err});
        };
    }
    return success;
}

fn releaseFirewallRules(
    allocator: std.mem.Allocator,
    old_cfg: *const config.Config,
    new_cfg: *const config.Config,
    affected: *const StringSet,
) bool {
    if (!build_options.uci_mode or old_cfg.use_nftables or new_cfg.use_nftables or affected.count() == 0) return true;
    const firewall = @import("impl/uci_firewall.zig");
    const uci = @import("uci/mod.zig");
    var uci_ctx = uci.UciContext.alloc() catch |err| {
        std.log.warn("Reload: failed to allocate UCI context for firewall release: {any}", .{err});
        return false;
    };
    defer uci_ctx.free();
    firewall.clearFirewallRulesForProjects(uci_ctx, allocator, affected) catch |err| {
        std.log.warn("Reload: failed to release changed firewall rules: {any}", .{err});
        return false;
    };
    return true;
}

fn activateFirewallRules(
    allocator: std.mem.Allocator,
    old_cfg: *const config.Config,
    new_cfg: *const config.Config,
    affected: *const StringSet,
) bool {
    if (old_cfg.use_nftables != new_cfg.use_nftables or new_cfg.use_nftables) {
        return refreshFirewallRules(allocator, new_cfg);
    }
    if (!build_options.uci_mode or affected.count() == 0) return true;

    const firewall = @import("impl/uci_firewall.zig");
    const uci = @import("uci/mod.zig");
    var uci_ctx = uci.UciContext.alloc() catch |err| {
        std.log.warn("Reload: failed to allocate UCI context for firewall activation: {any}", .{err});
        return false;
    };
    defer uci_ctx.free();
    var success = true;
    for (new_cfg.projects) |project| {
        if (!project.enabled or !affected.contains(project.section_name)) continue;
        firewall.applyFirewallRulesForProject(uci_ctx, allocator, project) catch |err| {
            success = false;
            std.log.warn("Reload: failed to apply firewall rules for project {s}: {any}", .{ project.section_name, err });
        };
    }
    firewall.reloadFirewall(allocator) catch |err| {
        success = false;
        std.log.warn("Reload: failed to reload firewall: {any}", .{err});
    };
    return success;
}

fn releaseFrpsNodes(old_cfg: *const config.Config, new_cfg: *const config.Config) u32 {
    var failures: u32 = 0;
    var old_it = old_cfg.frps_nodes.iterator();
    while (old_it.next()) |entry| {
        const replacement = new_cfg.frps_nodes.get(entry.key_ptr.*);
        if (!entry.value_ptr.enabled) continue;
        if (replacement != null and replacement.?.enabled and frpsNodeUnchanged(entry.value_ptr.*, replacement.?, old_cfg, new_cfg)) continue;
        if (!frps_forward.removeServer(entry.key_ptr.*)) failures += 1;
    }
    return failures;
}

fn activateFrpsNodes(allocator: std.mem.Allocator, old_cfg: *const config.Config, new_cfg: *const config.Config) u32 {
    var failures: u32 = 0;
    var new_it = new_cfg.frps_nodes.iterator();
    while (new_it.next()) |entry| {
        const name = entry.key_ptr.*;
        const new_node = entry.value_ptr.*;
        if (!new_node.enabled) continue;
        if (old_cfg.frps_nodes.get(name)) |old_node| {
            if (old_node.enabled and frpsNodeUnchanged(old_node, new_node, old_cfg, new_cfg) and frps_forward.isServerStarted(name)) continue;
        }
        frps_forward.startServer(allocator, name, new_node) catch |err| {
            failures += 1;
            std.log.warn("Reload: failed to start FRPS node {s}: {any}", .{ name, err });
        };
    }
    return failures;
}

fn frpsNodeUnchanged(old_node: config_types.FrpsNode, new_node: config_types.FrpsNode, old_cfg: *const config.Config, new_cfg: *const config.Config) bool {
    if (!old_node.eql(new_node)) return false;
    return new_node.source.mode != .external_file or frpConfigRootEql(old_cfg, new_cfg);
}

fn currentTs() u64 {
    const seconds = std.Io.Timestamp.now(compat.io(), .real).toSeconds();
    if (seconds < 0) return 0;
    return @intCast(seconds);
}

fn makeTestConfig(allocator: std.mem.Allocator, section_name: []const u8, enabled: bool) !config.Config {
    return makeTestConfigForSections(allocator, &.{section_name}, enabled);
}

fn makeTestProject(allocator: std.mem.Allocator, section_name: []const u8, enabled: bool) !config.Project {
    const section = try allocator.dupe(u8, section_name);
    errdefer allocator.free(section);
    const remark = try allocator.dupe(u8, "runtime-controller-test");
    errdefer allocator.free(remark);
    const target_address = try allocator.dupe(u8, "127.0.0.1");
    errdefer allocator.free(target_address);

    return .{
        .section_name = section,
        .remark = remark,
        .enabled = enabled,
        .listen_port = 18080,
        .target_address = target_address,
        .target_port = 80,
        .open_firewall_port = false,
        .add_firewall_forward = false,
    };
}

fn makeTestConfigForSections(allocator: std.mem.Allocator, section_names: []const []const u8, enabled: bool) !config.Config {
    const projects = try allocator.alloc(config.Project, section_names.len);
    var initialized: usize = 0;
    errdefer {
        for (projects[0..initialized]) |*project| project.deinit(allocator);
        allocator.free(projects);
    }
    for (section_names, 0..) |section_name, index| {
        projects[index] = try makeTestProject(allocator, section_name, enabled);
        initialized += 1;
    }

    const rathole_client_services = try allocator.alloc(config.RatholeClientService, 0);
    errdefer allocator.free(rathole_client_services);
    const rathole_server_services = try allocator.alloc(config.RatholeServerService, 0);
    errdefer allocator.free(rathole_server_services);
    const ddns_configs = try allocator.alloc(config_types.DdnsConfig, 0);
    errdefer allocator.free(ddns_configs);
    const log_path = try allocator.dupe(u8, "");
    errdefer allocator.free(log_path);

    return .{
        .projects = projects,
        .frpc_nodes = std.StringHashMap(config.FrpcNode).init(allocator),
        .frps_nodes = std.StringHashMap(config_types.FrpsNode).init(allocator),
        .rathole_client_nodes = std.StringHashMap(config.RatholeClientNode).init(allocator),
        .rathole_client_services = rathole_client_services,
        .rathole_server_nodes = std.StringHashMap(config.RatholeServerNode).init(allocator),
        .rathole_server_services = rathole_server_services,
        .ddns_configs = ddns_configs,
        .wol_targets = std.StringHashMap(config_types.WolTarget).init(allocator),
        .log_config = .{ .enabled = false, .file_path = log_path, .max_size = 0, .max_files = 0 },
    };
}

fn addTestFrpcNode(
    allocator: std.mem.Allocator,
    nodes: *std.StringHashMap(config.FrpcNode),
    name: []const u8,
    mode: config_types.FrpConfigMode,
) !void {
    const key = try allocator.dupe(u8, name);
    errdefer allocator.free(key);
    const path = if (mode == .external_file) try allocator.dupe(u8, "/etc/portweaver/frpc.toml") else "";
    errdefer if (path.len != 0) allocator.free(path);
    try nodes.put(key, .{ .source = .{ .mode = mode, .path = path } });
}

fn addTestFrpcMapping(allocator: std.mem.Allocator, project: *config.Project, node_name: []const u8) !void {
    const mappings = try allocator.alloc(config.PortMapping, 1);
    errdefer allocator.free(mappings);
    const listen_port = try allocator.dupe(u8, "18080");
    errdefer allocator.free(listen_port);
    const target_port = try allocator.dupe(u8, "80");
    errdefer allocator.free(target_port);
    const forwards = try allocator.alloc(config.FrpcForward, 1);
    errdefer allocator.free(forwards);
    const owned_node_name = try allocator.dupe(u8, node_name);
    errdefer allocator.free(owned_node_name);

    forwards[0] = .{ .node_name = owned_node_name, .remote_port = 18080 };
    mappings[0] = .{
        .listen_port = listen_port,
        .target_port = target_port,
        .frpc = forwards,
    };
    project.port_mappings = mappings;
}

fn testSnapshotOwnership(allocator: std.mem.Allocator) !void {
    var controller = try RuntimeController.init(allocator, try makeTestConfig(allocator, "first", false));
    defer controller.deinit();

    var first_arena = std.heap.ArenaAllocator.init(allocator);
    defer first_arena.deinit();
    var first_snapshot: Snapshot = undefined;
    {
        var guard = controller.acquire();
        defer guard.release();
        try controller.createInitialHandlesLocked();

        first_snapshot = try guard.snapshot(first_arena.allocator());
        try std.testing.expectEqual(@as(u64, 1), first_snapshot.generation);
        try std.testing.expectEqual(@as(usize, 1), first_snapshot.projects.len);
        try std.testing.expectEqualStrings("first", first_snapshot.projects[0].section_name);
        try std.testing.expect(first_snapshot.projects[0].section_name.ptr != controller.current_config.projects[0].section_name.ptr);

        const enabled = try guard.setProjectEnabled(0, true);
        try std.testing.expect(enabled.enabled);
        try std.testing.expect(controller.handles.items[0].cfg.enabled);
    }

    const original_generation = controller.generation;
    var replacement = try makeTestConfig(allocator, "second", false);
    const report = controller.applyConfig(&replacement);
    if (report.status == .rejected) {
        try std.testing.expectEqual(original_generation, controller.generation);
        try std.testing.expectEqualStrings("first", first_snapshot.projects[0].section_name);
        return error.OutOfMemory;
    }
    try std.testing.expectEqual(original_generation +% 1, controller.generation);
    try std.testing.expectEqualStrings("first", first_snapshot.projects[0].section_name);

    var guard = controller.acquire();
    defer guard.release();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const snapshot = try guard.snapshot(arena.allocator());
    try std.testing.expectEqualStrings("second", snapshot.projects[0].section_name);
    try std.testing.expect(!snapshot.projects[0].enabled);
}

test "runtime controller snapshots own config-derived response data" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, testSnapshotOwnership, .{});
}

test "runtime controller keeps membership snapshots in one generation" {
    const allocator = std.testing.allocator;
    var controller = try RuntimeController.init(allocator, try makeTestConfig(allocator, "first", false));
    defer controller.deinit();

    {
        var guard = controller.acquire();
        defer guard.release();
        try controller.createInitialHandlesLocked();
    }

    var added = try makeTestConfigForSections(allocator, &.{ "first", "second" }, false);
    _ = controller.applyConfig(&added);

    {
        var guard = controller.acquire();
        defer guard.release();
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const snapshot = try guard.snapshot(arena.allocator());
        try std.testing.expectEqual(@as(u64, 2), snapshot.generation);
        try std.testing.expectEqual(@as(usize, 2), snapshot.projects.len);
        try std.testing.expectEqualStrings("first", snapshot.projects[0].section_name);
        try std.testing.expectEqualStrings("second", snapshot.projects[1].section_name);
    }

    var removed = try makeTestConfig(allocator, "final", false);
    _ = controller.applyConfig(&removed);

    var guard = controller.acquire();
    defer guard.release();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const snapshot = try guard.snapshot(arena.allocator());
    try std.testing.expectEqual(@as(u64, 3), snapshot.generation);
    try std.testing.expectEqual(@as(usize, 1), snapshot.projects.len);
    try std.testing.expectEqualStrings("final", snapshot.projects[0].section_name);
}

test "loop topology groups listeners by actual shared runtime" {
    const allocator = std.testing.allocator;
    var controller = try RuntimeController.init(allocator, try makeTestConfigForSections(allocator, &.{ "alpha", "beta" }, false));
    defer controller.deinit();
    try controller.createInitialHandlesLocked();

    const alpha = controller.handles.items[0];
    const beta = controller.handles.items[1];
    alpha.shared_runtime_manager = &controller.app_loop_manager;
    beta.shared_runtime_manager = &controller.app_loop_manager;
    const alpha_lease = try controller.app_loop_manager.acquire(.global, alpha);
    const beta_lease = try controller.app_loop_manager.acquire(.global, beta);
    try std.testing.expectEqual(alpha_lease.runtime, beta_lease.runtime);
    const runtime_context = alpha_lease.runtime.ctx.?;

    const tcp = try allocator.create(project_status.TcpForwarder);
    tcp.* = .{ .allocator = allocator, .forwarder = null, .runtime = runtime_context, .listen_port = 18080 };
    try alpha.registerTcpHandle(tcp);
    const udp = try allocator.create(project_status.UdpForwarder);
    udp.* = .{ .allocator = allocator, .forwarder = null, .runtime = runtime_context, .listen_port = 18081 };
    try beta.registerUdpHandle(udp);

    var guard = controller.acquire();
    defer guard.release();
    var topology = try guard.loopTopology(allocator);
    defer topology.deinit(allocator);

    try std.testing.expectEqual(@as(u64, 1), topology.generation);
    try std.testing.expectEqualStrings(@tagName(build_options.forward_backend), topology.backend);
    try std.testing.expectEqual(@as(u32, 1), topology.runtime_count);
    try std.testing.expectEqual(@as(u32, 2), topology.project_count);
    try std.testing.expectEqual(@as(u32, 2), topology.listener_count);
    try std.testing.expectEqual(alpha_lease.runtime.runtime_id, topology.runtimes[0].runtime_id);
    try std.testing.expectEqualStrings("global", topology.runtimes[0].mode);
    try std.testing.expectEqualStrings("running", topology.runtimes[0].state);
    try std.testing.expectEqual(@as(u32, 2), topology.runtimes[0].reference_count);
    try std.testing.expectEqualStrings("alpha", topology.runtimes[0].projects[0].section_name);
    try std.testing.expectEqualStrings("tcp", topology.runtimes[0].projects[0].listeners[0].protocol);
    try std.testing.expectEqual(@as(u16, 18080), topology.runtimes[0].projects[0].listeners[0].local_port);
    try std.testing.expectEqualStrings("beta", topology.runtimes[0].projects[1].section_name);
    try std.testing.expectEqualStrings("udp", topology.runtimes[0].projects[1].listeners[0].protocol);
    try std.testing.expectEqual(@as(u16, 18081), topology.runtimes[0].projects[1].listeners[0].local_port);
}

const ApplyConfigWorker = struct {
    controller: *RuntimeController,
    candidate: *config.Config,
    attempting: std.atomic.Value(bool) = .init(false),
    complete: std.atomic.Value(bool) = .init(false),
};

fn applyConfigWorker(worker: *ApplyConfigWorker) void {
    worker.attempting.store(true, .release);
    _ = worker.controller.applyConfig(worker.candidate);
    worker.complete.store(true, .release);
}

test "runtime controller serializes config replacement with active requests" {
    const allocator = std.testing.allocator;
    var controller = try RuntimeController.init(allocator, try makeTestConfig(allocator, "first", false));
    defer controller.deinit();

    var guard = controller.acquire();
    var released = false;
    defer if (!released) guard.release();
    try controller.createInitialHandlesLocked();

    const result = blk: {
        var candidate = try makeTestConfig(allocator, "second", false);
        errdefer candidate.deinit(allocator);
        var worker = ApplyConfigWorker{
            .controller = &controller,
            .candidate = &candidate,
        };
        const thread = try std.Thread.spawn(.{}, applyConfigWorker, .{&worker});

        while (!worker.attempting.load(.acquire)) std.atomic.spinLoopHint();
        const replacement_blocked = !worker.complete.load(.acquire);

        guard.release();
        released = true;
        thread.join();

        break :blk .{
            .blocked = replacement_blocked,
            .complete = worker.complete.load(.acquire),
            .generation = controller.generation,
        };
    };

    try std.testing.expect(result.blocked);
    try std.testing.expect(result.complete);
    try std.testing.expectEqual(@as(u64, 2), result.generation);
}

fn testPrepareAddedHandles(allocator: std.mem.Allocator) !void {
    var candidate = try makeTestConfigForSections(allocator, &.{ "first", "second" }, false);
    defer candidate.deinit(allocator);

    var controller = try RuntimeController.init(allocator, try makeTestConfig(allocator, "first", false));
    defer controller.deinit();

    var guard = controller.acquire();
    defer guard.release();
    try controller.createInitialHandlesLocked();
    var plan = try ProjectReloadPlan.init(allocator, &controller, &candidate);
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 1), controller.handles.items.len);
    try std.testing.expectEqual(@as(usize, 2), plan.new_handles.items.len);
    try std.testing.expectEqualStrings("second", plan.new_handles.items[1].cfg.section_name);
}

test "runtime controller rolls back every added-handle allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, testPrepareAddedHandles, .{});
}

test "project reload plan preserves handles across section reorder" {
    const allocator = std.testing.allocator;
    var controller = try RuntimeController.init(allocator, try makeTestConfigForSections(allocator, &.{ "alpha", "beta" }, false));
    defer controller.deinit();
    try controller.createInitialHandlesLocked();

    const alpha = controller.handles.items[0];
    const beta = controller.handles.items[1];
    var candidate = try makeTestConfigForSections(allocator, &.{ "beta", "alpha" }, false);
    defer candidate.deinit(allocator);
    var plan = try ProjectReloadPlan.init(allocator, &controller, &candidate);
    defer plan.deinit();

    try std.testing.expectEqual(beta, plan.new_handles.items[0]);
    try std.testing.expectEqual(alpha, plan.new_handles.items[1]);
    try std.testing.expectEqual(@as(u32, 0), plan.changed_count);
    try std.testing.expect(!plan.stop_old[0] and !plan.stop_old[1]);
    try std.testing.expect(!plan.start_new[0] and !plan.start_new[1]);
}

test "project reload plan releases every changed listener before activation" {
    const allocator = std.testing.allocator;
    var controller = try RuntimeController.init(allocator, try makeTestConfigForSections(allocator, &.{ "alpha", "beta" }, true));
    defer controller.deinit();
    controller.current_config.projects[0].enable_app_forward = true;
    controller.current_config.projects[0].listen_port = 443;
    controller.current_config.projects[1].enable_app_forward = true;
    controller.current_config.projects[1].listen_port = 444;
    try controller.createInitialHandlesLocked();

    var candidate = try makeTestConfigForSections(allocator, &.{ "alpha", "beta" }, true);
    defer candidate.deinit(allocator);
    candidate.projects[0].enable_app_forward = true;
    candidate.projects[0].listen_port = 444;
    candidate.projects[1].enable_app_forward = true;
    candidate.projects[1].listen_port = 443;
    var plan = try ProjectReloadPlan.init(allocator, &controller, &candidate);
    defer plan.deinit();

    try std.testing.expect(plan.stop_old[0] and plan.stop_old[1]);
    try std.testing.expect(plan.start_new[0] and plan.start_new[1]);
    try std.testing.expectEqual(@as(u32, 2), plan.changed_count);
}

test "runtime controller rejects duplicate project sections without publishing" {
    const allocator = std.testing.allocator;
    var controller = try RuntimeController.init(allocator, try makeTestConfig(allocator, "active", false));
    defer controller.deinit();
    try controller.createInitialHandlesLocked();

    const original_handle = controller.handles.items[0];
    var duplicate = try makeTestConfigForSections(allocator, &.{ "duplicate", "duplicate" }, false);
    const report = controller.applyConfig(&duplicate);

    try std.testing.expectEqual(ApplyStatus.rejected, report.status);
    try std.testing.expectEqual(@as(u64, 1), controller.generation);
    try std.testing.expectEqual(@as(usize, 1), controller.handles.items.len);
    try std.testing.expectEqual(original_handle, controller.handles.items[0]);
    try std.testing.expectEqualStrings("active", controller.current_config.projects[0].section_name);
}

test "project reload plan excludes unrelated service deltas" {
    const allocator = std.testing.allocator;
    var controller = try RuntimeController.init(allocator, try makeTestConfig(allocator, "project", false));
    defer controller.deinit();
    try controller.createInitialHandlesLocked();

    var candidate = try makeTestConfig(allocator, "project", false);
    defer candidate.deinit(allocator);
    candidate.projects[0].connect_timeout_ms = 1234;
    var plan = try ProjectReloadPlan.init(allocator, &controller, &candidate);
    defer plan.deinit();

    try std.testing.expectEqual(@as(usize, 0), plan.frpc_affected.count());
    try std.testing.expectEqual(@as(usize, 0), plan.firewall_affected.count());
    try std.testing.expectEqual(@as(u32, 1), plan.changed_count);
}

test "project reload plan restarts only projects inheriting a changed loop mode" {
    const allocator = std.testing.allocator;
    var controller = try RuntimeController.init(allocator, try makeTestConfigForSections(allocator, &.{ "inherited", "explicit" }, true));
    defer controller.deinit();
    controller.current_config.projects[0].enable_app_forward = true;
    controller.current_config.projects[1].enable_app_forward = true;
    controller.current_config.projects[1].app_forward_loop_mode = .per_project;
    try controller.createInitialHandlesLocked();

    var candidate = try makeTestConfigForSections(allocator, &.{ "inherited", "explicit" }, true);
    defer candidate.deinit(allocator);
    candidate.app_forward_loop_mode = .per_listener;
    candidate.projects[0].enable_app_forward = true;
    candidate.projects[1].enable_app_forward = true;
    candidate.projects[1].app_forward_loop_mode = .per_project;
    var plan = try ProjectReloadPlan.init(allocator, &controller, &candidate);
    defer plan.deinit();

    try std.testing.expect(plan.stop_old[0] and plan.start_new[0]);
    try std.testing.expect(!plan.stop_old[1] and !plan.start_new[1]);
    try std.testing.expectEqual(@as(u32, 1), plan.changed_count);
}

test "project reload plan retries degraded application forwarding" {
    const allocator = std.testing.allocator;
    var controller = try RuntimeController.init(allocator, try makeTestConfig(allocator, "project", true));
    defer controller.deinit();
    controller.current_config.projects[0].enable_app_forward = true;
    try controller.createInitialHandlesLocked();
    controller.handles.items[0].startup_status = .partial;

    var candidate = try makeTestConfig(allocator, "project", true);
    defer candidate.deinit(allocator);
    candidate.projects[0].enable_app_forward = true;
    var plan = try ProjectReloadPlan.init(allocator, &controller, &candidate);
    defer plan.deinit();

    try std.testing.expect(plan.stop_old[0]);
    try std.testing.expect(plan.start_new[0]);
    try std.testing.expectEqual(@as(u32, 1), plan.changed_count);
}

test "FRP config root changes affect only external-file nodes" {
    const allocator = std.testing.allocator;
    var controller = try RuntimeController.init(allocator, try makeTestConfig(allocator, "project", false));
    defer controller.deinit();
    controller.current_config.frp_config_root = try allocator.dupe(u8, "/old-root");
    try addTestFrpcNode(allocator, &controller.current_config.frpc_nodes, "external", .external_file);
    try addTestFrpcNode(allocator, &controller.current_config.frpc_nodes, "builtin", .builtin);
    try controller.createInitialHandlesLocked();

    var candidate = try makeTestConfig(allocator, "project", false);
    defer candidate.deinit(allocator);
    candidate.frp_config_root = try allocator.dupe(u8, "/new-root");
    try addTestFrpcNode(allocator, &candidate.frpc_nodes, "external", .external_file);
    try addTestFrpcNode(allocator, &candidate.frpc_nodes, "builtin", .builtin);
    var plan = try ProjectReloadPlan.init(allocator, &controller, &candidate);
    defer plan.deinit();

    try std.testing.expect(plan.frpc_affected.contains("external"));
    try std.testing.expect(!plan.frpc_affected.contains("builtin"));

    const external_server = config_types.FrpsNode{ .source = .{ .mode = .external_file, .path = "/etc/portweaver/frps.toml" } };
    const builtin_server = config_types.FrpsNode{};
    try std.testing.expect(!frpsNodeUnchanged(external_server, external_server, &controller.current_config, &candidate));
    try std.testing.expect(frpsNodeUnchanged(builtin_server, builtin_server, &controller.current_config, &candidate));
}

test "failed FRPC application retries every configured and referenced node" {
    if (!build_options.frpc_mode) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var controller = try RuntimeController.init(allocator, try makeTestConfig(allocator, "project", false));
    defer controller.deinit();
    try addTestFrpcNode(allocator, &controller.current_config.frpc_nodes, "configured", .builtin);
    try addTestFrpcMapping(allocator, &controller.current_config.projects[0], "referenced-only");
    try controller.createInitialHandlesLocked();
    controller.frpc_config_applied = false;

    var candidate = try makeTestConfig(allocator, "project", false);
    defer candidate.deinit(allocator);
    try addTestFrpcNode(allocator, &candidate.frpc_nodes, "configured", .builtin);
    try addTestFrpcMapping(allocator, &candidate.projects[0], "referenced-only");
    var plan = try ProjectReloadPlan.init(allocator, &controller, &candidate);
    defer plan.deinit();

    try std.testing.expect(plan.frpc_affected.contains("configured"));
    try std.testing.expect(plan.frpc_affected.contains("referenced-only"));
    try std.testing.expectEqual(@as(usize, 2), plan.frpc_affected.count());
}
