const std = @import("std");
const build_options = @import("build_options");
const config = @import("config/mod.zig");
const config_types = @import("config/types.zig");
const project_status = @import("impl/project_status.zig");
const app_forward = @import("impl/app_forward.zig");
const event_log = @import("event_log.zig");
const compat = @import("compat.zig");

const frpc_forward = if (build_options.frpc_mode) @import("impl/frpc_forward.zig") else struct {};
const frps_forward = if (build_options.frps_mode) @import("impl/frps_forward.zig") else struct {};
const ddns_manager = if (build_options.ddns_mode) @import("impl/ddns_manager.zig") else struct {};
const rathole_enabled = build_options.rathole_client_mode or build_options.rathole_server_mode;
const rathole_forward = if (rathole_enabled) @import("impl/rathole_forward.zig") else struct {};

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

/// Owns the active configuration, project handles and all operations that can
/// replace or destroy them. A Guard is the only capability that exposes
/// control-plane commands to adapters such as UBUS.
pub const RuntimeController = struct {
    allocator: std.mem.Allocator,
    current_config: config.Config,
    handles: project_status.ProjectHandleList,
    generation: u64 = 1,
    start_ts: u64,
    mutex: std.Io.Mutex = .init,

    /// Takes ownership of cfg. Call deinit exactly once after all request
    /// adapters have stopped using the controller.
    pub fn init(allocator: std.mem.Allocator, cfg: config.Config) !RuntimeController {
        var owned_config = cfg;
        errdefer owned_config.deinit(allocator);
        return .{
            .allocator = allocator,
            .current_config = owned_config,
            .handles = try project_status.ProjectHandleList.initCapacity(allocator, owned_config.projects.len),
            .start_ts = currentTs(),
        };
    }

    /// Stops owned services and releases project handles before releasing their
    /// borrowed configuration. The caller must stop UBUS before calling this.
    pub fn deinit(self: *RuntimeController) void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        project_status.stopAll(&self.handles);
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

        try self.createInitialHandlesLocked();
        if (rathole_enabled) try rathole_forward.apply_config(self.allocator, &self.current_config);
        refreshFirewallRules(self.allocator, &self.current_config);
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
    pub fn applyConfig(self: *RuntimeController, new_cfg: *config.Config) void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        self.applyConfigLocked(new_cfg);
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

        pub fn setProjectEnabled(self: *Guard, id: u32, enabled: bool) !ProjectEnabledResult {
            const idx: usize = @intCast(id);
            if (idx >= self.controller.handles.items.len) return error.InvalidArgument;

            const project = self.controller.handles.items[idx];
            const old_enabled = project.cfg.enabled;
            project.cfg.enabled = enabled;
            project.last_changed = currentTs();
            project.setRuntimeEnabled(enabled);

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
                app_forward.startForwarding(project) catch |err| {
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
            handle.last_changed = self.start_ts;
            self.handles.appendAssumeCapacity(handle);
        }
    }

    fn startForwardingLocked(self: *RuntimeController) !bool {
        var has_app_forward = false;
        if (build_options.frpc_mode) frpc_forward.initialize(self.allocator);

        for (self.handles.items) |handle| {
            if (!handle.cfg.enabled) {
                handle.setDisabled();
                continue;
            }
            if (handle.cfg.enable_app_forward) has_app_forward = true;
            startForwardingForHandle(handle);
            if (build_options.frpc_mode) {
                frpc_forward.startForwarding(handle, &self.current_config.frpc_nodes) catch |err| {
                    std.log.err("Failed to start FRPC forwarding for project {d} ({s}): {any}", .{ handle.id + 1, handle.cfg.remark, err });
                };
            }
        }
        if (build_options.frpc_mode) {
            frpc_forward.startConfiguredClients(&self.current_config.frpc_nodes) catch |err| {
                std.log.warn("Failed to start configured FRPC clients: {any}", .{err});
            };
        }
        return has_app_forward;
    }

    fn applyConfigLocked(self: *RuntimeController, new_cfg: *config.Config) void {
        const old_cfg = &self.current_config;
        const old_projects = old_cfg.projects;
        const new_projects = new_cfg.projects;
        const common = @min(old_projects.len, new_projects.len);

        self.prepareAddedHandlesLocked(new_cfg) catch |err| {
            std.log.warn("Reload: unable to prepare projects, keeping current config: {any}", .{err});
            new_cfg.deinit(self.allocator);
            return;
        };

        var changed: u32 = 0;
        for (0..common) |i| {
            const handle = self.handles.items[i];
            // Compare the handle's runtime view rather than only the previous
            // persisted config. A reload must reconcile a temporary UBUS
            // enable/disable operation with the newly loaded configuration.
            if (handle.cfg.eql(new_projects[i])) {
                handle.cfg = new_projects[i];
                handle.use_nftables = new_cfg.use_nftables;
                continue;
            }

            const was_enabled = handle.cfg.enabled;
            const is_enabled = new_projects[i].enabled;
            std.log.info("Reload: project {d} ({s}) config changed, restarting", .{ i + 1, new_projects[i].remark });
            handle.teardownForwarders();
            handle.cfg = new_projects[i];
            handle.use_nftables = new_cfg.use_nftables;
            handle.last_changed = currentTs();
            if (is_enabled) startForwardingForHandle(handle);
            changed += 1;

            if (was_enabled != is_enabled) {
                if (is_enabled) {
                    event_log.logEventFmt(.project_started, @intCast(i), "Project {d} enabled via reload", .{i + 1});
                } else {
                    event_log.logEventFmt(.project_stopped, @intCast(i), "Project {d} disabled via reload", .{i + 1});
                }
            }
        }

        for (common..new_projects.len) |i| {
            const handle = self.handles.items[i];
            handle.last_changed = currentTs();
            changed += 1;
            if (!new_projects[i].enabled) {
                handle.setDisabled();
                event_log.logEventFmt(.project_stopped, @intCast(i), "Project {d} added (disabled)", .{i + 1});
                continue;
            }
            startForwardingForHandle(handle);
            event_log.logEventFmt(.project_started, @intCast(i), "Project {d} added and enabled", .{i + 1});
        }

        if (old_projects.len > new_projects.len) {
            for (new_projects.len..old_projects.len) |i| {
                const handle = self.handles.items[i];
                std.log.info("Reload: removing project {d} ({s})", .{ i + 1, handle.cfg.remark });
                handle.deinit();
                self.allocator.destroy(handle);
                changed += 1;
                event_log.logEventFmt(.project_stopped, @intCast(i), "Project {d} removed", .{i + 1});
            }
            self.handles.shrinkRetainingCapacity(new_projects.len);
        }

        if (build_options.frpc_mode) {
            frpc_forward.stopAll();
            frpc_forward.initialize(self.allocator);
            for (self.handles.items) |handle| {
                if (!handle.cfg.enabled) continue;
                frpc_forward.startForwarding(handle, &new_cfg.frpc_nodes) catch |err| {
                    std.log.warn("Reload: failed to rebuild FRPC project {d}: {any}", .{ handle.id + 1, err });
                };
            }
            frpc_forward.startConfiguredClients(&new_cfg.frpc_nodes) catch |err| {
                std.log.warn("Reload: failed to start configured FRPC clients: {any}", .{err});
            };
        }

        refreshFirewallRules(self.allocator, new_cfg);
        if (build_options.ddns_mode) {
            ddns_manager.applyConfig(self.allocator, new_cfg.ddns_configs) catch |err| {
                std.log.warn("Reload: failed to apply DDNS config: {any}", .{err});
            };
        }
        if (build_options.frps_mode) reloadFrpsNodes(self.allocator, old_cfg, new_cfg);
        if (rathole_enabled) {
            rathole_forward.apply_config(self.allocator, new_cfg) catch |err| {
                std.log.err("Reload: failed to apply Rathole configuration: {any}", .{err});
            };
        }

        old_cfg.deinit(self.allocator);
        self.current_config = new_cfg.*;
        self.generation +%= 1;
        event_log.logEventFmt(.info, -1, "Config reloaded: {d} project(s) changed", .{changed});
        std.log.info("Reload complete: {d} project(s) changed", .{changed});
    }

    fn prepareAddedHandlesLocked(self: *RuntimeController, cfg: *const config.Config) !void {
        const original_len = self.handles.items.len;
        if (cfg.projects.len <= original_len) return;
        try self.handles.ensureTotalCapacity(cfg.projects.len);
        errdefer {
            for (self.handles.items[original_len..]) |handle| {
                handle.deinit();
                self.allocator.destroy(handle);
            }
            self.handles.shrinkRetainingCapacity(original_len);
        }
        for (original_len..cfg.projects.len) |i| {
            const handle = try self.allocator.create(project_status.ProjectHandle);
            handle.* = project_status.ProjectHandle.init(self.allocator, i, cfg.projects[i], cfg.use_nftables);
            handle.last_changed = currentTs();
            self.handles.appendAssumeCapacity(handle);
        }
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

    fn findProjectLocked(self: *RuntimeController, name: []const u8) ?*project_status.ProjectHandle {
        for (self.handles.items) |project| {
            if (std.mem.eql(u8, project.cfg.section_name, name)) return project;
        }
        const index = std.fmt.parseUnsigned(usize, name, 10) catch return null;
        if (index < self.handles.items.len) return self.handles.items[index];
        return null;
    }
};

fn startForwardingForHandle(handle: *project_status.ProjectHandle) void {
    if (!handle.cfg.enable_app_forward) return;
    app_forward.startForwarding(handle) catch |err| {
        std.log.err("Reload: failed to start forwarding for project {d} ({s}): {any}", .{ handle.id + 1, handle.cfg.remark, err });
    };
}

fn refreshFirewallRules(allocator: std.mem.Allocator, cfg: *const config.Config) void {
    if (build_options.nftables_mode and cfg.use_nftables) {
        const nftables = @import("nftables/mod.zig");
        const nft_firewall = @import("impl/nft_firewall.zig");
        if (!nftables.isLoaded()) {
            std.log.warn("Reload: libnftables not available, skipping nftables rules", .{});
            return;
        }
        var ctx = nftables.NftablesContext.init(allocator) catch |err| {
            std.log.warn("Reload: failed to init nftables context: {any}", .{err});
            return;
        };
        defer ctx.deinit();
        nft_firewall.setupTable(&ctx, allocator) catch |err| {
            std.log.warn("Reload: failed to setup nftables table: {any}", .{err});
            return;
        };
        nft_firewall.clearRules(&ctx) catch |err| {
            std.log.warn("Reload: failed to clear nftables rules: {any}", .{err});
        };
        for (cfg.projects) |project| {
            if (!project.enabled) continue;
            nft_firewall.applyRulesForProject(&ctx, allocator, project) catch |err| {
                std.log.warn("Reload: failed to apply nftables rules for project: {any}", .{err});
            };
        }
        return;
    }
    if (build_options.uci_mode) {
        const firewall = @import("impl/uci_firewall.zig");
        const uci = @import("uci/mod.zig");
        var uci_ctx = uci.UciContext.alloc() catch |err| {
            std.log.warn("Reload: failed to alloc UCI context: {any}", .{err});
            return;
        };
        defer uci_ctx.free();
        firewall.clearFirewallRules(uci_ctx, allocator) catch |err| {
            std.log.warn("Reload: failed to clear firewall rules: {any}", .{err});
        };
        for (cfg.projects) |project| {
            if (!project.enabled) continue;
            firewall.applyFirewallRulesForProject(uci_ctx, allocator, project) catch |err| {
                std.log.warn("Reload: failed to apply firewall rules: {any}", .{err});
            };
        }
        firewall.reloadFirewall(allocator) catch |err| {
            std.log.warn("Reload: failed to reload firewall: {any}", .{err});
        };
    }
}

fn reloadFrpsNodes(allocator: std.mem.Allocator, old_cfg: *const config.Config, new_cfg: *const config.Config) void {
    var new_it = new_cfg.frps_nodes.iterator();
    while (new_it.next()) |entry| {
        const name = entry.key_ptr.*;
        const new_node = entry.value_ptr.*;
        if (!new_node.enabled) continue;
        if (old_cfg.frps_nodes.get(name)) |old_node| {
            if (old_node.eql(new_node) and new_node.source.mode == .builtin) continue;
        }
        frps_forward.restartServer(allocator, name, new_node) catch |err| {
            std.log.warn("Reload: failed to restart FRPS node {s}: {any}", .{ name, err });
        };
    }
    var old_it = old_cfg.frps_nodes.iterator();
    while (old_it.next()) |entry| {
        const name = entry.key_ptr.*;
        if (new_cfg.frps_nodes.get(name)) |new_node| {
            if (new_node.enabled) continue;
        }
        frps_forward.removeServer(name);
    }
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
    controller.applyConfig(&replacement);
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
    controller.applyConfig(&added);

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
    controller.applyConfig(&removed);

    var guard = controller.acquire();
    defer guard.release();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const snapshot = try guard.snapshot(arena.allocator());
    try std.testing.expectEqual(@as(u64, 3), snapshot.generation);
    try std.testing.expectEqual(@as(usize, 1), snapshot.projects.len);
    try std.testing.expectEqualStrings("final", snapshot.projects[0].section_name);
}

const ApplyConfigWorker = struct {
    controller: *RuntimeController,
    candidate: *config.Config,
    attempting: std.atomic.Value(bool) = .init(false),
    complete: std.atomic.Value(bool) = .init(false),
};

fn applyConfigWorker(worker: *ApplyConfigWorker) void {
    worker.attempting.store(true, .release);
    worker.controller.applyConfig(worker.candidate);
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
    try controller.prepareAddedHandlesLocked(&candidate);
    try std.testing.expectEqual(@as(usize, 2), controller.handles.items.len);
    try std.testing.expectEqualStrings("second", controller.handles.items[1].cfg.section_name);
}

test "runtime controller rolls back every added-handle allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, testPrepareAddedHandles, .{});
}
