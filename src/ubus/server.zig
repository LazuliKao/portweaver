const std = @import("std");
const build_options = @import("build_options");
const types = @import("../config/types.zig");
const app_forward = @import("../impl/app_forward.zig");
const ubus = @import("libubus.zig");
const ubox = @import("ubox.zig");
const libblobmsg_json = @import("libblobmsg_json.zig");
const c = ubox.c;
const project_status = @import("../impl/project_status.zig");
const frp_status = if (build_options.frpc_mode or build_options.frps_mode) @import("../impl/frp_status.zig") else struct {};
const frpc_forward = if (build_options.frpc_mode) @import("../impl/frpc_forward.zig") else struct {};
const frps_forward = if (build_options.frps_mode) @import("../impl/frps_forward.zig") else struct {};
const ddns_manager = if (build_options.ddns_mode) @import("../impl/ddns_manager.zig") else struct {};
const nftables = if (build_options.nftables_mode) @import("../nftables/mod.zig") else struct {};
const wol = if (build_options.wol_mode) @import("../impl/wol.zig") else struct {
    pub const WolManager = struct {
        pub fn init(allocator: std.mem.Allocator) WolManager {
            _ = allocator;
            return .{};
        }
        pub fn deinit(self: *WolManager) void {
            _ = self;
        }
    };
    pub fn sendWoLWithCooldown(macs: []const []const u8, cooldown: u64, mgr: *WolManager, id: u32) void {
        _ = macs;
        _ = cooldown;
        _ = mgr;
        _ = id;
    }
};
const compat = @import("../compat.zig");
const event_log = @import("../event_log.zig");
const serialization = @import("serialization.zig");
const RawJson = serialization.RawJson;
const wrapHandler = serialization.wrapHandler;
const reload = @import("../reload.zig");

const STATUS_RUNNING: [:0]const u8 = "running";
const STATUS_STOPPED: [:0]const u8 = "stopped";
const STATUS_DEGRADED: [:0]const u8 = "degraded";

const GlobalSnapshot = struct {
    status: [:0]const u8,
    total_projects: u32,
    active_ports: u32,
    total_bytes_in: u64,
    total_bytes_out: u64,
    uptime: u64,
};

const RuntimeState = struct {
    allocator: std.mem.Allocator,
    start_ts: u64,
    projects: *std.array_list.Managed(project_status.ProjectHandle),
    frpc_nodes: *const std.StringHashMap(types.FrpcNode),
    wol_targets: *const std.StringHashMap(types.WolTarget),
    enabled: []bool,
    last_changed: []u64,
    use_nftables: bool,
    mutex: std.Io.Mutex = .init,
    pub fn init(allocator: std.mem.Allocator, projects: *std.array_list.Managed(project_status.ProjectHandle), frpc_nodes: *const std.StringHashMap(types.FrpcNode), wol_targets: *const std.StringHashMap(types.WolTarget)) !*RuntimeState {
        const state = try allocator.create(RuntimeState);
        errdefer allocator.destroy(state);

        const now = currentTs();
        const enabled = try allocator.alloc(bool, projects.items.len);
        errdefer allocator.free(enabled);

        const last_changed = try allocator.alloc(u64, projects.items.len);
        errdefer allocator.free(last_changed);

        state.* = .{
            .allocator = allocator,
            .start_ts = now,
            .projects = projects,
            .frpc_nodes = frpc_nodes,
            .wol_targets = wol_targets,
            .enabled = enabled,
            .last_changed = last_changed,
            .use_nftables = if (projects.items.len > 0) projects.items[0].use_nftables else false,
        };

        for (projects.items, 0..) |project, idx| {
            state.enabled[idx] = project.cfg.enabled;
            state.last_changed[idx] = now;
        }

        return state;
    }

    pub fn deinit(self: *RuntimeState) void {
        self.allocator.free(self.enabled);
        self.allocator.free(self.last_changed);
        self.allocator.destroy(self);
    }

    fn syncFromProjectsLocked(self: *RuntimeState) !void {
        const new_len = self.projects.items.len;
        const new_enabled = try self.allocator.alloc(bool, new_len);
        errdefer self.allocator.free(new_enabled);
        const new_last_changed = try self.allocator.alloc(u64, new_len);
        errdefer self.allocator.free(new_last_changed);

        const now = currentTs();
        for (0..new_len) |i| {
            const project = &self.projects.items[i];
            const is_enabled = project.cfg.enabled;
            new_enabled[i] = is_enabled;

            if (i < self.enabled.len) {
                if (self.enabled[i] != is_enabled) {
                    new_last_changed[i] = now;
                } else {
                    new_last_changed[i] = self.last_changed[i];
                }
            } else {
                new_last_changed[i] = now;
            }
        }

        self.allocator.free(self.enabled);
        self.allocator.free(self.last_changed);
        self.enabled = new_enabled;
        self.last_changed = new_last_changed;
        self.use_nftables = if (new_len > 0) self.projects.items[0].use_nftables else false;
    }

    pub fn syncFromProjects(self: *RuntimeState) !void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        try self.syncFromProjectsLocked();
    }

    fn globalSnapshot(self: *RuntimeState) GlobalSnapshot {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        if (self.enabled.len != self.projects.items.len) {
            self.syncFromProjectsLocked() catch |err| {
                std.log.err("ubus: failed to sync state in snapshot: {any}", .{err});
            };
        }

        var enabled_projects: u32 = 0;
        var success_projects: u32 = 0;
        var active_ports: u32 = 0;
        var bytes_in: u64 = 0;
        var bytes_out: u64 = 0;

        var i: usize = 0;
        while (i < self.projects.items.len) : (i += 1) {
            const project = &self.projects.items[i];
            if (self.enabled[i]) {
                enabled_projects += 1;
                if (project.startup_status == .success) {
                    success_projects += 1;
                }
            }
            active_ports += project.active_ports;

            // Collect traffic stats from the project
            const info = project.getProjectRuntimeInfo();
            bytes_in += info.bytes_in;
            bytes_out += info.bytes_out;
        }

        // 判断整体状态：当启用的项目数为0时是STOPPED，当启用项目全部启动成功时是RUNNING，否则是DEGRADED
        const status: [:0]const u8 = if (enabled_projects == 0)
            STATUS_STOPPED
        else if (success_projects == enabled_projects)
            STATUS_RUNNING
        else
            STATUS_DEGRADED;

        const now = currentTs();
        return .{
            .status = status,
            .total_projects = @intCast(self.projects.items.len),
            .active_ports = active_ports,
            .total_bytes_in = bytes_in,
            .total_bytes_out = bytes_out,
            .uptime = now - self.start_ts,
        };
    }
};

pub var g_state: ?*RuntimeState = null;
var g_ctx: ?*c.ubus_context = null;
var g_thread: ?std.Thread = null;
var g_lifecycle_mutex: std.Io.Mutex = .init;
var g_wol_manager: ?wol.WolManager = null;
var g_wol_manager_mutex: std.Io.Mutex = .init;

const set_enabled_policy = [_]c.blobmsg_policy{
    .{ .name = "id", .type = c.BLOBMSG_TYPE_INT32 },
    .{ .name = "enabled", .type = c.BLOBMSG_TYPE_BOOL },
};

const frp_info_policy = [_]c.blobmsg_policy{
    .{ .name = "id", .type = c.BLOBMSG_TYPE_STRING },
};

const frp_proxy_stats_policy = [_]c.blobmsg_policy{
    .{ .name = "id", .type = c.BLOBMSG_TYPE_STRING },
};

const frps_info_policy = [_]c.blobmsg_policy{
    .{ .name = "id", .type = c.BLOBMSG_TYPE_STRING },
};

const frps_proxy_stats_policy = [_]c.blobmsg_policy{
    .{ .name = "id", .type = c.BLOBMSG_TYPE_STRING },
};

const ddns_info_policy = [_]c.blobmsg_policy{
    .{ .name = "name", .type = c.BLOBMSG_TYPE_STRING },
};

const wol_project_policy = [_]c.blobmsg_policy{
    .{ .name = "project", .type = c.BLOBMSG_TYPE_STRING },
    .{ .name = "target", .type = c.BLOBMSG_TYPE_STRING },
};

const restart_project_policy = [_]c.blobmsg_policy{
    .{ .name = "id", .type = c.BLOBMSG_TYPE_INT32 },
};

const method_names = struct {
    pub const get_status: [:0]const u8 = "get_status";
    pub const list_projects: [:0]const u8 = "list_projects";
    pub const set_enabled: [:0]const u8 = "set_enabled";
    pub const get_frp_status: [:0]const u8 = "get_frp_status";
    pub const get_frpc_info: [:0]const u8 = "get_frpc_info";
    pub const get_frpc_proxy_stats: [:0]const u8 = "get_frpc_proxy_stats";
    pub const clear_frpc_logs: [:0]const u8 = "clear_frpc_logs";
    pub const get_frps_info: [:0]const u8 = "get_frps_info";
    pub const get_frps_proxy_stats: [:0]const u8 = "get_frps_proxy_stats";
    pub const clear_frps_logs: [:0]const u8 = "clear_frps_logs";
    pub const get_events: [:0]const u8 = "get_events";
    pub const get_ddns_global_status: [:0]const u8 = "get_ddns_global_status";
    pub const get_ddns_status: [:0]const u8 = "get_ddns_status";
    pub const get_ddns_info: [:0]const u8 = "get_ddns_info";
    pub const clear_ddns_logs: [:0]const u8 = "clear_ddns_logs";
    pub const get_full_status: [:0]const u8 = "get_full_status";
    pub const reload_config: [:0]const u8 = "reload_config";
    pub const restart_project: [:0]const u8 = "restart_project";
    pub const get_nftables_rules: [:0]const u8 = "get_nftables_rules";
    pub const wol_wake: [:0]const u8 = "wol_wake";
    pub const wol_status: [:0]const u8 = "wol_status";
    pub const object_name: [:0]const u8 = "portweaver";
};

const field_names = struct {
    pub const status: [:0]const u8 = "status";
    pub const total_projects: [:0]const u8 = "total_projects";
    pub const active_ports: [:0]const u8 = "active_ports";
    pub const total_bytes_in: [:0]const u8 = "total_bytes_in";
    pub const total_bytes_out: [:0]const u8 = "total_bytes_out";
    pub const uptime: [:0]const u8 = "uptime";
    pub const projects: [:0]const u8 = "projects";
    pub const id: [:0]const u8 = "id";
    pub const remark: [:0]const u8 = "remark";
    pub const enabled: [:0]const u8 = "enabled";
    pub const bytes_in: [:0]const u8 = "bytes_in";
    pub const bytes_out: [:0]const u8 = "bytes_out";
    pub const last_changed: [:0]const u8 = "last_changed";
    pub const startup_status: [:0]const u8 = "startup_status";
    pub const error_code: [:0]const u8 = "error_code";
    pub const frp_enabled: [:0]const u8 = "frp_enabled";
    pub const frp_version: [:0]const u8 = "frp_version";
    pub const frp_status: [:0]const u8 = "frp_status";
    pub const last_error: [:0]const u8 = "last_error";
    pub const logs: [:0]const u8 = "logs";
    pub const events: [:0]const u8 = "events";
    pub const timestamp: [:0]const u8 = "timestamp";
    pub const event_type: [:0]const u8 = "type";
    pub const message: [:0]const u8 = "message";
    pub const project_id: [:0]const u8 = "project_id";
    pub const client_count: [:0]const u8 = "client_count";
    pub const forwarders: [:0]const u8 = "forwarders";
    pub const protocol: [:0]const u8 = "protocol";
    pub const local_port: [:0]const u8 = "local_port";
    pub const section: [:0]const u8 = "section";
    pub const name: [:0]const u8 = "name";
    pub const provider: [:0]const u8 = "provider";
    pub const last_update: [:0]const u8 = "last_update";
    pub const last_ip: [:0]const u8 = "last_ip";
    pub const ddns_enabled: [:0]const u8 = "ddns_enabled";
    pub const ddns_version: [:0]const u8 = "ddns_version";
    pub const ddns_status: [:0]const u8 = "ddns_status";
    pub const proxy_count: [:0]const u8 = "proxy_count";
    pub const server_count: [:0]const u8 = "server_count";
    pub const frp: [:0]const u8 = "frp";
    pub const ddns: [:0]const u8 = "ddns";
    pub const clients: [:0]const u8 = "clients";
    pub const servers: [:0]const u8 = "servers";
    pub const instances: [:0]const u8 = "instances";
    pub const version: [:0]const u8 = "version";
    pub const active_sessions: [:0]const u8 = "active_sessions";
    pub const success: [:0]const u8 = "success";
    pub const sent_count: [:0]const u8 = "sent_count";
    pub const mac_count: [:0]const u8 = "mac_count";
    pub const cooldown_ms: [:0]const u8 = "cooldown_ms";
    pub const detect_protocols: [:0]const u8 = "detect_protocols";
    pub const project: [:0]const u8 = "project";
};

pub fn start(allocator: std.mem.Allocator, projects: *std.array_list.Managed(project_status.ProjectHandle), frpc_nodes: *const std.StringHashMap(types.FrpcNode), wol_targets: *const std.StringHashMap(types.WolTarget)) !void {
    g_lifecycle_mutex.lockUncancelable(compat.io());
    defer g_lifecycle_mutex.unlock(compat.io());

    if (g_state != null) return;
    const state = try RuntimeState.init(allocator, projects, frpc_nodes, wol_targets);
    g_state = state;
    errdefer {
        g_state = null;
        state.deinit();
    }

    const thread = try std.Thread.spawn(.{}, ubusThread, .{state});
    g_thread = thread;
}

pub fn stop() void {
    ubox.uloopCancel() catch |err| {
        std.log.warn("ubus: failed to cancel uloop: {any}", .{err});
    };

    g_lifecycle_mutex.lockUncancelable(compat.io());
    const ctx_to_shutdown = g_ctx;
    const thread_to_join = g_thread;
    g_thread = null;

    // Keep the lifecycle lock while shutting down the context so the UBUS
    // thread cannot clear/free g_ctx between taking the snapshot and using it.
    if (ctx_to_shutdown) |ctx| {
        ubus.ubus_shutdown(ctx) catch |err| {
            std.log.warn("ubus: shutdown failed: {any}", .{err});
        };
    }
    g_lifecycle_mutex.unlock(compat.io());

    if (thread_to_join) |thread| {
        thread.join();
    }

    g_lifecycle_mutex.lockUncancelable(compat.io());
    defer g_lifecycle_mutex.unlock(compat.io());

    if (g_state) |state| {
        g_state = null;
        state.deinit();
    }

    if (g_wol_manager) |*mgr| {
        mgr.deinit();
        g_wol_manager = null;
    }

    g_ctx = null;
}

fn ubusThread(state: *RuntimeState) void {
    _ = state; // Store state reference for later use when forwarding metrics
    ubox.uloopInit() catch |err| {
        std.log.warn("ubus: failed to init uloop: {any}", .{err});
        return;
    };
    defer ubox.uloopDone() catch |err| {
        std.log.warn("ubus: failed to cleanup uloop: {any}", .{err});
    };

    const ctx_opt = ubus.ubus_connect(null) catch |err| blk: {
        std.log.warn("ubus: connect failed: {any}", .{err});
        break :blk null;
    };
    if (ctx_opt == null) {
        std.log.warn("ubus: unable to connect to socket", .{});
        return;
    }
    const ctx = ctx_opt.?;
    g_lifecycle_mutex.lockUncancelable(compat.io());
    g_ctx = ctx;
    g_lifecycle_mutex.unlock(compat.io());
    defer {
        g_lifecycle_mutex.lockUncancelable(compat.io());
        if (g_ctx == ctx) {
            g_ctx = null;
        }
        g_lifecycle_mutex.unlock(compat.io());

        ubus.ubus_free(ctx) catch |err| {
            std.log.warn("ubus: free context failed: {any}", .{err});
        };
    }

    const commonMethods = [_]c.ubus_method{
        .{
            .name = method_names.get_status,
            .handler = wrapHandler(getStatus, void, null),
            .mask = 0,
            .tags = 0,
            .policy = null,
            .n_policy = 0,
        },
        .{
            .name = method_names.list_projects,
            .handler = wrapHandler(listProjects, void, null),
            .mask = 0,
            .tags = 0,
            .policy = null,
            .n_policy = 0,
        },
        .{
            .name = method_names.set_enabled,
            .handler = wrapHandler(setEnabled, SetEnabledArgs, &set_enabled_policy),
            .mask = 0,
            .tags = 0,
            .policy = &set_enabled_policy,
            .n_policy = @intCast(set_enabled_policy.len),
        },
        .{
            .name = method_names.get_events,
            .handler = wrapHandler(getEvents, void, null),
            .mask = 0,
            .tags = 0,
            .policy = null,
            .n_policy = 0,
        },
        .{
            .name = method_names.get_full_status,
            .handler = wrapHandler(getFullStatus, void, null),
            .mask = 0,
            .tags = 0,
            .policy = null,
            .n_policy = 0,
        },
        .{
            .name = method_names.reload_config,
            .handler = wrapHandler(handleReloadConfig, void, null),
            .mask = 0,
            .tags = 0,
            .policy = null,
            .n_policy = 0,
        },
        .{
            .name = method_names.restart_project,
            .handler = wrapHandler(handleRestartProject, RestartProjectArgs, &restart_project_policy),
            .mask = 0,
            .tags = 0,
            .policy = &restart_project_policy,
            .n_policy = @intCast(restart_project_policy.len),
        },
    };
    const nftablesMethods = if (build_options.nftables_mode) [_]c.ubus_method{
        .{
            .name = method_names.get_nftables_rules,
            .handler = wrapHandler(getNftablesRules, void, null),
            .mask = 0,
            .tags = 0,
            .policy = null,
            .n_policy = 0,
        },
    } else [_]c.ubus_method{};
    const frpMethods = if (build_options.frpc_mode or build_options.frps_mode) [_]c.ubus_method{
        .{
            .name = method_names.get_frp_status,
            .handler = wrapHandler(getFrpStatus, void, null),
            .mask = 0,
            .tags = 0,
            .policy = null,
            .n_policy = 0,
        },
    } else [_]c.ubus_method{};
    const frpcMethods = if (build_options.frpc_mode) [_]c.ubus_method{
        .{
            .name = method_names.get_frpc_info,
            .handler = wrapHandler(getFrpcInfo, GetFrpcInfoArgs, &frp_info_policy),
            .mask = 0,
            .tags = 0,
            .policy = &frp_info_policy,
            .n_policy = @intCast(frp_info_policy.len),
        },
        .{
            .name = method_names.get_frpc_proxy_stats,
            .handler = wrapHandler(getFrpProxyStats, GetFrpcProxyStatsArgs, &frp_proxy_stats_policy),
            .mask = 0,
            .tags = 0,
            .policy = &frp_proxy_stats_policy,
            .n_policy = @intCast(frp_proxy_stats_policy.len),
        },
        .{
            .name = method_names.clear_frpc_logs,
            .handler = wrapHandler(clearFrpLogs, GetFrpcInfoArgs, &frp_info_policy),
            .mask = 0,
            .tags = 0,
            .policy = &frp_info_policy,
            .n_policy = @intCast(frp_info_policy.len),
        },
    } else [_]c.ubus_method{};
    const frpsMethods = if (build_options.frps_mode) [_]c.ubus_method{
        .{
            .name = method_names.get_frps_info,
            .handler = wrapHandler(getFrpsInfo, GetFrpcInfoArgs, &frps_info_policy),
            .mask = 0,
            .tags = 0,
            .policy = &frps_info_policy,
            .n_policy = @intCast(frps_info_policy.len),
        },
        .{
            .name = method_names.get_frps_proxy_stats,
            .handler = wrapHandler(getFrpsProxyStats, GetFrpcProxyStatsArgs, &frps_proxy_stats_policy),
            .mask = 0,
            .tags = 0,
            .policy = &frps_proxy_stats_policy,
            .n_policy = @intCast(frps_proxy_stats_policy.len),
        },
        .{
            .name = method_names.clear_frps_logs,
            .handler = wrapHandler(clearFrpsLogs, GetFrpcInfoArgs, &frps_info_policy),
            .mask = 0,
            .tags = 0,
            .policy = &frps_info_policy,
            .n_policy = @intCast(frps_info_policy.len),
        },
    } else [_]c.ubus_method{};
    const ddnsMethods = if (build_options.ddns_mode) [_]c.ubus_method{
        .{
            .name = method_names.get_ddns_global_status,
            .handler = wrapHandler(getDdnsGlobalStatus, void, null),
            .mask = 0,
            .tags = 0,
            .policy = null,
            .n_policy = 0,
        },
        .{
            .name = method_names.get_ddns_status,
            .handler = wrapHandler(getDdnsStatuses, void, null),
            .mask = 0,
            .tags = 0,
            .policy = null,
            .n_policy = 0,
        },
        .{
            .name = method_names.get_ddns_info,
            .handler = wrapHandler(getDdnsInfo, GetDdnsInfoArgs, &ddns_info_policy),
            .mask = 0,
            .tags = 0,
            .policy = &ddns_info_policy,
            .n_policy = @intCast(ddns_info_policy.len),
        },
        .{
            .name = method_names.clear_ddns_logs,
            .handler = wrapHandler(clearDdnsLogs, GetDdnsInfoArgs, &ddns_info_policy),
            .mask = 0,
            .tags = 0,
            .policy = &ddns_info_policy,
            .n_policy = @intCast(ddns_info_policy.len),
        },
    } else [_]c.ubus_method{};
    const wolMethods = if (build_options.wol_mode) [_]c.ubus_method{
        .{
            .name = method_names.wol_wake,
            .handler = wrapHandler(wolWake, WolProjectArgs, &wol_project_policy),
            .mask = 0,
            .tags = 0,
            .policy = &wol_project_policy,
            .n_policy = @intCast(wol_project_policy.len),
        },
        .{
            .name = method_names.wol_status,
            .handler = wrapHandler(wolStatus, WolProjectArgs, &wol_project_policy),
            .mask = 0,
            .tags = 0,
            .policy = &wol_project_policy,
            .n_policy = @intCast(wol_project_policy.len),
        },
    } else [_]c.ubus_method{};
    const methods = commonMethods ++ nftablesMethods ++ frpMethods ++ frpcMethods ++ frpsMethods ++ ddnsMethods ++ wolMethods;
    var obj_type = c.ubus_object_type{
        .name = method_names.object_name,
        .id = 0,
        .methods = &methods,
        .n_methods = @intCast(methods.len),
    };

    var obj = std.mem.zeroes(c.ubus_object);
    obj.name = method_names.object_name;
    obj.type = &obj_type;
    obj.methods = &methods;
    obj.n_methods = @intCast(methods.len);

    _ = ubus.ubus_add_object(ctx, &obj) catch |err| {
        std.log.warn("ubus: add object failed: {any}", .{err});
        return;
    };

    ubox.uloopFdAdd(&ctx.sock, @intCast(c.ULOOP_BLOCKING | c.ULOOP_READ)) catch |err| {
        std.log.warn("ubus: add fd failed: {any}", .{err});
        return;
    };

    std.log.info("ubus: server started successfully.", .{});

    ubox.uloopRun(-1) catch {};
}

// === RPC argument & response structures ===

const GetStatusResponse = struct {
    status: []const u8,
    total_projects: u32,
    active_ports: u32,
    total_bytes_in: u64,
    total_bytes_out: u64,
    uptime: u64,
};

const ForwarderStatsInfo = struct {
    protocol: []const u8,
    local_port: u32,
    bytes_in: u64,
    bytes_out: u64,
    active_sessions: u32,
};

const ProjectStatusInfo = struct {
    id: u32,
    section_name: []const u8,
    enabled: bool,
    status: []const u8,
    startup_status: []const u8,
    active_ports: u32,
    bytes_in: u64,
    bytes_out: u64,
    active_sessions: u32,
    last_changed: u64,
    error_code: ?i32 = null,
    enable_app_stats: bool,
    enable_firewall_stats: bool,
    forwarders: []const ForwarderStatsInfo,
};

const ListProjectsResponse = struct {
    projects: []const ProjectStatusInfo,
};

const SetEnabledArgs = struct {
    id: u32,
    enabled: bool,
};

const SetEnabledResponse = struct {
    id: u32,
    enabled: bool,
    status: []const u8,
    last_changed: u64,
};

const RestartProjectArgs = struct {
    id: u32,
};

const RestartProjectResponse = struct {
    id: u32,
    status: []const u8,
};

const ReloadConfigResponse = struct {
    success: bool,
    changes: u32,
    message: []const u8,
};

const FrpcStatusInfo = struct {
    enabled: bool,
    status: ?[]const u8 = null,
    last_error: ?[]const u8 = null,
    client_count: u32,
};

const FrpsStatusInfo = struct {
    enabled: bool,
    status: ?[]const u8 = null,
    last_error: ?[]const u8 = null,
    client_count: u32,
    proxy_count: u32,
    server_count: u32,
};

const GetFrpStatusResponse = struct {
    frp_enabled: bool,
    frp_version: ?[]const u8 = null,
    frpc: FrpcStatusInfo,
    frps: FrpsStatusInfo,
};

const GetFrpcInfoArgs = struct {
    id: []const u8,
};

const GetFrpInfoResponse = struct {
    status: []const u8,
    last_error: []const u8,
    logs: []const []const u8,
};

const GetFrpcProxyStatsArgs = struct {
    id: []const u8,
};

const EventInfo = struct {
    timestamp: i64,
    type: []const u8,
    message: []const u8,
    project_id: i32,
};

const GetEventsResponse = struct {
    events: []const EventInfo,
};

const GetDdnsGlobalStatusResponse = struct {
    ddns_enabled: bool,
    ddns_version: ?[]const u8 = null,
};

const DdnsStatusInfo = struct {
    name: []const u8,
    provider: []const u8,
    status: []const u8,
    last_update: i64,
    last_ip: []const u8,
    message: []const u8,
};

const GetDdnsStatusesResponse = struct {
    ddns_status: []const DdnsStatusInfo,
};

const GetDdnsInfoArgs = struct {
    name: []const u8,
};

const GetDdnsInfoResponse = struct {
    status: []const u8,
    last_error: []const u8,
    logs: []const []const u8,
};

const FrpStatusSection = struct {
    enabled: bool,
    version: ?[]const u8 = null,
    clients: []const ClientSummaryInfo,
    servers: []const ServerSummaryInfo,
};

const ClientSummaryInfo = struct {
    name: []const u8,
    status: []const u8,
    client_count: u32,
    last_error: []const u8,
};

const ServerSummaryInfo = struct {
    name: []const u8,
    status: []const u8,
    client_count: u32,
    proxy_count: u32,
    server_count: u32,
    last_error: []const u8,
};

const DdnsStatusSection = struct {
    enabled: bool,
    version: ?[]const u8 = null,
    instances: []const DdnsStatusInfo,
};

const FullStatusResponse = struct {
    status: []const u8,
    uptime: u64,
    total_projects: u32,
    active_ports: u32,
    total_bytes_in: u64,
    total_bytes_out: u64,
    projects: []const ProjectStatusInfo,
    frp: FrpStatusSection,
    ddns: DdnsStatusSection,
    events: []const EventInfo,
};

const WolProjectArgs = struct {
    project: ?[]const u8 = null,
    target: ?[]const u8 = null,
};

const WolWakeResponse = struct {
    success: bool,
    sent_count: u32,
};

const WolStatusResponse = struct {
    enabled: bool,
    mac_count: u32,
    cooldown_ms: u64,
    detect_protocols: []const []const u8,
};

fn getStatus(allocator: std.mem.Allocator, state: *RuntimeState) !GetStatusResponse {
    _ = allocator;
    const snapshot = state.globalSnapshot();
    return .{
        .status = snapshot.status,
        .total_projects = snapshot.total_projects,
        .active_ports = snapshot.active_ports,
        .total_bytes_in = snapshot.total_bytes_in,
        .total_bytes_out = snapshot.total_bytes_out,
        .uptime = snapshot.uptime,
    };
}

fn listProjects(allocator: std.mem.Allocator, state: *RuntimeState) !ListProjectsResponse {
    state.mutex.lockUncancelable(compat.io());
    defer state.mutex.unlock(compat.io());

    if (state.enabled.len != state.projects.items.len) {
        try state.syncFromProjectsLocked();
    }

    var projects_list: std.ArrayList(ProjectStatusInfo) = .empty;
    errdefer projects_list.deinit(allocator);

    for (state.projects.items, 0..) |*project, i| {
        const info = project.getProjectRuntimeInfo();

        var forwarders_list: std.ArrayList(ForwarderStatsInfo) = .empty;
        errdefer forwarders_list.deinit(allocator);

        const forwarder_stats = project.getForwarderStats(allocator) catch &[_]project_status.ForwarderStats{};
        defer if (forwarder_stats.len > 0) allocator.free(forwarder_stats);

        for (forwarder_stats) |fwd_stat| {
            try forwarders_list.append(allocator, .{
                .protocol = fwd_stat.protocol,
                .local_port = @intCast(fwd_stat.local_port),
                .bytes_in = fwd_stat.bytes_in,
                .bytes_out = fwd_stat.bytes_out,
                .active_sessions = fwd_stat.active_sessions,
            });
        }

        try projects_list.append(allocator, .{
            .id = @intCast(i),
            .section_name = project.cfg.section_name,
            .enabled = state.enabled[i],
            .status = if (state.enabled[i]) STATUS_RUNNING else STATUS_STOPPED,
            .startup_status = project.startup_status.toString(),
            .active_ports = project.active_ports,
            .bytes_in = info.bytes_in,
            .bytes_out = info.bytes_out,
            .active_sessions = info.active_sessions,
            .last_changed = state.last_changed[i],
            .error_code = if (info.startup_status == .failed and info.error_code != 0) info.error_code else null,
            .enable_app_stats = project.cfg.enable_app_stats,
            .enable_firewall_stats = project.cfg.enable_firewall_stats,
            .forwarders = try forwarders_list.toOwnedSlice(allocator),
        });
    }

    return .{
        .projects = try projects_list.toOwnedSlice(allocator),
    };
}

fn setEnabled(allocator: std.mem.Allocator, state: *RuntimeState, args: SetEnabledArgs) !SetEnabledResponse {
    _ = allocator;
    const idx: usize = @intCast(args.id);

    state.mutex.lockUncancelable(compat.io());
    defer state.mutex.unlock(compat.io());

    if (state.enabled.len != state.projects.items.len) {
        try state.syncFromProjectsLocked();
    }

    if (idx >= state.projects.items.len) {
        return error.InvalidArgument;
    }

    const old_enabled = state.enabled[idx];
    state.enabled[idx] = args.enabled;
    const now = currentTs();
    state.last_changed[idx] = now;

    var project = &state.projects.items[idx];
    project.setRuntimeEnabled(args.enabled);

    if (old_enabled != args.enabled) {
        if (args.enabled) {
            event_log.logEventFmt(.project_started, @intCast(idx), "Project {d} enabled via UBUS", .{idx + 1});
        } else {
            event_log.logEventFmt(.project_stopped, @intCast(idx), "Project {d} disabled via UBUS", .{idx + 1});
        }
    }

    return .{
        .id = args.id,
        .enabled = args.enabled,
        .status = if (args.enabled) STATUS_RUNNING else STATUS_STOPPED,
        .last_changed = now,
    };
}

fn getFrpStatus(allocator: std.mem.Allocator, state: *RuntimeState) !GetFrpStatusResponse {
    _ = state;
    const status = try frp_status.getFrpStatus(allocator);
    return .{
        .frp_enabled = status.frp_enabled,
        .frp_version = status.frp_version,
        .frpc = .{
            .enabled = status.frpc.enabled,
            .status = status.frpc.status,
            .last_error = status.frpc.last_error,
            .client_count = @intCast(status.frpc.client_count),
        },
        .frps = .{
            .enabled = status.frps.enabled,
            .status = status.frps.status,
            .last_error = status.frps.last_error,
            .client_count = @intCast(status.frps.client_count),
            .proxy_count = @intCast(status.frps.proxy_count),
            .server_count = @intCast(status.frps.server_count),
        },
    };
}

fn getFrpcInfo(allocator: std.mem.Allocator, state: *RuntimeState, args: GetFrpcInfoArgs) !GetFrpInfoResponse {
    _ = state;
    const result = try frpc_forward.getClientStatus(allocator, args.id);

    var logs_list: std.ArrayList([]const u8) = .empty;
    var lines_iter = std.mem.splitScalar(u8, result.logs, '\n');
    while (lines_iter.next()) |line| {
        if (line.len > 0) {
            try logs_list.append(allocator, line);
        }
    }

    return .{
        .status = result.status,
        .last_error = result.last_error,
        .logs = try logs_list.toOwnedSlice(allocator),
    };
}

fn getFrpsInfo(allocator: std.mem.Allocator, state: *RuntimeState, args: GetFrpcInfoArgs) !GetFrpInfoResponse {
    _ = state;
    const result = try frps_forward.getServerStatus(allocator, args.id);

    var logs_list: std.ArrayList([]const u8) = .empty;
    var lines_iter = std.mem.splitScalar(u8, result.logs, '\n');
    while (lines_iter.next()) |line| {
        if (line.len > 0) {
            try logs_list.append(allocator, line);
        }
    }

    return .{
        .status = result.status,
        .last_error = result.last_error,
        .logs = try logs_list.toOwnedSlice(allocator),
    };
}

fn getFrpProxyStats(allocator: std.mem.Allocator, state: *RuntimeState, args: GetFrpcProxyStatsArgs) !RawJson {
    _ = state;
    const result = try frpc_forward.getProxyStats(allocator, args.id);
    return .{ .json = result };
}

fn getFrpsProxyStats(allocator: std.mem.Allocator, state: *RuntimeState, args: GetFrpcProxyStatsArgs) !RawJson {
    _ = state;
    const result = try frps_forward.getProxyStats(allocator, args.id);
    return .{ .json = result };
}

fn clearFrpLogs(allocator: std.mem.Allocator, state: *RuntimeState, args: GetFrpcInfoArgs) !void {
    _ = allocator;
    _ = state;
    frpc_forward.clearClientLogs(args.id);
}

fn clearFrpsLogs(allocator: std.mem.Allocator, state: *RuntimeState, args: GetFrpcInfoArgs) !void {
    _ = allocator;
    _ = state;
    frps_forward.clearServerLogs(args.id);
}

fn getEvents(allocator: std.mem.Allocator, state: *RuntimeState) !GetEventsResponse {
    _ = state;
    var list: std.ArrayList(EventInfo) = .empty;
    errdefer list.deinit(allocator);

    if (event_log.getGlobal()) |logger| {
        const events = try logger.getEvents(allocator);
        defer event_log.EventLogger.freeEvents(allocator, events);

        for (events) |event| {
            try list.append(allocator, .{
                .timestamp = event.timestamp,
                .type = event.event_type.toString(),
                .message = try allocator.dupe(u8, event.message),
                .project_id = event.project_id,
            });
        }
    }

    return .{
        .events = try list.toOwnedSlice(allocator),
    };
}

fn getDdnsGlobalStatus(allocator: std.mem.Allocator, state: *RuntimeState) !GetDdnsGlobalStatusResponse {
    _ = state;
    const ddns_enabled = build_options.ddns_mode;
    var version: ?[]const u8 = null;
    if (ddns_enabled) {
        const libddns = @import("../impl/ddns/libddns.zig");
        const ver = libddns.getVersion(allocator) catch |err| {
            std.log.warn("Failed to get DDNS version: {any}", .{err});
            return .{ .ddns_enabled = ddns_enabled, .ddns_version = null };
        };
        version = ver;
    }
    return .{
        .ddns_enabled = ddns_enabled,
        .ddns_version = version,
    };
}

fn getDdnsStatuses(allocator: std.mem.Allocator, state: *RuntimeState) !GetDdnsStatusesResponse {
    _ = state;
    const statuses = try ddns_manager.getStatus(allocator);
    defer {
        for (statuses) |*s| {
            var status_copy = s.*;
            status_copy.deinit(allocator);
        }
        allocator.free(statuses);
    }

    var list: std.ArrayList(DdnsStatusInfo) = .empty;
    errdefer list.deinit(allocator);

    for (statuses) |status| {
        try list.append(allocator, .{
            .name = try allocator.dupe(u8, status.name),
            .provider = try allocator.dupe(u8, status.provider),
            .status = try allocator.dupe(u8, status.status),
            .last_update = status.last_update,
            .last_ip = try allocator.dupe(u8, status.last_ip),
            .message = try allocator.dupe(u8, status.message),
        });
    }

    return .{
        .ddns_status = try list.toOwnedSlice(allocator),
    };
}

fn getDdnsInfo(allocator: std.mem.Allocator, state: *RuntimeState, args: GetDdnsInfoArgs) !GetDdnsInfoResponse {
    _ = state;
    var info = try ddns_manager.getInstanceStatus(allocator, args.name);
    defer info.deinit(allocator);

    var logs_list: std.ArrayList([]const u8) = .empty;
    for (info.logs.items) |log| {
        try logs_list.append(allocator, try allocator.dupe(u8, log));
    }

    return .{
        .status = try allocator.dupe(u8, info.status),
        .last_error = try allocator.dupe(u8, info.last_error),
        .logs = try logs_list.toOwnedSlice(allocator),
    };
}

fn clearDdnsLogs(allocator: std.mem.Allocator, state: *RuntimeState, args: GetDdnsInfoArgs) !void {
    _ = allocator;
    _ = state;
    try ddns_manager.clearInstanceLogs(args.name);
}

fn getFullStatus(allocator: std.mem.Allocator, state: *RuntimeState) !FullStatusResponse {
    const snapshot = state.globalSnapshot();
    const projects_res = try listProjects(allocator, state);

    const frp_enabled = build_options.frpc_mode or build_options.frps_mode;
    var frp_version: ?[]const u8 = null;
    if (frp_enabled) {
        if (build_options.frpc_mode) {
            const libfrpc_lib = @import("../impl/frpc/libfrpc.zig");
            if (libfrpc_lib.getVersion(allocator) catch null) |v| {
                frp_version = v;
            }
        } else if (build_options.frps_mode) {
            const libfrps_lib = @import("../impl/frps/libfrps.zig");
            if (libfrps_lib.getVersion(allocator) catch null) |v| {
                frp_version = v;
            }
        }
    }

    var clients_list: std.ArrayList(ClientSummaryInfo) = .empty;
    if (build_options.frpc_mode) {
        if (frpc_forward.getAllClientSummaries(allocator) catch null) |items| {
            defer frpc_forward.freeClientSummaries(allocator, items);
            for (items) |item| {
                try clients_list.append(allocator, .{
                    .name = try allocator.dupe(u8, item.name),
                    .status = try allocator.dupe(u8, item.status),
                    .client_count = @intCast(item.client_count),
                    .last_error = try allocator.dupe(u8, item.last_error),
                });
            }
        }
    }

    var servers_list: std.ArrayList(ServerSummaryInfo) = .empty;
    if (build_options.frps_mode) {
        if (frps_forward.getAllServerSummaries(allocator) catch null) |items| {
            defer frps_forward.freeServerSummaries(allocator, items);
            for (items) |item| {
                try servers_list.append(allocator, .{
                    .name = try allocator.dupe(u8, item.name),
                    .status = try allocator.dupe(u8, item.status),
                    .client_count = @intCast(item.client_count),
                    .proxy_count = @intCast(item.proxy_count),
                    .server_count = @intCast(item.server_count),
                    .last_error = try allocator.dupe(u8, item.last_error),
                });
            }
        }
    }

    var ddns_version: ?[]const u8 = null;
    if (build_options.ddns_mode) {
        const libddns_lib = @import("../impl/ddns/libddns.zig");
        if (libddns_lib.getVersion(allocator) catch null) |v| {
            ddns_version = v;
        }
    }

    var instances_list: std.ArrayList(DdnsStatusInfo) = .empty;
    if (build_options.ddns_mode) {
        if (ddns_manager.getStatus(allocator) catch null) |stats| {
            defer {
                for (stats) |*s| {
                    var sc = s.*;
                    sc.deinit(allocator);
                }
                allocator.free(stats);
            }
            for (stats) |stat| {
                try instances_list.append(allocator, .{
                    .name = try allocator.dupe(u8, stat.name),
                    .provider = try allocator.dupe(u8, stat.provider),
                    .status = try allocator.dupe(u8, stat.status),
                    .last_update = stat.last_update,
                    .last_ip = try allocator.dupe(u8, stat.last_ip),
                    .message = try allocator.dupe(u8, stat.message),
                });
            }
        }
    }

    const events_res = getEvents(allocator, state) catch |err| blk: {
        std.log.warn("ubus: failed to get events: {any}", .{err});
        break :blk GetEventsResponse{ .events = &[_]EventInfo{} };
    };

    return .{
        .status = snapshot.status,
        .uptime = snapshot.uptime,
        .total_projects = snapshot.total_projects,
        .active_ports = snapshot.active_ports,
        .total_bytes_in = snapshot.total_bytes_in,
        .total_bytes_out = snapshot.total_bytes_out,
        .projects = projects_res.projects,
        .frp = .{
            .enabled = frp_enabled,
            .version = frp_version,
            .clients = try clients_list.toOwnedSlice(allocator),
            .servers = try servers_list.toOwnedSlice(allocator),
        },
        .ddns = .{
            .enabled = build_options.ddns_mode,
            .version = ddns_version,
            .instances = try instances_list.toOwnedSlice(allocator),
        },
        .events = events_res.events,
    };
}

const GetNftablesRulesResponse = struct {
    rules: []const u8,
};

fn getNftablesRules(allocator: std.mem.Allocator, state: *RuntimeState) !GetNftablesRulesResponse {
    if (!build_options.nftables_mode) {
        return .{ .rules = "nftables support not compiled" };
    }

    if (!state.use_nftables) {
        return .{ .rules = "nftables backend is disabled" };
    }

    var ctx = nftables.NftablesContext.init(allocator) catch {
        return .{ .rules = "Failed to initialize nftables context" };
    };
    defer ctx.deinit();

    const rules_raw = ctx.listRules() orelse "No rules found or table does not exist";
    const rules = try allocator.dupe(u8, rules_raw);
    return .{ .rules = rules };
}

fn handleRestartProject(allocator: std.mem.Allocator, state: *RuntimeState, args: RestartProjectArgs) !RestartProjectResponse {
    const idx: usize = @intCast(args.id);

    state.mutex.lockUncancelable(compat.io());
    defer state.mutex.unlock(compat.io());

    if (idx >= state.projects.items.len) {
        return error.InvalidArgument;
    }

    var project = &state.projects.items[idx];
    if (!project.cfg.enabled) {
        return error.InvalidArgument;
    }

    // Tear down forwarders only, keep config alive
    project.teardownForwarders();

    // Re-start application layer forwarding
    app_forward.startForwarding(allocator, project) catch |err| {
        std.log.warn("ubus: failed to restart project {d}: {any}", .{ args.id, err });
        project.setStartupFailedCode(-1);
    };

    // Re-start FRPC forwarding (if enabled)
    if (build_options.frpc_mode) {
        frpc_forward.startForwarding(allocator, project, state.frpc_nodes) catch |err| {
            std.log.warn("ubus: failed to restart FRPC for project {d}: {any}", .{ args.id, err });
        };
    }

    // Log the restart
    event_log.logEventFmt(.project_started, @intCast(args.id), "Project {d} restarted via UBUS", .{args.id + 1});

    return .{
        .id = args.id,
        .status = STATUS_RUNNING,
    };
}

fn handleReloadConfig(allocator: std.mem.Allocator, state: *RuntimeState) !ReloadConfigResponse {
    _ = allocator;

    // Delegate to the shared reload module — it handles config re-reading,
    // diff comparison, teardown, restart, firewall refresh, and sub-service reload.
    reload.apply();

    try state.syncFromProjects();

    return .{
        .success = true,
        .changes = 0, // Individual counts are logged by reload.apply()
        .message = "Config reload triggered successfully",
    };
}

fn findProjectByNameOrIndex(state: *RuntimeState, name: []const u8) ?*project_status.ProjectHandle {
    for (state.projects.items) |*project| {
        if (std.mem.eql(u8, project.cfg.remark, name)) {
            return project;
        }
    }
    const idx = std.fmt.parseUnsigned(usize, name, 10) catch return null;
    if (idx < state.projects.items.len) {
        return &state.projects.items[idx];
    }
    return null;
}

fn getWolManager(allocator: std.mem.Allocator) *wol.WolManager {
    g_wol_manager_mutex.lockUncancelable(compat.io());
    defer g_wol_manager_mutex.unlock(compat.io());
    if (g_wol_manager == null) {
        g_wol_manager = wol.WolManager.init(allocator);
    }
    return &g_wol_manager.?;
}

fn wolWake(allocator: std.mem.Allocator, state: *RuntimeState, args: WolProjectArgs) !WolWakeResponse {
    const mgr = getWolManager(allocator);

    if (args.target) |target_name| {
        const target = state.wol_targets.get(target_name) orelse return error.NotFound;
        if (!target.enabled) {
            return .{ .success = false, .sent_count = 0 };
        }
        if (target.mac_addresses.len == 0) {
            return .{ .success = true, .sent_count = 0 };
        }
        wol.sendWoLWithCooldown(target.mac_addresses, target.cooldown_ms, target.log_enabled, mgr, 9999);
        return .{ .success = true, .sent_count = @intCast(target.mac_addresses.len) };
    } else if (args.project) |project_name| {
        const project = findProjectByNameOrIndex(state, project_name) orelse return error.NotFound;
        const cfg = project.cfg;
        if (!cfg.enable_wol) {
            return .{ .success = false, .sent_count = 0 };
        }
        if (cfg.resolved_wol_macs.len == 0) {
            return .{ .success = true, .sent_count = 0 };
        }
        wol.sendWoLWithCooldown(cfg.resolved_wol_macs, cfg.resolved_wol_cooldown_ms, cfg.resolved_wol_log_enabled, mgr, @intCast(project.id));
        return .{ .success = true, .sent_count = @intCast(cfg.resolved_wol_macs.len) };
    } else {
        return error.InvalidValue;
    }
}

fn wolStatus(allocator: std.mem.Allocator, state: *RuntimeState, args: WolProjectArgs) !WolStatusResponse {
    _ = allocator;

    if (args.target) |target_name| {
        const target = state.wol_targets.get(target_name) orelse return error.NotFound;
        return .{
            .enabled = target.enabled,
            .mac_count = @intCast(target.mac_addresses.len),
            .cooldown_ms = target.cooldown_ms,
            .detect_protocols = &[_][]const u8{},
        };
    } else if (args.project) |project_name| {
        const project = findProjectByNameOrIndex(state, project_name) orelse return error.NotFound;
        const cfg = project.cfg;
        return .{
            .enabled = cfg.enable_wol,
            .mac_count = @intCast(cfg.resolved_wol_macs.len),
            .cooldown_ms = cfg.resolved_wol_cooldown_ms,
            .detect_protocols = cfg.detect_protocols,
        };
    } else {
        return error.InvalidValue;
    }
}

fn currentTs() u64 {
    const seconds = std.Io.Timestamp.now(compat.io(), .real).toSeconds();
    if (seconds < 0) return 0;
    return @intCast(seconds);
}

pub fn notifyReload() void {
    g_lifecycle_mutex.lockUncancelable(compat.io());
    defer g_lifecycle_mutex.unlock(compat.io());
    if (g_state) |state| {
        state.syncFromProjects() catch |err| {
            std.log.err("ubus: failed to sync state after reload: {any}", .{err});
        };
    }
}
