const std = @import("std");
const build_options = @import("build_options");
const types = @import("../config/types.zig");
const app_forward = @import("../impl/app_forward.zig");
const ubus = @import("libubus.zig");
const ubox = @import("ubox.zig");
const c = ubox.c;
const project_status = @import("../impl/project_status.zig");
const frp_status = if (build_options.frpc_mode) @import("../impl/frp_status.zig") else struct {};
const frp_forward = if (build_options.frpc_mode) @import("../impl/frp_forward.zig") else struct {};
const ddns_manager = if (build_options.ddns_mode) @import("../impl/ddns_manager.zig") else struct {};
const main = @import("../main.zig");
const event_log = main.event_log;
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
    projects: std.array_list.Managed(project_status.ProjectHandle),
    enabled: []bool,
    last_changed: []u64,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, projects: std.array_list.Managed(project_status.ProjectHandle)) !*RuntimeState {
        const state = try allocator.create(RuntimeState);
        const now = currentTs();
        state.* = .{
            .allocator = allocator,
            .start_ts = now,
            .projects = projects,
            .enabled = try allocator.alloc(bool, projects.items.len),
            .last_changed = try allocator.alloc(u64, projects.items.len),
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

    fn globalSnapshot(self: *RuntimeState) GlobalSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();

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

var g_state: ?*RuntimeState = null;

const set_enabled_policy = [_]c.blobmsg_policy{
    .{ .name = "id", .type = c.BLOBMSG_TYPE_INT32 },
    .{ .name = "enabled", .type = c.BLOBMSG_TYPE_BOOL },
};

const frp_info_policy = [_]c.blobmsg_policy{
    .{ .name = "id", .type = c.BLOBMSG_TYPE_STRING },
};

const ddns_info_policy = [_]c.blobmsg_policy{
    .{ .name = "name", .type = c.BLOBMSG_TYPE_STRING },
};

const method_names = struct {
    pub const get_status: [:0]const u8 = "get_status";
    pub const list_projects: [:0]const u8 = "list_projects";
    pub const set_enabled: [:0]const u8 = "set_enabled";
    pub const get_frp_status: [:0]const u8 = "get_frp_status";
    pub const get_frp_info: [:0]const u8 = "get_frp_info";
    pub const clear_frp_logs: [:0]const u8 = "clear_frp_logs";
    pub const get_events: [:0]const u8 = "get_events";
    pub const get_ddns_status: [:0]const u8 = "get_ddns_status";
    pub const get_ddns_info: [:0]const u8 = "get_ddns_info";
    pub const clear_ddns_logs: [:0]const u8 = "clear_ddns_logs";
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
    pub const ddns_statuses: [:0]const u8 = "ddns_statuses";
};

pub fn start(allocator: std.mem.Allocator, projects: std.array_list.Managed(project_status.ProjectHandle)) !void {
    if (g_state != null) return;
    const state = try RuntimeState.init(allocator, projects);
    g_state = state;

    const thread = try std.Thread.spawn(.{}, ubusThread, .{state});
    thread.detach();
}

fn ubusThread(state: *RuntimeState) void {
    _ = state; // Store state reference for later use when forwarding metrics
    ubox.uloopInit() catch |err| {
        std.log.warn("ubus: failed to init uloop: {any}", .{err});
        return;
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

    const commonMethods = [_]c.ubus_method{
        .{
            .name = method_names.get_status,
            .handler = handleGetStatus,
            .mask = 0,
            .tags = 0,
            .policy = null,
            .n_policy = 0,
        },
        .{
            .name = method_names.list_projects,
            .handler = handleListProjects,
            .mask = 0,
            .tags = 0,
            .policy = null,
            .n_policy = 0,
        },
        .{
            .name = method_names.set_enabled,
            .handler = handleSetEnabled,
            .mask = 0,
            .tags = 0,
            .policy = &set_enabled_policy,
            .n_policy = @intCast(set_enabled_policy.len),
        },
    };
    const frpMethods = if (build_options.frpc_mode) [_]c.ubus_method{
        .{
            .name = method_names.get_frp_status,
            .handler = handleGetFrpStatus,
            .mask = 0,
            .tags = 0,
            .policy = null,
            .n_policy = 0,
        },
        .{
            .name = method_names.get_frp_info,
            .handler = handleGetFrpInfo,
            .mask = 0,
            .tags = 0,
            .policy = &frp_info_policy,
            .n_policy = @intCast(frp_info_policy.len),
        },
        .{
            .name = method_names.clear_frp_logs,
            .handler = handleClearFrpLogs,
            .mask = 0,
            .tags = 0,
            .policy = &frp_info_policy,
            .n_policy = @intCast(frp_info_policy.len),
        },
        .{
            .name = method_names.get_events,
            .handler = handleGetEvents,
            .mask = 0,
            .tags = 0,
            .policy = null,
            .n_policy = 0,
        },
    } else [_]c.ubus_method{};
    const ddnsMethods = if (build_options.ddns_mode) [_]c.ubus_method{
        .{
            .name = method_names.get_ddns_status,
            .handler = handleGetDdnsStatuses,
            .mask = 0,
            .tags = 0,
            .policy = null,
            .n_policy = 0,
        },
        .{
            .name = method_names.get_ddns_info,
            .handler = handleGetDdnsInfo,
            .mask = 0,
            .tags = 0,
            .policy = &ddns_info_policy,
            .n_policy = @intCast(ddns_info_policy.len),
        },
        .{
            .name = method_names.clear_ddns_logs,
            .handler = handleClearDdnsLogs,
            .mask = 0,
            .tags = 0,
            .policy = &ddns_info_policy,
            .n_policy = @intCast(ddns_info_policy.len),
        },
    } else [_]c.ubus_method{};
    const methods = commonMethods ++ frpMethods ++ ddnsMethods;
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
        ubus.ubus_free(ctx) catch {};
        return;
    };

    ubox.uloopFdAdd(&ctx.sock, @intCast(c.ULOOP_BLOCKING | c.ULOOP_READ)) catch |err| {
        std.log.warn("ubus: add fd failed: {any}", .{err});
        ubus.ubus_free(ctx) catch {};
        return;
    };

    std.log.info("ubus: server started successfully.", .{});

    ubox.uloopRun(-1) catch {};
    ubus.ubus_free(ctx) catch {};
    ubox.uloopDone() catch {};
}

fn handleGetStatus(ctx: [*c]c.ubus_context, obj: [*c]c.ubus_object, req: [*c]c.ubus_request_data, method: [*c]const u8, msg: [*c]c.blob_attr) callconv(.c) c_int {
    _ = obj;
    _ = method;
    _ = msg;
    const state = g_state orelse return c.UBUS_STATUS_UNKNOWN_ERROR;

    var buf: c.blob_buf = std.mem.zeroes(c.blob_buf);
    ubox.blobBufInit(&buf, c.BLOBMSG_TYPE_TABLE) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    defer ubox.blobBufFree(&buf) catch {};

    const snapshot = state.globalSnapshot();

    addString(&buf, field_names.status, snapshot.status) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    addU32(&buf, field_names.total_projects, snapshot.total_projects) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    addU32(&buf, field_names.active_ports, snapshot.active_ports) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    addU64(&buf, field_names.total_bytes_in, snapshot.total_bytes_in) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    addU64(&buf, field_names.total_bytes_out, snapshot.total_bytes_out) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    addU64(&buf, field_names.uptime, snapshot.uptime) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

    _ = ubus.ubus_send_reply(ctx, req, buf.head) catch {
        return c.UBUS_STATUS_UNKNOWN_ERROR;
    };
    return c.UBUS_STATUS_OK;
}

fn handleListProjects(ctx: [*c]c.ubus_context, obj: [*c]c.ubus_object, req: [*c]c.ubus_request_data, method: [*c]const u8, msg: [*c]c.blob_attr) callconv(.c) c_int {
    _ = obj;
    _ = method;
    _ = msg;
    const state = g_state orelse return c.UBUS_STATUS_UNKNOWN_ERROR;

    var buf: c.blob_buf = std.mem.zeroes(c.blob_buf);
    ubox.blobBufInit(&buf, c.BLOBMSG_TYPE_TABLE) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    defer ubox.blobBufFree(&buf) catch {};

    const arr = ubox.blobmsgOpenNested(&buf, field_names.projects, true) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    if (arr == null) return c.UBUS_STATUS_UNKNOWN_ERROR;

    state.mutex.lock();
    defer state.mutex.unlock();

    var i: usize = 0;
    while (i < state.projects.items.len) : (i += 1) {
        const item = ubox.blobmsgOpenNested(&buf, null, false) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        if (item == null) return c.UBUS_STATUS_UNKNOWN_ERROR;

        const project = &state.projects.items[i];

        addU32(&buf, field_names.id, @intCast(i)) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        // addString(&buf, field_names.remark, state.remarks[i]) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addBool(&buf, field_names.enabled, state.enabled[i]) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addString(&buf, field_names.status, if (state.enabled[i]) STATUS_RUNNING else STATUS_STOPPED) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addString(&buf, field_names.startup_status, project.startup_status.toString()) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

        const info = project.getProjectRuntimeInfo();

        addU32(&buf, field_names.active_ports, project.active_ports) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addU64(&buf, field_names.bytes_in, info.bytes_in) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addU64(&buf, field_names.bytes_out, info.bytes_out) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addU64(&buf, field_names.last_changed, state.last_changed[i]) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

        // 如果启动失败，返回错误代码（使用运行时信息）
        if (info.startup_status == .failed and info.error_code != 0) {
            addI32(&buf, field_names.error_code, info.error_code) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        }

        // Add forwarders array with per-port statistics
        const fwd_arr = ubox.blobmsgOpenNested(&buf, field_names.forwarders, true) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        if (fwd_arr != null) {
            const forwarder_stats = project.getForwarderStats(state.allocator) catch &[_]project_status.ForwarderStats{};
            defer if (forwarder_stats.len > 0) state.allocator.free(forwarder_stats);

            for (forwarder_stats) |fwd_stat| {
                const fwd_item = ubox.blobmsgOpenNested(&buf, null, false) catch continue;
                if (fwd_item == null) continue;

                // Add protocol
                const proto_z = state.allocator.dupeZ(u8, fwd_stat.protocol) catch continue;
                defer state.allocator.free(proto_z);
                addString(&buf, field_names.protocol, proto_z) catch {};

                // Add local port
                addU32(&buf, field_names.local_port, @intCast(fwd_stat.local_port)) catch {};

                // Add traffic stats
                addU64(&buf, field_names.bytes_in, fwd_stat.bytes_in) catch {};
                addU64(&buf, field_names.bytes_out, fwd_stat.bytes_out) catch {};

                ubox.blobNestEnd(&buf, fwd_item) catch {};
            }

            ubox.blobNestEnd(&buf, fwd_arr) catch {};
        }

        ubox.blobNestEnd(&buf, item) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    }

    ubox.blobNestEnd(&buf, arr) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

    _ = ubus.ubus_send_reply(ctx, req, buf.head) catch {
        return c.UBUS_STATUS_UNKNOWN_ERROR;
    };
    return c.UBUS_STATUS_OK;
}

fn handleSetEnabled(ctx: [*c]c.ubus_context, obj: [*c]c.ubus_object, req: [*c]c.ubus_request_data, method: [*c]const u8, msg: [*c]c.blob_attr) callconv(.c) c_int {
    _ = obj;
    _ = method;
    if (msg == null) return c.UBUS_STATUS_INVALID_ARGUMENT;
    const state = g_state orelse return c.UBUS_STATUS_UNKNOWN_ERROR;

    var tb: [set_enabled_policy.len]?*c.blob_attr = .{ null, null };
    const data_ptr = c.blob_data(msg);
    const data_len = c.blob_len(msg);
    ubox.blobmsgParse(set_enabled_policy[0..], tb[0..], data_ptr, data_len) catch return c.UBUS_STATUS_INVALID_ARGUMENT;

    if (tb[0] == null or tb[1] == null) return c.UBUS_STATUS_INVALID_ARGUMENT;
    const id = c.blobmsg_get_u32(tb[0].?);
    const idx: usize = @intCast(id);
    const enabled_flag = c.blobmsg_get_bool(tb[1].?);

    state.mutex.lock();
    if (idx >= state.projects.items.len) {
        state.mutex.unlock();
        return c.UBUS_STATUS_INVALID_ARGUMENT;
    }
    // Update state and control actual forwarding
    state.enabled[idx] = enabled_flag;
    state.last_changed[idx] = currentTs();

    // Actually enable/disable the project forwarding
    var project = &state.projects.items[idx];
    project.setRuntimeEnabled(enabled_flag);

    state.mutex.unlock();

    var buf: c.blob_buf = std.mem.zeroes(c.blob_buf);
    ubox.blobBufInit(&buf, c.BLOBMSG_TYPE_TABLE) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    defer ubox.blobBufFree(&buf) catch {};

    addU32(&buf, field_names.id, id) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    addBool(&buf, field_names.enabled, enabled_flag) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    addString(&buf, field_names.status, if (enabled_flag) STATUS_RUNNING else STATUS_STOPPED) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    addU64(&buf, field_names.last_changed, currentTs()) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

    _ = ubus.ubus_send_reply(ctx, req, buf.head) catch {
        return c.UBUS_STATUS_UNKNOWN_ERROR;
    };
    return c.UBUS_STATUS_OK;
}

fn handleGetFrpStatus(ctx: [*c]c.ubus_context, obj: [*c]c.ubus_object, req: [*c]c.ubus_request_data, method: [*c]const u8, msg: [*c]c.blob_attr) callconv(.c) c_int {
    _ = obj;
    _ = method;
    _ = msg;
    const state = g_state orelse return c.UBUS_STATUS_UNKNOWN_ERROR;

    var buf: c.blob_buf = std.mem.zeroes(c.blob_buf);
    ubox.blobBufInit(&buf, c.BLOBMSG_TYPE_TABLE) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    defer ubox.blobBufFree(&buf) catch {};

    const status = frp_status.getFrpStatus(state.allocator) catch |err| {
        std.log.warn("Failed to get frp status: {any}", .{err});
        addBool(&buf, field_names.frp_enabled, false) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        _ = ubus.ubus_send_reply(ctx, req, buf.head) catch {};
        return c.UBUS_STATUS_OK;
    };
    defer {
        if (status.version) |v| state.allocator.free(v);
        if (status.status) |s| state.allocator.free(s);
        if (status.last_error) |e| state.allocator.free(e);
    }

    addBool(&buf, field_names.frp_enabled, status.enabled) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    if (status.version) |v| {
        const ztv = state.allocator.dupeZ(u8, v) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        defer state.allocator.free(ztv);
        addString(&buf, field_names.frp_version, ztv) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    }

    // Add FRP client status
    if (status.status) |s| {
        const zts = state.allocator.dupeZ(u8, s) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        defer state.allocator.free(zts);
        addString(&buf, field_names.frp_status, zts) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    }

    // Add last error if present
    if (status.last_error) |e| {
        const zte = state.allocator.dupeZ(u8, e) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        defer state.allocator.free(zte);
        addString(&buf, field_names.last_error, zte) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    }

    // Add client count
    addU32(&buf, field_names.client_count, @intCast(status.client_count)) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

    _ = ubus.ubus_send_reply(ctx, req, buf.head) catch {
        return c.UBUS_STATUS_UNKNOWN_ERROR;
    };
    return c.UBUS_STATUS_OK;
}

fn handleGetFrpInfo(ctx: [*c]c.ubus_context, obj: [*c]c.ubus_object, req: [*c]c.ubus_request_data, method: [*c]const u8, msg: [*c]c.blob_attr) callconv(.c) c_int {
    _ = obj;
    _ = method;
    if (msg == null) return c.UBUS_STATUS_INVALID_ARGUMENT;
    const state = g_state orelse return c.UBUS_STATUS_UNKNOWN_ERROR;

    // Parse the "id" (node_name) parameter
    var tb: [frp_info_policy.len]?*c.blob_attr = .{null};
    const data_ptr = c.blob_data(msg);
    const data_len = c.blob_len(msg);
    ubox.blobmsgParse(frp_info_policy[0..], tb[0..], data_ptr, data_len) catch return c.UBUS_STATUS_INVALID_ARGUMENT;

    if (tb[0] == null) return c.UBUS_STATUS_INVALID_ARGUMENT;
    const node_name_cstr = c.blobmsg_get_string(tb[0].?);
    const node_name = std.mem.span(node_name_cstr);

    // Get client status from frp_forward
    const result = frp_forward.getClientStatus(state.allocator, node_name) catch |err| {
        std.log.warn("Failed to get FRP client status for node '{s}': {any}", .{ node_name, err });
        return c.UBUS_STATUS_UNKNOWN_ERROR;
    };
    defer state.allocator.free(result.status);
    defer state.allocator.free(result.last_error);
    defer state.allocator.free(result.logs);

    // Build response
    var buf: c.blob_buf = std.mem.zeroes(c.blob_buf);
    ubox.blobBufInit(&buf, c.BLOBMSG_TYPE_TABLE) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    defer ubox.blobBufFree(&buf) catch {};

    // Add frp_status field (null-terminated)
    const status_z = state.allocator.dupeZ(u8, result.status) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    defer state.allocator.free(status_z);
    addString(&buf, field_names.frp_status, status_z) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

    // Add last_error field (null-terminated)
    const error_z = state.allocator.dupeZ(u8, result.last_error) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    defer state.allocator.free(error_z);
    addString(&buf, field_names.last_error, error_z) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

    // Add logs as array of strings (split by newlines)
    const logs_cookie = ubox.blobmsgOpenNested(&buf, field_names.logs, true) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    var lines_iter = std.mem.splitScalar(u8, result.logs, '\n');
    while (lines_iter.next()) |line| {
        if (line.len > 0) {
            const line_z = state.allocator.dupeZ(u8, line) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
            defer state.allocator.free(line_z);
            // Add string to array: use empty name for array elements
            ubox.blobmsgAddField(&buf, c.BLOBMSG_TYPE_STRING, "", line_z.ptr, line_z.len + 1) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        }
    }
    ubox.blobNestEnd(&buf, logs_cookie) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

    _ = ubus.ubus_send_reply(ctx, req, buf.head) catch {
        return c.UBUS_STATUS_UNKNOWN_ERROR;
    };
    return c.UBUS_STATUS_OK;
}

fn handleClearFrpLogs(ctx: [*c]c.ubus_context, obj: [*c]c.ubus_object, req: [*c]c.ubus_request_data, method: [*c]const u8, msg: [*c]c.blob_attr) callconv(.c) c_int {
    _ = obj;
    _ = method;
    if (msg == null) return c.UBUS_STATUS_INVALID_ARGUMENT;

    // Parse the "id" parameter (node name)
    var tb: [frp_info_policy.len]?*c.blob_attr = .{null};
    const data_ptr = c.blob_data(msg);
    const data_len = c.blob_len(msg);
    ubox.blobmsgParse(frp_info_policy[0..], tb[0..], data_ptr, data_len) catch return c.UBUS_STATUS_INVALID_ARGUMENT;

    if (tb[0] == null) return c.UBUS_STATUS_INVALID_ARGUMENT;
    const node_name_cstr = c.blobmsg_get_string(tb[0].?);
    const node_name = std.mem.span(node_name_cstr);

    // Clear logs for the specified node (idempotent operation)
    frp_forward.clearClientLogs(node_name);

    // Return empty success response
    var buf: c.blob_buf = std.mem.zeroes(c.blob_buf);
    ubox.blobBufInit(&buf, c.BLOBMSG_TYPE_TABLE) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    defer ubox.blobBufFree(&buf) catch {};

    _ = ubus.ubus_send_reply(ctx, req, buf.head) catch {
        return c.UBUS_STATUS_UNKNOWN_ERROR;
    };
    return c.UBUS_STATUS_OK;
}

fn handleGetEvents(ctx: [*c]c.ubus_context, obj: [*c]c.ubus_object, req: [*c]c.ubus_request_data, method: [*c]const u8, msg: [*c]c.blob_attr) callconv(.c) c_int {
    _ = obj;
    _ = method;
    _ = msg;
    const state = g_state orelse return c.UBUS_STATUS_UNKNOWN_ERROR;

    var buf: c.blob_buf = std.mem.zeroes(c.blob_buf);
    ubox.blobBufInit(&buf, c.BLOBMSG_TYPE_TABLE) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    defer ubox.blobBufFree(&buf) catch {};

    // Open the events array
    const arr = ubox.blobmsgOpenNested(&buf, field_names.events, true) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    if (arr == null) return c.UBUS_STATUS_UNKNOWN_ERROR;

    // Get events from the global logger
    if (event_log.getGlobal()) |logger| {
        const events = logger.getEvents(state.allocator) catch {
            ubox.blobNestEnd(&buf, arr) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
            _ = ubus.ubus_send_reply(ctx, req, buf.head) catch {};
            return c.UBUS_STATUS_OK;
        };
        defer event_log.EventLogger.freeEvents(state.allocator, events);

        for (events) |event| {
            const item = ubox.blobmsgOpenNested(&buf, null, false) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
            if (item == null) return c.UBUS_STATUS_UNKNOWN_ERROR;

            // Add timestamp as i64
            addI64(&buf, field_names.timestamp, event.timestamp) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

            // Add event type as string
            const type_str = event.event_type.toString();
            addString(&buf, field_names.event_type, type_str) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

            // Add message (need to convert to null-terminated)
            const msg_z = state.allocator.dupeZ(u8, event.message) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
            defer state.allocator.free(msg_z);
            addString(&buf, field_names.message, msg_z) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

            // Add project_id
            addI32(&buf, field_names.project_id, event.project_id) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

            ubox.blobNestEnd(&buf, item) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        }
    }

    ubox.blobNestEnd(&buf, arr) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

    _ = ubus.ubus_send_reply(ctx, req, buf.head) catch {
        return c.UBUS_STATUS_UNKNOWN_ERROR;
    };
    return c.UBUS_STATUS_OK;
}

fn handleGetDdnsStatuses(ctx: [*c]c.ubus_context, obj: [*c]c.ubus_object, req: [*c]c.ubus_request_data, method: [*c]const u8, msg: [*c]c.blob_attr) callconv(.c) c_int {
    _ = obj;
    _ = method;
    _ = msg;
    const state = g_state orelse return c.UBUS_STATUS_UNKNOWN_ERROR;

    var buf: c.blob_buf = std.mem.zeroes(c.blob_buf);
    ubox.blobBufInit(&buf, c.BLOBMSG_TYPE_TABLE) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    defer ubox.blobBufFree(&buf) catch {};

    // Get DDNS statuses
    const statuses = ddns_manager.getStatuses(state.allocator) catch {
        return c.UBUS_STATUS_UNKNOWN_ERROR;
    };
    defer {
        for (statuses) |*s| {
            var status_copy = s.*;
            status_copy.deinit(state.allocator);
        }
        state.allocator.free(statuses);
    }

    // Open the ddns_statuses array
    const arr = ubox.blobmsgOpenNested(&buf, field_names.ddns_statuses, true) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    if (arr == null) return c.UBUS_STATUS_UNKNOWN_ERROR;

    for (statuses) |status| {
        const item = ubox.blobmsgOpenNested(&buf, "", false) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        if (item == null) return c.UBUS_STATUS_UNKNOWN_ERROR;

        // Convert to null-terminated strings for UBUS
        const section_z = state.allocator.dupeZ(u8, status.section) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        defer state.allocator.free(section_z);
        const name_z = state.allocator.dupeZ(u8, status.name) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        defer state.allocator.free(name_z);
        const provider_z = state.allocator.dupeZ(u8, status.provider) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        defer state.allocator.free(provider_z);
        const status_z = state.allocator.dupeZ(u8, status.status) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        defer state.allocator.free(status_z);
        const last_ip_z = state.allocator.dupeZ(u8, status.last_ip) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        defer state.allocator.free(last_ip_z);
        const message_z = state.allocator.dupeZ(u8, status.message) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        defer state.allocator.free(message_z);

        addString(&buf, field_names.section, section_z) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addString(&buf, field_names.name, name_z) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addString(&buf, field_names.provider, provider_z) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addString(&buf, field_names.status, status_z) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addI64(&buf, field_names.last_update, status.last_update) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addString(&buf, field_names.last_ip, last_ip_z) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addString(&buf, field_names.message, message_z) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

        ubox.blobNestEnd(&buf, item) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    }

    ubox.blobNestEnd(&buf, arr) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

    _ = ubus.ubus_send_reply(ctx, req, buf.head) catch {
        return c.UBUS_STATUS_UNKNOWN_ERROR;
    };
    return c.UBUS_STATUS_OK;
}

fn handleGetDdnsInfo(ctx: [*c]c.ubus_context, obj: [*c]c.ubus_object, req: [*c]c.ubus_request_data, method: [*c]const u8, msg: [*c]c.blob_attr) callconv(.c) c_int {
    _ = obj;
    _ = method;
    if (msg == null) return c.UBUS_STATUS_INVALID_ARGUMENT;
    const state = g_state orelse return c.UBUS_STATUS_UNKNOWN_ERROR;

    // Parse the "name" parameter
    var tb: [ddns_info_policy.len]?*c.blob_attr = .{null};
    const data_ptr = c.blob_data(msg);
    const data_len = c.blob_len(msg);
    ubox.blobmsgParse(ddns_info_policy[0..], tb[0..], data_ptr, data_len) catch return c.UBUS_STATUS_INVALID_ARGUMENT;

    if (tb[0] == null) return c.UBUS_STATUS_INVALID_ARGUMENT;
    const name_cstr = c.blobmsg_get_string(tb[0].?);
    const name = std.mem.span(name_cstr);

    // Get DDNS info from manager
    var info = ddns_manager.getInstanceStatus(state.allocator, name) catch |err| {
        std.log.warn("Failed to get DDNS info for instance '{s}': {any}", .{ name, err });
        return c.UBUS_STATUS_UNKNOWN_ERROR;
    };
    defer info.deinit(state.allocator);

    // Build response
    var buf: c.blob_buf = std.mem.zeroes(c.blob_buf);
    ubox.blobBufInit(&buf, c.BLOBMSG_TYPE_TABLE) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    defer ubox.blobBufFree(&buf) catch {};

    // Add status field
    const status_z = state.allocator.dupeZ(u8, info.status) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    defer state.allocator.free(status_z);
    addString(&buf, field_names.status, status_z) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

    // Add last_error field
    const error_z = state.allocator.dupeZ(u8, info.last_error) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    defer state.allocator.free(error_z);
    addString(&buf, field_names.last_error, error_z) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

    // Add logs as array of strings
    const logs_cookie = ubox.blobmsgOpenNested(&buf, field_names.logs, true) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    for (info.logs.items) |log| {
        const log_z = state.allocator.dupeZ(u8, log) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        defer state.allocator.free(log_z);
        ubox.blobmsgAddField(&buf, c.BLOBMSG_TYPE_STRING, "", log_z.ptr, log_z.len + 1) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    }
    ubox.blobNestEnd(&buf, logs_cookie) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

    _ = ubus.ubus_send_reply(ctx, req, buf.head) catch {
        return c.UBUS_STATUS_UNKNOWN_ERROR;
    };
    return c.UBUS_STATUS_OK;
}

fn handleClearDdnsLogs(ctx: [*c]c.ubus_context, obj: [*c]c.ubus_object, req: [*c]c.ubus_request_data, method: [*c]const u8, msg: [*c]c.blob_attr) callconv(.c) c_int {
    _ = obj;
    _ = method;
    if (msg == null) return c.UBUS_STATUS_INVALID_ARGUMENT;

    // Parse the "name" parameter
    var tb: [ddns_info_policy.len]?*c.blob_attr = .{null};
    const data_ptr = c.blob_data(msg);
    const data_len = c.blob_len(msg);
    ubox.blobmsgParse(ddns_info_policy[0..], tb[0..], data_ptr, data_len) catch return c.UBUS_STATUS_INVALID_ARGUMENT;

    if (tb[0] == null) return c.UBUS_STATUS_INVALID_ARGUMENT;
    const name_cstr = c.blobmsg_get_string(tb[0].?);
    const name = std.mem.span(name_cstr);

    // Clear logs
    ddns_manager.clearInstanceLogs(name) catch |err| {
        std.log.warn("Failed to clear DDNS logs for instance '{s}': {any}", .{ name, err });
        return c.UBUS_STATUS_UNKNOWN_ERROR;
    };

    // Return empty success response
    var buf: c.blob_buf = std.mem.zeroes(c.blob_buf);
    ubox.blobBufInit(&buf, c.BLOBMSG_TYPE_TABLE) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
    defer ubox.blobBufFree(&buf) catch {};

    _ = ubus.ubus_send_reply(ctx, req, buf.head) catch {
        return c.UBUS_STATUS_UNKNOWN_ERROR;
    };
    return c.UBUS_STATUS_OK;
}

fn addString(buf: *c.blob_buf, name: [:0]const u8, val: [:0]const u8) !void {
    try ubox.blobmsgAddField(buf, c.BLOBMSG_TYPE_STRING, name, val.ptr, val.len + 1);
}

fn addBool(buf: *c.blob_buf, name: [:0]const u8, val: bool) !void {
    var v: u8 = if (val) 1 else 0;
    try ubox.blobmsgAddField(buf, c.BLOBMSG_TYPE_BOOL, name, &v, 1);
}

fn addU32(buf: *c.blob_buf, name: [:0]const u8, val: u32) !void {
    var be = std.mem.nativeToBig(u32, val);
    try ubox.blobmsgAddField(buf, c.BLOBMSG_TYPE_INT32, name, &be, @sizeOf(u32));
}

fn addI32(buf: *c.blob_buf, name: [:0]const u8, val: i32) !void {
    const unsigned: u32 = @bitCast(val);
    var be = std.mem.nativeToBig(u32, unsigned);
    try ubox.blobmsgAddField(buf, c.BLOBMSG_TYPE_INT32, name, &be, @sizeOf(i32));
}

fn addU64(buf: *c.blob_buf, name: [:0]const u8, val: u64) !void {
    var be = std.mem.nativeToBig(u64, val);
    try ubox.blobmsgAddField(buf, c.BLOBMSG_TYPE_INT64, name, &be, @sizeOf(u64));
}

fn addI64(buf: *c.blob_buf, name: [:0]const u8, val: i64) !void {
    const unsigned: u64 = @bitCast(val);
    var be = std.mem.nativeToBig(u64, unsigned);
    try ubox.blobmsgAddField(buf, c.BLOBMSG_TYPE_INT64, name, &be, @sizeOf(i64));
}

fn currentTs() u64 {
    const ts = std.time.timestamp();
    if (ts < 0) return 0;
    return @intCast(ts);
}
