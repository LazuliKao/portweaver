const std = @import("std");
const types = @import("../config/types.zig");
const ubus = @import("libubus.zig");
const ubox = @import("ubox.zig");
const c = ubox.c;

const STATUS_RUNNING: [:0]const u8 = "running";
const STATUS_STOPPED: [:0]const u8 = "stopped";
const STATUS_DEGRADED: [:0]const u8 = "degraded";

const ProjectState = struct {
    id: usize,
    remark: [:0]u8,
    enabled: bool,
    status: [:0]const u8,
    active_ports: u32 = 0,
    bytes_in: u64 = 0,
    bytes_out: u64 = 0,
    last_changed: u64,
};

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
    projects: []ProjectState,
    mutex: std.Thread.Mutex = .{},

    pub fn init(allocator: std.mem.Allocator, projects: []const types.Project) !*RuntimeState {
        const state = try allocator.create(RuntimeState);
        const now = currentTs();
        state.* = .{
            .allocator = allocator,
            .start_ts = now,
            .projects = try allocator.alloc(ProjectState, projects.len),
        };

        for (projects, 0..) |project, idx| {
            const remark_z = try allocator.dupeZ(u8, project.remark);
            state.projects[idx] = .{
                .id = idx,
                .remark = remark_z,
                .enabled = project.enabled,
                .status = if (project.enabled) STATUS_RUNNING else STATUS_STOPPED,
                .last_changed = now,
            };
        }

        return state;
    }

    pub fn deinit(self: *RuntimeState) void {
        for (self.projects) |p| self.allocator.free(p.remark);
        self.allocator.free(self.projects);
        self.allocator.destroy(self);
    }

    fn globalSnapshot(self: *RuntimeState) GlobalSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();

        var running: usize = 0;
        var active_ports: u32 = 0;
        var bytes_in: u64 = 0;
        var bytes_out: u64 = 0;
        for (self.projects) |p| {
            if (p.enabled) running += 1;
            active_ports += p.active_ports;
            bytes_in += p.bytes_in;
            bytes_out += p.bytes_out;
        }

        const status: [:0]const u8 = if (self.projects.len == 0)
            STATUS_STOPPED
        else if (running == self.projects.len)
            STATUS_RUNNING
        else if (running == 0)
            STATUS_STOPPED
        else
            STATUS_DEGRADED;

        const now = currentTs();
        return .{
            .status = status,
            .total_projects = @intCast(self.projects.len),
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

const method_names = struct {
    pub const get_status: [:0]const u8 = "get_status";
    pub const list_projects: [:0]const u8 = "list_projects";
    pub const set_enabled: [:0]const u8 = "set_enabled";
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
};

pub fn start(allocator: std.mem.Allocator, projects: []const types.Project) !void {
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

    var methods = [_]c.ubus_method{
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

    std.log.info("ubus: server started successfully.\n", .{});

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

    for (state.projects) |p| {
        const item = ubox.blobmsgOpenNested(&buf, null, false) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        if (item == null) return c.UBUS_STATUS_UNKNOWN_ERROR;

        addU32(&buf, field_names.id, @intCast(p.id)) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addString(&buf, field_names.remark, p.remark) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addBool(&buf, field_names.enabled, p.enabled) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addString(&buf, field_names.status, p.status) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addU32(&buf, field_names.active_ports, p.active_ports) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addU64(&buf, field_names.bytes_in, p.bytes_in) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addU64(&buf, field_names.bytes_out, p.bytes_out) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
        addU64(&buf, field_names.last_changed, p.last_changed) catch return c.UBUS_STATUS_UNKNOWN_ERROR;

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
    if (idx >= state.projects.len) {
        state.mutex.unlock();
        return c.UBUS_STATUS_INVALID_ARGUMENT;
    }

    var p = &state.projects[idx];
    p.enabled = enabled_flag;
    p.status = if (enabled_flag) STATUS_RUNNING else STATUS_STOPPED;
    p.last_changed = currentTs();
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

fn addU64(buf: *c.blob_buf, name: [:0]const u8, val: u64) !void {
    var be = std.mem.nativeToBig(u64, val);
    try ubox.blobmsgAddField(buf, c.BLOBMSG_TYPE_INT64, name, &be, @sizeOf(u64));
}

fn currentTs() u64 {
    const ts = std.time.timestamp();
    if (ts < 0) return 0;
    return @intCast(ts);
}
