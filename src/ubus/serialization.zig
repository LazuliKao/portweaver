const std = @import("std");
const ubox = @import("ubox.zig");
const libubus = @import("libubus.zig");
const libblobmsg_json = @import("libblobmsg_json.zig");
const c = ubox.c;

pub const RawJson = struct {
    json: []const u8,
};

pub fn serializeRoot(buf: *c.blob_buf, value: anytype, allocator: std.mem.Allocator) !void {
    const T = @TypeOf(value);
    const type_info = @typeInfo(T);
    switch (type_info) {
        .@"struct" => |info| {
            if (T == RawJson) {
                const json_z = try allocator.dupeZ(u8, value.json);
                try libblobmsg_json.blobmsg_add_json_from_string(buf, json_z);
            } else {
                inline for (info.fields) |field| {
                    const field_name_z: [:0]const u8 = field.name[0..field.name.len :0];
                    try serialize(buf, field_name_z, @field(value, field.name), allocator);
                }
            }
        },
        else => @compileError("Root value must be a struct"),
    }
}

pub fn serialize(buf: *c.blob_buf, name: ?[:0]const u8, value: anytype, allocator: std.mem.Allocator) !void {
    const T = @TypeOf(value);
    const type_info = @typeInfo(T);
    const field_name: [:0]const u8 = name orelse "";

    switch (type_info) {
        .bool => {
            var v: u8 = if (value) 1 else 0;
            try ubox.blobmsgAddField(buf, c.BLOBMSG_TYPE_BOOL, field_name, &v, 1);
        },
        .int => |info| {
            if (info.bits <= 32) {
                var be = std.mem.nativeToBig(i32, @intCast(value));
                try ubox.blobmsgAddField(buf, c.BLOBMSG_TYPE_INT32, field_name, &be, 4);
            } else {
                var be = std.mem.nativeToBig(i64, @intCast(value));
                try ubox.blobmsgAddField(buf, c.BLOBMSG_TYPE_INT64, field_name, &be, 8);
            }
        },
        .pointer => |info| {
            if (info.size == .slice and info.child == u8) {
                const is_null_terminated = (info.sentinel_ptr != null and @as(*const u8, @ptrCast(@alignCast(info.sentinel_ptr.?))).* == 0);
                if (is_null_terminated) {
                    try ubox.blobmsgAddField(buf, c.BLOBMSG_TYPE_STRING, field_name, value.ptr, value.len + 1);
                } else {
                    const val_z = try allocator.dupeZ(u8, value);
                    try ubox.blobmsgAddField(buf, c.BLOBMSG_TYPE_STRING, field_name, val_z.ptr, val_z.len + 1);
                }
            } else if (info.size == .slice) {
                const cookie = try ubox.blobmsgOpenNested(buf, name, true);
                if (cookie) |cookie_ptr| {
                    for (value) |item| {
                        try serialize(buf, null, item, allocator);
                    }
                    try ubox.blobNestEnd(buf, cookie_ptr);
                }
            } else {
                try serialize(buf, name, value.*, allocator);
            }
        },
        .array => {
            const cookie = try ubox.blobmsgOpenNested(buf, name, true);
            if (cookie) |cookie_ptr| {
                for (value) |item| {
                    try serialize(buf, null, item, allocator);
                }
                try ubox.blobNestEnd(buf, cookie_ptr);
            }
        },
        .optional => {
            if (value) |val| {
                try serialize(buf, name, val, allocator);
            }
        },
        .@"struct" => |info| {
            if (T == RawJson) {
                const json_z = try allocator.dupeZ(u8, value.json);
                try libblobmsg_json.blobmsg_add_json_from_string(buf, json_z);
            } else {
                const cookie = try ubox.blobmsgOpenNested(buf, name, false);
                if (cookie) |cookie_ptr| {
                    inline for (info.fields) |field| {
                        const field_name_z: [:0]const u8 = field.name[0..field.name.len :0];
                        try serialize(buf, field_name_z, @field(value, field.name), allocator);
                    }
                    try ubox.blobNestEnd(buf, cookie_ptr);
                }
            }
        },
        .@"enum" => {
            const tag = @tagName(value);
            const tag_z = try allocator.dupeZ(u8, tag);
            try ubox.blobmsgAddField(buf, c.BLOBMSG_TYPE_STRING, field_name, tag_z.ptr, tag_z.len + 1);
        },
        else => @compileError("Unsupported type for serialization: " ++ @typeName(T)),
    }
}

fn findPolicyIndex(comptime name: []const u8, comptime policy: []const c.blobmsg_policy) ?usize {
    inline for (policy, 0..) |p, idx| {
        const p_name = std.mem.span(p.name);
        if (std.mem.eql(u8, p_name, name)) {
            return idx;
        }
    }
    return null;
}

fn parseAttr(comptime FT: type, attr: *c.blob_attr) !FT {
    const info = @typeInfo(FT);
    switch (info) {
        .bool => return ubox.blobmsgGetBool(attr),
        .int => |int_info| {
            if (int_info.bits <= 32) {
                const val = ubox.blobmsgGetU32(attr);
                return @intCast(val);
            } else if (int_info.bits <= 64) {
                const val = ubox.blobmsgGetU64(attr);
                return @intCast(val);
            } else {
                @compileError("Unsupported integer bit width for parsing: " ++ @typeName(FT));
            }
        },
        .pointer => |ptr_info| {
            if (ptr_info.size == .slice and ptr_info.child == u8) {
                const cstr = ubox.blobmsgGetString(attr);
                return std.mem.span(cstr);
            }
            @compileError("Unsupported pointer type for parsing: " ++ @typeName(FT));
        },
        .optional => |opt_info| {
            return try parseAttr(opt_info.child, attr);
        },
        else => @compileError("Unsupported type for parsing: " ++ @typeName(FT)),
    }
}

pub fn parseArgs(comptime T: type, msg: ?*c.blob_attr, comptime policy: []const c.blobmsg_policy) !T {
    const actual_msg = msg orelse return error.InvalidArgument;
    const data_ptr = ubox.blobData(actual_msg);
    const data_len = ubox.blobLen(actual_msg);

    var tb: [32]?*c.blob_attr = undefined;
    if (policy.len > tb.len) @panic("Policy too large for standard buffer");
    @memset(tb[0..policy.len], null);

    try ubox.blobmsgParse(policy, tb[0..policy.len], data_ptr, data_len);

    var result: T = undefined;
    const struct_info = @typeInfo(T).@"struct";

    inline for (struct_info.fields) |field| {
        const idx = comptime blk: {
            break :blk findPolicyIndex(field.name, policy) orelse {
                @compileError("Field '" ++ field.name ++ "' not found in ubus policy");
            };
        };

        if (tb[idx]) |attr| {
            @field(result, field.name) = try parseAttr(field.type, attr);
        } else {
            if (@typeInfo(field.type) == .optional) {
                @field(result, field.name) = null;
            } else {
                return error.InvalidArgument;
            }
        }
    }
    return result;
}

pub fn mapZigErrorToUbus(err: anyerror) c_int {
    return switch (err) {
        error.OutOfMemory => c.UBUS_STATUS_NO_MEMORY,
        error.InvalidArgument => c.UBUS_STATUS_INVALID_ARGUMENT,
        error.NotFound => c.UBUS_STATUS_NOT_FOUND,
        error.PermissionDenied => c.UBUS_STATUS_PERMISSION_DENIED,
        else => c.UBUS_STATUS_UNKNOWN_ERROR,
    };
}

pub fn wrapHandler(comptime func: anytype, comptime ArgsType: type, comptime policy: ?[]const c.blobmsg_policy) c.ubus_handler_t {
    return struct {
        fn wrapper(ctx: [*c]c.ubus_context, obj: [*c]c.ubus_object, req: [*c]c.ubus_request_data, method: [*c]const u8, msg: [*c]c.blob_attr) callconv(.c) c_int {
            _ = obj;
            _ = method;

            const server = @import("server.zig");
            const state = server.g_state orelse return c.UBUS_STATUS_UNKNOWN_ERROR;

            var arena = std.heap.ArenaAllocator.init(state.allocator);
            defer arena.deinit();
            const alloc = arena.allocator();

            const ReturnType = @typeInfo(@TypeOf(func)).@"fn".return_type.?;
            const inner_return_type = switch (@typeInfo(ReturnType)) {
                .error_union => |eu| eu.payload,
                else => ReturnType,
            };

            if (ArgsType == void) {
                if (inner_return_type == void) {
                    func(alloc, state) catch |err| {
                        std.log.warn("ubus handler error: {any}", .{err});
                        return mapZigErrorToUbus(err);
                    };
                } else {
                    const res = func(alloc, state) catch |err| {
                        std.log.warn("ubus handler error: {any}", .{err});
                        return mapZigErrorToUbus(err);
                    };
                    var buf = std.mem.zeroes(c.blob_buf);
                    ubox.blobBufInit(&buf, c.BLOBMSG_TYPE_TABLE) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
                    defer ubox.blobBufFree(&buf) catch {};
                    serializeRoot(&buf, res, alloc) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
                    _ = libubus.ubus_send_reply(ctx, req, buf.head) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
                }
            } else {
                const args = parseArgs(ArgsType, msg, policy.?) catch |err| {
                    std.log.warn("ubus argument parsing error: {any}", .{err});
                    return c.UBUS_STATUS_INVALID_ARGUMENT;
                };
                if (inner_return_type == void) {
                    func(alloc, state, args) catch |err| {
                        std.log.warn("ubus handler error: {any}", .{err});
                        return mapZigErrorToUbus(err);
                    };
                } else {
                    const res = func(alloc, state, args) catch |err| {
                        std.log.warn("ubus handler error: {any}", .{err});
                        return mapZigErrorToUbus(err);
                    };
                    var buf = std.mem.zeroes(c.blob_buf);
                    ubox.blobBufInit(&buf, c.BLOBMSG_TYPE_TABLE) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
                    defer ubox.blobBufFree(&buf) catch {};
                    serializeRoot(&buf, res, alloc) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
                    _ = libubus.ubus_send_reply(ctx, req, buf.head) catch return c.UBUS_STATUS_UNKNOWN_ERROR;
                }
            }

            return c.UBUS_STATUS_OK;
        }
    }.wrapper;
}
