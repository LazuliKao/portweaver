const std = @import("std");
const ubox = @import("ubox.zig");
const c = ubox.c;
const DynamicLibLoader = @import("../loader/dynamic_lib.zig").DynamicLibLoader;

// 定义函数类型
const blobmsg_add_json_from_string_fn = *const fn (buf: [*c]c.blob_buf, str: [*c]const u8) callconv(.c) bool;
const blobmsg_add_json_element_fn = *const fn (buf: [*c]c.blob_buf, name: [*c]const u8, obj: ?*c.json_object) callconv(.c) bool;

// 全局变量
var fn_add_json_from_string: ?blobmsg_add_json_from_string_fn = null;
var fn_add_json_element: ?blobmsg_add_json_element_fn = null;

var lib_loader = DynamicLibLoader.init();

fn ensureLibLoaded() !void {
    if (lib_loader.isLoaded()) return;
    try lib_loader.load("libblobmsg_json");
}

fn loadFunction(comptime T: type, comptime name: [:0]const u8, cache: *?T) !T {
    if (cache.*) |func| {
        return func;
    }

    try ensureLibLoaded();

    const func = try lib_loader.lookup(T, name);
    cache.* = func;
    return func;
}

// 包装函数
pub inline fn blobmsg_add_json_from_string(buf: *c.blob_buf, json: [:0]const u8) !void {
    const func = try loadFunction(blobmsg_add_json_from_string_fn, "blobmsg_add_json_from_string", &fn_add_json_from_string);
    if (!func(buf, json)) return error.BlobAddJsonFailed;
}

pub inline fn blobmsg_add_json_element(buf: *c.blob_buf, name: [:0]const u8, obj: *c.json_object) !void {
    const func = try loadFunction(blobmsg_add_json_element_fn, "blobmsg_add_json_element", &fn_add_json_element);
    if (!func(buf, name, obj)) return error.BlobAddJsonElementFailed;
}

pub inline fn isLoaded() bool {
    return lib_loader.isLoaded();
}
