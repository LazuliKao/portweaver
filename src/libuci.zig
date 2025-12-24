const std = @import("std");

// 从 C 头文件导入类型定义 - 导出这些类型以便其他模块使用
pub const c = @cImport({
    @cInclude("uci.h");
});

const uci_alloc_context_fn = *const fn () callconv(.c) [*c]c.uci_context;
const uci_free_context_fn = *const fn (ctx: [*c]c.uci_context) callconv(.c) void;
const uci_perror_fn = *const fn (ctx: [*c]c.uci_context, str: [*c]const u8) callconv(.c) void;
const uci_get_errorstr_fn = *const fn (ctx: [*c]c.uci_context, dest: [*c][*c]u8, str: [*c]const u8) callconv(.c) void;
const uci_import_fn = *const fn (ctx: [*c]c.uci_context, stream: [*c]c.FILE, name: [*c]const u8, package: [*c][*c]c.uci_package, single: bool) callconv(.c) c_int;
const uci_export_fn = *const fn (ctx: [*c]c.uci_context, stream: [*c]c.FILE, package: [*c]c.uci_package, header: bool) callconv(.c) c_int;
const uci_load_fn = *const fn (ctx: [*c]c.uci_context, name: [*c]const u8, package: [*c][*c]c.uci_package) callconv(.c) c_int;
const uci_unload_fn = *const fn (ctx: [*c]c.uci_context, p: [*c]c.uci_package) callconv(.c) c_int;
const uci_lookup_ptr_fn = *const fn (ctx: [*c]c.uci_context, ptr: [*c]c.uci_ptr, str: [*c]u8, extended: bool) callconv(.c) c_int;
const uci_add_section_fn = *const fn (ctx: [*c]c.uci_context, p: [*c]c.uci_package, @"type": [*c]const u8, res: [*c][*c]c.uci_section) callconv(.c) c_int;
const uci_set_fn = *const fn (ctx: [*c]c.uci_context, ptr: [*c]c.uci_ptr) callconv(.c) c_int;
const uci_add_list_fn = *const fn (ctx: [*c]c.uci_context, ptr: [*c]c.uci_ptr) callconv(.c) c_int;
const uci_del_list_fn = *const fn (ctx: [*c]c.uci_context, ptr: [*c]c.uci_ptr) callconv(.c) c_int;
const uci_reorder_section_fn = *const fn (ctx: [*c]c.uci_context, s: [*c]c.uci_section, pos: c_int) callconv(.c) c_int;
const uci_rename_fn = *const fn (ctx: [*c]c.uci_context, ptr: [*c]c.uci_ptr) callconv(.c) c_int;
const uci_delete_fn = *const fn (ctx: [*c]c.uci_context, ptr: [*c]c.uci_ptr) callconv(.c) c_int;
const uci_save_fn = *const fn (ctx: [*c]c.uci_context, p: [*c]c.uci_package) callconv(.c) c_int;
const uci_commit_fn = *const fn (ctx: [*c]c.uci_context, p: [*c][*c]c.uci_package, overwrite: bool) callconv(.c) c_int;
const uci_list_configs_fn = *const fn (ctx: [*c]c.uci_context, list: [*c][*c][*c]u8) callconv(.c) c_int;
const uci_set_savedir_fn = *const fn (ctx: [*c]c.uci_context, dir: [*c]const u8) callconv(.c) c_int;
const uci_set_confdir_fn = *const fn (ctx: [*c]c.uci_context, dir: [*c]const u8) callconv(.c) c_int;
const uci_set_conf2dir_fn = *const fn (ctx: [*c]c.uci_context, dir: [*c]const u8) callconv(.c) c_int;
const uci_add_delta_path_fn = *const fn (ctx: [*c]c.uci_context, dir: [*c]const u8) callconv(.c) c_int;
const uci_revert_fn = *const fn (ctx: [*c]c.uci_context, ptr: [*c]c.uci_ptr) callconv(.c) c_int;
const uci_parse_argument_fn = *const fn (ctx: [*c]c.uci_context, stream: [*c]c.FILE, str: [*c][*c]u8, result: [*c][*c]u8) callconv(.c) c_int;
const uci_set_backend_fn = *const fn (ctx: [*c]c.uci_context, name: [*c]const u8) callconv(.c) c_int;
const uci_validate_text_fn = *const fn (str: [*c]const u8) callconv(.c) bool;
const uci_parse_ptr_fn = *const fn (ctx: [*c]c.uci_context, ptr: [*c]c.uci_ptr, str: [*c]u8) callconv(.c) c_int;
const uci_lookup_next_fn = *const fn (ctx: [*c]c.uci_context, e: [*c][*c]c.uci_element, list: [*c]c.uci_list, name: [*c]const u8) callconv(.c) c_int;
const uci_parse_section_fn = *const fn (s: [*c]c.uci_section, opts: [*c]const c.uci_parse_option, n_opts: c_int, tb: [*c][*c]c.uci_option) callconv(.c) void;
const uci_hash_options_fn = *const fn (tb: [*c][*c]c.uci_option, n_opts: c_int) callconv(.c) u32;

// const uci_alloc_context_fn = *const @TypeOf(@field(c, "uci_alloc_context"));
// const uci_free_context_fn = *const @TypeOf(@field(c, "uci_free_context"));
// const uci_perror_fn = *const @TypeOf(@field(c, "uci_perror"));
// const uci_get_errorstr_fn = *const @TypeOf(@field(c, "uci_get_errorstr"));
// const uci_import_fn = *const @TypeOf(@field(c, "uci_import"));
// const uci_export_fn = *const @TypeOf(@field(c, "uci_export"));
// const uci_load_fn = *const @TypeOf(@field(c, "uci_load"));
// const uci_unload_fn = *const @TypeOf(@field(c, "uci_unload"));
// const uci_lookup_ptr_fn = *const @TypeOf(@field(c, "uci_lookup_ptr"));
// const uci_add_section_fn = *const @TypeOf(@field(c, "uci_add_section"));
// const uci_set_fn = *const @TypeOf(@field(c, "uci_set"));
// const uci_add_list_fn = *const @TypeOf(@field(c, "uci_add_list"));
// const uci_del_list_fn = *const @TypeOf(@field(c, "uci_del_list"));
// const uci_reorder_section_fn = *const @TypeOf(@field(c, "uci_reorder_section"));
// const uci_rename_fn = *const @TypeOf(@field(c, "uci_rename"));
// const uci_delete_fn = *const @TypeOf(@field(c, "uci_delete"));
// const uci_save_fn = *const @TypeOf(@field(c, "uci_save"));
// const uci_commit_fn = *const @TypeOf(@field(c, "uci_commit"));
// const uci_list_configs_fn = *const @TypeOf(@field(c, "uci_list_configs"));
// const uci_set_savedir_fn = *const @TypeOf(@field(c, "uci_set_savedir"));
// const uci_set_confdir_fn = *const @TypeOf(@field(c, "uci_set_confdir"));
// const uci_set_conf2dir_fn = *const @TypeOf(@field(c, "uci_set_conf2dir"));
// const uci_add_delta_path_fn = *const @TypeOf(@field(c, "uci_add_delta_path"));
// const uci_revert_fn = *const @TypeOf(@field(c, "uci_revert"));
// const uci_parse_argument_fn = *const @TypeOf(@field(c, "uci_parse_argument"));
// const uci_set_backend_fn = *const @TypeOf(@field(c, "uci_set_backend"));
// const uci_validate_text_fn = *const @TypeOf(@field(c, "uci_validate_text"));
// const uci_parse_ptr_fn = *const @TypeOf(@field(c, "uci_parse_ptr"));
// const uci_lookup_next_fn = *const @TypeOf(@field(c, "uci_lookup_next"));
// const uci_parse_section_fn = *const @TypeOf(@field(c, "uci_parse_section"));
// const uci_hash_options_fn = *const @TypeOf(@field(c, "uci_hash_options"));

var lib_handle: ?std.DynLib = null;
var fn_alloc_context: ?uci_alloc_context_fn = null;
var fn_free_context: ?uci_free_context_fn = null;
var fn_perror: ?uci_perror_fn = null;
var fn_get_errorstr: ?uci_get_errorstr_fn = null;
var fn_import: ?uci_import_fn = null;
var fn_export: ?uci_export_fn = null;
var fn_load: ?uci_load_fn = null;
var fn_unload: ?uci_unload_fn = null;
var fn_lookup_ptr: ?uci_lookup_ptr_fn = null;
var fn_add_section: ?uci_add_section_fn = null;
var fn_set: ?uci_set_fn = null;
var fn_add_list: ?uci_add_list_fn = null;
var fn_del_list: ?uci_del_list_fn = null;
var fn_reorder_section: ?uci_reorder_section_fn = null;
var fn_rename: ?uci_rename_fn = null;
var fn_delete: ?uci_delete_fn = null;
var fn_save: ?uci_save_fn = null;
var fn_commit: ?uci_commit_fn = null;
var fn_list_configs: ?uci_list_configs_fn = null;
var fn_set_savedir: ?uci_set_savedir_fn = null;
var fn_set_confdir: ?uci_set_confdir_fn = null;
var fn_set_conf2dir: ?uci_set_conf2dir_fn = null;
var fn_add_delta_path: ?uci_add_delta_path_fn = null;
var fn_revert: ?uci_revert_fn = null;
var fn_parse_argument: ?uci_parse_argument_fn = null;
var fn_set_backend: ?uci_set_backend_fn = null;
var fn_validate_text: ?uci_validate_text_fn = null;
var fn_parse_ptr: ?uci_parse_ptr_fn = null;
var fn_lookup_next: ?uci_lookup_next_fn = null;
var fn_parse_section: ?uci_parse_section_fn = null;
var fn_hash_options: ?uci_hash_options_fn = null;
fn ensureLibLoaded() !void {
    if (lib_handle != null) return;

    const lib_paths = [_][]const u8{
        "/lib/libuci.so.20250120",
        "/lib/libuci.so",
        "libuci.so",
    };

    var last_error: ?std.DynLib.Error = null;

    for (lib_paths) |path| {
        const lib = std.DynLib.open(path) catch |err| {
            last_error = err;
            continue;
        };
        lib_handle = lib;
        return;
    }

    if (last_error) |err| {
        return err;
    }
    return error.LibLoadFailed;
}

fn loadFunction(comptime T: type, comptime name: [:0]const u8, cache: *?T) !T {
    if (cache.*) |func| {
        return func;
    }

    try ensureLibLoaded();

    const func = lib_handle.?.lookup(T, name) orelse {
        std.debug.print("Failed to lookup {s}\n", .{name});
        return error.FunctionNotFound;
    };

    cache.* = func;
    return func;
}

pub inline fn uci_alloc_context() ![*c]c.uci_context {
    const func = try loadFunction(uci_alloc_context_fn, "uci_alloc_context", &fn_alloc_context);
    return func();
}

pub inline fn uci_free_context(ctx: [*c]c.uci_context) !void {
    const func = try loadFunction(uci_free_context_fn, "uci_free_context", &fn_free_context);
    func(ctx);
}

pub inline fn uci_perror(ctx: [*c]c.uci_context, str: [*c]const u8) !void {
    const func = try loadFunction(uci_perror_fn, "uci_perror", &fn_perror);
    func(ctx, str);
}

pub inline fn uci_get_errorstr(ctx: [*c]c.uci_context, dest: [*c][*c]u8, str: [*c]const u8) !void {
    const func = try loadFunction(uci_get_errorstr_fn, "uci_get_errorstr", &fn_get_errorstr);
    func(ctx, dest, str);
}

pub inline fn uci_import(ctx: [*c]c.uci_context, stream: [*c]c.FILE, name: [*c]const u8, package: [*c][*c]c.uci_package, single: bool) !c_int {
    const func = try loadFunction(uci_import_fn, "uci_import", &fn_import);
    return func(ctx, stream, name, package, single);
}

pub inline fn uci_export(ctx: [*c]c.uci_context, stream: [*c]c.FILE, package: [*c]c.uci_package, header: bool) !c_int {
    const func = try loadFunction(uci_export_fn, "uci_export", &fn_export);
    return func(ctx, stream, package, header);
}

pub inline fn uci_load(ctx: [*c]c.uci_context, name: [*c]const u8, package: [*c][*c]c.uci_package) !c_int {
    const func = try loadFunction(uci_load_fn, "uci_load", &fn_load);
    return func(ctx, name, package);
}

pub inline fn uci_unload(ctx: [*c]c.uci_context, p: [*c]c.uci_package) !c_int {
    const func = try loadFunction(uci_unload_fn, "uci_unload", &fn_unload);
    return func(ctx, p);
}

pub inline fn uci_lookup_ptr(ctx: [*c]c.uci_context, ptr: [*c]c.uci_ptr, str: [*c]u8, extended: bool) !c_int {
    const func = try loadFunction(uci_lookup_ptr_fn, "uci_lookup_ptr", &fn_lookup_ptr);
    return func(ctx, ptr, str, extended);
}

pub inline fn uci_add_section(ctx: [*c]c.uci_context, p: [*c]c.uci_package, @"type": [*c]const u8, res: [*c][*c]c.uci_section) !c_int {
    const func = try loadFunction(uci_add_section_fn, "uci_add_section", &fn_add_section);
    return func(ctx, p, @"type", res);
}

pub inline fn uci_set(ctx: [*c]c.uci_context, ptr: [*c]c.uci_ptr) !c_int {
    const func = try loadFunction(uci_set_fn, "uci_set", &fn_set);
    return func(ctx, ptr);
}

pub inline fn uci_add_list(ctx: [*c]c.uci_context, ptr: [*c]c.uci_ptr) !c_int {
    const func = try loadFunction(uci_add_list_fn, "uci_add_list", &fn_add_list);
    return func(ctx, ptr);
}

pub inline fn uci_del_list(ctx: [*c]c.uci_context, ptr: [*c]c.uci_ptr) !c_int {
    const func = try loadFunction(uci_del_list_fn, "uci_del_list", &fn_del_list);
    return func(ctx, ptr);
}

pub inline fn uci_reorder_section(ctx: [*c]c.uci_context, s: [*c]c.uci_section, pos: c_int) !c_int {
    const func = try loadFunction(uci_reorder_section_fn, "uci_reorder_section", &fn_reorder_section);
    return func(ctx, s, pos);
}

pub inline fn uci_rename(ctx: [*c]c.uci_context, ptr: [*c]c.uci_ptr) !c_int {
    const func = try loadFunction(uci_rename_fn, "uci_rename", &fn_rename);
    return func(ctx, ptr);
}

pub inline fn uci_delete(ctx: [*c]c.uci_context, ptr: [*c]c.uci_ptr) !c_int {
    const func = try loadFunction(uci_delete_fn, "uci_delete", &fn_delete);
    return func(ctx, ptr);
}

pub inline fn uci_save(ctx: [*c]c.uci_context, p: [*c]c.uci_package) !c_int {
    const func = try loadFunction(uci_save_fn, "uci_save", &fn_save);
    return func(ctx, p);
}

pub inline fn uci_commit(ctx: [*c]c.uci_context, p: [*c][*c]c.uci_package, overwrite: bool) !c_int {
    const func = try loadFunction(uci_commit_fn, "uci_commit", &fn_commit);
    return func(ctx, p, overwrite);
}

pub inline fn uci_list_configs(ctx: [*c]c.uci_context, list: [*c][*c][*c]u8) !c_int {
    const func = try loadFunction(uci_list_configs_fn, "uci_list_configs", &fn_list_configs);
    return func(ctx, list);
}

pub inline fn uci_set_savedir(ctx: [*c]c.uci_context, dir: [*c]const u8) !c_int {
    const func = try loadFunction(uci_set_savedir_fn, "uci_set_savedir", &fn_set_savedir);
    return func(ctx, dir);
}

pub inline fn uci_set_confdir(ctx: [*c]c.uci_context, dir: [*c]const u8) !c_int {
    const func = try loadFunction(uci_set_confdir_fn, "uci_set_confdir", &fn_set_confdir);
    return func(ctx, dir);
}

pub inline fn uci_set_conf2dir(ctx: [*c]c.uci_context, dir: [*c]const u8) !c_int {
    const func = try loadFunction(uci_set_conf2dir_fn, "uci_set_conf2dir", &fn_set_conf2dir);
    return func(ctx, dir);
}

pub inline fn uci_add_delta_path(ctx: [*c]c.uci_context, dir: [*c]const u8) !c_int {
    const func = try loadFunction(uci_add_delta_path_fn, "uci_add_delta_path", &fn_add_delta_path);
    return func(ctx, dir);
}

pub inline fn uci_revert(ctx: [*c]c.uci_context, ptr: [*c]c.uci_ptr) !c_int {
    const func = try loadFunction(uci_revert_fn, "uci_revert", &fn_revert);
    return func(ctx, ptr);
}

pub inline fn uci_parse_argument(ctx: [*c]c.uci_context, stream: [*c]c.FILE, str: [*c][*c]u8, result: [*c][*c]u8) !c_int {
    const func = try loadFunction(uci_parse_argument_fn, "uci_parse_argument", &fn_parse_argument);
    return func(ctx, stream, str, result);
}

pub inline fn uci_set_backend(ctx: [*c]c.uci_context, name: [*c]const u8) !c_int {
    const func = try loadFunction(uci_set_backend_fn, "uci_set_backend", &fn_set_backend);
    return func(ctx, name);
}

pub inline fn uci_validate_text(str: [*c]const u8) !bool {
    const func = try loadFunction(uci_validate_text_fn, "uci_validate_text", &fn_validate_text);
    return func(str);
}

pub inline fn uci_parse_ptr(ctx: [*c]c.uci_context, ptr: [*c]c.uci_ptr, str: [*c]u8) !c_int {
    const func = try loadFunction(uci_parse_ptr_fn, "uci_parse_ptr", &fn_parse_ptr);
    return func(ctx, ptr, str);
}

pub inline fn uci_lookup_next(ctx: [*c]c.uci_context, e: [*c][*c]c.uci_element, list: [*c]c.uci_list, name: [*c]const u8) !c_int {
    const func = try loadFunction(uci_lookup_next_fn, "uci_lookup_next", &fn_lookup_next);
    return func(ctx, e, list, name);
}

pub inline fn uci_parse_section(s: [*c]c.uci_section, opts: [*c]const c.uci_parse_option, n_opts: c_int, tb: [*c][*c]c.uci_option) !void {
    const func = try loadFunction(uci_parse_section_fn, "uci_parse_section", &fn_parse_section);
    func(s, opts, n_opts, tb);
}

pub inline fn uci_hash_options(tb: [*c][*c]c.uci_option, n_opts: c_int) !u32 {
    const func = try loadFunction(uci_hash_options_fn, "uci_hash_options", &fn_hash_options);
    return func(tb, n_opts);
}

pub inline fn isLoaded() bool {
    return lib_handle != null;
}

pub const config = @import("config.zig");
