const DynamicLibLoader = @import("../loader/dynamic_lib.zig").DynamicLibLoader;

pub const c = @cImport({
    @cInclude("libnftables.h");
});

const nft_ctx_new_fn = *const fn (flags: u32) callconv(.c) ?*c.nft_ctx;
const nft_ctx_free_fn = *const fn (ctx: ?*c.nft_ctx) callconv(.c) void;
const nft_run_cmd_from_buffer_fn = *const fn (ctx: ?*c.nft_ctx, buf: [*:0]const u8) callconv(.c) c_int;
const nft_run_cmd_from_filename_fn = *const fn (ctx: ?*c.nft_ctx, filename: [*:0]const u8) callconv(.c) c_int;
const nft_ctx_buffer_output_fn = *const fn (ctx: ?*c.nft_ctx) callconv(.c) c_int;
const nft_ctx_buffer_error_fn = *const fn (ctx: ?*c.nft_ctx) callconv(.c) c_int;
const nft_ctx_get_output_buffer_fn = *const fn (ctx: ?*c.nft_ctx) callconv(.c) ?[*:0]const u8;
const nft_ctx_get_error_buffer_fn = *const fn (ctx: ?*c.nft_ctx) callconv(.c) ?[*:0]const u8;
const nft_ctx_get_dry_run_fn = *const fn (ctx: ?*c.nft_ctx) callconv(.c) bool;
const nft_ctx_set_dry_run_fn = *const fn (ctx: ?*c.nft_ctx, dry: bool) callconv(.c) void;
const nft_ctx_output_get_flags_fn = *const fn (ctx: ?*c.nft_ctx) callconv(.c) c_uint;
const nft_ctx_output_set_flags_fn = *const fn (ctx: ?*c.nft_ctx, flags: u32) callconv(.c) void;
const nft_ctx_get_debug_fn = *const fn (ctx: ?*c.nft_ctx) callconv(.c) c_int;
const nft_ctx_set_debug_fn = *const fn (ctx: ?*c.nft_ctx, level: u32) callconv(.c) void;
const nft_ctx_get_max_errors_fn = *const fn (ctx: ?*c.nft_ctx) callconv(.c) c_uint;
const nft_ctx_set_max_errors_fn = *const fn (ctx: ?*c.nft_ctx, max: c_uint) callconv(.c) void;
const nft_ctx_set_output_fn = *const fn (ctx: ?*c.nft_ctx, fp: ?*c.FILE) callconv(.c) c_int;
const nft_ctx_set_error_fn = *const fn (ctx: ?*c.nft_ctx, fp: ?*c.FILE) callconv(.c) c_int;
const nft_ctx_output_json_schema_fn = *const fn (ctx: ?*c.nft_ctx, json_schema: [*:0]const u8) callconv(.c) c_int;

var lib_loader = DynamicLibLoader.init();
var fn_nft_ctx_new: ?nft_ctx_new_fn = null;
var fn_nft_ctx_free: ?nft_ctx_free_fn = null;
var fn_nft_run_cmd_from_buffer: ?nft_run_cmd_from_buffer_fn = null;
var fn_nft_run_cmd_from_filename: ?nft_run_cmd_from_filename_fn = null;
var fn_nft_ctx_buffer_output: ?nft_ctx_buffer_output_fn = null;
var fn_nft_ctx_buffer_error: ?nft_ctx_buffer_error_fn = null;
var fn_nft_ctx_get_output_buffer: ?nft_ctx_get_output_buffer_fn = null;
var fn_nft_ctx_get_error_buffer: ?nft_ctx_get_error_buffer_fn = null;
var fn_nft_ctx_get_dry_run: ?nft_ctx_get_dry_run_fn = null;
var fn_nft_ctx_set_dry_run: ?nft_ctx_set_dry_run_fn = null;
var fn_nft_ctx_output_get_flags: ?nft_ctx_output_get_flags_fn = null;
var fn_nft_ctx_output_set_flags: ?nft_ctx_output_set_flags_fn = null;
var fn_nft_ctx_get_debug: ?nft_ctx_get_debug_fn = null;
var fn_nft_ctx_set_debug: ?nft_ctx_set_debug_fn = null;
var fn_nft_ctx_get_max_errors: ?nft_ctx_get_max_errors_fn = null;
var fn_nft_ctx_set_max_errors: ?nft_ctx_set_max_errors_fn = null;
var fn_nft_ctx_set_output: ?nft_ctx_set_output_fn = null;
var fn_nft_ctx_set_error: ?nft_ctx_set_error_fn = null;
var fn_nft_ctx_output_json_schema: ?nft_ctx_output_json_schema_fn = null;

fn ensureLibLoaded() !void {
    if (lib_loader.isLoaded()) return;
    try lib_loader.load("nftables");
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

pub inline fn nft_ctx_new(flags: u32) !?*c.nft_ctx {
    const func = try loadFunction(nft_ctx_new_fn, "nft_ctx_new", &fn_nft_ctx_new);
    return func(flags);
}

pub inline fn nft_ctx_free(ctx: ?*c.nft_ctx) !void {
    const func = try loadFunction(nft_ctx_free_fn, "nft_ctx_free", &fn_nft_ctx_free);
    func(ctx);
}

pub inline fn nft_run_cmd_from_buffer(ctx: ?*c.nft_ctx, buf: [*:0]const u8) !c_int {
    const func = try loadFunction(nft_run_cmd_from_buffer_fn, "nft_run_cmd_from_buffer", &fn_nft_run_cmd_from_buffer);
    return func(ctx, buf);
}

pub inline fn nft_run_cmd_from_filename(ctx: ?*c.nft_ctx, filename: [*:0]const u8) !c_int {
    const func = try loadFunction(nft_run_cmd_from_filename_fn, "nft_run_cmd_from_filename", &fn_nft_run_cmd_from_filename);
    return func(ctx, filename);
}

pub inline fn nft_ctx_buffer_output(ctx: ?*c.nft_ctx) !c_int {
    const func = try loadFunction(nft_ctx_buffer_output_fn, "nft_ctx_buffer_output", &fn_nft_ctx_buffer_output);
    return func(ctx);
}

pub inline fn nft_ctx_buffer_error(ctx: ?*c.nft_ctx) !c_int {
    const func = try loadFunction(nft_ctx_buffer_error_fn, "nft_ctx_buffer_error", &fn_nft_ctx_buffer_error);
    return func(ctx);
}

pub inline fn nft_ctx_get_output_buffer(ctx: ?*c.nft_ctx) !?[*:0]const u8 {
    const func = try loadFunction(nft_ctx_get_output_buffer_fn, "nft_ctx_get_output_buffer", &fn_nft_ctx_get_output_buffer);
    return func(ctx);
}

pub inline fn nft_ctx_get_error_buffer(ctx: ?*c.nft_ctx) !?[*:0]const u8 {
    const func = try loadFunction(nft_ctx_get_error_buffer_fn, "nft_ctx_get_error_buffer", &fn_nft_ctx_get_error_buffer);
    return func(ctx);
}

pub inline fn nft_ctx_get_dry_run(ctx: ?*c.nft_ctx) !bool {
    const func = try loadFunction(nft_ctx_get_dry_run_fn, "nft_ctx_get_dry_run", &fn_nft_ctx_get_dry_run);
    return func(ctx);
}

pub inline fn nft_ctx_set_dry_run(ctx: ?*c.nft_ctx, dry: bool) !void {
    const func = try loadFunction(nft_ctx_set_dry_run_fn, "nft_ctx_set_dry_run", &fn_nft_ctx_set_dry_run);
    func(ctx, dry);
}

pub inline fn nft_ctx_output_get_flags(ctx: ?*c.nft_ctx) !c_uint {
    const func = try loadFunction(nft_ctx_output_get_flags_fn, "nft_ctx_output_get_flags", &fn_nft_ctx_output_get_flags);
    return func(ctx);
}

pub inline fn nft_ctx_output_set_flags(ctx: ?*c.nft_ctx, flags: u32) !void {
    const func = try loadFunction(nft_ctx_output_set_flags_fn, "nft_ctx_output_set_flags", &fn_nft_ctx_output_set_flags);
    func(ctx, flags);
}

pub inline fn nft_ctx_get_debug(ctx: ?*c.nft_ctx) !c_int {
    const func = try loadFunction(nft_ctx_get_debug_fn, "nft_ctx_get_debug", &fn_nft_ctx_get_debug);
    return func(ctx);
}

pub inline fn nft_ctx_set_debug(ctx: ?*c.nft_ctx, level: u32) !void {
    const func = try loadFunction(nft_ctx_set_debug_fn, "nft_ctx_set_debug", &fn_nft_ctx_set_debug);
    func(ctx, level);
}

pub inline fn nft_ctx_get_max_errors(ctx: ?*c.nft_ctx) !c_uint {
    const func = try loadFunction(nft_ctx_get_max_errors_fn, "nft_ctx_get_max_errors", &fn_nft_ctx_get_max_errors);
    return func(ctx);
}

pub inline fn nft_ctx_set_max_errors(ctx: ?*c.nft_ctx, max: c_uint) !void {
    const func = try loadFunction(nft_ctx_set_max_errors_fn, "nft_ctx_set_max_errors", &fn_nft_ctx_set_max_errors);
    func(ctx, max);
}

pub inline fn nft_ctx_set_output(ctx: ?*c.nft_ctx, fp: ?*c.FILE) !c_int {
    const func = try loadFunction(nft_ctx_set_output_fn, "nft_ctx_set_output", &fn_nft_ctx_set_output);
    return func(ctx, fp);
}

pub inline fn nft_ctx_set_error(ctx: ?*c.nft_ctx, fp: ?*c.FILE) !c_int {
    const func = try loadFunction(nft_ctx_set_error_fn, "nft_ctx_set_error", &fn_nft_ctx_set_error);
    return func(ctx, fp);
}

pub inline fn nft_ctx_output_json_schema(ctx: ?*c.nft_ctx, json_schema: [*:0]const u8) !c_int {
    const func = try loadFunction(nft_ctx_output_json_schema_fn, "nft_ctx_output_json_schema", &fn_nft_ctx_output_json_schema);
    return func(ctx, json_schema);
}

pub fn isLoaded() bool {
    return lib_loader.isLoaded();
}
