const std = @import("std");
const builtin = @import("builtin");
pub const c = @cImport({
    @cInclude("forwarder.h");
});

pub fn versionString() [:0]const u8 {
    return std.mem.span(c.uv_get_version_string());
}
pub inline fn printVersion() void {
    std.log.debug("libuv version: {s}\n", .{versionString()});
}
