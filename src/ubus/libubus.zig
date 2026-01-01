const std = @import("std");
const builtin = @import("builtin");

// pub const c = @cImport({
//     // @cDefine("_POSIX_C_SOURCE", "200809L");
//     @cDefine("_GNU_SOURCE", "1");
//     // if (builtin.os.tag == .windows) {
//     //     @cDefine("__CYGWIN__", "1");
//     // } else {
//     // @cDefine("__linux__", "1");
//     // }
//     @cInclude("unistd.h");
//     @cInclude("signal.h");
//     @cInclude("libubox/blobmsg_json.h");
//     @cInclude("libubus.h");
// });
const c = @cImport({
    @cDefine("__linux__", "1");
    @cDefine("_GNU_SOURCE", "1");
    @cInclude("byteswap.h");
    @cInclude("unistd.h");
    @cInclude("signal.h");
    @cInclude("libubox/blobmsg_json.h");
    @cInclude("libubus.h");
    // @cInclude("ubusmsg.h");
    // @cInclude("ubus_common.h");
    // @cInclude("ubusd_acl.h");
    // @cInclude("ubusd_obj.h");
});

pub fn ubus_lookup_id(ctx: ?*c.struct_ubus_context, path: [*:0]const u8, id: *u32) c.int {
    return c.ubus_lookup_id(ctx, path.ptr, id);
}
