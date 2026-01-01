const std = @import("std");
const builtin = @import("builtin");

const c = @cImport({
    @cInclude("posix_missing_fix.h");
    @cInclude("unistd.h");
    @cInclude("signal.h");
    @cInclude("libubox/blobmsg_json.h");
    @cInclude("libubus.h");
});
