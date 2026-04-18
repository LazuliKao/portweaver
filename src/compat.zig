const std = @import("std");
const builtin = @import("builtin");

pub fn io() std.Io {
    return std.Options.debug_io;
}

pub fn getenv(name: [:0]const u8) ?[]const u8 {
    const value = std.c.getenv(name.ptr) orelse return null;
    return std.mem.span(value);
}

pub fn sleepNanos(nanos: u64) void {
    if (nanos == 0) return;

    switch (builtin.os.tag) {
        .windows => {
            const interval_100ns: i64 = -@as(i64, @intCast(@divFloor(nanos + 99, 100)));
            _ = std.os.windows.ntdll.NtDelayExecution(.TRUE, @ptrCast(&interval_100ns));
        },
        else => {
            var req = std.posix.timespec{
                .sec = @intCast(@divFloor(nanos, std.time.ns_per_s)),
                .nsec = @intCast(@mod(nanos, std.time.ns_per_s)),
            };
            while (true) {
                var rem: std.posix.timespec = undefined;
                const rc = std.c.nanosleep(&req, &rem);
                if (rc == 0) break;
                const err = std.posix.errno(rc);
                if (err == .INTR) {
                    req = rem;
                    continue;
                }
                break;
            }
        },
    }
}

pub fn isDebugBuild() bool {
    return builtin.mode == .Debug;
}
