const std = @import("std");
const uv = @import("uv.zig");
const common = @import("common.zig");

pub const ForwardError = common.ForwardError;

const c = uv.c;

pub const InitResult = struct {
    forwarder: TcpForwarder,
    error_code: i32,
};

pub const TcpForwarder = struct {
    allocator: std.mem.Allocator,
    forwarder: ?*c.tcp_forwarder_t,
    last_error_code: i32 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        listen_port: u16,
        target_address: []const u8,
        target_port: u16,
        family: common.AddressFamily,
        enable_stats: bool,
        out_error_code: *i32,
    ) !TcpForwarder {
        var self: TcpForwarder = undefined;
        self.allocator = allocator;

        const target_z = allocator.dupeZ(u8, target_address) catch unreachable;
        defer allocator.free(target_z);

        const c_family: c.addr_family_t = switch (family) {
            .ipv4 => c.ADDR_FAMILY_IPV4,
            .ipv6 => c.ADDR_FAMILY_IPV6,
            .any => c.ADDR_FAMILY_ANY,
        };

        var error_code: i32 = 0;
        const forwarder_ptr = c.tcp_forwarder_create(
            listen_port,
            target_z.ptr,
            target_port,
            c_family,
            if (enable_stats) 1 else 0,
            &error_code,
        );

        if (forwarder_ptr == null) {
            std.debug.print("[TCP] ERROR on port {d}: error_code={d}\n", .{ listen_port, error_code });
            out_error_code.* = error_code;
            self.last_error_code = error_code;
            return ForwardError.ListenFailed;
        }

        self.forwarder = forwarder_ptr.?;
        self.last_error_code = 0;
        out_error_code.* = 0;

        return self;
    }
    pub fn start(self: *TcpForwarder) !void {
        const r = c.tcp_forwarder_start(self.forwarder);
        if (r != 0) {
            self.last_error_code = r;
            return ForwardError.ListenFailed;
        }
    }

    pub fn stop(self: *TcpForwarder) void {
        c.tcp_forwarder_stop(self.forwarder);
    }

    pub fn deinit(self: *TcpForwarder) void {
        if (self.forwarder) |f| {
            c.tcp_forwarder_stop(f);
            c.tcp_forwarder_destroy(f);
            self.forwarder = null;
        }
    }

    pub fn getHandle(self: *TcpForwarder) *c.tcp_forwarder_t {
        return self.forwarder;
    }

    pub fn getLastErrorCode(self: *TcpForwarder) i32 {
        return self.last_error_code;
    }

    pub fn getStats(self: *TcpForwarder) common.TrafficStats {
        const c_stats = c.tcp_forwarder_get_stats(self.forwarder);
        return .{
            .bytes_in = c_stats.bytes_in,
            .bytes_out = c_stats.bytes_out,
        };
    }
};

pub fn getStatsRaw(fwd: *c.tcp_forwarder_t) common.TrafficStats {
    const c_stats = c.tcp_forwarder_get_stats(fwd);
    return .{ .bytes_in = c_stats.bytes_in, .bytes_out = c_stats.bytes_out };
}
