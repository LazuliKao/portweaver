const std = @import("std");
const uv = @import("uv.zig");
const common = @import("common.zig");

pub const ForwardError = common.ForwardError;

const c = uv.c;

pub const TcpForwarder = struct {
    allocator: std.mem.Allocator,
    forwarder: *c.tcp_forwarder_t,

    pub fn init(
        allocator: std.mem.Allocator,
        listen_port: u16,
        target_address: []const u8,
        target_port: u16,
        family: common.AddressFamily,
        enable_stats: bool,
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

        const forwarder_ptr = c.tcp_forwarder_create(
            listen_port,
            target_z.ptr,
            target_port,
            c_family,
            if (enable_stats) 1 else 0,
        );

        if (forwarder_ptr == null) {
            std.debug.print("[TCP] ERROR: Failed to create TCP forwarder on port {d}\n", .{listen_port});
            return ForwardError.ListenFailed;
        }

        self.forwarder = forwarder_ptr.?;

        return self;
    }

    pub fn start(self: *TcpForwarder) !void {
        if (c.tcp_forwarder_start(self.forwarder) != 0) {
            return ForwardError.ListenFailed;
        }
    }

    pub fn stop(self: *TcpForwarder) void {
        c.tcp_forwarder_stop(self.forwarder);
    }

    pub fn deinit(self: *TcpForwarder) void {
        c.tcp_forwarder_destroy(self.forwarder);
    }

    pub fn getHandle(self: *TcpForwarder) *c.tcp_forwarder_t {
        return self.forwarder;
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
