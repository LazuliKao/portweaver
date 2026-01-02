const std = @import("std");
const uv = @import("uv.zig");
const common = @import("common.zig");

pub const ForwardError = common.ForwardError;

const c = uv.c;

pub const UdpForwarder = struct {
    allocator: std.mem.Allocator,
    listen_port: u16,
    target_address: []const u8,
    target_port: u16,
    family: common.AddressFamily,
    enable_stats: bool,
    last_error_code: i32 = 0,

    forwarder: ?*c.udp_forwarder_t = null,

    pub fn init(
        allocator: std.mem.Allocator,
        listen_port: u16,
        target_address: []const u8,
        target_port: u16,
        family: common.AddressFamily,
        enable_stats: bool,
        out_error_code: *i32,
    ) !UdpForwarder {
        var self: UdpForwarder = undefined;
        self.allocator = allocator;
        self.listen_port = listen_port;
        self.target_address = target_address;
        self.target_port = target_port;
        self.family = family;
        self.enable_stats = enable_stats;

        const addr_family: c.addr_family_t = switch (self.family) {
            .ipv4 => c.ADDR_FAMILY_IPV4,
            .ipv6 => c.ADDR_FAMILY_IPV6,
            .any => c.ADDR_FAMILY_ANY,
        };

        const target_host_z = allocator.dupeZ(u8, self.target_address) catch unreachable;
        defer allocator.free(target_host_z);

        var error_code: i32 = 0;
        const forwarder = c.udp_forwarder_create(
            self.listen_port,
            target_host_z.ptr,
            self.target_port,
            addr_family,
            if (self.enable_stats) 1 else 0,
            &error_code,
        );
        if (forwarder == null) {
            std.debug.print("[UDP] ERROR on port {d}: error_code={d}\n", .{ self.listen_port, error_code });
            self.last_error_code = error_code;
            out_error_code.* = error_code;
            return ForwardError.ListenFailed;
        }
        self.forwarder = forwarder;
        self.last_error_code = 0;
        out_error_code.* = 0;

        return self;
    }

    pub fn deinit(self: *UdpForwarder) void {
        if (self.forwarder) |f| {
            c.udp_forwarder_stop(f);
            c.udp_forwarder_destroy(f);
            self.forwarder = null;
        }
    }

    pub fn start(self: *UdpForwarder) !void {
        if (self.forwarder == null) {
            // Init should have created the forwarder already
            return ForwardError.ListenFailed;
        }

        std.debug.print("[UDP] Listening on port {d}, forwarding to {s}:{d}\n", .{
            self.listen_port,
            self.target_address,
            self.target_port,
        });

        const rc = c.udp_forwarder_start(self.forwarder.?);
        if (rc != 0) {
            self.last_error_code = rc;
            return ForwardError.ListenFailed;
        }
        self.last_error_code = 0;
    }

    pub fn stop(self: *UdpForwarder) void {
        if (self.forwarder) |f| {
            c.udp_forwarder_stop(f);
        }
    }

    pub fn getHandle(self: *UdpForwarder) *c.udp_forwarder_t {
        return self.forwarder.?;
    }

    pub fn getLastErrorCode(self: *UdpForwarder) i32 {
        return self.last_error_code;
    }

    pub fn getStats(self: *UdpForwarder) common.TrafficStats {
        if (self.forwarder) |f| {
            const c_stats = c.udp_forwarder_get_stats(f);
            return .{
                .bytes_in = c_stats.bytes_in,
                .bytes_out = c_stats.bytes_out,
            };
        }
        return .{ .bytes_in = 0, .bytes_out = 0 };
    }
};

pub fn getStatsRaw(fwd: *c.udp_forwarder_t) common.TrafficStats {
    const c_stats = c.udp_forwarder_get_stats(fwd);
    return .{ .bytes_in = c_stats.bytes_in, .bytes_out = c_stats.bytes_out };
}
