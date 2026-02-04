const std = @import("std");
const uv = @import("uv.zig");
const common = @import("common.zig");
const project_status = @import("../project_status.zig");
const TrafficStats = project_status.TrafficStats;

pub const ForwardError = common.ForwardError;

const c = uv.c;

pub const UdpForwarder = struct {
    allocator: std.mem.Allocator,
    forwarder: ?*c.udp_forwarder_t = null,
    pub fn init(allocator: std.mem.Allocator, projectHandle: *project_status.ProjectHandle, listen_port: u16, target_port: u16) !*UdpForwarder {
        var error_code: i32 = 0;
        const fwd = try allocator.create(UdpForwarder);
        fwd.* = UdpForwarder.setup(allocator, listen_port, projectHandle.cfg.target_address, target_port, projectHandle.cfg.family, projectHandle.cfg.enable_stats, &error_code) catch |err| {
            allocator.destroy(fwd);
            projectHandle.setStartupFailedCode(error_code);
            return err;
        };
        return fwd;
    }
    fn setup(
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

        const addr_family: c.addr_family_t = switch (family) {
            .ipv4 => c.ADDR_FAMILY_IPV4,
            .ipv6 => c.ADDR_FAMILY_IPV6,
            .any => c.ADDR_FAMILY_ANY,
        };

        const target_host_z = allocator.dupeZ(u8, target_address) catch unreachable;
        defer allocator.free(target_host_z);

        const forwarder = c.udp_forwarder_create(
            listen_port,
            target_host_z.ptr,
            target_port,
            addr_family,
            if (enable_stats) 1 else 0,
            out_error_code,
        );
        if (forwarder == null) {
            std.log.debug("[UDP] ERROR on port {d}: error_code={d}", .{ listen_port, out_error_code.* });
            return ForwardError.ListenFailed;
        }
        self.forwarder = forwarder;
        out_error_code.* = 0;

        return self;
    }

    pub fn deinit(self: *UdpForwarder) void {
        if (self.forwarder) |f| {
            c.udp_forwarder_stop(f);
            c.udp_forwarder_destroy(f);
            self.forwarder = null;
        }
        self.allocator.destroy(self);
    }

    pub fn start(self: *UdpForwarder, projectHandle: *project_status.ProjectHandle) !void {
        if (self.forwarder == null) {
            return ForwardError.ListenFailed;
        }
        const rc = c.udp_forwarder_start(self.forwarder.?);
        if (rc != 0) {
            projectHandle.setStartupFailedCode(rc);
            return ForwardError.ListenFailed;
        }
    }

    pub fn stop(self: *UdpForwarder) void {
        if (self.forwarder) |f| {
            c.udp_forwarder_stop(f);
        }
    }

    pub fn getStats(self: *UdpForwarder) TrafficStats {
        if (self.forwarder) |f| {
            const c_stats = c.udp_forwarder_get_stats(f);
            return .{
                .bytes_in = c_stats.bytes_in,
                .bytes_out = c_stats.bytes_out,
                .listen_port = c_stats.listen_port,
            };
        }
        return .{ .bytes_in = 0, .bytes_out = 0, .listen_port = 0 };
    }
};
