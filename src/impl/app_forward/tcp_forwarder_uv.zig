const std = @import("std");
const uv = @import("uv.zig");
const common = @import("common.zig");
const project_status = @import("../project_status.zig");
const TrafficStats = project_status.TrafficStats;
pub const ForwardError = common.ForwardError;

const c = uv.c;

pub const TcpForwarder = struct {
    allocator: std.mem.Allocator,
    forwarder: ?*c.tcp_forwarder_t,
    pub fn init(allocator: std.mem.Allocator, projectHandle: *project_status.ProjectHandle, listen_port: u16, target_port: u16) !*TcpForwarder {
        var error_code: i32 = 0;
        const fwd = try allocator.create(TcpForwarder);
        fwd.* = TcpForwarder.setup(allocator, listen_port, projectHandle.cfg.target_address, target_port, projectHandle.cfg.family, projectHandle.cfg.enable_stats, &error_code) catch |err| {
            allocator.destroy(fwd);
            projectHandle.setStartupFailedCode(error_code);
            return err;
        };
        return fwd;
    }
    pub fn setup(
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

        const forwarder_ptr = c.tcp_forwarder_create(
            listen_port,
            target_z.ptr,
            target_port,
            c_family,
            if (enable_stats) 1 else 0,
            out_error_code,
        );

        if (forwarder_ptr == null) {
            std.log.debug("[TCP] ERROR on port {d}: error_code={d}", .{ listen_port, out_error_code.* });
            return ForwardError.ListenFailed;
        }

        self.forwarder = forwarder_ptr.?;
        out_error_code.* = 0;

        return self;
    }
    pub fn start(self: *TcpForwarder, projectHandle: *project_status.ProjectHandle) !void {
        if (self.forwarder == null) {
            // Init should have created the forwarder already
            return ForwardError.ListenFailed;
        }
        const r = c.tcp_forwarder_start(self.forwarder);
        if (r != 0) {
            projectHandle.setStartupFailedCode(r);
            return ForwardError.ListenFailed;
        }
    }

    pub fn stop(self: *TcpForwarder) void {
        if (self.forwarder) |f| {
            c.tcp_forwarder_stop(f);
        }
    }

    pub fn deinit(self: *TcpForwarder) void {
        if (self.forwarder) |f| {
            c.tcp_forwarder_stop(f);
            c.tcp_forwarder_destroy(f);
            self.forwarder = null;
        }
        self.allocator.destroy(self);
    }

    pub fn getStats(self: *TcpForwarder) TrafficStats {
        if (self.forwarder) |f| {
            const c_stats = c.tcp_forwarder_get_stats(f);
            return .{
                .bytes_in = c_stats.bytes_in,
                .bytes_out = c_stats.bytes_out,
                .listen_port = c_stats.listen_port,
            };
        }
        return .{ .bytes_in = 0, .bytes_out = 0, .listen_port = 0 };
    }
};
