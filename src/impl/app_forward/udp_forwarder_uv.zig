const std = @import("std");
const common = @import("common.zig");
const project_status = @import("../project_status.zig");
const TrafficStats = project_status.TrafficStats;
const compat = @import("../../compat.zig");

pub const ForwardError = common.ForwardError;

const uv = @import("uv.zig");
const c = uv.c;

pub const UdpForwarder = struct {
    allocator: std.mem.Allocator,
    forwarder: ?*c.udp_forwarder_t = null,
    runtime: ?*c.forwarder_runtime_t = null,
    lock: std.Io.Mutex = .init,

    pub fn createOnRuntimeThread(allocator: std.mem.Allocator, projectHandle: *project_status.ProjectHandle, token: uv.RuntimeThreadToken, listen_port: u16, target_port: u16) !*UdpForwarder {
        var error_code: i32 = 0;
        const runtime = uv.runtimeFromToken(token);
        const fwd = try allocator.create(UdpForwarder);
        fwd.* = .{
            .allocator = allocator,
            .forwarder = null,
        };

        fwd.setup(runtime, listen_port, projectHandle.cfg.target_address, target_port, projectHandle.cfg.family, projectHandle.cfg.enable_stats, &error_code) catch |err| {
            allocator.destroy(fwd);
            projectHandle.setStartupFailedCode(error_code);
            return err;
        };
        return fwd;
    }

    fn setup(
        self: *UdpForwarder,
        runtime: *c.forwarder_runtime_t,
        listen_port: u16,
        target_address: []const u8,
        target_port: u16,
        family: common.AddressFamily,
        enable_stats: bool,
        out_error_code: *i32,
    ) !void {
        const addr_family: c.addr_family_t = switch (family) {
            .ipv4 => c.ADDR_FAMILY_IPV4,
            .ipv6 => c.ADDR_FAMILY_IPV6,
            .any => c.ADDR_FAMILY_ANY,
        };

        const target_host_z = try self.allocator.dupeZ(u8, target_address);
        defer self.allocator.free(target_host_z);

        const forwarder = c.udp_forwarder_create_on_runtime(
            runtime,
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
        self.runtime = runtime;
        out_error_code.* = 0;
    }

    pub fn startOnRuntimeThread(self: *UdpForwarder, token: uv.RuntimeThreadToken, projectHandle: *project_status.ProjectHandle) !void {
        const runtime = uv.runtimeFromToken(token);
        if (!self.belongsToRuntime(runtime)) return ForwardError.ListenFailed;
        if (self.forwarder == null) return ForwardError.ListenFailed;
        const rc = c.udp_forwarder_start(self.forwarder.?);
        if (rc != 0) {
            projectHandle.setStartupFailedCode(rc);
            return ForwardError.ListenFailed;
        }
    }

    pub fn requestStop(self: *UdpForwarder) void {
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());
        if (self.forwarder) |f| {
            c.udp_forwarder_request_stop(f);
        }
    }

    pub fn belongsToRuntime(self: *const UdpForwarder, runtime: *c.forwarder_runtime_t) bool {
        return self.runtime == runtime;
    }

    /// Must run on the owning runtime thread after stop/close callbacks drained.
    pub fn destroyOnRuntimeThread(self: *UdpForwarder, token: uv.RuntimeThreadToken) void {
        const runtime = uv.runtimeFromToken(token);
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());
        if (self.runtime != runtime) return;
        if (self.forwarder) |f| {
            c.udp_forwarder_destroy(f);
            self.forwarder = null;
        }
        self.runtime = null;
    }

    pub fn destroyWrapper(self: *UdpForwarder) void {
        self.allocator.destroy(self);
    }

    pub fn getStats(self: *UdpForwarder) TrafficStats {
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());
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
