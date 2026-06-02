const std = @import("std");
const common = @import("common.zig");
const project_status = @import("../project_status.zig");
const TrafficStats = project_status.TrafficStats;
const compat = @import("../../compat.zig");
pub const ForwardError = common.ForwardError;

const forwarder_runtime = @import("forwarder_runtime.zig");
const c = forwarder_runtime.c;

pub const TcpForwarder = struct {
    allocator: std.mem.Allocator,
    forwarder: ?*c.tcp_forwarder_t,
    runtime: ?*c.forwarder_runtime_t = null,
    lock: std.Io.Mutex = .init,

    pub fn createOnRuntimeThread(allocator: std.mem.Allocator, projectHandle: *project_status.ProjectHandle, token: forwarder_runtime.RuntimeThreadToken, listen_port: u16, target_port: u16) !*TcpForwarder {
        var error_code: i32 = 0;
        const runtime_ctx = forwarder_runtime.runtimeFromToken(token);
        const fwd = try allocator.create(TcpForwarder);
        fwd.* = .{
            .allocator = allocator,
            .forwarder = null,
        };

        fwd.setup(runtime_ctx, listen_port, projectHandle.cfg.target_address, target_port, projectHandle.cfg.family, projectHandle.cfg.enable_app_stats, projectHandle.cfg.connect_timeout_ms orelse 0, &error_code) catch |err| {
            allocator.destroy(fwd);
            projectHandle.setStartupFailedCode(error_code);
            return err;
        };
        return fwd;
    }

    fn setup(
        self: *TcpForwarder,
        runtime: *c.forwarder_runtime_t,
        listen_port: u16,
        target_address: []const u8,
        target_port: u16,
        family: common.AddressFamily,
        enable_stats: bool,
        connect_timeout_ms: u32,
        out_error_code: *i32,
    ) !void {
        const target_z = try self.allocator.dupeZ(u8, target_address);
        defer self.allocator.free(target_z);

        const c_family: c.addr_family_t = switch (family) {
            .ipv4 => c.ADDR_FAMILY_IPV4,
            .ipv6 => c.ADDR_FAMILY_IPV6,
            .any => c.ADDR_FAMILY_ANY,
        };

        const forwarder_ptr = c.tcp_forwarder_create_on_runtime(
            runtime,
            listen_port,
            target_z.ptr,
            target_port,
            c_family,
            if (enable_stats) 1 else 0,
            connect_timeout_ms,
            out_error_code,
        );

        if (forwarder_ptr == null) {
            std.log.debug("[TCP] ERROR on port {d}: error_code={d}", .{ listen_port, out_error_code.* });
            return ForwardError.ListenFailed;
        }

        self.forwarder = forwarder_ptr.?;
        self.runtime = runtime;
        out_error_code.* = 0;
    }

    pub fn startOnRuntimeThread(self: *TcpForwarder, token: forwarder_runtime.RuntimeThreadToken, projectHandle: *project_status.ProjectHandle) !void {
        const runtime_ctx = forwarder_runtime.runtimeFromToken(token);
        if (!self.belongsToRuntime(runtime_ctx)) return ForwardError.ListenFailed;
        if (self.forwarder == null) return ForwardError.ListenFailed;
        const r = c.tcp_forwarder_start(self.forwarder);
        if (r != 0) {
            projectHandle.setStartupFailedCode(r);
            return ForwardError.ListenFailed;
        }
    }

    pub fn requestStop(self: *TcpForwarder) void {
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());
        if (self.forwarder) |f| {
            c.tcp_forwarder_request_stop(f);
        }
    }

    pub fn belongsToRuntime(self: *const TcpForwarder, runtime: *c.forwarder_runtime_t) bool {
        return self.runtime == runtime;
    }

    /// Must run on the owning runtime thread after stop/close callbacks drained.
    pub fn destroyOnRuntimeThread(self: *TcpForwarder, token: forwarder_runtime.RuntimeThreadToken) void {
        const runtime_ctx = forwarder_runtime.runtimeFromToken(token);
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());
        if (self.runtime != runtime_ctx) return;
        if (self.forwarder) |f| {
            c.tcp_forwarder_destroy(f);
            self.forwarder = null;
        }
        self.runtime = null;
    }

    pub fn destroyWrapper(self: *TcpForwarder) void {
        self.allocator.destroy(self);
    }

    pub fn getStats(self: *TcpForwarder) TrafficStats {
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());
        if (self.forwarder) |f| {
            const c_stats = c.tcp_forwarder_get_stats(f);
            return .{
                .bytes_in = c_stats.bytes_in,
                .bytes_out = c_stats.bytes_out,
                .listen_port = c_stats.listen_port,
                .active_sessions = c_stats.active_sessions,
            };
        }
        return .{ .bytes_in = 0, .bytes_out = 0, .listen_port = 0, .active_sessions = 0 };
    }
};
