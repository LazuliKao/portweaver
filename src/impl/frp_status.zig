const std = @import("std");
const build_options = @import("build_options");

pub const FrpStatus = struct {
    frp_enabled: bool,
    frp_version: ?[]const u8,
    frpc: FrpcStatus,
    frps: FrpsStatus,
};

pub const FrpcStatus = struct {
    enabled: bool,
    status: ?[]const u8,
    last_error: ?[]const u8,
    client_count: usize,
};

pub const FrpsStatus = struct {
    enabled: bool,
    status: ?[]const u8,
    last_error: ?[]const u8,
    client_count: usize,
    proxy_count: usize,
    server_count: usize,
};

pub fn getFrpStatus(allocator: std.mem.Allocator) !FrpStatus {
    const frpc_enabled = build_options.frpc_mode;
    const frps_enabled = build_options.frps_mode;
    const frp_enabled = frpc_enabled or frps_enabled;

    var frp_version: ?[]const u8 = null;
    errdefer if (frp_version) |v| allocator.free(v);

    if (frp_enabled) {
        if (frpc_enabled) {
            const libfrpc = @import("frpc/libfrpc.zig");
            frp_version = try libfrpc.getVersion(allocator);
        } else if (frps_enabled) {
            const libfrps = @import("frps/libfrps.zig");
            frp_version = try libfrps.getVersion(allocator);
        }
    }

    const frpc_status = try getFrpcStatus(allocator);
    errdefer {
        if (frpc_status.status) |s| allocator.free(s);
        if (frpc_status.last_error) |e| allocator.free(e);
    }

    const frps_status = try getFrpsStatus(allocator);
    errdefer {
        if (frps_status.status) |s| allocator.free(s);
        if (frps_status.last_error) |e| allocator.free(e);
    }

    return FrpStatus{
        .frp_enabled = frp_enabled,
        .frp_version = frp_version,
        .frpc = frpc_status,
        .frps = frps_status,
    };
}

fn getFrpcStatus(allocator: std.mem.Allocator) !FrpcStatus {
    const frpc_enabled = build_options.frpc_mode;

    if (!frpc_enabled) {
        return FrpcStatus{
            .enabled = false,
            .status = null,
            .last_error = null,
            .client_count = 0,
        };
    }

    const frpc_forward = @import("frpc_forward.zig");

    const agg_status = try frpc_forward.getAggregatedStatus(allocator);
    errdefer {
        allocator.free(agg_status.status);
        if (agg_status.last_error.len > 0) allocator.free(agg_status.last_error);
    }

    return FrpcStatus{
        .enabled = true,
        .status = agg_status.status,
        .last_error = if (agg_status.last_error.len > 0) agg_status.last_error else null,
        .client_count = agg_status.client_count,
    };
}

fn getFrpsStatus(allocator: std.mem.Allocator) !FrpsStatus {
    const frps_enabled = build_options.frps_mode;

    if (!frps_enabled) {
        return FrpsStatus{
            .enabled = false,
            .status = null,
            .last_error = null,
            .client_count = 0,
            .proxy_count = 0,
            .server_count = 0,
        };
    }

    const libfrps = @import("frps/libfrps.zig");

    const stats = try libfrps.getServerStats(allocator);
    errdefer {
        allocator.free(stats.status);
        allocator.free(stats.last_error);
    }

    return FrpsStatus{
        .enabled = true,
        .status = stats.status,
        .last_error = if (stats.last_error.len > 0) stats.last_error else null,
        .client_count = stats.client_count,
        .proxy_count = stats.proxy_count,
        .server_count = stats.server_count,
    };
}
