const std = @import("std");
const build_options = @import("build_options");

pub const FrpStatus = struct {
    frpc: FrpcStatus,
    frps: FrpsStatus,
};

pub const FrpcStatus = struct {
    enabled: bool,
    version: ?[]const u8,
    status: ?[]const u8,
    last_error: ?[]const u8,
    client_count: usize,
};

pub const FrpsStatus = struct {
    enabled: bool,
    version: ?[]const u8,
};

/// Get FRP status (both client and server)
pub fn getFrpStatus(allocator: std.mem.Allocator) !FrpStatus {
    const frpc_status = try getFrpcStatus(allocator);
    const frps_status = try getFrpsStatus(allocator);

    return FrpStatus{
        .frpc = frpc_status,
        .frps = frps_status,
    };
}

/// Get FRPC status
fn getFrpcStatus(allocator: std.mem.Allocator) !FrpcStatus {
    const frpc_enabled = build_options.frpc_mode;

    if (!frpc_enabled) {
        return FrpcStatus{
            .enabled = false,
            .version = null,
            .status = null,
            .last_error = null,
            .client_count = 0,
        };
    }

    const libfrpc = @import("frpc/libfrpc.zig");
    const frpc_forward = @import("frpc_forward.zig");

    const version = try libfrpc.getVersion(allocator);
    errdefer allocator.free(version);

    const agg_status = try frpc_forward.getAggregatedStatus(allocator);
    errdefer {
        allocator.free(agg_status.status);
        if (agg_status.last_error.len > 0) allocator.free(agg_status.last_error);
    }

    return FrpcStatus{
        .enabled = true,
        .version = version,
        .status = agg_status.status,
        .last_error = if (agg_status.last_error.len > 0) agg_status.last_error else null,
        .client_count = agg_status.client_count,
    };
}

/// Get FRPS status
fn getFrpsStatus(allocator: std.mem.Allocator) !FrpsStatus {
    const frps_enabled = build_options.frps_mode;

    if (!frps_enabled) {
        return FrpsStatus{
            .enabled = false,
            .version = null,
        };
    }

    const libfrps = @import("frps/libfrps.zig");
    const version = try libfrps.getVersion(allocator);

    return FrpsStatus{
        .enabled = true,
        .version = version,
    };
}
