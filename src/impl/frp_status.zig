const std = @import("std");
const build_options = @import("build_options");

pub const FrpcStatus = struct {
    enabled: bool,
    version: ?[]const u8,
    status: ?[]const u8,
    last_error: ?[]const u8,
    client_count: usize,
};

/// 获取 FRPC 功能状态和版本信息
pub fn getFrpcStatus(allocator: std.mem.Allocator) !FrpcStatus {
    // 检查编译时是否启用了 FRPC 支持
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

    // 如果启用了 FRPC，获取版本信息
    const libfrp = @import("frpc/libfrpc.zig");
    const frpc_forward = @import("frpc_forward.zig");

    const version = try libfrp.getVersion(allocator);
    defer allocator.free(version);

    // 获取聚合状态
    const agg_status = try frpc_forward.getAggregatedStatus(allocator);
    defer {
        allocator.free(agg_status.status);
        if (agg_status.last_error.len > 0) allocator.free(agg_status.last_error);
    }

    return FrpcStatus{
        .enabled = false,
        .version = null,
        .status = null,
        .last_error = null,
        .client_count = 0,
    };
}
