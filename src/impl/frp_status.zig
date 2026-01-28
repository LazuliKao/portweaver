const std = @import("std");
const build_options = @import("build_options");

pub const FrpStatus = struct {
    enabled: bool,
    version: ?[]const u8,
    status: ?[]const u8,
    last_error: ?[]const u8,
    client_count: usize,
};

/// 获取 FRP 功能状态和版本信息
pub fn getFrpStatus(allocator: std.mem.Allocator) !FrpStatus {
    // 检查编译时是否启用了 FRP 支持
    const frpc_enabled = build_options.frpc_mode;

    if (!frpc_enabled) {
        return FrpStatus{
            .enabled = false,
            .version = null,
            .status = null,
            .last_error = null,
            .client_count = 0,
        };
    }

    // 如果启用了 FRP，获取版本信息
    const libfrp = @import("frpc/libfrp.zig");
    const frp_forward = @import("frp_forward.zig");

    const version = try libfrp.getVersion(allocator);

    // 获取聚合状态
    const agg_status = try frp_forward.getAggregatedStatus(allocator);

    return FrpStatus{
        .enabled = frpc_enabled,
        .version = version,
        .status = agg_status.status,
        .last_error = if (agg_status.last_error.len > 0) agg_status.last_error else null,
        .client_count = agg_status.client_count,
    };
}
