const std = @import("std");
const build_options = @import("build_options");

pub const FrpStatus = struct {
    enabled: bool,
    version: ?[]const u8,
};

/// 获取 FRP 功能状态和版本信息
pub fn getFrpStatus(allocator: std.mem.Allocator) !FrpStatus {
    // 检查编译时是否启用了 FRP 支持
    const frpc_enabled = build_options.frpc_mode;

    if (!frpc_enabled) {
        return FrpStatus{
            .enabled = false,
            .version = null,
        };
    }

    // 如果启用了 FRP，获取版本信息
    const libfrp = @import("frpc/libfrp.zig");
    const version = try libfrp.getVersion(allocator);

    return FrpStatus{
        .enabled = true,
        .version = version,
    };
}
