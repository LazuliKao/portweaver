const std = @import("std");
const uci = @import("uci/mod.zig");
const firewall = @import("impl/firewall.zig");
const app_forward = @import("impl/app_forward.zig");
const config = @import("config/mod.zig");

pub fn main() !void {
    // 示例：演示如何使用应用层转发
    try demoAppForward();

    // 原有的防火墙配置功能
    try printFirewallConfig();

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    firewall.reloadFirewall(allocator) catch |err| {
        std.debug.print("Error reloading firewall: {}\n", .{err});
    };
}

/// 演示应用层端口转发功能
pub fn demoAppForward() !void {
    std.debug.print("=== Application Layer Port Forwarding Demo ===\n", .{});
    std.debug.print("To enable app-layer forwarding, set 'enable_app_forward = true' in config\n", .{});
    std.debug.print("Example: Forward TCP port 8080 to 127.0.0.1:80\n", .{});
    std.debug.print("See example_config.json and APP_FORWARD.md for more details\n", .{});
    std.debug.print("==============================================\n\n", .{});
}

/// Print all firewall configuration settings
pub fn printFirewallConfig() !void {
    std.debug.print("Loading firewall configuration...\n", .{});

    // Allocate UCI context
    var uci_ctx = try uci.UciContext.alloc();
    defer uci_ctx.free();

    uci_ctx.perror("UCI context allocated");

    // // Try to load the firewall config
    const config_name: [*c]const u8 = "firewall";
    var package = uci_ctx.load(config_name) catch |err| {
        std.debug.print("Error loading firewall config: {}\n", .{err});
        uci_ctx.perror(config_name);
        return;
    };

    if (!package.isNull()) {
        defer package.unload() catch |err| {
            std.debug.print("Error unloading package: {}\n", .{err});
        };

        std.debug.print("Firewall configuration:\n", .{});
        try listConfigSections(package);
    } else {
        std.debug.print("Firewall package is null\n", .{});
    }
}

/// Get all sections and options from a UCI package
pub fn listConfigSections(package: uci.UciPackage) !void {
    // 简化实现：由于我们现在使用 opaque 类型，
    // 实际的遍历需要通过 C 函数接口
    std.debug.print("Package loaded successfully!\n", .{});

    var sec_it = uci.sections(package);
    while (sec_it.next()) |sec| {
        const sec_name = uci.cStr(sec.name());
        const sec_type = uci.cStr(sec.sectionType());
        std.debug.print("section: {s} ({s})\n", .{ sec_name, sec_type });

        var opt_it = sec.options();
        while (opt_it.next()) |opt| {
            const opt_name = uci.cStr(opt.name());
            if (opt.isString()) {
                std.debug.print("  {s} = {s}\n", .{ opt_name, uci.cStr(opt.getString()) });
            } else if (opt.isList()) {
                std.debug.print("  {s} = [", .{opt_name});
                var val_it = opt.values();
                var first = true;
                while (val_it.next()) |val| {
                    if (!first) std.debug.print(", ", .{});
                    first = false;
                    std.debug.print("{s}", .{uci.cStr(val)});
                }
                std.debug.print("]\n", .{});
            } else {
                std.debug.print("  {s} = <unknown>\n", .{opt_name});
            }
        }
    }
}
