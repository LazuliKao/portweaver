const std = @import("std");
const uci = @import("uci/mod.zig");

pub fn main() !void {
    // var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    // defer arena.deinit();
    // const allocator = arena.allocator();

    try printFirewallConfig();
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
