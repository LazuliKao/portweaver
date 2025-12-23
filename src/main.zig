const std = @import("std");
const uci = @import("uci.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // 不再需要手动调用 initLibUci，函数会在首次使用时自动延迟加载
    try printFirewallConfig(allocator);
}

/// Print all firewall configuration settings
pub fn printFirewallConfig(allocator: std.mem.Allocator) !void {
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
        try listConfigSections(allocator, package);
    } else {
        std.debug.print("Firewall package is null\n", .{});
    }
}

/// Get all sections and options from a UCI package
pub fn listConfigSections(_: std.mem.Allocator, package: uci.UciPackage) !void {
    // 简化实现：由于我们现在使用 opaque 类型，
    // 实际的遍历需要通过 C 函数接口
    std.debug.print("Package loaded successfully!\n", .{});
    // print [*c]*c.uci_context

    _ = package;
}
