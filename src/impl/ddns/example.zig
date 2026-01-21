const std = @import("std");
const ddns = @import("libddns.zig");

fn myLogCallback(instance_id: i32, level: ddns.LogLevel, message: []const u8) void {
    const level_str = switch (level) {
        .debug => "DEBUG",
        .info => "INFO",
        .warn => "WARN",
        .err => "ERROR",
    };
    std.debug.print("[Instance {d}] [{s}] {s}\n", .{ instance_id, level_str, message });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    ddns.setLogCallback(myLogCallback);

    var instance = try ddns.DdnsInstance.init(allocator, .cloudflare);
    defer instance.deinit();

    try instance.setCredentials("your-email@example.com", "your-api-token");

    try instance.addDomain(.{
        .domain_name = "example.com",
        .sub_domain = "www",
        .ipv4_enabled = true,
        .ipv6_enabled = false,
    });

    try instance.updateOnce();

    try instance.startAutoUpdate(300);

    std.time.sleep(10 * std.time.ns_per_s);

    try instance.stopAutoUpdate();

    ddns.cleanup();
}
