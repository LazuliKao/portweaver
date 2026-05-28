const std = @import("std");
const types = @import("../../config/types.zig");

pub const ForwardError = error{
    ListenFailed,
    ConnectFailed,
    AcceptFailed,
    TransferFailed,
    InvalidAddress,
};

pub inline fn getThreadConfig() std.Thread.SpawnConfig {
    return .{};
}

pub const AddressFamily = types.AddressFamily;
pub const Project = types.Project;
pub const PortMapping = types.PortMapping;

pub const PortRange = struct { start: u16, end: u16 };

pub fn parsePortRange(port_str: []const u8) !PortRange {
    const trimmed = std.mem.trim(u8, port_str, " \t\r\n");

    if (std.mem.indexOf(u8, trimmed, "-")) |dash_pos| {
        const start_str = trimmed[0..dash_pos];
        const end_str = trimmed[dash_pos + 1 ..];

        const start_port = try types.parsePort(start_str);
        const end_port = try types.parsePort(end_str);

        if (start_port >= end_port) return types.ConfigError.InvalidValue;

        return .{ .start = start_port, .end = end_port };
    }

    const port = try types.parsePort(trimmed);
    return .{ .start = port, .end = port };
}

pub fn portToString(port: u16, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "{}", .{port}) catch unreachable;
}

test "app forward common: parsePortRange handles single and ranged ports" {
    const single = try parsePortRange(" 8080 ");
    try std.testing.expectEqual(@as(u16, 8080), single.start);
    try std.testing.expectEqual(@as(u16, 8080), single.end);

    const ranged = try parsePortRange(" 1000-1005 ");
    try std.testing.expectEqual(@as(u16, 1000), ranged.start);
    try std.testing.expectEqual(@as(u16, 1005), ranged.end);
}

test "app forward common: parsePortRange rejects invalid ranges" {
    try std.testing.expectError(types.ConfigError.InvalidValue, parsePortRange("1005-1000"));
    try std.testing.expectError(types.ConfigError.InvalidValue, parsePortRange("8080-8080"));
    try std.testing.expectError(types.ConfigError.InvalidValue, parsePortRange("0-10"));
}

test "app forward common: portToString formats port" {
    var buf: [5]u8 = undefined;
    const port = portToString(65535, &buf);

    try std.testing.expectEqualStrings("65535", port);
}
