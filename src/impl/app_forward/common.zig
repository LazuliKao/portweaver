const std = @import("std");
const types = @import("../../config/types.zig");

pub const ForwardError = error{
    ListenFailed,
    ConnectFailed,
    AcceptFailed,
    TransferFailed,
    InvalidAddress,
};

pub const THREAD_STACK_SIZE = 4 * 1024;

pub inline fn getThreadConfig() std.Thread.SpawnConfig {
    return .{ .stack_size = THREAD_STACK_SIZE };
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

        return .{ .start = start_port, .end = end_port };
    }

    const port = try types.parsePort(trimmed);
    return .{ .start = port, .end = port };
}

pub fn portToString(port: u16, allocator: std.mem.Allocator) ![]u8 {
    return try std.fmt.allocPrint(allocator, "{}", .{port});
}
