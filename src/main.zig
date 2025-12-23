const std = @import("std");
const libuci = @import("libuci.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    try libuci.initLibUci();
    // try libuci.test1();
    try libuci.printFirewallConfig(allocator);
}
