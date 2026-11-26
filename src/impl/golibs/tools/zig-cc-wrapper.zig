const std = @import("std");

fn appendFiltered(allocator: std.mem.Allocator, output: *std.ArrayList([]const u8), input: []const [:0]const u8) !void {
    for (input) |arg| {
        if (!std.mem.eql(u8, arg, "-mthreads")) try output.append(allocator, arg);
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    const zig = init.environ_map.get("PORTWEAVER_ZIG") orelse {
        std.debug.print("zig-cc-wrapper: missing Zig executable\n", .{});
        std.process.exit(2);
    };
    const name = std.fs.path.basename(args[0]);
    const is_ar = std.ascii.eqlIgnoreCase(name, "ar") or std.ascii.eqlIgnoreCase(name, "ar.exe");
    var child_args: std.ArrayList([]const u8) = .empty;
    try child_args.append(allocator, zig);
    if (is_ar) {
        try child_args.append(allocator, "ar");
        try child_args.appendSlice(allocator, args[1..]);
    } else {
        if (args.len < 2 or (!std.mem.eql(u8, args[1], "cc") and !std.mem.eql(u8, args[1], "c++"))) {
            std.debug.print("usage: zig-cc-wrapper <cc|c++> [arguments...]\n", .{});
            std.process.exit(2);
        }
        const target = init.environ_map.get("PORTWEAVER_ZIG_TARGET") orelse {
            std.debug.print("zig-cc-wrapper: missing target\n", .{});
            std.process.exit(2);
        };
        try child_args.appendSlice(allocator, &.{ args[1], "-target", target });
        try appendFiltered(allocator, &child_args, args[2..]);
    }
    var child = std.process.spawn(init.io, .{ .argv = child_args.items }) catch |err| {
        std.debug.print("zig-cc-wrapper: failed to start Zig: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    const term = try child.wait(init.io);
    switch (term) {
        .exited => |code| std.process.exit(@intCast(@min(code, 255))),
        else => std.process.exit(1),
    }
}

test "filter only mthreads and preserve argument boundaries" {
    const input = [_][:0]const u8{ "-mthreads", "-m64", "-ffile-prefix-map=C:/Program Files/Go=.", "-Wl", "option", "path with spaces.c", "-mthreads" };
    const expected = [_][]const u8{ "-m64", "-ffile-prefix-map=C:/Program Files/Go=.", "-Wl", "option", "path with spaces.c" };
    var result: std.ArrayList([]const u8) = .empty;
    defer result.deinit(std.testing.allocator);
    try appendFiltered(std.testing.allocator, &result, &input);
    try std.testing.expectEqual(expected.len, result.items.len);
    for (expected, result.items) |want, got| try std.testing.expectEqualStrings(want, got);
}
