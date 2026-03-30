const std = @import("std");
const process_lock = @import("process_lock.zig");

test "single instance enforcement" {
    const allocator = std.testing.allocator;

    // First instance should succeed
    try process_lock.ensureSingleInstance(allocator);
    defer process_lock.cleanup();

    // Verify PID file exists
    const file = try std.fs.cwd().openFile(
        if (@import("builtin").os.tag == .windows) "portweaver.pid" else "/var/run/portweaver.pid",
        .{},
    );
    file.close();
}

test "cleanup removes PID file" {
    const allocator = std.testing.allocator;

    // Create PID file
    try process_lock.ensureSingleInstance(allocator);

    // Cleanup
    process_lock.cleanup();

    // Verify PID file is removed
    const result = std.fs.cwd().openFile(
        if (@import("builtin").os.tag == .windows) "portweaver.pid" else "/var/run/portweaver.pid",
        .{},
    );

    try std.testing.expectError(error.FileNotFound, result);
}
