const std = @import("std");
const process_lock = @import("process_lock.zig");
const compat = @import("compat.zig");

test "single instance enforcement" {
    const allocator = std.testing.allocator;
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pid_file_path = process_lock.getPidFilePath(&path_buf);

    // First instance should succeed
    try process_lock.ensureSingleInstance(allocator);
    defer process_lock.cleanup();

    if (@import("builtin").os.tag == .windows) {
        try std.testing.expect(!process_lock.shouldExitForTakeover());
    } else {
        // Verify PID file exists on file-lock based platforms.
        const file = try std.Io.Dir.cwd().openFile(compat.io(), pid_file_path, .{});
        file.close(compat.io());
    }
}

test "cleanup removes PID file" {
    const allocator = std.testing.allocator;
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pid_file_path = process_lock.getPidFilePath(&path_buf);

    // Create PID file
    try process_lock.ensureSingleInstance(allocator);

    // Cleanup
    process_lock.cleanup();

    if (@import("builtin").os.tag == .windows) {
        try std.testing.expect(!process_lock.shouldExitForTakeover());
        return;
    }

    // Verify PID file is removed on file-lock based platforms.
    const result = std.Io.Dir.cwd().openFile(compat.io(), pid_file_path, .{});

    try std.testing.expectError(error.FileNotFound, result);
}
