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

    // Verify PID file exists
    const file = try std.Io.Dir.cwd().openFile(compat.io(), pid_file_path, .{});
    file.close(compat.io());
}

test "cleanup removes PID file" {
    const allocator = std.testing.allocator;
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pid_file_path = process_lock.getPidFilePath(&path_buf);

    // Create PID file
    try process_lock.ensureSingleInstance(allocator);

    // Cleanup
    process_lock.cleanup();

    // Verify PID file is removed
    const result = std.Io.Dir.cwd().openFile(compat.io(), pid_file_path, .{});

    try std.testing.expectError(error.FileNotFound, result);
}
