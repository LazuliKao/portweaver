const std = @import("std");
const builtin = @import("builtin");

/// Returns PID file path (platform-specific)
/// Windows: current working directory
/// Linux/Unix: prefer XDG_RUNTIME_DIR, fallback to /tmp
pub fn getPidFilePath(buf: *[std.fs.max_path_bytes]u8) []const u8 {
    if (builtin.os.tag == .windows) {
        return "portweaver.pid";
    }

    if (std.posix.getenv("XDG_RUNTIME_DIR")) |runtime_dir| {
        return std.fmt.bufPrint(buf, "{s}/portweaver.pid", .{std.mem.sliceTo(runtime_dir, 0)}) catch "/tmp/portweaver.pid";
    }

    return "/tmp/portweaver.pid";
}

/// Ensures single instance by checking and managing PID file
/// Automatically kills old process if found
pub fn ensureSingleInstance(allocator: std.mem.Allocator) !void {
    // Try to read existing PID file
    if (readPidFile(allocator)) |old_pid| {
        defer allocator.free(old_pid);

        // Check if process is still running
        if (isProcessRunning(old_pid)) {
            std.log.warn("Found existing PortWeaver process (PID: {s}), attempting to terminate...", .{old_pid});

            // Try to kill the old process
            killProcess(old_pid) catch |err| {
                std.log.err("Failed to kill old process: {any}", .{err});
                return error.OldProcessStillRunning;
            };

            std.log.info("Old process terminated successfully", .{});

            // Wait a moment for the process to fully terminate
            std.Thread.sleep(500 * std.time.ns_per_ms);
        } else {
            std.log.info("Stale PID file found (process not running), removing...", .{});
        }
    } else |err| {
        if (err != error.FileNotFound) {
            std.log.warn("Failed to read PID file: {any}", .{err});
        }
    }

    // Write our own PID to the file
    try writePidFile(allocator);
}

/// Removes PID file on clean exit
pub fn cleanup() void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pid_file_path = getPidFilePath(&path_buf);

    std.fs.cwd().deleteFile(pid_file_path) catch |err| {
        std.log.warn("Failed to remove PID file: {any}", .{err});
    };
}

/// Reads PID from file
fn readPidFile(allocator: std.mem.Allocator) ![]const u8 {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pid_file_path = getPidFilePath(&path_buf);

    const file = try std.fs.cwd().openFile(pid_file_path, .{});
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 1024);
    defer allocator.free(content);

    const trimmed = std.mem.trim(u8, content, &std.ascii.whitespace);
    return try allocator.dupe(u8, trimmed);
}

/// Writes current process PID to file
fn writePidFile(allocator: std.mem.Allocator) !void {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pid_file_path = getPidFilePath(&path_buf);

    const file = try std.fs.cwd().createFile(pid_file_path, .{ .truncate = true });
    defer file.close();

    const pid = std.c.getpid();

    const pid_str = try std.fmt.allocPrint(allocator, "{}\n", .{pid});
    defer allocator.free(pid_str);

    try file.writeAll(pid_str);
}

/// Checks if a process with given PID is running
fn isProcessRunning(pid_str: []const u8) bool {
    if (builtin.os.tag == .windows) {
        return isProcessRunningWindows(pid_str);
    } else {
        return isProcessRunningUnix(pid_str);
    }
}

/// Unix/Linux implementation: check /proc/<pid>
fn isProcessRunningUnix(pid_str: []const u8) bool {
    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/proc/{s}", .{pid_str}) catch return false;

    std.fs.accessAbsolute(path, .{}) catch return false;
    return true;
}

/// Windows implementation: use tasklist command
fn isProcessRunningWindows(pid_str: []const u8) bool {
    var buf: [256]u8 = undefined;
    const cmd = std.fmt.bufPrint(&buf, "tasklist /FI \"PID eq {s}\" 2>nul | findstr {s} >nul", .{ pid_str, pid_str }) catch return false;

    const result = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &[_][]const u8{ "cmd", "/C", cmd },
    }) catch return false;
    defer {
        std.heap.page_allocator.free(result.stdout);
        std.heap.page_allocator.free(result.stderr);
    }

    return switch (result.term) {
        .Exited => |code| code == 0,
        else => false,
    };
}

/// Kills process by PID
fn killProcess(pid_str: []const u8) !void {
    if (builtin.os.tag == .windows) {
        try killProcessWindows(pid_str);
    } else {
        try killProcessUnix(pid_str);
    }
}

/// Unix/Linux implementation: send SIGTERM
fn killProcessUnix(pid_str: []const u8) !void {
    const pid = try std.fmt.parseInt(i32, pid_str, 10);

    // Send SIGTERM first (graceful)
    const term_result = std.c.kill(pid, std.posix.SIG.TERM);
    if (term_result != 0) {
        std.log.warn("SIGTERM failed, trying SIGKILL...", .{});

        // If SIGTERM fails, try SIGKILL (force)
        const kill_result = std.c.kill(pid, std.posix.SIG.KILL);
        if (kill_result != 0) {
            return error.KillFailed;
        }
    }
}

/// Windows implementation: use taskkill command
fn killProcessWindows(pid_str: []const u8) !void {
    // Try graceful termination first
    const result = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &[_][]const u8{ "taskkill", "/PID", pid_str },
    }) catch |err| {
        std.log.warn("taskkill failed: {any}, trying /F flag...", .{err});

        // Force kill if graceful fails
        const force_result = try std.process.Child.run(.{
            .allocator = std.heap.page_allocator,
            .argv = &[_][]const u8{ "taskkill", "/F", "/PID", pid_str },
        });
        defer {
            std.heap.page_allocator.free(force_result.stdout);
            std.heap.page_allocator.free(force_result.stderr);
        }

        const success = switch (force_result.term) {
            .Exited => |code| code == 0,
            else => false,
        };
        if (!success) {
            return error.KillFailed;
        }
        return;
    };
    defer {
        std.heap.page_allocator.free(result.stdout);
        std.heap.page_allocator.free(result.stderr);
    }

    const success = switch (result.term) {
        .Exited => |code| code == 0,
        else => false,
    };
    if (!success) {
        return error.KillFailed;
    }
}
