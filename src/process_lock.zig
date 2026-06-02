const std = @import("std");
const builtin = @import("builtin");
const compat = @import("compat.zig");
const windows = std.os.windows;

const takeover_delay_ns = 5 * std.time.ns_per_s;
const lock_retry_interval_ns = 100 * std.time.ns_per_ms;
const lock_retry_attempts = 150;
const windows_wait_object_0: windows.DWORD = 0x00000000;
const windows_wait_abandoned: windows.DWORD = 0x00000080;
const windows_wait_timeout: windows.DWORD = 0x00000102;
const windows_wait_failed: windows.DWORD = 0xffffffff;
const windows_infinite: windows.DWORD = 0xffffffff;
const windows_mutex_name = std.unicode.utf8ToUtf16LeStringLiteral("Local\\PortWeaver.InstanceMutex");
const windows_takeover_event_name = std.unicode.utf8ToUtf16LeStringLiteral("Local\\PortWeaver.TakeoverEvent");

var lock_file: ?std.Io.File = null;
var windows_mutex: ?windows.HANDLE = null;
var windows_takeover_event: ?windows.HANDLE = null;

const WindowsMutexCreateResult = struct {
    handle: windows.HANDLE,
    already_exists: bool,
};

extern "kernel32" fn CreateMutexW(
    lpMutexAttributes: ?*const anyopaque,
    bInitialOwner: windows.BOOL,
    lpName: ?[*:0]const u16,
) callconv(.winapi) ?windows.HANDLE;

extern "kernel32" fn ReleaseMutex(hMutex: windows.HANDLE) callconv(.winapi) windows.BOOL;

extern "kernel32" fn CreateEventW(
    lpEventAttributes: ?*const anyopaque,
    bManualReset: windows.BOOL,
    bInitialState: windows.BOOL,
    lpName: ?[*:0]const u16,
) callconv(.winapi) ?windows.HANDLE;

extern "kernel32" fn SetEvent(hEvent: windows.HANDLE) callconv(.winapi) windows.BOOL;

extern "kernel32" fn WaitForSingleObject(
    hHandle: windows.HANDLE,
    dwMilliseconds: windows.DWORD,
) callconv(.winapi) windows.DWORD;

/// Returns the PID file path used by file-lock based platforms.
/// Windows keeps this path for compatibility, but instance ownership is coordinated
/// with named kernel objects instead of a PID file lock.
pub fn getPidFilePath(buf: *[std.fs.max_path_bytes]u8) []const u8 {
    if (builtin.os.tag == .windows) {
        if (compat.getenv("LOCALAPPDATA")) |local_app_data| {
            return std.fmt.bufPrint(buf, "{s}\\portweaver.pid", .{local_app_data}) catch "portweaver.pid";
        }
        return "portweaver.pid";
    }

    if (compat.getenv("XDG_RUNTIME_DIR")) |runtime_dir| {
        return std.fmt.bufPrint(buf, "{s}/portweaver.pid", .{runtime_dir}) catch "/tmp/portweaver.pid";
    }

    return "/tmp/portweaver.pid";
}

/// Ensures only one PortWeaver instance owns the runtime lock.
/// Windows uses a named mutex plus a named takeover event so the running instance
/// can exit cleanly. Other platforms keep the existing file-lock behavior.
pub fn ensureSingleInstance(allocator: std.mem.Allocator) !void {
    if (builtin.os.tag == .windows) {
        return ensureSingleInstanceWindows();
    }

    if (lock_file != null) return;

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pid_file_path = getPidFilePath(&path_buf);

    lock_file = try acquireOrTakeOverLock(allocator, pid_file_path);
    errdefer {
        if (lock_file) |file| {
            file.close(compat.io());
            lock_file = null;
        }
    }

    try writeCurrentPid(allocator, lock_file.?);
}

/// Reports whether the running instance should exit to hand control to a new one.
/// Non-Windows platforms never receive this signal and always return false.
pub fn shouldExitForTakeover() bool {
    if (builtin.os.tag != .windows) return false;

    const takeover_event = windows_takeover_event orelse return false;
    const wait_result = WaitForSingleObject(takeover_event, 0);
    return switch (wait_result) {
        windows_wait_object_0 => true,
        windows_wait_timeout => false,
        windows_wait_failed => blk: {
            std.log.warn("Failed to poll takeover event: {any}", .{windows.GetLastError()});
            break :blk false;
        },
        else => blk: {
            std.log.warn("Unexpected takeover wait result: {d}", .{wait_result});
            break :blk false;
        },
    };
}

/// Blocks until the process should shut down.
/// On Windows, waits on the takeover event (kernel-level, no polling).
/// On non-Windows, waits on a condition variable (signal-ready).
pub fn waitForShutdown() void {
    if (builtin.os.tag == .windows) {
        const takeover_event = windows_takeover_event orelse {
            // No takeover event — sleep until killed externally
            while (true) {
                compat.sleepNanos(std.time.ns_per_s);
            }
        };
        const wait_result = WaitForSingleObject(takeover_event, windows_infinite);
        switch (wait_result) {
            windows_wait_object_0, windows_wait_abandoned => {},
            windows_wait_failed => {
                std.log.warn("waitForShutdown: WaitForSingleObject failed: {any}", .{windows.GetLastError()});
            },
            else => {
                std.log.warn("waitForShutdown: unexpected result: {d}", .{wait_result});
            },
        }
    } else {
        // Non-Windows: block until killed externally (SIGINT/SIGTERM)
        shutdown_mutex.lockUncancelable(compat.io());
        defer shutdown_mutex.unlock(compat.io());
        while (!shutdown_requested) {
            shutdown_cond.waitUncancelable(compat.io(), &shutdown_mutex);
        }
    }
}

/// Signals the process to shut down. Safe to call from any thread.
pub fn requestShutdown() void {
    shutdown_requested = true;
    shutdown_mutex.lockUncancelable(compat.io());
    shutdown_cond.broadcast(compat.io());
    shutdown_mutex.unlock(compat.io());
}

var shutdown_mutex: std.Io.Mutex = .init;
var shutdown_cond: std.Io.Condition = .init;
var shutdown_requested: bool = false;

/// Releases the active platform lock and removes the PID file on clean exit.
pub fn cleanup() void {
    if (builtin.os.tag == .windows) {
        cleanupWindowsLock();
        return;
    }

    if (lock_file) |file| {
        file.close(compat.io());
        lock_file = null;
    }

    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pid_file_path = getPidFilePath(&path_buf);

    std.Io.Dir.cwd().deleteFile(compat.io(), pid_file_path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => std.log.warn("Failed to remove PID file: {any}", .{err}),
    };
}

fn ensureSingleInstanceWindows() !void {
    if (windows_mutex != null) return;

    const takeover_event = try createOrOpenWindowsTakeoverEvent();
    errdefer windows.CloseHandle(takeover_event);

    const mutex_result = try createOrOpenWindowsMutex();
    errdefer {
        if (mutex_result.already_exists) {
            windows.CloseHandle(mutex_result.handle);
        } else {
            releaseWindowsMutex(mutex_result.handle);
            windows.CloseHandle(mutex_result.handle);
        }
    }

    if (mutex_result.already_exists) {
        std.log.warn("Another PortWeaver instance is already running. Taking over in 5 seconds...", .{});
        compat.sleepNanos(takeover_delay_ns);

        std.log.warn("Requesting running PortWeaver instance to exit cleanly...", .{});
        try signalWindowsTakeoverEvent(takeover_event);

        std.log.info("Waiting for previous PortWeaver instance to release ownership...", .{});
        try waitForWindowsMutexOwnership(mutex_result.handle);
    }

    clearWindowsTakeoverSignal(takeover_event);
    windows_takeover_event = takeover_event;
    windows_mutex = mutex_result.handle;
}

fn cleanupWindowsLock() void {
    if (windows_mutex) |mutex| {
        releaseWindowsMutex(mutex);
        windows.CloseHandle(mutex);
        windows_mutex = null;
    }

    if (windows_takeover_event) |takeover_event| {
        windows.CloseHandle(takeover_event);
        windows_takeover_event = null;
    }
}

fn createOrOpenWindowsMutex() !WindowsMutexCreateResult {
    const mutex = CreateMutexW(null, windows.BOOL.TRUE, windows_mutex_name) orelse {
        std.log.err("CreateMutexW failed: {any}", .{windows.GetLastError()});
        return error.CreateMutexFailed;
    };

    return .{
        .handle = mutex,
        .already_exists = windows.GetLastError() == .ALREADY_EXISTS,
    };
}

fn createOrOpenWindowsTakeoverEvent() !windows.HANDLE {
    const takeover_event = CreateEventW(null, windows.BOOL.FALSE, windows.BOOL.FALSE, windows_takeover_event_name) orelse {
        std.log.err("CreateEventW failed: {any}", .{windows.GetLastError()});
        return error.CreateEventFailed;
    };

    return takeover_event;
}

fn signalWindowsTakeoverEvent(takeover_event: windows.HANDLE) !void {
    const false_bool: windows.BOOL = @enumFromInt(0);
    if (SetEvent(takeover_event) == false_bool) {
        std.log.err("SetEvent failed: {any}", .{windows.GetLastError()});
        return error.SignalTakeoverFailed;
    }
}

fn waitForWindowsMutexOwnership(mutex: windows.HANDLE) !void {
    const wait_result = WaitForSingleObject(mutex, windows_infinite);
    switch (wait_result) {
        windows_wait_object_0 => {},
        windows_wait_abandoned => {
            std.log.warn("Previous PortWeaver instance abandoned the mutex; continuing takeover.", .{});
        },
        windows_wait_failed => {
            std.log.err("WaitForSingleObject for mutex failed: {any}", .{windows.GetLastError()});
            return error.WaitForMutexFailed;
        },
        else => {
            std.log.err("Unexpected mutex wait result: {d}", .{wait_result});
            return error.WaitForMutexFailed;
        },
    }
}

fn clearWindowsTakeoverSignal(takeover_event: windows.HANDLE) void {
    const wait_result = WaitForSingleObject(takeover_event, 0);
    switch (wait_result) {
        windows_wait_object_0, windows_wait_timeout => {},
        windows_wait_failed => {
            std.log.warn("Failed to clear takeover event state: {any}", .{windows.GetLastError()});
        },
        else => {
            std.log.warn("Unexpected takeover event clear result: {d}", .{wait_result});
        },
    }
}

fn releaseWindowsMutex(mutex: windows.HANDLE) void {
    if (ReleaseMutex(mutex) == windows.BOOL.FALSE) {
        std.log.warn("ReleaseMutex failed during cleanup: {any}", .{windows.GetLastError()});
    }
}

fn acquireOrTakeOverLock(allocator: std.mem.Allocator, pid_file_path: []const u8) !std.Io.File {
    return acquireLockFile(pid_file_path) catch |err| switch (err) {
        error.WouldBlock => try takeOverExistingInstance(allocator, pid_file_path),
        else => err,
    };
}

fn takeOverExistingInstance(allocator: std.mem.Allocator, pid_file_path: []const u8) !std.Io.File {
    const existing_pid = readPidFile(allocator) catch |err| switch (err) {
        error.FileNotFound => null,
        else => blk: {
            std.log.warn("PortWeaver lock is held, but PID could not be read: {any}", .{err});
            break :blk null;
        },
    };
    defer if (existing_pid) |pid| allocator.free(pid);

    if (existing_pid) |pid| {
        std.log.warn(
            "Another PortWeaver instance is already running (PID: {s}). Taking over in 5 seconds...",
            .{pid},
        );
    } else {
        std.log.warn("Another PortWeaver instance is already running. Taking over in 5 seconds...", .{});
    }

    compat.sleepNanos(takeover_delay_ns);

    if (existing_pid) |pid| {
        std.log.warn("Stopping previous PortWeaver instance (PID: {s})...", .{pid});
        killProcess(allocator, pid) catch |err| {
            std.log.warn("Failed to stop previous instance cleanly: {any}", .{err});
        };
    }

    return waitForLockRelease(pid_file_path);
}

fn waitForLockRelease(pid_file_path: []const u8) !std.Io.File {
    var attempt: usize = 0;
    while (attempt < lock_retry_attempts) : (attempt += 1) {
        const file = acquireLockFile(pid_file_path) catch |err| switch (err) {
            error.WouldBlock => {
                compat.sleepNanos(lock_retry_interval_ns);
                continue;
            },
            else => return err,
        };

        return file;
    }

    return error.OldProcessStillRunning;
}

fn acquireLockFile(pid_file_path: []const u8) !std.Io.File {
    return std.Io.Dir.cwd().createFile(compat.io(), pid_file_path, .{
        .read = true,
        .truncate = false,
        .lock = .exclusive,
        .lock_nonblocking = true,
    }) catch |err| switch (err) {
        error.PathAlreadyExists => return std.Io.Dir.cwd().openFile(compat.io(), pid_file_path, .{
            .mode = .read_write,
            .lock = .exclusive,
            .lock_nonblocking = true,
        }),
        else => return err,
    };
}

/// Reads PID from file.
fn readPidFile(allocator: std.mem.Allocator) ![]const u8 {
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const pid_file_path = getPidFilePath(&path_buf);

    const file = try std.Io.Dir.cwd().openFile(compat.io(), pid_file_path, .{});
    defer file.close(compat.io());

    var buf: [1024]u8 = undefined;
    var reader = file.reader(compat.io(), &buf);
    const content = try reader.interface.allocRemaining(allocator, .limited(1024));
    defer allocator.free(content);

    const trimmed = std.mem.trim(u8, content, &std.ascii.whitespace);
    return try allocator.dupe(u8, trimmed);
}

fn writeCurrentPid(allocator: std.mem.Allocator, file: std.Io.File) !void {
    const pid = std.c.getpid();
    const pid_str = try std.fmt.allocPrint(allocator, "{}\n", .{pid});
    defer allocator.free(pid_str);

    try file.setLength(compat.io(), 0);
    try file.writeStreamingAll(compat.io(), pid_str);
    try file.sync(compat.io());
}

/// Kills process by PID.
fn killProcess(allocator: std.mem.Allocator, pid_str: []const u8) !void {
    if (builtin.os.tag == .windows) {
        try killProcessWindows(allocator, pid_str);
    } else {
        try killProcessUnix(pid_str);
    }
}

/// Unix/Linux implementation: send SIGTERM, then SIGKILL if necessary.
fn killProcessUnix(pid_str: []const u8) !void {
    const pid = try std.fmt.parseInt(i32, pid_str, 10);

    const term_result = std.c.kill(pid, std.posix.SIG.TERM);
    if (term_result != 0) {
        std.log.warn("SIGTERM failed, trying SIGKILL...", .{});

        const kill_result = std.c.kill(pid, std.posix.SIG.KILL);
        if (kill_result != 0) {
            return error.KillFailed;
        }
    }
}

/// Windows implementation: use taskkill, then force with /F if needed.
fn killProcessWindows(allocator: std.mem.Allocator, pid_str: []const u8) !void {
    if (runProcess(allocator, &[_][]const u8{ "taskkill", "/PID", pid_str })) {
        return;
    } else |_| {
        std.log.warn("taskkill /PID failed, trying force mode...", .{});
    }

    if (runProcess(allocator, &[_][]const u8{ "taskkill", "/F", "/PID", pid_str })) {
        return;
    } else |err| {
        std.log.warn("taskkill /F /PID failed: {any}", .{err});
        return error.KillFailed;
    }
}

fn runProcess(allocator: std.mem.Allocator, argv: []const []const u8) !void {
    const result = try std.process.run(allocator, compat.io(), .{ .argv = argv });
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    if (result.term != .exited or result.term.exited != 0) {
        return error.ProcessCommandFailed;
    }
}
