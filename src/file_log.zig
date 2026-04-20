const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const time = std.time;
const Thread = std.Thread;
const compat = @import("compat.zig");

pub const LogConfig = struct {
    enabled: bool = true,
    file_path: []const u8 = "/tmp/portweaver.log",
    max_size: usize = 1024 * 1024,
    max_files: usize = 3,
    flush_interval_ms: u64 = 100,

    pub fn deinit(self: *LogConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.file_path);
        self.* = undefined;
    }
};

pub fn defaultLogConfig(allocator: std.mem.Allocator) !LogConfig {
    return .{
        .enabled = true,
        .file_path = try allocator.dupe(u8, "/tmp/portweaver.log"),
        .max_size = 1024 * 1024,
        .max_files = 3,
        .flush_interval_ms = 100,
    };
}

pub const FileLogger = struct {
    allocator: std.mem.Allocator,
    config: LogConfig,
    file: ?std.Io.File,
    file_path: []const u8,
    current_size: usize,
    lock: std.Io.Mutex,
    stop_thread: bool,
    thread: ?Thread,
    write_count: usize,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: LogConfig) !*Self {
        const self = try allocator.create(Self);
        errdefer allocator.destroy(self);

        const file_path = try allocator.dupe(u8, config.file_path);
        errdefer allocator.free(file_path);

        self.* = .{
            .allocator = allocator,
            .config = config,
            .file = null,
            .file_path = file_path,
            .current_size = 0,
            .lock = .init,
            .stop_thread = false,
            .thread = null,
            .write_count = 0,
        };

        if (config.enabled) {
            self.openFile() catch |err| {
                std.log.warn("Failed to open log file: {any}", .{err});
            };
        }

        if (config.enabled) {
            self.thread = Thread.spawn(.{}, flushThread, .{self}) catch |err| blk: {
                std.log.warn("Failed to spawn flush thread: {any}", .{err});
                break :blk null;
            };
        }

        return self;
    }

    pub fn deinit(self: *Self) void {
        self.lock.lockUncancelable(compat.io());
        self.stop_thread = true;
        self.lock.unlock(compat.io());

        if (self.thread) |t| {
            t.join();
        }

        if (self.file) |f| {
            f.close(compat.io());
            self.file = null;
        }

        self.allocator.free(self.file_path);
        self.allocator.destroy(self);
    }

    fn openFile(self: *Self) !void {
        const file = std.Io.Dir.cwd().createFile(
            compat.io(),
            self.file_path,
            .{
                .truncate = false,
                .read = true,
            },
        ) catch |err| blk: {
            if (err == error.FileNotFound) {
                var dir_path: [std.fs.max_path_bytes]u8 = undefined;
                const path_len = mem.lastIndexOf(u8, self.file_path, "/") orelse 0;
                if (path_len > 0) {
                    const dir = self.file_path[0..path_len];
                    @memcpy(dir_path[0..dir.len], dir);
                    try std.Io.Dir.cwd().createDirPath(compat.io(), dir);
                }
                _ = try std.Io.Dir.cwd().createFile(compat.io(), self.file_path, .{});
                break :blk try std.Io.Dir.cwd().openFile(compat.io(), self.file_path, .{ .mode = .write_only });
            } else {
                return err;
            }
        };
        self.file = file;

        const stat = self.file.?.stat(compat.io()) catch {
            self.current_size = 0;
            return;
        };
        self.current_size = std.math.cast(usize, stat.size) orelse std.math.maxInt(usize);

        var writer = self.file.?.writer(compat.io(), &.{});
        try writer.seekTo(stat.size);
    }

    fn rotate(self: *Self) void {
        if (self.file) |f| {
            f.close(compat.io());
            self.file = null;
        }

        var i: usize = self.config.max_files;
        while (i > 0) : (i -= 1) {
            const old_path = std.fmt.allocPrint(self.allocator, "{s}.{d}", .{ self.file_path, i }) catch continue;
            defer self.allocator.free(old_path);

            const new_path = std.fmt.allocPrint(self.allocator, "{s}.{d}", .{ self.file_path, i + 1 }) catch continue;
            defer self.allocator.free(new_path);

            std.Io.Dir.rename(std.Io.Dir.cwd(), old_path, std.Io.Dir.cwd(), new_path, compat.io()) catch {};
        }

        const rotated_path = std.fmt.allocPrint(self.allocator, "{s}.1", .{self.file_path}) catch return;
        defer self.allocator.free(rotated_path);

        std.Io.Dir.rename(std.Io.Dir.cwd(), self.file_path, std.Io.Dir.cwd(), rotated_path, compat.io()) catch {};

        const excess_path = std.fmt.allocPrint(self.allocator, "{s}.{d}", .{ self.file_path, self.config.max_files + 1 }) catch return;
        defer self.allocator.free(excess_path);
        std.Io.Dir.cwd().deleteFile(compat.io(), excess_path) catch {};

        self.openFile() catch |err| {
            std.log.warn("Failed to reopen log file after rotation: {any}", .{err});
        };
        self.current_size = 0;
    }

    pub fn log(self: *Self, level: std.log.Level, comptime scope: @EnumLiteral(), comptime format: []const u8, args: anytype) void {
        if (!self.config.enabled) return;

        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());

        if (self.file == null) return;

        var buf: [4096]u8 = undefined;
        var fba = std.heap.FixedBufferAllocator.init(&buf);
        const allocator = fba.allocator();

        const timestamp = std.Io.Timestamp.now(compat.io(), .real).toSeconds();
        const epoch_days = @divFloor(timestamp, 86400);
        const secs_of_day = @mod(timestamp, 86400);
        const hours = @divFloor(secs_of_day, 3600);
        const mins = @divFloor(@rem(secs_of_day, 3600), 60);
        const secs = @rem(secs_of_day, 60);

        const days_since_epoch: i64 = epoch_days;
        const year_cycle = @divFloor(days_since_epoch, 146097);
        const remaining_days = @rem(days_since_epoch, 146097);
        const year_cycle_start = year_cycle * 400;
        const century = @divFloor(remaining_days * 4 + 3, 146097);
        const year_start = year_cycle_start + century * 100;
        const century_day = remaining_days - (century * 100 * 365 + @divTrunc(century, 4));
        const year_4cycle = @divFloor(century_day * 4 + 3, 1461);
        const year = year_start + year_4cycle;
        const year_day = century_day - year_4cycle * 365 - @divTrunc(year_4cycle, 4);
        const month_adj = @divFloor(year_day * 12 + 6, 367);
        const month = month_adj + 1;
        const day = year_day - @divFloor(month_adj * 367, 12) + 1;

        const level_str = switch (level) {
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .err => "ERROR",
        };

        const scope_str = switch (scope) {
            .default => "",
            else => @tagName(scope),
        };

        const message = if (scope_str.len > 0)
            std.fmt.allocPrint(allocator, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} [{s}] [{s}] " ++ format ++ "\n", .{ year, month, day, hours, mins, secs, level_str, scope_str } ++ args) catch return
        else
            std.fmt.allocPrint(allocator, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} [{s}] " ++ format ++ "\n", .{ year, month, day, hours, mins, secs, level_str } ++ args) catch return;

        if (self.current_size + message.len > self.config.max_size) {
            self.rotate();
        }

        self.file.?.writeStreamingAll(compat.io(), message) catch {
            self.file.?.close(compat.io());
            self.file = null;
            return;
        };

        self.current_size += message.len;
        self.write_count += 1;
    }

    fn flushThread(self: *Self) void {
        while (true) {
            self.lock.lockUncancelable(compat.io());
            const should_stop = self.stop_thread;
            const should_flush = self.file != null and self.write_count > 0;
            self.lock.unlock(compat.io());

            if (should_stop) break;

            if (should_flush) {
                self.lock.lockUncancelable(compat.io());
                if (self.file) |f| {
                    f.sync(compat.io()) catch {};
                    self.write_count = 0;
                }
                self.lock.unlock(compat.io());
            }

            compat.sleepNanos(self.config.flush_interval_ms * time.ns_per_ms);
        }
    }

    pub fn flush(self: *Self) void {
        self.lock.lockUncancelable(compat.io());
        defer self.lock.unlock(compat.io());

        if (self.file) |f| {
            f.sync(compat.io()) catch {};
        }
    }
};

var global_file_logger: ?*FileLogger = null;
var global_logger_lock: std.Io.Mutex = .init;

pub fn initGlobalFileLogger(allocator: std.mem.Allocator, config: LogConfig) void {
    global_logger_lock.lockUncancelable(compat.io());
    defer global_logger_lock.unlock(compat.io());

    if (global_file_logger == null) {
        global_file_logger = FileLogger.init(allocator, config) catch |err| {
            std.log.err("Failed to initialize file logger: {any}", .{err});
            return;
        };
    }
}

pub fn deinitGlobalFileLogger() void {
    global_logger_lock.lockUncancelable(compat.io());
    defer global_logger_lock.unlock(compat.io());

    if (global_file_logger) |logger| {
        logger.deinit();
        global_file_logger = null;
    }
}

pub fn getGlobalFileLogger() ?*FileLogger {
    global_logger_lock.lockUncancelable(compat.io());
    defer global_logger_lock.unlock(compat.io());
    return global_file_logger;
}

pub fn logToFile(level: std.log.Level, comptime scope: @EnumLiteral(), comptime format: []const u8, args: anytype) void {
    if (getGlobalFileLogger()) |logger| {
        logger.log(level, scope, format, args);
    }
}

test "FileLogger basic operations" {
    const allocator = std.testing.allocator;

    const config = LogConfig{
        .enabled = true,
        .file_path = "/tmp/test_portweaver.log",
        .max_size = 1024,
        .max_files = 2,
    };

    std.Io.Dir.cwd().deleteFile(compat.io(), config.file_path) catch {};
    var i: usize = 1;
    while (i <= config.max_files + 1) : (i += 1) {
        const path = try std.fmt.allocPrint(allocator, "{s}.{d}", .{ config.file_path, i });
        defer allocator.free(path);
        std.Io.Dir.cwd().deleteFile(compat.io(), path) catch {};
    }

    var logger = try FileLogger.init(allocator, config);
    defer logger.deinit();

    logger.log(.info, .default, "Test message {}", .{1});
    logger.log(.err, .default, "Error message", .{});

    try std.testing.expect(logger.file != null);
}

test "FileLogger rotation" {
    const allocator = std.testing.allocator;

    const config = LogConfig{
        .enabled = true,
        .file_path = "/tmp/test_portweaver_rotate.log",
        .max_size = 100,
        .max_files = 2,
    };

    std.Io.Dir.cwd().deleteFile(compat.io(), config.file_path) catch {};
    var i: usize = 1;
    while (i <= config.max_files + 2) : (i += 1) {
        const path = try std.fmt.allocPrint(allocator, "{s}.{d}", .{ config.file_path, i });
        defer allocator.free(path);
        std.Io.Dir.cwd().deleteFile(compat.io(), path) catch {};
    }

    var logger = try FileLogger.init(allocator, config);
    defer logger.deinit();

    var j: usize = 0;
    while (j < 20) : (j += 1) {
        logger.log(.info, .default, "Test message number {} with some padding", .{j});
    }

    const file1_exists = if (std.Io.Dir.cwd().access(compat.io(), config.file_path, .{})) |_| true else |err| switch (err) {
        error.FileNotFound => false,
        else => return err,
    };
    try std.testing.expect(file1_exists);
}
