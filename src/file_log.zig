const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const time = std.time;
const Thread = std.Thread;
const compat = @import("compat.zig");

pub const LogFormat = enum {
    plain,
    json,

    pub fn fromString(s: []const u8) ?LogFormat {
        if (std.mem.eql(u8, s, "plain")) return .plain;
        if (std.mem.eql(u8, s, "json")) return .json;
        return null;
    }
};
pub const LogConfig = struct {
    enabled: bool = true,
    file_path: []const u8 = "/tmp/portweaver.log",
    max_size: usize = 1024 * 1024,
    max_files: usize = 3,
    flush_interval_ms: u64 = 100,
    format: LogFormat = .plain,

    pub fn deinit(self: *LogConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.file_path);
        self.* = undefined;
    }

    pub fn eql(a: @This(), b: @This()) bool {
        return a.enabled == b.enabled and
            std.mem.eql(u8, a.file_path, b.file_path) and
            a.max_size == b.max_size and
            a.max_files == b.max_files and
            a.flush_interval_ms == b.flush_interval_ms and
            a.format == b.format;
    }
};

pub fn defaultLogConfig(allocator: std.mem.Allocator) !LogConfig {
    return .{
        .enabled = true,
        .file_path = try allocator.dupe(u8, "/tmp/portweaver.log"),
        .max_size = 1024 * 1024,
        .max_files = 3,
        .flush_interval_ms = 100,
        .format = .plain,
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

    fn escapeJson(out: []u8, in: []const u8) []const u8 {
        var pos: usize = 0;
        for (in) |c| {
            switch (c) {
                '\\' => {
                    if (pos + 2 > out.len) return out[0..pos];
                    out[pos] = '\\';
                    out[pos + 1] = '\\';
                    pos += 2;
                },
                '"' => {
                    if (pos + 2 > out.len) return out[0..pos];
                    out[pos] = '\\';
                    out[pos + 1] = '"';
                    pos += 2;
                },
                '\n' => {
                    if (pos + 2 > out.len) return out[0..pos];
                    out[pos] = '\\';
                    out[pos + 1] = 'n';
                    pos += 2;
                },
                else => {
                    if (pos >= out.len) return out[0..pos];
                    out[pos] = c;
                    pos += 1;
                },
            }
        }
        return out[0..pos];
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
        const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(timestamp) };
        const epoch_day = epoch_seconds.getEpochDay();
        const day_seconds = epoch_seconds.getDaySeconds();
        const year_day = epoch_day.calculateYearDay();
        const month_day = year_day.calculateMonthDay();

        const year = year_day.year;
        const month = month_day.month.numeric();
        const day = month_day.day_index + 1;
        const hours = day_seconds.getHoursIntoDay();
        const mins = day_seconds.getMinutesIntoHour();
        const secs = day_seconds.getSecondsIntoMinute();

        const scope_str = switch (scope) {
            .default => "",
            else => @tagName(scope),
        };

        var json_buf: [4096]u8 = undefined;

        const message = switch (self.config.format) {
            .plain => blk: {
                const level_str = switch (level) {
                    .debug => "DEBUG",
                    .info => "INFO",
                    .warn => "WARN",
                    .err => "ERROR",
                };
                break :blk if (scope_str.len > 0)
                    std.fmt.allocPrint(allocator, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} [{s}] [{s}] " ++ format ++ "\n", .{ year, month, day, hours, mins, secs, level_str, scope_str } ++ args) catch return
                else
                    std.fmt.allocPrint(allocator, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} [{s}] " ++ format ++ "\n", .{ year, month, day, hours, mins, secs, level_str } ++ args) catch return;
            },
            .json => blk: {
                const level_str = switch (level) {
                    .debug => "debug",
                    .info => "info",
                    .warn => "warn",
                    .err => "error",
                };
                const raw_msg = std.fmt.allocPrint(allocator, format, args) catch return;
                var pos: usize = 0;
                const prefix = std.fmt.bufPrint(json_buf[pos..], "{{\"ts\":\"{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}\",\"level\":\"{s}\"", .{ year, month, day, hours, mins, secs, level_str }) catch return;
                pos += prefix.len;
                if (scope_str.len > 0) {
                    const scope_part = std.fmt.bufPrint(json_buf[pos..], ",\"scope\":\"{s}\"", .{scope_str}) catch return;
                    pos += scope_part.len;
                }
                const msg_prefix = std.fmt.bufPrint(json_buf[pos..], ",\"msg\":\"", .{}) catch return;
                pos += msg_prefix.len;
                const escaped = Self.escapeJson(json_buf[pos..], raw_msg);
                pos += escaped.len;
                if (pos + 3 > json_buf.len) return;
                json_buf[pos] = '"';
                json_buf[pos + 1] = '}';
                json_buf[pos + 2] = '\n';
                pos += 3;
                break :blk json_buf[0..pos];
            },
        };

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

test "FileLogger JSON format" {
    const allocator = std.testing.allocator;

    const test_path = "/tmp/test_portweaver_json.log";
    std.Io.Dir.cwd().deleteFile(compat.io(), test_path) catch {};

    const config = LogConfig{
        .enabled = true,
        .file_path = test_path,
        .max_size = 4096,
        .max_files = 2,
        .format = .json,
    };

    var logger = try FileLogger.init(allocator, config);
    defer logger.deinit();

    logger.log(.info, .FRPC, "Connected to server {s}", .{"192.168.1.1"});
    logger.log(.err, .default, "Connection failed: \"{s}\"", .{"timeout"});
    logger.log(.debug, .FRPC, "Line with\nnewline and \\ backslash", .{});

    logger.flush();

    // Read the file and verify each line is valid JSON
    const file = try std.Io.Dir.cwd().openFile(compat.io(), test_path, .{});
    defer file.close(compat.io());

    var read_buf: [4096]u8 = undefined;
    const bytes_read = try file.readPositionalAll(compat.io(), &read_buf, 0);
    const content = read_buf[0..bytes_read];

    // Split by newlines and validate each line
    var line_count: usize = 0;
    var iter = mem.splitScalar(u8, content, '\n');
    while (iter.next()) |line| {
        if (line.len == 0) continue;
        line_count += 1;

        // Must start with { and end with }
        try std.testing.expect(line[0] == '{');
        try std.testing.expect(line[line.len - 1] == '}');

        // Must contain required fields
        try std.testing.expect(mem.indexOf(u8, line, "\"ts\":") != null);
        try std.testing.expect(mem.indexOf(u8, line, "\"level\":") != null);
        try std.testing.expect(mem.indexOf(u8, line, "\"msg\":") != null);

        // Timestamp must use ISO format with T separator
        try std.testing.expect(mem.indexOf(u8, line, "\"ts\":\"") != null);
    }
    try std.testing.expectEqual(@as(usize, 3), line_count);

    // Check specific line content from the same read buffer
    var lines = mem.splitScalar(u8, content, '\n');

    // First line: .info level with FRPC scope
    const line1 = lines.next().?;
    try std.testing.expect(mem.indexOf(u8, line1, "\"level\":\"info\"") != null);
    try std.testing.expect(mem.indexOf(u8, line1, "\"scope\":\"FRPC\"") != null);
    try std.testing.expect(mem.indexOf(u8, line1, "192.168.1.1") != null);

    // Second line: .err level with no scope (default)
    const line2 = lines.next().?;
    try std.testing.expect(mem.indexOf(u8, line2, "\"level\":\"error\"") != null);
    try std.testing.expect(mem.indexOf(u8, line2, "\"scope\"") == null);
    // Check that quotes in message are escaped
    try std.testing.expect(mem.indexOf(u8, line2, "\\\"timeout\\\"") != null);

    // Third line: check escaping of newline and backslash
    const line3 = lines.next().?;
    try std.testing.expect(mem.indexOf(u8, line3, "\\n") != null);
    try std.testing.expect(mem.indexOf(u8, line3, "\\\\") != null);

    std.Io.Dir.cwd().deleteFile(compat.io(), test_path) catch {};
}
