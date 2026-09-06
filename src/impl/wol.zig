const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const event_log = @import("../event_log.zig");
const compat = @import("../compat.zig");

const DEFAULT_QUEUE_CAPACITY = 256;

pub const EnqueueResult = struct {
    queued: u32 = 0,
    skipped: u32 = 0,
    failed: u32 = 0,
};

pub const Status = struct {
    queue_depth: u32 = 0,
    active_jobs: u32 = 0,
    pending_count: u32 = 0,
    cooldown_remaining_ms: u64 = 0,
    last_attempt_ms_ago: ?u64 = null,
    last_success_ms_ago: ?u64 = null,
    last_error: ?[]const u8 = null,
};

const Job = struct {
    mac: [6]u8,
    cooldown_ms: u64,
    log_enabled: bool,
    project_id: i32,
};

const CooldownEntry = struct {
    cooldown_until_ms: ?i64 = null,
    pending: bool = false,
    last_attempt_ms: ?i64 = null,
    last_success_ms: ?i64 = null,
    last_error: ?ErrorClass = null,
};

const ErrorClass = enum {
    send_failed,
};

const SendFn = *const fn (?*anyopaque, [6]u8) anyerror!void;
const ClockFn = *const fn (?*anyopaque) i64;
const STATUS_RETENTION_MS = 5 * std.time.ms_per_min;

/// Process-wide asynchronous WoL sender. The service owns its queue, worker,
/// and cooldown state; callers only enqueue value-owned jobs.
pub const WolService = struct {
    allocator: std.mem.Allocator,
    queue: std.array_list.Managed(Job),
    queue_capacity: usize,
    cooldowns: std.AutoHashMap([6]u8, CooldownEntry),
    mutex: std.Io.Mutex = .init,
    condition: std.Io.Condition = .init,
    thread: ?std.Thread = null,
    stop_requested: bool = false,
    active_jobs: usize = 0,
    send_fn: SendFn,
    send_context: ?*anyopaque,
    clock_fn: ClockFn,
    clock_context: ?*anyopaque,

    const Options = struct {
        queue_capacity: usize = DEFAULT_QUEUE_CAPACITY,
        send_fn: SendFn = defaultSend,
        send_context: ?*anyopaque = null,
        clock_fn: ClockFn = defaultClock,
        clock_context: ?*anyopaque = null,
    };

    /// The returned service owns all allocations and must be deinitialized.
    pub fn init(allocator: std.mem.Allocator) !*WolService {
        return initWithOptions(allocator, .{});
    }

    fn initWithOptions(allocator: std.mem.Allocator, options: Options) !*WolService {
        if (options.queue_capacity == 0) return error.InvalidQueueCapacity;

        const self = try allocator.create(WolService);
        errdefer allocator.destroy(self);

        self.* = .{
            .allocator = allocator,
            .queue = try std.array_list.Managed(Job).initCapacity(allocator, options.queue_capacity),
            .queue_capacity = options.queue_capacity,
            .cooldowns = std.AutoHashMap([6]u8, CooldownEntry).init(allocator),
            .send_fn = options.send_fn,
            .send_context = options.send_context,
            .clock_fn = options.clock_fn,
            .clock_context = options.clock_context,
        };
        errdefer self.queue.deinit();
        errdefer self.cooldowns.deinit();

        self.thread = try std.Thread.spawn(.{}, workerMain, .{self});
        return self;
    }

    pub fn deinit(self: *WolService) void {
        self.mutex.lockUncancelable(compat.io());
        self.stop_requested = true;
        self.condition.broadcast(compat.io());
        self.mutex.unlock(compat.io());

        if (self.thread) |thread| {
            thread.join();
            self.thread = null;
        }

        self.cooldowns.deinit();
        self.queue.deinit();
        const allocator = self.allocator;
        allocator.destroy(self);
    }

    /// Enqueues all eligible MACs without performing network I/O on the caller.
    pub fn enqueue(self: *WolService, mac_list: []const []const u8, cooldown_ms: u64, log_enabled: bool, project_id: i32) EnqueueResult {
        var result = EnqueueResult{};

        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        if (self.stop_requested) {
            result.failed = @intCast(mac_list.len);
            return result;
        }

        const now = self.clock_fn(self.clock_context);
        self.pruneExpired(now);
        for (mac_list) |mac_str| {
            const mac = parseMac(mac_str) orelse {
                result.failed += 1;
                continue;
            };

            const entry = self.cooldowns.getOrPut(mac) catch {
                result.failed += 1;
                continue;
            };
            if (!entry.found_existing) entry.value_ptr.* = .{};

            if (entry.value_ptr.pending or cooldownActive(entry.value_ptr.cooldown_until_ms, now)) {
                result.skipped += 1;
                continue;
            }
            if (self.queue.items.len >= self.queue_capacity) {
                result.failed += 1;
                if (!entry.found_existing) _ = self.cooldowns.remove(mac);
                continue;
            }

            self.queue.appendAssumeCapacity(.{
                .mac = mac,
                .cooldown_ms = cooldown_ms,
                .log_enabled = log_enabled,
                .project_id = project_id,
            });
            entry.value_ptr.pending = true;
            result.queued += 1;
        }

        if (result.queued > 0) self.condition.broadcast(compat.io());
        return result;
    }

    /// Returns aggregate state for the supplied MACs without exposing them.
    pub fn status(self: *WolService, mac_list: []const []const u8) Status {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        const now = self.clock_fn(self.clock_context);
        self.pruneExpired(now);
        var result = Status{
            .queue_depth = @intCast(self.queue.items.len),
            .active_jobs = @intCast(self.active_jobs),
        };
        var latest_attempt: ?i64 = null;
        var latest_success: ?i64 = null;
        var latest_error: ?struct { time: i64, value: ErrorClass } = null;

        for (mac_list) |mac_str| {
            const mac = parseMac(mac_str) orelse continue;
            const entry = self.cooldowns.get(mac) orelse continue;
            if (entry.pending) result.pending_count += 1;
            if (entry.cooldown_until_ms) |until| {
                if (until > now) {
                    const remaining: u64 = @intCast(until - now);
                    result.cooldown_remaining_ms = @max(result.cooldown_remaining_ms, remaining);
                }
            }
            if (entry.last_attempt_ms) |attempt| {
                if (latest_attempt == null or attempt > latest_attempt.?) latest_attempt = attempt;
            }
            if (entry.last_success_ms) |success| {
                if (latest_success == null or success > latest_success.?) latest_success = success;
            }
            if (entry.last_error) |err| {
                const error_time = entry.last_attempt_ms orelse continue;
                if (latest_error == null or error_time > latest_error.?.time) {
                    latest_error = .{ .time = error_time, .value = err };
                }
            }
        }

        if (latest_attempt) |attempt| result.last_attempt_ms_ago = elapsedMillis(now, attempt);
        if (latest_success) |success| result.last_success_ms_ago = elapsedMillis(now, success);
        if (latest_error) |err| result.last_error = @tagName(err.value);
        return result;
    }

    fn workerMain(self: *WolService) void {
        while (true) {
            self.mutex.lockUncancelable(compat.io());
            while (self.queue.items.len == 0 and !self.stop_requested) {
                self.condition.waitUncancelable(compat.io(), &self.mutex);
            }
            if (self.queue.items.len == 0 and self.stop_requested) {
                self.mutex.unlock(compat.io());
                return;
            }
            const job = self.queue.orderedRemove(0);
            self.active_jobs += 1;
            self.mutex.unlock(compat.io());

            self.send_fn(self.send_context, job.mac) catch |err| {
                self.finishJob(job, false);
                event_log.logEventFmt(.wol_failed, job.project_id, "WoL magic packet send failed: {}", .{err});
                if (job.log_enabled) std.log.err("[WoL] magic packet send failed: {any}", .{err});
                continue;
            };

            self.finishJob(job, true);
            event_log.logEventFmt(.wol_sent, job.project_id, "WoL magic packet sent", .{});
            if (job.log_enabled) std.log.info("[WoL] magic packet sent", .{});
        }
    }

    fn finishJob(self: *WolService, job: Job, succeeded: bool) void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        if (self.cooldowns.getPtr(job.mac)) |entry| {
            const now = self.clock_fn(self.clock_context);
            entry.pending = false;
            entry.last_attempt_ms = now;
            if (succeeded) {
                const cooldown: i64 = @intCast(job.cooldown_ms);
                entry.cooldown_until_ms = std.math.add(i64, now, cooldown) catch std.math.maxInt(i64);
                entry.last_success_ms = now;
                entry.last_error = null;
            } else {
                entry.cooldown_until_ms = null;
                entry.last_error = .send_failed;
            }
        }
        self.active_jobs -= 1;
        self.condition.broadcast(compat.io());
    }

    fn waitUntilIdle(self: *WolService) void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        while (self.queue.items.len > 0 or self.active_jobs > 0) {
            self.condition.waitUncancelable(compat.io(), &self.mutex);
        }
    }

    fn pruneExpired(self: *WolService, now: i64) void {
        while (true) {
            var iterator = self.cooldowns.iterator();
            var expired_key: ?[6]u8 = null;
            while (iterator.next()) |entry| {
                const last_attempt = entry.value_ptr.last_attempt_ms orelse std.math.minInt(i64);
                const status_expired = now -| last_attempt >= STATUS_RETENTION_MS;
                if (!entry.value_ptr.pending and !cooldownActive(entry.value_ptr.cooldown_until_ms, now) and status_expired) {
                    expired_key = entry.key_ptr.*;
                    break;
                }
            }
            if (expired_key) |key| {
                _ = self.cooldowns.remove(key);
            } else {
                return;
            }
        }
    }
};

var global_service: ?*WolService = null;
var global_mutex: std.Io.Mutex = .init;

pub fn initGlobal(allocator: std.mem.Allocator) !void {
    global_mutex.lockUncancelable(compat.io());
    defer global_mutex.unlock(compat.io());
    if (global_service != null) return;
    global_service = try WolService.init(allocator);
}

pub fn deinitGlobal() void {
    global_mutex.lockUncancelable(compat.io());
    defer global_mutex.unlock(compat.io());
    if (global_service) |service| {
        service.deinit();
        global_service = null;
    }
}

pub fn enqueueGlobal(mac_list: []const []const u8, cooldown_ms: u64, log_enabled: bool, project_id: i32) EnqueueResult {
    global_mutex.lockUncancelable(compat.io());
    defer global_mutex.unlock(compat.io());
    const service = global_service orelse return .{ .failed = @intCast(mac_list.len) };
    return service.enqueue(mac_list, cooldown_ms, log_enabled, project_id);
}

pub fn statusGlobal(mac_list: []const []const u8) Status {
    global_mutex.lockUncancelable(compat.io());
    defer global_mutex.unlock(compat.io());
    const service = global_service orelse return .{};
    return service.status(mac_list);
}

fn cooldownActive(cooldown_until_ms: ?i64, now: i64) bool {
    const cooldown_until = cooldown_until_ms orelse return false;
    return now < cooldown_until;
}

fn elapsedMillis(now: i64, then: i64) u64 {
    if (now <= then) return 0;
    return @intCast(now - then);
}

fn defaultClock(_: ?*anyopaque) i64 {
    return std.Io.Timestamp.now(compat.io(), .awake).toMilliseconds();
}

fn defaultSend(_: ?*anyopaque, mac: [6]u8) !void {
    try sendMagicPacket(mac);
}

/// Build a WoL magic packet: 6 bytes of 0xFF followed by 16 repetitions of the 6-byte MAC.
pub fn buildMagicPacket(mac: [6]u8) [102]u8 {
    var packet: [102]u8 = undefined;
    @memset(packet[0..6], 0xFF);
    for (0..16) |rep| {
        const offset = 6 + rep * 6;
        @memcpy(packet[offset .. offset + 6], &mac);
    }
    return packet;
}

/// Send a WoL magic packet via UDP broadcast to 255.255.255.255:9.
pub fn sendMagicPacket(mac: [6]u8) !void {
    const packet = buildMagicPacket(mac);
    const sock_rc = linux.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    const fd: i32 = switch (posix.errno(sock_rc)) {
        .SUCCESS => @intCast(sock_rc),
        else => return error.SocketCreateFailed,
    };
    defer _ = linux.close(fd);

    const enabled: u32 = 1;
    const setopt_rc = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.BROADCAST, @ptrCast(&enabled), @sizeOf(u32));
    if (posix.errno(setopt_rc) != .SUCCESS) return error.SetSockOptFailed;

    const addr = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, 9),
        .addr = 0xFFFFFFFF,
    };
    const send_rc = linux.sendto(fd, &packet, packet.len, 0, @ptrCast(&addr), @sizeOf(linux.sockaddr.in));
    if (posix.errno(send_rc) != .SUCCESS) return error.SendFailed;
    if (send_rc != packet.len) return error.ShortSend;
}

/// Parse a colon-separated MAC string into a value-owned six-byte key.
pub fn parseMac(mac_str: []const u8) ?[6]u8 {
    if (mac_str.len != 17) return null;
    var result: [6]u8 = undefined;
    for (0..6) |i| {
        const start = i * 3;
        if (i < 5 and mac_str[start + 2] != ':') return null;
        result[i] = std.fmt.parseInt(u8, mac_str[start .. start + 2], 16) catch return null;
    }
    return result;
}

test "magic packet format" {
    const mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const packet = buildMagicPacket(mac);
    try std.testing.expectEqual(@as(usize, 102), packet.len);
    for (packet[0..6]) |byte| try std.testing.expectEqual(@as(u8, 0xFF), byte);
    for (0..16) |rep| {
        const offset = 6 + rep * 6;
        try std.testing.expectEqualSlices(u8, &mac, packet[offset .. offset + 6]);
    }
}

test "parseMac validates canonical format" {
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, &(parseMac("aA:Bb:cC:Dd:Ee:Ff").?));
    try std.testing.expect(parseMac("AA-BB-CC-DD-EE-FF") == null);
    try std.testing.expect(parseMac("GG:BB:CC:DD:EE:FF") == null);
    try std.testing.expect(parseMac("") == null);
}

const FakeSender = struct {
    calls: usize = 0,
    fail: bool = false,

    fn send(context: ?*anyopaque, _: [6]u8) !void {
        const self: *FakeSender = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        if (self.fail) return error.InjectedFailure;
    }
};

const FakeClock = struct {
    now: i64 = 1000,

    fn read(context: ?*anyopaque) i64 {
        const self: *FakeClock = @ptrCast(@alignCast(context.?));
        return self.now;
    }
};

test "service shares cooldown and commits only successful sends" {
    var sender = FakeSender{};
    var clock = FakeClock{};
    const service = try WolService.initWithOptions(std.testing.allocator, .{
        .send_fn = FakeSender.send,
        .send_context = &sender,
        .clock_fn = FakeClock.read,
        .clock_context = &clock,
    });
    defer service.deinit();

    const macs = &[_][]const u8{"AA:BB:CC:DD:EE:FF"};
    try std.testing.expectEqual(@as(u32, 1), service.enqueue(macs, 1000, false, 1).queued);
    service.waitUntilIdle();
    try std.testing.expectEqual(@as(u32, 1), service.enqueue(macs, 1000, false, 1).skipped);

    clock.now += 1000;
    sender.fail = true;
    try std.testing.expectEqual(@as(u32, 1), service.enqueue(macs, 1000, false, 1).queued);
    service.waitUntilIdle();
    try std.testing.expectEqual(@as(u32, 1), service.enqueue(macs, 1000, false, 1).queued);
    service.waitUntilIdle();
    try std.testing.expectEqual(@as(usize, 3), sender.calls);
}

test "service status reports cooldown and the latest send result" {
    var sender = FakeSender{};
    var clock = FakeClock{};
    const service = try WolService.initWithOptions(std.testing.allocator, .{
        .send_fn = FakeSender.send,
        .send_context = &sender,
        .clock_fn = FakeClock.read,
        .clock_context = &clock,
    });
    defer service.deinit();

    const macs = &[_][]const u8{"AA:BB:CC:DD:EE:FF"};
    _ = service.enqueue(macs, 1000, false, 1);
    service.waitUntilIdle();

    var status = service.status(macs);
    try std.testing.expectEqual(@as(u64, 1000), status.cooldown_remaining_ms);
    try std.testing.expectEqual(@as(?u64, 0), status.last_attempt_ms_ago);
    try std.testing.expectEqual(@as(?u64, 0), status.last_success_ms_ago);
    try std.testing.expect(status.last_error == null);

    clock.now += 1000;
    sender.fail = true;
    _ = service.enqueue(macs, 1000, false, 1);
    service.waitUntilIdle();

    status = service.status(macs);
    try std.testing.expectEqual(@as(?[]const u8, "send_failed"), status.last_error);
    try std.testing.expectEqual(@as(?u64, 0), status.last_attempt_ms_ago);
}

const BlockingSender = struct {
    mutex: std.Io.Mutex = .init,
    condition: std.Io.Condition = .init,
    started: bool = false,
    released: bool = false,

    fn send(context: ?*anyopaque, _: [6]u8) !void {
        const self: *BlockingSender = @ptrCast(@alignCast(context.?));
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        self.started = true;
        self.condition.broadcast(compat.io());
        while (!self.released) self.condition.waitUncancelable(compat.io(), &self.mutex);
    }

    fn waitUntilStarted(self: *BlockingSender) void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        while (!self.started) self.condition.waitUncancelable(compat.io(), &self.mutex);
    }

    fn release(self: *BlockingSender) void {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());
        self.released = true;
        self.condition.broadcast(compat.io());
    }
};

test "service bounds its queue and suppresses duplicate pending work" {
    var sender = BlockingSender{};
    const service = try WolService.initWithOptions(std.testing.allocator, .{
        .queue_capacity = 1,
        .send_fn = BlockingSender.send,
        .send_context = &sender,
    });
    defer service.deinit();
    defer sender.release();

    const first = &[_][]const u8{"AA:BB:CC:DD:EE:01"};
    try std.testing.expectEqual(@as(u32, 1), service.enqueue(first, 1000, false, 1).queued);
    sender.waitUntilStarted();
    try std.testing.expectEqual(@as(u32, 1), service.enqueue(first, 1000, false, 1).skipped);
    try std.testing.expectEqual(@as(u32, 1), service.enqueue(&[_][]const u8{"AA:BB:CC:DD:EE:02"}, 1000, false, 1).queued);
    try std.testing.expectEqual(@as(u32, 1), service.enqueue(&[_][]const u8{"AA:BB:CC:DD:EE:03"}, 1000, false, 1).failed);

    sender.release();
    service.waitUntilIdle();
}
