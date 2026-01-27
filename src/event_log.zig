const std = @import("std");

/// Event types for the activity log
pub const EventType = enum(u8) {
    /// Project started successfully
    project_started = 0,
    /// Project stopped
    project_stopped = 1,
    /// Project failed to start
    project_failed = 2,
    /// FRP client connected
    frp_connected = 3,
    /// FRP client disconnected
    frp_disconnected = 4,
    /// FRP client error
    frp_error = 5,
    /// Generic info event
    info = 6,
    /// Generic warning event
    warning = 7,
    /// Generic error event
    err = 8,

    pub fn toString(self: EventType) [:0]const u8 {
        return switch (self) {
            .project_started => "project_started",
            .project_stopped => "project_stopped",
            .project_failed => "project_failed",
            .frp_connected => "frp_connected",
            .frp_disconnected => "frp_disconnected",
            .frp_error => "frp_error",
            .info => "info",
            .warning => "warning",
            .err => "error",
        };
    }
};

/// A single event in the activity log
pub const Event = struct {
    /// Unix timestamp in milliseconds
    timestamp: i64,
    /// Type of event
    event_type: EventType,
    /// Event message (owned by the event, must be freed)
    message: []const u8,
    /// Optional project ID (-1 if not applicable)
    project_id: i32,

    pub fn deinit(self: *Event, allocator: std.mem.Allocator) void {
        allocator.free(self.message);
    }
};

/// Thread-safe, capacity-limited event logger
pub const EventLogger = struct {
    allocator: std.mem.Allocator,
    events: std.array_list.Managed(Event),
    lock: std.Thread.Mutex,
    capacity: usize,

    const Self = @This();

    /// Initialize a new event logger with the specified capacity
    pub fn init(allocator: std.mem.Allocator, capacity: usize) !Self {
        return Self{
            .allocator = allocator,
            .events = try std.array_list.Managed(Event).initCapacity(allocator, capacity),
            .lock = .{},
            .capacity = capacity,
        };
    }

    /// Deinitialize the event logger and free all events
    pub fn deinit(self: *Self) void {
        self.lock.lock();
        defer self.lock.unlock();

        for (self.events.items) |*event| {
            event.deinit(self.allocator);
        }
        self.events.deinit();
    }

    /// Add an event to the log
    /// If the log is at capacity, the oldest event is removed
    pub fn addEvent(self: *Self, event_type: EventType, message: []const u8, project_id: i32) !void {
        self.lock.lock();
        defer self.lock.unlock();

        // Trim oldest events if at capacity
        while (self.events.items.len >= self.capacity) {
            var oldest = self.events.orderedRemove(0);
            oldest.deinit(self.allocator);
        }

        // Duplicate the message so we own it
        const owned_message = try self.allocator.dupe(u8, message);
        errdefer self.allocator.free(owned_message);

        const event = Event{
            .timestamp = std.time.milliTimestamp(),
            .event_type = event_type,
            .message = owned_message,
            .project_id = project_id,
        };

        try self.events.append(event);
    }

    /// Add an event with formatted message
    pub fn addEventFmt(self: *Self, event_type: EventType, project_id: i32, comptime fmt: []const u8, args: anytype) void {
        var buf: [512]u8 = undefined;
        const message = std.fmt.bufPrint(&buf, fmt, args) catch |err| {
            std.log.warn("Failed to format event message: {any}", .{err});
            return;
        };
        self.addEvent(event_type, message, project_id) catch |err| {
            std.log.warn("Failed to add event: {any}", .{err});
        };
    }

    /// Get a copy of all events (caller must free the returned slice and its contents)
    /// Returns events in chronological order (oldest first)
    pub fn getEvents(self: *Self, allocator: std.mem.Allocator) ![]Event {
        self.lock.lock();
        defer self.lock.unlock();

        const result = try allocator.alloc(Event, self.events.items.len);
        errdefer allocator.free(result);

        for (self.events.items, 0..) |event, i| {
            result[i] = Event{
                .timestamp = event.timestamp,
                .event_type = event.event_type,
                .message = try allocator.dupe(u8, event.message),
                .project_id = event.project_id,
            };
        }

        return result;
    }

    /// Free a slice of events returned by getEvents
    pub fn freeEvents(allocator: std.mem.Allocator, events: []Event) void {
        for (events) |*event| {
            allocator.free(event.message);
        }
        allocator.free(events);
    }

    /// Get the current number of events in the log
    pub fn count(self: *Self) usize {
        self.lock.lock();
        defer self.lock.unlock();
        return self.events.items.len;
    }

    /// Clear all events from the log
    pub fn clear(self: *Self) void {
        self.lock.lock();
        defer self.lock.unlock();

        for (self.events.items) |*event| {
            event.deinit(self.allocator);
        }
        self.events.clearRetainingCapacity();
    }
};

/// Default capacity for the global event logger
pub const DEFAULT_CAPACITY: usize = 20;

/// Global event logger instance (initialized lazily)
var global_logger: ?EventLogger = null;
var global_logger_lock: std.Thread.Mutex = .{};

/// Initialize the global event logger
/// This should be called once at startup
pub fn initGlobal(allocator: std.mem.Allocator) void {
    global_logger_lock.lock();
    defer global_logger_lock.unlock();

    if (global_logger == null) {
        global_logger = EventLogger.init(allocator, DEFAULT_CAPACITY) catch |err| {
            std.log.err("Failed to initialize event logger: {any}", .{err});
            return;
        };
        std.log.info("Event logger initialized with capacity {d}", .{DEFAULT_CAPACITY});
    }
}

/// Deinitialize the global event logger
pub fn deinitGlobal() void {
    global_logger_lock.lock();
    defer global_logger_lock.unlock();

    if (global_logger) |*logger| {
        logger.deinit();
        global_logger = null;
    }
}

/// Get the global event logger
/// Returns null if not initialized
pub fn getGlobal() ?*EventLogger {
    global_logger_lock.lock();
    defer global_logger_lock.unlock();
    return if (global_logger) |*logger| logger else null;
}

/// Convenience function to add an event to the global logger
pub fn logEvent(event_type: EventType, message: []const u8, project_id: i32) void {
    if (getGlobal()) |logger| {
        logger.addEvent(event_type, message, project_id) catch |err| {
            std.log.warn("Failed to log event: {any}", .{err});
        };
    }
}

/// Convenience function to add a formatted event to the global logger
pub fn logEventFmt(event_type: EventType, project_id: i32, comptime fmt: []const u8, args: anytype) void {
    if (getGlobal()) |logger| {
        logger.addEventFmt(event_type, project_id, fmt, args);
    }
}

// Tests
test "EventLogger basic operations" {
    const allocator = std.testing.allocator;

    var logger = try EventLogger.init(allocator, 5);
    defer logger.deinit();

    // Add some events
    try logger.addEvent(.project_started, "Project 1 started", 0);
    try logger.addEvent(.project_started, "Project 2 started", 1);
    try logger.addEvent(.frp_connected, "FRP connected", -1);

    try std.testing.expectEqual(@as(usize, 3), logger.count());

    // Get events
    const events = try logger.getEvents(allocator);
    defer EventLogger.freeEvents(allocator, events);

    try std.testing.expectEqual(@as(usize, 3), events.len);
    try std.testing.expectEqualStrings("Project 1 started", events[0].message);
}

test "EventLogger capacity limit" {
    const allocator = std.testing.allocator;

    var logger = try EventLogger.init(allocator, 3);
    defer logger.deinit();

    // Add more events than capacity
    try logger.addEvent(.info, "Event 1", -1);
    try logger.addEvent(.info, "Event 2", -1);
    try logger.addEvent(.info, "Event 3", -1);
    try logger.addEvent(.info, "Event 4", -1);
    try logger.addEvent(.info, "Event 5", -1);

    // Should only have 3 events (the newest ones)
    try std.testing.expectEqual(@as(usize, 3), logger.count());

    const events = try logger.getEvents(allocator);
    defer EventLogger.freeEvents(allocator, events);

    try std.testing.expectEqualStrings("Event 3", events[0].message);
    try std.testing.expectEqualStrings("Event 4", events[1].message);
    try std.testing.expectEqualStrings("Event 5", events[2].message);
}
