const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const event_log = @import("../event_log.zig");
const compat = @import("../compat.zig");

/// Per-MAC cooldown manager (global, in-memory, not persisted).
/// Maps MAC string to the last WoL send timestamp (milliseconds).
pub const WolManager = struct {
    cooldown_map: std.StringHashMap(i64),
    mutex: std.Io.Mutex,

    pub fn init(allocator: std.mem.Allocator) WolManager {
        return .{
            .cooldown_map = std.StringHashMap(i64).init(allocator),
            .mutex = .init,
        };
    }

    pub fn deinit(self: *WolManager) void {
        self.cooldown_map.deinit();
    }

    /// Returns true if enough time has passed since the last WoL for this MAC.
    /// On success (returns true), updates the timestamp.
    pub fn shouldSend(self: *WolManager, mac_key: []const u8, cooldown_ms: u64) bool {
        self.mutex.lockUncancelable(compat.io());
        defer self.mutex.unlock(compat.io());

        const now: i64 = @intCast(std.Io.Timestamp.now(compat.io(), .real).toMilliseconds());

        if (self.cooldown_map.get(mac_key)) |last_sent| {
            const elapsed = now - last_sent;
            const cooldown_i64: i64 = @intCast(cooldown_ms);
            if (elapsed >= cooldown_i64) {
                // Cooldown expired — update and allow send
                self.cooldown_map.put(mac_key, now) catch return false;
                return true;
            }
            // Still within cooldown window
            return false;
        }

        // First time seeing this MAC — allow send and record timestamp
        self.cooldown_map.put(mac_key, now) catch return false;
        return true;
    }
};

/// Build a WoL magic packet: 6 bytes of 0xFF followed by 16 repetitions of the 6-byte MAC.
/// Total: 102 bytes.
pub fn buildMagicPacket(mac: [6]u8) [102]u8 {
    var packet: [102]u8 = undefined;
    // 6 bytes of 0xFF
    for (0..6) |i| {
        packet[i] = 0xFF;
    }
    // 16 repetitions of the MAC address
    for (0..16) |rep| {
        const offset = 6 + rep * 6;
        for (0..6) |j| {
            packet[offset + j] = mac[j];
        }
    }
    return packet;
}

/// Send a WoL magic packet via UDP broadcast to 255.255.255.255:9.
/// Opens a UDP socket, sets SO_BROADCAST, sends, and closes.
pub fn sendMagicPacket(mac: [6]u8) !void {
    const packet = buildMagicPacket(mac);

    // Create UDP socket using linux raw syscall
    const sock_rc = linux.socket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    const fd: i32 = switch (posix.errno(sock_rc)) {
        .SUCCESS => @intCast(sock_rc),
        else => return error.SocketCreateFailed,
    };
    defer _ = linux.close(fd);

    // Enable SO_BROADCAST
    const enabled: u32 = 1;
    {
        const setopt_rc = linux.setsockopt(fd, posix.SOL.SOCKET, posix.SO.BROADCAST, @ptrCast(&enabled), @sizeOf(u32));
        switch (posix.errno(setopt_rc)) {
            .SUCCESS => {},
            else => return error.SetSockOptFailed,
        }
    }

    // Broadcast address: 255.255.255.255:9
    const addr = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, 9),
        .addr = 0xFFFFFFFF, // 255.255.255.255
    };

    // Send the magic packet
    const send_rc = linux.sendto(fd, &packet, packet.len, 0, @ptrCast(&addr), @sizeOf(linux.sockaddr.in));
    switch (posix.errno(send_rc)) {
        .SUCCESS => {},
        else => return error.SendFailed,
    }
}

/// Parse a colon-separated MAC string (e.g. "AA:BB:CC:DD:EE:FF") into 6 bytes.
/// Returns null if the format is invalid.
pub fn parseMac(mac_str: []const u8) ?[6]u8 {
    // Expected format: XX:XX:XX:XX:XX:XX = 17 characters
    if (mac_str.len != 17) return null;

    var result: [6]u8 = undefined;
    for (0..6) |i| {
        const start = i * 3;
        // Verify colon separator (except after last group)
        if (i < 5 and mac_str[start + 2] != ':') return null;

        result[i] = std.fmt.parseInt(u8, mac_str[start .. start + 2], 16) catch return null;
    }
    return result;
}

pub fn sendWoLWithCooldown(mac_list: []const []const u8, cooldown_ms: u64, log_enabled: bool, wol_mgr: *WolManager, project_id: i32) void {
    var sent_count: u32 = 0;
    var skipped_count: u32 = 0;
    var error_count: u32 = 0;

    for (mac_list) |mac_str| {
        const mac = parseMac(mac_str) orelse {
            event_log.logEventFmt(.warning, project_id, "WoL: invalid MAC address: {s}", .{mac_str});
            if (log_enabled) {
                std.log.warn("[WoL] invalid MAC address: {s}", .{mac_str});
            }
            error_count += 1;
            continue;
        };

        if (!wol_mgr.shouldSend(mac_str, cooldown_ms)) {
            skipped_count += 1;
            if (log_enabled) {
                std.log.info("[WoL] skip sending to {s} (cooldown active)", .{mac_str});
            }
            continue;
        }

        sendMagicPacket(mac) catch |err| {
            event_log.logEventFmt(.warning, project_id, "WoL: send failed for {s}: {}", .{ mac_str, err });
            if (log_enabled) {
                std.log.err("[WoL] send failed to {s}: {any}", .{ mac_str, err });
            }
            error_count += 1;
            continue;
        };

        sent_count += 1;
        if (log_enabled) {
            std.log.info("[WoL] successfully sent magic packet to {s}", .{mac_str});
        }
    }

    // Log summary if any MACs were processed
    if (sent_count > 0) {
        event_log.logEventFmt(.info, project_id, "WoL: sent {d} magic packet(s)", .{sent_count});
    }
    if (skipped_count > 0) {
        event_log.logEventFmt(.info, project_id, "WoL: {d} MAC(s) skipped (cooldown active)", .{skipped_count});
    }
}

// =============================================================================
// Tests
// =============================================================================

test "magic packet format" {
    const mac = [6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const packet = buildMagicPacket(mac);

    // Total size must be 102
    try std.testing.expectEqual(@as(usize, 102), packet.len);

    // First 6 bytes must be 0xFF
    for (0..6) |i| {
        try std.testing.expectEqual(@as(u8, 0xFF), packet[i]);
    }

    // 16 repetitions of the MAC starting at offset 6
    for (0..16) |rep| {
        const offset = 6 + rep * 6;
        for (0..6) |j| {
            try std.testing.expectEqual(mac[j], packet[offset + j]);
        }
    }
}

test "parseMac valid" {
    const result = parseMac("AA:BB:CC:DD:EE:FF");
    try std.testing.expect(result != null);
    const mac = result.?;
    try std.testing.expectEqual(@as(u8, 0xAA), mac[0]);
    try std.testing.expectEqual(@as(u8, 0xBB), mac[1]);
    try std.testing.expectEqual(@as(u8, 0xCC), mac[2]);
    try std.testing.expectEqual(@as(u8, 0xDD), mac[3]);
    try std.testing.expectEqual(@as(u8, 0xEE), mac[4]);
    try std.testing.expectEqual(@as(u8, 0xFF), mac[5]);
}

test "parseMac lowercase" {
    const result = parseMac("aa:bb:cc:dd:ee:ff");
    try std.testing.expect(result != null);
    const mac = result.?;
    try std.testing.expectEqual(@as(u8, 0xAA), mac[0]);
    try std.testing.expectEqual(@as(u8, 0xFF), mac[5]);
}

test "parseMac mixed case" {
    const result = parseMac("aA:Bb:cC:Dd:Ee:Ff");
    try std.testing.expect(result != null);
}

test "parseMac invalid length" {
    try std.testing.expectEqual(@as(?[6]u8, null), parseMac("AA:BB:CC:DD:EE"));
    try std.testing.expectEqual(@as(?[6]u8, null), parseMac("AA:BB:CC:DD:EE:FF:00"));
    try std.testing.expectEqual(@as(?[6]u8, null), parseMac(""));
}

test "parseMac invalid separator" {
    try std.testing.expectEqual(@as(?[6]u8, null), parseMac("AA-BB-CC-DD-EE-FF"));
    try std.testing.expectEqual(@as(?[6]u8, null), parseMac("AA.BB.CC.DD.EE.FF"));
}

test "parseMac invalid hex" {
    try std.testing.expectEqual(@as(?[6]u8, null), parseMac("GG:BB:CC:DD:EE:FF"));
    try std.testing.expectEqual(@as(?[6]u8, null), parseMac("AA:BB:CC:DD:EE:ZZ"));
}

test "parseMac zero MAC" {
    const result = parseMac("00:00:00:00:00:00");
    try std.testing.expect(result != null);
    const mac = result.?;
    for (mac) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }
}

test "cooldown first call returns true" {
    var mgr = WolManager.init(std.testing.allocator);
    defer mgr.deinit();

    try std.testing.expect(mgr.shouldSend("AA:BB:CC:DD:EE:FF", 1000));
}

test "cooldown second call within window returns false" {
    var mgr = WolManager.init(std.testing.allocator);
    defer mgr.deinit();

    try std.testing.expect(mgr.shouldSend("AA:BB:CC:DD:EE:FF", 10000));
    // Immediate second call should be blocked by cooldown
    try std.testing.expect(!mgr.shouldSend("AA:BB:CC:DD:EE:FF", 10000));
}

test "cooldown different MACs are independent" {
    var mgr = WolManager.init(std.testing.allocator);
    defer mgr.deinit();

    try std.testing.expect(mgr.shouldSend("AA:BB:CC:DD:EE:01", 10000));
    // Different MAC should not be affected
    try std.testing.expect(mgr.shouldSend("AA:BB:CC:DD:EE:02", 10000));
}

test "cooldown zero ms always allows" {
    var mgr = WolManager.init(std.testing.allocator);
    defer mgr.deinit();

    try std.testing.expect(mgr.shouldSend("AA:BB:CC:DD:EE:FF", 0));
    // With 0ms cooldown, even immediate call should succeed (elapsed >= 0)
    // Note: this depends on at least 0ms passing, which is always true
    // but the timestamp might be the same millisecond.
    // With 0 cooldown, the comparison is elapsed >= 0, which is always true.
    try std.testing.expect(mgr.shouldSend("AA:BB:CC:DD:EE:FF", 0));
}

test "cooldown expiry allows resend" {
    var mgr = WolManager.init(std.testing.allocator);
    defer mgr.deinit();

    // Use a very short cooldown (1ms)
    try std.testing.expect(mgr.shouldSend("AA:BB:CC:DD:EE:FF", 1));

    // Sleep just over 1ms to allow cooldown to expire
    compat.sleepNanos(2 * std.time.ns_per_ms);

    try std.testing.expect(mgr.shouldSend("AA:BB:CC:DD:EE:FF", 1));
}
