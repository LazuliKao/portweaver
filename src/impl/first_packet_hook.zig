const std = @import("std");
const types = @import("../config/types.zig");
const protocol_detector = @import("protocol_detector.zig");
const forwarder_runtime = @import("app_forward/forwarder_runtime.zig");
const c = forwarder_runtime.c;
const build_options = @import("build_options");
const event_log = @import("../event_log.zig");

const INSPECTION_REJECT: c_int = 0;
const INSPECTION_ALLOW: c_int = 1;
const INSPECTION_NEED_MORE: c_int = 2;
const INSPECTION_ALLOW_WAKE: c_int = 3;

/// Immutable, allocator-owned policy shared by every connection on a forwarder.
pub const CallbackContext = struct {
    allocator: std.mem.Allocator,
    project_id: usize,
    enable_wol: bool,
    wol_trigger_mode: types.WolTriggerMode,
    detect_protocols: []protocol_detector.Protocol,
    wol_macs: []const []const u8,
    wol_cooldown_ms: u64,
    wol_log_enabled: bool,
    wol_wake_delay_ms: u32,
    wol_retry_interval_ms: u32,
    wol_retry_window_ms: u32,
    enable_protocol_filter: bool,
    allowed_protocols: []protocol_detector.Protocol,
    tls_allowed_snis: []const []const u8,

    fn init(allocator: std.mem.Allocator, cfg: *const types.Project, project_id: usize) !CallbackContext {
        const detect_protocols = try dupeProtocols(allocator, cfg.detect_protocols);
        errdefer allocator.free(detect_protocols);
        const allowed_protocols = try dupeProtocols(allocator, cfg.allowed_protocols);
        errdefer allocator.free(allowed_protocols);
        const wol_macs = try dupeStrings(allocator, cfg.resolved_wol_macs);
        errdefer freeStrings(allocator, wol_macs);
        const tls_allowed_snis = try dupeStrings(allocator, cfg.tls_allowed_snis);
        errdefer freeStrings(allocator, tls_allowed_snis);

        return .{
            .allocator = allocator,
            .project_id = project_id,
            .enable_wol = cfg.enable_wol,
            .wol_trigger_mode = cfg.wol_trigger_mode,
            .detect_protocols = detect_protocols,
            .wol_macs = wol_macs,
            .wol_cooldown_ms = cfg.resolved_wol_cooldown_ms,
            .wol_log_enabled = cfg.resolved_wol_log_enabled,
            .wol_wake_delay_ms = @intCast(cfg.resolved_wol_wake_delay_ms),
            .wol_retry_interval_ms = @intCast(cfg.resolved_wol_retry_interval_ms),
            .wol_retry_window_ms = @intCast(cfg.resolved_wol_retry_window_ms),
            .enable_protocol_filter = cfg.enable_protocol_filter,
            .allowed_protocols = allowed_protocols,
            .tls_allowed_snis = tls_allowed_snis,
        };
    }

    fn deinit(self: *CallbackContext) void {
        self.allocator.free(self.detect_protocols);
        self.allocator.free(self.allowed_protocols);
        freeStrings(self.allocator, self.wol_macs);
        freeStrings(self.allocator, self.tls_allowed_snis);
    }
};

fn dupeProtocols(allocator: std.mem.Allocator, names: []const []const u8) ![]protocol_detector.Protocol {
    const protocols = try allocator.alloc(protocol_detector.Protocol, names.len);
    errdefer allocator.free(protocols);
    for (names, 0..) |name, i| {
        protocols[i] = protocol_detector.protocolFromString(name) orelse return error.InvalidProtocol;
    }
    return protocols;
}

fn dupeStrings(allocator: std.mem.Allocator, strings: []const []const u8) ![]const []const u8 {
    const copies = try allocator.alloc([]const u8, strings.len);
    errdefer allocator.free(copies);
    var initialized: usize = 0;
    errdefer for (copies[0..initialized]) |copy| allocator.free(copy);
    for (strings, 0..) |string, i| {
        copies[i] = try allocator.dupe(u8, string);
        initialized += 1;
    }
    return copies;
}

fn freeStrings(allocator: std.mem.Allocator, strings: []const []const u8) void {
    for (strings) |string| allocator.free(string);
    allocator.free(strings);
}

/// Register the first-packet callback on a TCP forwarder.
/// Only call when enable_wol or enable_protocol_filter is true.
/// The context is heap-allocated and its lifetime is tied to the forwarder.
pub fn registerCallback(forwarder_ptr: ?*c.tcp_forwarder_t, allocator: std.mem.Allocator, cfg: *const types.Project, project_id: usize) !void {
    const forwarder = forwarder_ptr orelse return error.InvalidForwarder;
    const ctx = try allocator.create(CallbackContext);
    errdefer allocator.destroy(ctx);
    ctx.* = try CallbackContext.init(allocator, cfg, project_id);
    errdefer ctx.deinit();
    c.tcp_forwarder_set_first_packet_cb(forwarder, firstPacketCallback, @ptrCast(ctx), destroyCallbackContext);
    if (build_options.wol_mode and ctx.enable_wol) {
        const mode: c.tcp_wol_trigger_mode_t = switch (ctx.wol_trigger_mode) {
            .on_connect => c.TCP_WOL_ON_CONNECT,
            .on_protocol => c.TCP_WOL_ON_PROTOCOL,
        };
        c.tcp_forwarder_set_wol_policy(
            forwarder,
            mode,
            ctx.wol_wake_delay_ms,
            ctx.wol_retry_interval_ms,
            ctx.wol_retry_window_ms,
            triggerWakeCallback,
        );
    }
}

fn containsProtocol(protocols: []const protocol_detector.Protocol, needle: protocol_detector.Protocol) bool {
    for (protocols) |protocol| {
        if (protocol == needle) return true;
    }
    return false;
}

/// Match an SNI hostname against a pattern.
/// Supports exact case-insensitive match and wildcard patterns like "*.example.com".
fn matchSni(sni: []const u8, pattern: []const u8) bool {
    // Wildcard pattern: "*.example.com" matches "foo.example.com", "bar.baz.example.com"
    if (pattern.len >= 2 and pattern[0] == '*' and pattern[1] == '.') {
        const suffix = pattern[1..]; // ".example.com"
        if (sni.len >= suffix.len) {
            // Compare the suffix portion case-insensitively
            const sni_tail = sni[sni.len - suffix.len ..];
            if (std.ascii.eqlIgnoreCase(sni_tail, suffix)) {
                return true;
            }
        }
        return false;
    }
    // Exact case-insensitive match
    return std.ascii.eqlIgnoreCase(sni, pattern);
}

/// Check if an SNI matches any pattern in the allowed list.
fn matchAnySni(sni: []const u8, patterns: []const []const u8) bool {
    for (patterns) |pattern| {
        if (matchSni(sni, pattern)) return true;
    }
    return false;
}

/// Releases the immutable policy only after the backend drains all sessions.
fn destroyCallbackContext(user_data: ?*anyopaque) callconv(.c) void {
    const ctx: *CallbackContext = @ptrCast(@alignCast(user_data orelse return));
    const allocator = ctx.allocator;
    ctx.deinit();
    allocator.destroy(ctx);
}

fn enqueueWake(ctx: *const CallbackContext) bool {
    if (!build_options.wol_mode or ctx.wol_macs.len == 0) return false;
    const wol = @import("wol.zig");
    const result = wol.enqueueGlobal(ctx.wol_macs, ctx.wol_cooldown_ms, ctx.wol_log_enabled, @intCast(ctx.project_id));
    if (result.failed > 0) {
        std.log.warn("[WoL] failed to enqueue {d} magic packet(s)", .{result.failed});
    }
    return result.queued > 0;
}

fn triggerWakeCallback(user_data: ?*anyopaque) callconv(.c) c_int {
    const ctx: *CallbackContext = @ptrCast(@alignCast(user_data orelse return 0));
    return if (enqueueWake(ctx)) 1 else 0;
}

fn supportsDirection(protocol: protocol_detector.Protocol, is_client_to_target: bool) bool {
    return switch (protocol) {
        .vnc => !is_client_to_target,
        .ssh, .telnet => true,
        else => is_client_to_target,
    };
}

/// Incrementally inspects the accumulated initial payload in either direction.
fn firstPacketCallback(user_data: ?*anyopaque, data: [*c]const u8, len: usize, is_client_to_target: c_int) callconv(.c) c_int {
    const ctx: *CallbackContext = @ptrCast(@alignCast(user_data orelse return INSPECTION_ALLOW));
    const slice = data[0..len];

    const client_to_target = is_client_to_target != 0;
    if (!ctx.enable_protocol_filter and !(ctx.enable_wol and ctx.wol_trigger_mode == .on_protocol and client_to_target)) {
        return INSPECTION_ALLOW;
    }

    switch (protocol_detector.inspectProtocol(slice)) {
        .need_more => return INSPECTION_NEED_MORE,
        .unknown => {
            if (ctx.enable_protocol_filter) {
                event_log.logEvent(.connection_rejected, "Unknown protocol rejected", @intCast(ctx.project_id));
                return INSPECTION_REJECT;
            }
            return INSPECTION_ALLOW;
        },
        .matched => |protocol| {
            if (!supportsDirection(protocol, client_to_target)) {
                return if (len < protocol_detector.MAX_INSPECTION_BYTES) INSPECTION_NEED_MORE else INSPECTION_REJECT;
            }
            const proto_str = protocol_detector.protocolToString(protocol);
            event_log.logEventFmt(.protocol_detected, @intCast(ctx.project_id), "Detected protocol {s}", .{proto_str});

            // Protocol filtering: reject if not in allowed list
            if (ctx.enable_protocol_filter) {
                if (!containsProtocol(ctx.allowed_protocols, protocol)) {
                    std.log.info("[Hook:{d}] Protocol filter: rejecting {s} (not in allowed list)", .{ ctx.project_id, proto_str });
                    event_log.logEventFmt(.connection_rejected, @intCast(ctx.project_id), "Rejected protocol {s}", .{proto_str});
                    return INSPECTION_REJECT;
                }

                // TLS SNI filtering: if TLS is detected and SNI filter is configured
                if (protocol == .tls and ctx.tls_allowed_snis.len > 0) {
                    switch (protocol_detector.tlsPayloadState(slice)) {
                        .need_more => return INSPECTION_NEED_MORE,
                        .invalid => return INSPECTION_REJECT,
                        .complete => {},
                    }
                    const sni = protocol_detector.extractTlsSni(slice);
                    if (sni) |hostname| {
                        if (!matchAnySni(hostname, ctx.tls_allowed_snis)) {
                            std.log.info("[Hook:{d}] TLS SNI filter: rejecting {s} (not in allowed SNI list)", .{ ctx.project_id, hostname });
                            event_log.logEvent(.connection_rejected, "Rejected TLS SNI", @intCast(ctx.project_id));
                            return INSPECTION_REJECT;
                        }
                    } else {
                        std.log.info("[Hook:{d}] TLS SNI filter: rejecting connection (no SNI found)", .{ctx.project_id});
                        event_log.logEvent(.connection_rejected, "Rejected TLS connection without SNI", @intCast(ctx.project_id));
                        return INSPECTION_REJECT;
                    }
                }
            }

            // WoL: trigger if protocol is in detect list
            if (build_options.wol_mode and ctx.enable_wol and ctx.wol_trigger_mode == .on_protocol) {
                if (containsProtocol(ctx.detect_protocols, protocol)) {
                    _ = enqueueWake(ctx);
                    return INSPECTION_ALLOW_WAKE;
                }
            }
        },
    }

    return INSPECTION_ALLOW;
}

test "matchSni: exact and wildcard matching" {
    // Exact match (case-insensitive)
    try std.testing.expect(matchSni("example.com", "example.com"));
    try std.testing.expect(matchSni("Example.COM", "example.com"));
    try std.testing.expect(!matchSni("other.com", "example.com"));

    // Wildcard match
    try std.testing.expect(matchSni("foo.example.com", "*.example.com"));
    try std.testing.expect(matchSni("bar.baz.example.com", "*.example.com"));
    try std.testing.expect(matchSni("FOO.Example.COM", "*.example.com"));
    try std.testing.expect(!matchSni("example.com", "*.example.com"));
    try std.testing.expect(!matchSni("notexample.com", "*.example.com"));

    // Edge cases
    try std.testing.expect(!matchSni("", "*.example.com"));
    try std.testing.expect(matchSni("a.b", "*.b"));
}

test "callback context owns copied policy" {
    const allocator = std.testing.allocator;
    var cfg = types.Project{
        .listen_port = 10000,
        .target_address = "127.0.0.1",
        .target_port = 10001,
        .detect_protocols = &.{"rdp"},
        .allowed_protocols = &.{"tls"},
        .tls_allowed_snis = &.{"*.example.com"},
        .resolved_wol_macs = &.{"00:11:22:33:44:55"},
    };
    var ctx = try CallbackContext.init(allocator, &cfg, 7);
    defer ctx.deinit();

    try std.testing.expectEqual(protocol_detector.Protocol.rdp, ctx.detect_protocols[0]);
    try std.testing.expectEqual(protocol_detector.Protocol.tls, ctx.allowed_protocols[0]);
    try std.testing.expectEqualStrings("*.example.com", ctx.tls_allowed_snis[0]);
    try std.testing.expectEqualStrings("00:11:22:33:44:55", ctx.wol_macs[0]);
}

test "first packet callback waits for fragments and strictly rejects unknown data" {
    const allocator = std.testing.allocator;
    var cfg = types.Project{
        .listen_port = 10000,
        .target_address = "127.0.0.1",
        .target_port = 10001,
        .enable_protocol_filter = true,
        .allowed_protocols = &.{"rdp"},
    };
    var ctx = try CallbackContext.init(allocator, &cfg, 3);
    defer ctx.deinit();

    const rdp = [_]u8{ 0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00 };
    try std.testing.expectEqual(INSPECTION_NEED_MORE, firstPacketCallback(&ctx, rdp[0..6].ptr, 6, 1));
    try std.testing.expectEqual(INSPECTION_ALLOW, firstPacketCallback(&ctx, &rdp, rdp.len, 1));

    const unknown = [_]u8{0x7f} ** protocol_detector.MAX_INSPECTION_BYTES;
    try std.testing.expectEqual(INSPECTION_REJECT, firstPacketCallback(&ctx, &unknown, unknown.len, 1));
}
