const std = @import("std");
const types = @import("../config/types.zig");
const protocol_detector = @import("protocol_detector.zig");
const forwarder_runtime = @import("app_forward/forwarder_runtime.zig");
const c = forwarder_runtime.c;
const wol = @import("wol.zig");
const compat = @import("../compat.zig");

/// Global WoL manager instance (lazy-initialized).
/// The callback is a C function and cannot capture state, so this must be module-level.
var g_wol_manager: ?wol.WolManager = null;
var g_wol_init_mutex: std.Io.Mutex = .init;

/// Get or initialize the global WolManager. Thread-safe via mutex.
fn getWolManager(allocator: std.mem.Allocator) *wol.WolManager {
    g_wol_init_mutex.lockUncancelable(compat.io());
    defer g_wol_init_mutex.unlock(compat.io());
    if (g_wol_manager == null) {
        g_wol_manager = wol.WolManager.init(allocator);
    }
    return &g_wol_manager.?;
}

/// Context passed as user_data to the C first-packet callback.
/// Stores a pointer to the project config (NOT ProjectHandle, to avoid
/// circular import: project_status → app_forward → wol_callback → project_status).
/// The allocator is stored so the context itself can be freed later.
pub const CallbackContext = struct {
    project_cfg: *const types.Project,
    allocator: std.mem.Allocator,
    project_id: usize,
};

/// Register the first-packet callback on a TCP forwarder.
/// Only call when enable_wol or enable_protocol_filter is true.
/// The context is heap-allocated and its lifetime is tied to the forwarder.
pub fn registerCallback(forwarder_ptr: ?*c.tcp_forwarder_t, allocator: std.mem.Allocator, cfg: *const types.Project, project_id: usize) void {
    if (forwarder_ptr == null) return;
    const ctx = allocator.create(CallbackContext) catch |err| {
        std.log.warn("[WoL] Failed to allocate callback context: {}", .{err});
        return;
    };
    ctx.* = .{
        .project_cfg = cfg,
        .allocator = allocator,
        .project_id = project_id,
    };
    c.tcp_forwarder_set_first_packet_cb(forwarder_ptr, firstPacketCallback, @ptrCast(ctx));
}

/// Case-insensitive check if a protocol string is in a list.
fn containsProtocol(protocols: []const []const u8, needle: []const u8) bool {
    for (protocols) |p| {
        if (std.ascii.eqlIgnoreCase(p, needle)) return true;
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

/// C-compatible first-packet callback.
/// - Detects protocol using protocol_detector
/// - Triggers WoL if protocol is in detect_protocols
/// - Returns 0 (reject) if protocol filter is enabled and protocol not in allowed_protocols
/// - For TLS: additionally checks SNI against tls_allowed_snis if configured
/// - Returns 1 (allow) otherwise
fn firstPacketCallback(user_data: ?*anyopaque, data: [*c]const u8, len: usize, is_client_to_target: c_int) callconv(.c) c_int {
    const ctx: *CallbackContext = @ptrCast(@alignCast(user_data orelse return 1));
    const cfg = ctx.project_cfg;
    const slice = data[0..len];

    // Only inspect client→target traffic; allow server→target responses
    if (is_client_to_target == 0) return 1;

    const detected = protocol_detector.detectProtocol(slice);
    if (detected) |protocol| {
        const proto_str = protocol_detector.protocolToString(protocol);

        // Protocol filtering: reject if not in allowed list
        if (cfg.enable_protocol_filter) {
            if (!containsProtocol(cfg.allowed_protocols, proto_str)) {
                std.log.info("[Hook:{d}] Protocol filter: rejecting {s} (not in allowed list)", .{ ctx.project_id, proto_str });
                return 0;
            }

            // TLS SNI filtering: if TLS is detected and SNI filter is configured
            if (protocol == .tls and cfg.tls_allowed_snis.len > 0) {
                const sni = protocol_detector.extractTlsSni(slice);
                if (sni) |hostname| {
                    if (!matchAnySni(hostname, cfg.tls_allowed_snis)) {
                        std.log.info("[Hook:{d}] TLS SNI filter: rejecting {s} (not in allowed SNI list)", .{ ctx.project_id, hostname });
                        return 0;
                    }
                } else {
                    // Cannot extract SNI — reject when SNI filter is enabled
                    std.log.info("[Hook:{d}] TLS SNI filter: rejecting connection (no SNI found)", .{ctx.project_id});
                    return 0;
                }
            }
        }

        // WoL: trigger if protocol is in detect list
        if (cfg.enable_wol) {
            if (containsProtocol(cfg.detect_protocols, proto_str)) {
                if (cfg.resolved_wol_macs.len > 0) {
                    const mgr = getWolManager(ctx.allocator);
                    wol.sendWoLWithCooldown(cfg.resolved_wol_macs, cfg.resolved_wol_cooldown_ms, cfg.resolved_wol_log_enabled, mgr, @intCast(ctx.project_id));
                }
            }
        }
    }

    return 1;
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
