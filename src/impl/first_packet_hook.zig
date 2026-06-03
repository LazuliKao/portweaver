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

/// C-compatible first-packet callback.
/// - Detects protocol using wol_detector
/// - Triggers WoL (placeholder) if protocol is in detect_protocols
/// - Returns 0 (reject) if protocol filter is enabled and protocol not in allowed_protocols
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
                std.log.info("[WoL:{d}] Protocol filter: rejecting {s} (not in allowed list)", .{ ctx.project_id, proto_str });
                return 0;
            }
        }

        // WoL: trigger if protocol is in detect list
        if (cfg.enable_wol) {
            if (containsProtocol(cfg.detect_protocols, proto_str)) {
                if (cfg.wol_mac_addresses.len > 0) {
                    const mgr = getWolManager(ctx.allocator);
                    wol.sendWoLWithCooldown(cfg.wol_mac_addresses, cfg.wol_cooldown_ms, mgr, @intCast(ctx.project_id));
                }
            }
        }
    }

    return 1;
}
