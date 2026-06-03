const std = @import("std");
const types = @import("types.zig");
const wol = @import("../impl/wol.zig");
const wol_detector = @import("../impl/wol_detector.zig");

/// Parse a port mapping string in the format: "[listen_port][frpc_node:port]...:target_port/protocol"
/// Examples:
///   "[8080][node1:9888][node2:9999]:80/tcp"  - with FRPC nodes
///   "8080-8090:80-90/udp"  - port range with protocol
///   "443:8443/tcp"         - single port with protocol
///   "80"                   - single port (tcp default, target_port = listen_port)
///   "8080:80"              - single port with different target (tcp default)
pub fn parsePortMapping(allocator: std.mem.Allocator, s: []const u8) !types.PortMapping {
    const trimmed = std.mem.trim(u8, s, " \t\r\n");
    if (trimmed.len == 0) return types.ConfigError.InvalidValue;

    var mapping = types.PortMapping{
        .listen_port = undefined,
        .target_port = undefined,
        .protocol = .tcp,
    };
    errdefer mapping.deinit(allocator);

    var frpc_list = std.array_list.Managed(types.FrpcForward).init(allocator);
    errdefer {
        for (frpc_list.items) |*f| f.deinit(allocator);
        frpc_list.deinit();
    }

    // 解析格式：[port][frpc1][frpc2]:target/protocol
    var work_str = trimmed;
    var listen_port_str: ?[]const u8 = null;

    // 提取所有 [] 包裹的部分
    while (std.mem.startsWith(u8, work_str, "[")) {
        const close_idx = std.mem.indexOf(u8, work_str, "]") orelse return types.ConfigError.InvalidValue;
        const content = work_str[1..close_idx];
        work_str = std.mem.trim(u8, work_str[close_idx + 1 ..], " \t\r\n");

        // 判断是端口还是 FRPC 节点
        if (std.mem.indexOf(u8, content, ":")) |colon_pos| {
            // 包含 ':'  -> FRPC 节点
            const node_name = std.mem.trim(u8, content[0..colon_pos], " \t\r\n");
            const port_str = std.mem.trim(u8, content[colon_pos + 1 ..], " \t\r\n");

            if (node_name.len == 0) return types.ConfigError.InvalidValue;
            const port = try types.parsePort(port_str);

            try frpc_list.append(.{
                .node_name = try allocator.dupe(u8, node_name),
                .remote_port = port,
            });
        } else {
            // 不包含 ':' -> 监听端口
            if (listen_port_str != null) return types.ConfigError.InvalidValue; // 只能有一个监听端口
            listen_port_str = content;
        }
    }

    // 剩余部分: :target_port/protocol 或 target_port/protocol
    // Split by '/' to extract protocol
    var protocol_split = std.mem.splitScalar(u8, work_str, '/');
    const port_part = protocol_split.next() orelse return types.ConfigError.InvalidValue;

    if (protocol_split.next()) |proto_str| {
        mapping.protocol = try types.parseProtocol(proto_str);
    }

    // 解析 port_part：可能是 ":target" 或 "listen:target" 或 "listen"
    var port_split = std.mem.splitScalar(u8, port_part, ':');
    const first_part = port_split.next() orelse return types.ConfigError.InvalidValue;

    if (port_split.next()) |target_str| {
        // 有 ':'，格式为 listen:target
        const trimmed_target = std.mem.trim(u8, target_str, " \t\r\n");
        mapping.target_port = try allocator.dupe(u8, trimmed_target);

        const trimmed_first = std.mem.trim(u8, first_part, " \t\r\n");
        if (trimmed_first.len > 0) {
            // 有 listen_port 在 ':' 之前
            if (listen_port_str != null) return types.ConfigError.InvalidValue; // 冲突
            mapping.listen_port = try allocator.dupe(u8, trimmed_first);
        } else {
            // ':' 之前为空，使用 [] 中的 listen_port
            if (listen_port_str == null) return types.ConfigError.InvalidValue;
            mapping.listen_port = try allocator.dupe(u8, listen_port_str.?);
        }
    } else {
        // 没有 ':'，只有一个部分
        const trimmed_first = std.mem.trim(u8, first_part, " \t\r\n");

        if (listen_port_str) |lps| {
            // 已经从 [] 中提取了 listen_port
            mapping.listen_port = try allocator.dupe(u8, lps);
            if (trimmed_first.len > 0) {
                mapping.target_port = try allocator.dupe(u8, trimmed_first);
            } else {
                // 没有 target，使用 listen
                mapping.target_port = try allocator.dupe(u8, lps);
            }
        } else {
            // 没有 [] 提取，使用 first_part 作为 listen
            if (trimmed_first.len == 0) return types.ConfigError.InvalidValue;
            mapping.listen_port = try allocator.dupe(u8, trimmed_first);
            mapping.target_port = try allocator.dupe(u8, trimmed_first);
        }
    }

    // Validate port string formats (single port or range)
    try types.validatePortString(mapping.listen_port);
    try types.validatePortString(mapping.target_port);

    // If listen is a range, ensure target is also a range and sizes match.
    const listen_dash = std.mem.indexOf(u8, mapping.listen_port, "-");
    const target_dash = std.mem.indexOf(u8, mapping.target_port, "-");

    if (listen_dash) |ld| {
        if (target_dash == null) return types.ConfigError.InvalidValue;

        const l_start = try types.parsePort(mapping.listen_port[0..ld]);
        const l_end = try types.parsePort(mapping.listen_port[ld + 1 ..]);
        const td = target_dash.?; // already checked availability
        const t_start = try types.parsePort(mapping.target_port[0..td]);
        const t_end = try types.parsePort(mapping.target_port[td + 1 ..]);

        if (l_end - l_start != t_end - t_start) return types.ConfigError.InvalidValue;
    } else if (target_dash != null) {
        // target is a range but listen is single -> invalid
        return types.ConfigError.InvalidValue;
    }

    if (frpc_list.items.len > 0) {
        mapping.frpc = try frpc_list.toOwnedSlice();
    }

    return mapping;
}

/// Parse FRPC forward string like "node:port" or just "node" (port defaults to 0).
pub fn parseFrpcForwardString(allocator: std.mem.Allocator, s: []const u8) !types.FrpcForward {
    const trimmed = std.mem.trim(u8, s, " \t\r\n");
    if (trimmed.len == 0) return types.ConfigError.InvalidValue;

    if (std.mem.indexOf(u8, trimmed, ":")) |colon_pos| {
        const node_name = std.mem.trim(u8, trimmed[0..colon_pos], " \t\r\n");
        const port_str = std.mem.trim(u8, trimmed[colon_pos + 1 ..], " \t\r\n");

        if (node_name.len == 0) return types.ConfigError.InvalidValue;
        const port = try types.parsePort(port_str);

        return .{ .node_name = try allocator.dupe(u8, node_name), .remote_port = port };
    }

    // No explicit port; default to 0 (server may assign).
    return .{ .node_name = try allocator.dupe(u8, trimmed), .remote_port = 0 };
}

/// Minimum cooldown in milliseconds (1 second)
pub const WOL_COOLDOWN_MIN_MS: u64 = 1000;
/// Maximum cooldown in milliseconds (5 minutes)
pub const WOL_COOLDOWN_MAX_MS: u64 = 300000;

/// Result of WoL config validation. Collects errors without requiring an allocator.
pub const WolValidationResult = struct {
    mac_errors: u32 = 0,
    protocol_errors: u32 = 0,
    cooldown_error: bool = false,
    first_error: []const u8 = "",

    pub fn isValid(self: WolValidationResult) bool {
        return self.mac_errors == 0 and self.protocol_errors == 0 and !self.cooldown_error;
    }
};

/// Validate WoL and protocol filter configuration fields.
/// Returns a WolValidationResult indicating whether the config is valid.
/// Empty lists are considered valid (use defaults).
pub fn validateWolConfig(project: *const types.Project) WolValidationResult {
    var result = WolValidationResult{};

    // Validate MAC addresses
    for (project.wol_mac_addresses) |mac_str| {
        if (wol.parseMac(mac_str) == null) {
            result.mac_errors += 1;
            if (result.first_error.len == 0) {
                result.first_error = "Invalid MAC address";
            }
        }
    }

    // Validate detect_protocols
    for (project.detect_protocols) |proto_name| {
        if (wol_detector.protocolFromString(proto_name) == null) {
            result.protocol_errors += 1;
            if (result.first_error.len == 0) {
                result.first_error = "Invalid protocol name in detect_protocols";
            }
        }
    }

    // Validate allowed_protocols
    for (project.allowed_protocols) |proto_name| {
        if (wol_detector.protocolFromString(proto_name) == null) {
            result.protocol_errors += 1;
            if (result.first_error.len == 0) {
                result.first_error = "Invalid protocol name in allowed_protocols";
            }
        }
    }

    // Validate cooldown range
    if (project.wol_cooldown_ms < WOL_COOLDOWN_MIN_MS or project.wol_cooldown_ms > WOL_COOLDOWN_MAX_MS) {
        result.cooldown_error = true;
        if (result.first_error.len == 0) {
            result.first_error = "Cooldown out of range";
        }
    }

    return result;
}
test "parsePortMapping tests" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 测试字符串
    const test_cases = [_][]const u8{
        "[2][node1:9888]:80/tcp",
        "[2][node1:9888][node2:9999]:80/tcp",
        "2:80/tcp",
        "[2]:80/tcp",
    };

    for (test_cases) |test_str| {
        var result = try parsePortMapping(allocator, test_str);
        defer result.deinit(allocator);
    }
}

test "validateWolConfig: valid config with all fields passes" {
    const proj = types.Project{
        .listen_port = 3389,
        .target_address = "192.168.1.100",
        .target_port = 3389,
        .enable_wol = true,
        .wol_mac_addresses = &.{ "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66" },
        .detect_protocols = &.{ "rdp", "ssh" },
        .allowed_protocols = &.{ "rdp", "ssh", "http" },
        .wol_cooldown_ms = 30000,
        .enable_protocol_filter = true,
    };
    const result = validateWolConfig(&proj);
    try std.testing.expect(result.isValid());
}

test "validateWolConfig: empty lists are valid (defaults)" {
    const proj = types.Project{
        .listen_port = 3389,
        .target_address = "192.168.1.100",
        .target_port = 3389,
    };
    const result = validateWolConfig(&proj);
    try std.testing.expect(result.isValid());
}

test "validateWolConfig: invalid MAC address rejected" {
    const proj = types.Project{
        .listen_port = 3389,
        .target_address = "192.168.1.100",
        .target_port = 3389,
        .enable_wol = true,
        .wol_mac_addresses = &.{ "AA:BB:CC:DD:EE:FF", "not-a-mac" },
    };
    const result = validateWolConfig(&proj);
    try std.testing.expect(!result.isValid());
    try std.testing.expectEqual(@as(u32, 1), result.mac_errors);
}

test "validateWolConfig: invalid protocol in detect_protocols rejected" {
    const proj = types.Project{
        .listen_port = 3389,
        .target_address = "192.168.1.100",
        .target_port = 3389,
        .detect_protocols = &.{ "rdp", "invalidproto" },
    };
    const result = validateWolConfig(&proj);
    try std.testing.expect(!result.isValid());
    try std.testing.expectEqual(@as(u32, 1), result.protocol_errors);
}

test "validateWolConfig: invalid protocol in allowed_protocols rejected" {
    const proj = types.Project{
        .listen_port = 3389,
        .target_address = "192.168.1.100",
        .target_port = 3389,
        .enable_protocol_filter = true,
        .allowed_protocols = &.{ "rdp", "unknown" },
    };
    const result = validateWolConfig(&proj);
    try std.testing.expect(!result.isValid());
    try std.testing.expectEqual(@as(u32, 1), result.protocol_errors);
}

test "validateWolConfig: cooldown too low rejected" {
    const proj = types.Project{
        .listen_port = 3389,
        .target_address = "192.168.1.100",
        .target_port = 3389,
        .wol_cooldown_ms = 500,
    };
    const result = validateWolConfig(&proj);
    try std.testing.expect(!result.isValid());
    try std.testing.expect(result.cooldown_error);
}

test "validateWolConfig: cooldown too high rejected" {
    const proj = types.Project{
        .listen_port = 3389,
        .target_address = "192.168.1.100",
        .target_port = 3389,
        .wol_cooldown_ms = 400000,
    };
    const result = validateWolConfig(&proj);
    try std.testing.expect(!result.isValid());
    try std.testing.expect(result.cooldown_error);
}

test "validateWolConfig: cooldown at boundaries accepted" {
    // At min boundary (1000)
    const proj_min = types.Project{
        .listen_port = 3389,
        .target_address = "192.168.1.100",
        .target_port = 3389,
        .wol_cooldown_ms = 1000,
    };
    try std.testing.expect(validateWolConfig(&proj_min).isValid());

    // At max boundary (300000)
    const proj_max = types.Project{
        .listen_port = 3389,
        .target_address = "192.168.1.100",
        .target_port = 3389,
        .wol_cooldown_ms = 300000,
    };
    try std.testing.expect(validateWolConfig(&proj_max).isValid());
}

test "validateWolConfig: multiple errors collected" {
    const proj = types.Project{
        .listen_port = 3389,
        .target_address = "192.168.1.100",
        .target_port = 3389,
        .wol_mac_addresses = &.{ "bad-mac1", "bad-mac2" },
        .detect_protocols = &.{"fakeproto"},
        .wol_cooldown_ms = 50,
    };
    const result = validateWolConfig(&proj);
    try std.testing.expect(!result.isValid());
    try std.testing.expectEqual(@as(u32, 2), result.mac_errors);
    try std.testing.expectEqual(@as(u32, 1), result.protocol_errors);
    try std.testing.expect(result.cooldown_error);
}
