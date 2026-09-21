const std = @import("std");
const types = @import("types.zig");
const wol = @import("../impl/wol.zig");
const protocol_detector = @import("../impl/protocol_detector.zig");

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
pub const WOL_WAKE_DELAY_MAX_MS: u64 = 300000;
pub const WOL_RETRY_INTERVAL_MIN_MS: u64 = 100;
pub const WOL_RETRY_WINDOW_MAX_MS: u64 = 300000;

fn containsProtocol(protocols: []const []const u8, needle: []const u8) bool {
    for (protocols) |protocol| {
        if (std.ascii.eqlIgnoreCase(protocol, needle)) return true;
    }
    return false;
}

fn hasDuplicateStrings(values: []const []const u8) bool {
    for (values, 0..) |value, index| {
        for (values[index + 1 ..]) |other| {
            if (std.ascii.eqlIgnoreCase(value, other)) return true;
        }
    }
    return false;
}

fn hasTcpMapping(project: *const types.Project) bool {
    if (project.port_mappings.len == 0) {
        return project.protocol != .udp;
    }
    for (project.port_mappings) |mapping| {
        if (mapping.protocol != .udp) return true;
    }
    return false;
}

fn supportsProtocolWake(protocol_name: []const u8) bool {
    const protocol = protocol_detector.protocolFromString(protocol_name) orelse return false;
    return switch (protocol) {
        .rdp, .http, .tls, .socks5, .postgresql, .minecraft, .mqtt, .smb => true,
        .ssh, .vnc, .telnet => false,
    };
}

fn isValidSniPattern(pattern: []const u8) bool {
    if (pattern.len == 0 or pattern.len > 253) return false;

    var hostname = pattern;
    if (std.mem.startsWith(u8, hostname, "*.")) {
        hostname = hostname[2..];
    } else if (std.mem.indexOfScalar(u8, hostname, '*') != null) {
        return false;
    }
    if (hostname.len == 0 or hostname[0] == '.' or hostname[hostname.len - 1] == '.') return false;

    var label_start: usize = 0;
    for (hostname, 0..) |char, index| {
        if (char == '.') {
            if (index == label_start or index - label_start > 63) return false;
            if (hostname[label_start] == '-' or hostname[index - 1] == '-') return false;
            label_start = index + 1;
        } else if (!std.ascii.isAlphanumeric(char) and char != '-') {
            return false;
        }
    }
    return hostname.len - label_start <= 63 and hostname[label_start] != '-' and hostname[hostname.len - 1] != '-';
}

/// Validate global features (rathole nodes/services and WoL targets).
pub fn validateGlobalConfig(config: *types.Config) !void {
    var rathole_client_nodes = config.rathole_client_nodes.iterator();
    while (rathole_client_nodes.next()) |entry| {
        const node = entry.value_ptr.*;
        const valid_source = switch (node.source.mode) {
            .builtin => node.remote_addr.len != 0,
            .external_file => node.source.path.len != 0,
            .external_uci => node.source.content.len != 0,
        };
        if (entry.key_ptr.*.len == 0 or !valid_source) {
            std.log.err("Config validation failed: rathole_client_node '{s}' missing remote_addr", .{entry.key_ptr.*});
            return types.ConfigError.InvalidValue;
        }
        if (node.source.mode == .builtin and node.transport == .noise and node.noise_remote_public_key.len == 0) {
            std.log.err("Config validation failed: rathole_client_node '{s}' missing noise_remote_public_key", .{entry.key_ptr.*});
            return types.ConfigError.InvalidValue;
        }
    }
    for (config.rathole_client_services, 0..) |service, index| {
        const node = config.rathole_client_nodes.get(service.node_name) orelse {
            std.log.err("Config validation failed: rathole_client_service '{s}' references unknown node '{s}'", .{ service.service_name, service.node_name });
            return types.ConfigError.InvalidValue;
        };
        // External TOML owns the service list, so retained UCI services are inactive.
        if (node.source.mode != .builtin) continue;
        if (service.node_name.len == 0 or service.service_name.len == 0 or service.local_address.len == 0 or service.local_port == 0) {
            std.log.err("Config validation failed: rathole_client_service '{s}' missing required fields", .{service.service_name});
            return types.ConfigError.InvalidValue;
        }
        if (service.enabled and node.enabled and service.token.len == 0 and node.default_token.len == 0) {
            std.log.err("Config validation failed: rathole_client_service '{s}' enabled without token", .{service.service_name});
            return types.ConfigError.InvalidValue;
        }
        for (config.rathole_client_services[index + 1 ..]) |other| {
            if (std.mem.eql(u8, service.node_name, other.node_name) and std.mem.eql(u8, service.service_name, other.service_name)) {
                std.log.err("Config validation failed: duplicate rathole_client_service '{s}' for node '{s}'", .{ service.service_name, service.node_name });
                return types.ConfigError.InvalidValue;
            }
        }
    }

    var rathole_server_nodes = config.rathole_server_nodes.iterator();
    while (rathole_server_nodes.next()) |entry| {
        const node = entry.value_ptr.*;
        const valid_source = switch (node.source.mode) {
            .builtin => node.bind_addr.len != 0,
            .external_file => node.source.path.len != 0,
            .external_uci => node.source.content.len != 0,
        };
        if (entry.key_ptr.*.len == 0 or !valid_source) {
            std.log.err("Config validation failed: rathole_server_node '{s}' missing bind_addr", .{entry.key_ptr.*});
            return types.ConfigError.InvalidValue;
        }
        if (node.source.mode == .builtin and node.transport == .noise and node.noise_local_private_key.len == 0) {
            std.log.err("Config validation failed: rathole_server_node '{s}' missing noise_local_private_key", .{entry.key_ptr.*});
            return types.ConfigError.InvalidValue;
        }
    }
    for (config.rathole_server_services, 0..) |service, index| {
        const node = config.rathole_server_nodes.get(service.node_name) orelse {
            std.log.err("Config validation failed: rathole_server_service '{s}' references unknown node '{s}'", .{ service.service_name, service.node_name });
            return types.ConfigError.InvalidValue;
        };
        // External TOML owns the service list, so retained UCI services are inactive.
        if (node.source.mode != .builtin) continue;
        if (service.node_name.len == 0 or service.service_name.len == 0 or service.bind_address.len == 0 or service.bind_port == 0) {
            std.log.err("Config validation failed: rathole_server_service '{s}' missing required fields", .{service.service_name});
            return types.ConfigError.InvalidValue;
        }
        if (service.enabled and node.enabled and service.token.len == 0 and node.default_token.len == 0) {
            std.log.err("Config validation failed: rathole_server_service '{s}' enabled without token", .{service.service_name});
            return types.ConfigError.InvalidValue;
        }
        for (config.rathole_server_services[index + 1 ..]) |other| {
            if (std.mem.eql(u8, service.node_name, other.node_name) and std.mem.eql(u8, service.service_name, other.service_name)) {
                std.log.err("Config validation failed: duplicate rathole_server_service '{s}' for node '{s}'", .{ service.service_name, service.node_name });
                return types.ConfigError.InvalidValue;
            }
        }
    }

    var target_it = config.wol_targets.iterator();
    while (target_it.next()) |entry| {
        const target = entry.value_ptr;
        if (entry.key_ptr.*.len == 0 or target.mac_addresses.len == 0) {
            std.log.err("Config validation: wol_target '{s}' has no MAC addresses", .{entry.key_ptr.*});
            return types.ConfigError.InvalidValue;
        }
        if (target.cooldown_ms < WOL_COOLDOWN_MIN_MS or target.cooldown_ms > WOL_COOLDOWN_MAX_MS) {
            std.log.err("Config validation: wol_target '{s}' cooldown_ms ({d}) out of bounds [{d}, {d}]", .{ entry.key_ptr.*, target.cooldown_ms, WOL_COOLDOWN_MIN_MS, WOL_COOLDOWN_MAX_MS });
            return types.ConfigError.InvalidValue;
        }
        if (target.wake_delay_ms > WOL_WAKE_DELAY_MAX_MS or
            target.retry_interval_ms < WOL_RETRY_INTERVAL_MIN_MS or
            target.retry_window_ms == 0 or
            target.retry_window_ms > WOL_RETRY_WINDOW_MAX_MS or
            target.wake_delay_ms > target.retry_window_ms or
            target.retry_interval_ms > target.retry_window_ms)
        {
            std.log.err("Config validation: wol_target '{s}' has invalid retry/delay timing parameters", .{entry.key_ptr.*});
            return types.ConfigError.InvalidValue;
        }
        if (hasDuplicateStrings(target.mac_addresses)) {
            std.log.err("Config validation: wol_target '{s}' has duplicate MAC addresses", .{entry.key_ptr.*});
            return types.ConfigError.InvalidValue;
        }
        for (target.mac_addresses) |mac| {
            if (wol.parseMac(mac) == null) {
                std.log.err("Config validation: wol_target '{s}' has invalid MAC address '{s}'", .{ entry.key_ptr.*, mac });
                return types.ConfigError.InvalidValue;
            }
        }
    }
}

/// Validates a project and allocates implicit owned fields against global targets.
pub fn validateProject(allocator: std.mem.Allocator, project: *types.Project, config: *const types.Config) !void {
    const p_name = if (project.remark.len > 0) project.remark else if (project.section_name.len > 0) project.section_name else "unnamed";

    if (hasDuplicateStrings(project.detect_protocols) or
        hasDuplicateStrings(project.allowed_protocols) or
        hasDuplicateStrings(project.tls_allowed_snis))
    {
        std.log.warn("Project '{s}': duplicate protocol or SNI entries found", .{p_name});
        return types.ConfigError.InvalidValue;
    }

    for (project.detect_protocols) |protocol| {
        if (protocol_detector.protocolFromString(protocol) == null) {
            std.log.warn("Project '{s}': unknown detect_protocol '{s}'", .{ p_name, protocol });
            return types.ConfigError.InvalidValue;
        }
    }
    for (project.allowed_protocols) |protocol| {
        if (protocol_detector.protocolFromString(protocol) == null) {
            std.log.warn("Project '{s}': unknown allowed_protocol '{s}'", .{ p_name, protocol });
            return types.ConfigError.InvalidValue;
        }
    }
    for (project.tls_allowed_snis) |pattern| {
        if (!isValidSniPattern(pattern)) {
            std.log.warn("Project '{s}': invalid TLS SNI pattern '{s}'", .{ p_name, pattern });
            return types.ConfigError.InvalidValue;
        }
    }

    if (project.enable_wol or project.enable_protocol_filter) {
        if (!project.enable_app_forward or !hasTcpMapping(project)) {
            std.log.warn("Project '{s}': WoL and protocol filter require enable_app_forward=true and TCP mapping", .{p_name});
            return types.ConfigError.InvalidValue;
        }
    }

    if (project.enable_wol) {
        if (project.wol_target.len == 0) {
            // Auto-fallback: if there is exactly one WoL target in the system, adopt it with a warning
            if (config.wol_targets.count() == 1) {
                var it = config.wol_targets.iterator();
                if (it.next()) |only_target| {
                    std.log.warn("Project '{s}': enable_wol is true but wol_target is not specified; defaulting to only configured target '{s}'", .{ p_name, only_target.key_ptr.* });
                    project.wol_target = try allocator.dupe(u8, only_target.key_ptr.*);
                }
            } else {
                std.log.warn("Project '{s}': enable_wol is true but wol_target is not specified ({d} targets available)", .{ p_name, config.wol_targets.count() });
                return types.ConfigError.InvalidValue;
            }
        }

        const target = config.wol_targets.get(project.wol_target) orelse {
            std.log.warn("Project '{s}': references non-existent wol_target '{s}'", .{ p_name, project.wol_target });
            return types.ConfigError.InvalidValue;
        };
        if (!target.enabled or target.mac_addresses.len == 0) {
            std.log.warn("Project '{s}': references disabled or empty wol_target '{s}'", .{ p_name, project.wol_target });
            return types.ConfigError.InvalidValue;
        }

        if (project.wol_trigger_mode == .on_protocol) {
            if (project.detect_protocols.len == 0) {
                std.log.warn("Project '{s}': on_protocol WoL requires detect_protocols", .{p_name});
                return types.ConfigError.InvalidValue;
            }
            for (project.detect_protocols) |protocol| {
                if (!supportsProtocolWake(protocol)) {
                    std.log.warn("Project '{s}': detect_protocol '{s}' does not support WoL wake", .{ p_name, protocol });
                    return types.ConfigError.InvalidValue;
                }
            }
        }
    }

    if (project.enable_protocol_filter and project.allowed_protocols.len == 0) {
        std.log.warn("Project '{s}': enable_protocol_filter is true but allowed_protocols is empty", .{p_name});
        return types.ConfigError.InvalidValue;
    }
    if (project.tls_allowed_snis.len > 0 and
        (!project.enable_protocol_filter or !containsProtocol(project.allowed_protocols, "tls")))
    {
        std.log.warn("Project '{s}': tls_allowed_snis requires enable_protocol_filter and 'tls' in allowed_protocols", .{p_name});
        return types.ConfigError.InvalidValue;
    }
}

/// Validate all WoL targets and project feature invariants after parsing.
pub fn validateConfig(allocator: std.mem.Allocator, config: *types.Config) !void {
    try validateGlobalConfig(config);
    for (config.projects) |*project| {
        try validateProject(allocator, project, config);
    }
}

/// Reject runtime configuration that requests features omitted from this build.
pub fn validateFeatureAvailability(config: *types.Config, wol_available: bool) !void {
    if (wol_available) return;
    for (config.projects) |*project| {
        if (project.enable_wol) {
            std.log.warn("Project '{s}': WoL requested but not enabled in this build; disabling WoL for this project", .{project.remark});
            project.enable_wol = false;
        }
    }
}

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
/// This field-level helper is retained for callers that need error counts.
pub fn validateWolConfig(project: *const types.Project) WolValidationResult {
    var result = WolValidationResult{};

    // Validate MAC addresses
    for (project.resolved_wol_macs) |mac_str| {
        if (wol.parseMac(mac_str) == null) {
            result.mac_errors += 1;
            if (result.first_error.len == 0) {
                result.first_error = "Invalid MAC address";
            }
        }
    }

    // Validate detect_protocols
    for (project.detect_protocols) |proto_name| {
        if (protocol_detector.protocolFromString(proto_name) == null) {
            result.protocol_errors += 1;
            if (result.first_error.len == 0) {
                result.first_error = "Invalid protocol name in detect_protocols";
            }
        }
    }

    // Validate allowed_protocols
    for (project.allowed_protocols) |proto_name| {
        if (protocol_detector.protocolFromString(proto_name) == null) {
            result.protocol_errors += 1;
            if (result.first_error.len == 0) {
                result.first_error = "Invalid protocol name in allowed_protocols";
            }
        }
    }

    // Validate cooldown range
    if (project.resolved_wol_cooldown_ms < WOL_COOLDOWN_MIN_MS or project.resolved_wol_cooldown_ms > WOL_COOLDOWN_MAX_MS) {
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
        .resolved_wol_macs = &.{ "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66" },
        .detect_protocols = &.{ "rdp", "ssh" },
        .allowed_protocols = &.{ "rdp", "ssh", "http" },
        .resolved_wol_cooldown_ms = 30000,
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
        .resolved_wol_macs = &.{ "AA:BB:CC:DD:EE:FF", "not-a-mac" },
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
        .resolved_wol_cooldown_ms = 500,
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
        .resolved_wol_cooldown_ms = 400000,
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
        .resolved_wol_cooldown_ms = 1000,
    };
    try std.testing.expect(validateWolConfig(&proj_min).isValid());

    // At max boundary (300000)
    const proj_max = types.Project{
        .listen_port = 3389,
        .target_address = "192.168.1.100",
        .target_port = 3389,
        .resolved_wol_cooldown_ms = 300000,
    };
    try std.testing.expect(validateWolConfig(&proj_max).isValid());
}

test "validateWolConfig: multiple errors collected" {
    const proj = types.Project{
        .listen_port = 3389,
        .target_address = "192.168.1.100",
        .target_port = 3389,
        .resolved_wol_macs = &.{ "bad-mac1", "bad-mac2" },
        .detect_protocols = &.{"fakeproto"},
        .resolved_wol_cooldown_ms = 50,
    };
    const result = validateWolConfig(&proj);
    try std.testing.expect(!result.isValid());
    try std.testing.expectEqual(@as(u32, 2), result.mac_errors);
    try std.testing.expectEqual(@as(u32, 1), result.protocol_errors);
    try std.testing.expect(result.cooldown_error);
}
