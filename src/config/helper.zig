const std = @import("std");
const types = @import("types.zig");

/// Parse a port mapping string in the format: "[listen_port][frp_node:port]...:target_port/protocol"
/// Examples:
///   "[8080][node1:9888][node2:9999]:80/tcp"  - with FRP nodes
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

    var frp_list = std.array_list.Managed(types.FrpForward).init(allocator);
    errdefer {
        for (frp_list.items) |*f| f.deinit(allocator);
        frp_list.deinit();
    }

    // 解析格式：[port][frp1][frp2]:target/protocol
    var work_str = trimmed;
    var listen_port_str: ?[]const u8 = null;

    // 提取所有 [] 包裹的部分
    while (std.mem.startsWith(u8, work_str, "[")) {
        const close_idx = std.mem.indexOf(u8, work_str, "]") orelse return types.ConfigError.InvalidValue;
        const content = work_str[1..close_idx];
        work_str = std.mem.trim(u8, work_str[close_idx + 1 ..], " \t\r\n");

        // 判断是端口还是 FRP 节点
        if (std.mem.indexOf(u8, content, ":")) |colon_pos| {
            // 包含 ':'  -> FRP 节点
            const node_name = std.mem.trim(u8, content[0..colon_pos], " \t\r\n");
            const port_str = std.mem.trim(u8, content[colon_pos + 1 ..], " \t\r\n");

            if (node_name.len == 0) return types.ConfigError.InvalidValue;
            const port = try types.parsePort(port_str);

            try frp_list.append(.{
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

    if (frp_list.items.len > 0) {
        mapping.frp = try frp_list.toOwnedSlice();
    }

    return mapping;
}

/// Parse FRP forward string like "node:port" or just "node" (port defaults to 0).
pub fn parseFrpForwardString(allocator: std.mem.Allocator, s: []const u8) !types.FrpForward {
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

test "parsePortMapping tests" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 测试字符串
    const test_cases = [_][]const u8{
        "[2][node1:9888]:80/tcp",
        "[2][node1:9888][node2:9999]:80/tcp",
        "2:80/tcp",
        "[2]:80/tcp",
    };

    std.debug.print("测试 FRP 格式解析:\n", .{});
    for (test_cases) |test_str| {
        var result = parsePortMapping(allocator, test_str) catch |err| {
            std.debug.print("输入: {s}\n  -> 解析失败：{any}\n", .{ test_str, err });
            continue;
        };
        defer result.deinit(allocator);
        std.debug.print("\n输入: {s}\n", .{test_str});
        std.debug.print("  -> 解析成功：{any}\n", .{result});
    }
}
