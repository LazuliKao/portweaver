const std = @import("std");
const types = @import("types.zig");
const helper = @import("helper.zig");

fn parseJsonBool(v: std.json.Value) !bool {
    return switch (v) {
        .bool => |b| b,
        .integer => |i| i != 0,
        .string => |s| try types.parseBool(s),
        else => types.ConfigError.InvalidValue,
    };
}

fn parseJsonPort(v: std.json.Value) !u16 {
    return switch (v) {
        .integer => |i| {
            if (i <= 0 or i > 65535) return types.ConfigError.InvalidValue;
            return @intCast(i);
        },
        .string => |s| try types.parsePort(s),
        else => types.ConfigError.InvalidValue,
    };
}

fn parseJsonString(v: std.json.Value) ![]const u8 {
    return switch (v) {
        .string => |s| s,
        else => types.ConfigError.InvalidValue,
    };
}

fn parseJsonPortString(v: std.json.Value, allocator: std.mem.Allocator) ![]const u8 {
    switch (v) {
        .integer => |i| {
            if (i <= 0 or i > 65535) return types.ConfigError.InvalidValue;
            // 对于整数，直接分配并返回，无需额外的 dupe
            const result = try std.fmt.allocPrint(allocator, "{d}", .{i});
            try types.validatePortString(result);
            return result;
        },
        .string => |str| {
            // 对于字符串，需要 trim 和 dupe（因为 JSON 缓冲区会被释放）
            const trimmed = std.mem.trim(u8, str, " \t\r\n");
            try types.validatePortString(trimmed);
            return try allocator.dupe(u8, trimmed);
        },
        else => return types.ConfigError.InvalidValue,
    }
}

fn appendZoneString(list: *std.array_list.Managed([]const u8), allocator: std.mem.Allocator, s: []const u8) !void {
    const trimmed = std.mem.trim(u8, s, " \t\r\n");
    if (trimmed.len == 0) return;
    try list.append(try allocator.dupe(u8, trimmed));
}

fn parseJsonZones(
    allocator: std.mem.Allocator,
    v: std.json.Value,
    out: *std.array_list.Managed([]const u8),
) !void {
    switch (v) {
        .string => |s| try appendZoneString(out, allocator, s),
        .array => |a| {
            for (a.items) |item| {
                const s = try parseJsonString(item);
                try appendZoneString(out, allocator, s);
            }
        },
        else => return types.ConfigError.InvalidValue,
    }
}

fn parseJsonFrpcForwards(
    allocator: std.mem.Allocator,
    v: std.json.Value,
) ![]types.FrpcForward {
    var list = std.array_list.Managed(types.FrpcForward).init(allocator);
    errdefer {
        for (list.items) |*f| f.deinit(allocator);
        list.deinit();
    }

    switch (v) {
        .string => |s| {
            const fwd = try helper.parseFrpcForwardString(allocator, s);
            try list.append(fwd);
        },
        .array => |a| {
            for (a.items) |item| {
                const s = try parseJsonString(item);
                const fwd = try helper.parseFrpcForwardString(allocator, s);
                try list.append(fwd);
            }
        },
        else => return types.ConfigError.InvalidValue,
    }

    return try list.toOwnedSlice();
}

pub fn loadFromJsonFile(allocator: std.mem.Allocator, path: []const u8) !types.Config {
    std.fs.cwd().access(path, .{}) catch |err| {
        std.log.debug("File not found: {s}", .{path});
        return err;
    };
    const json_text = std.fs.cwd().readFileAlloc(allocator, path, 1 << 20) catch return types.ConfigError.JsonParseError;
    defer allocator.free(json_text);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_text, .{}) catch return types.ConfigError.JsonParseError;
    defer parsed.deinit();

    var list = std.array_list.Managed(types.Project).init(allocator);
    errdefer {
        for (list.items) |*p| p.deinit(allocator);
        list.deinit();
    }

    const root = parsed.value;
    const projects_value: std.json.Value = switch (root) {
        .array => root,
        .object => |o| o.get("projects") orelse return types.ConfigError.MissingField,
        else => return types.ConfigError.InvalidValue,
    };

    if (projects_value != .array) return types.ConfigError.InvalidValue;

    for (projects_value.array.items) |item| {
        if (item != .object) return types.ConfigError.InvalidValue;
        const obj = item.object;

        var project = types.Project{
            .listen_port = 0,
            .target_address = undefined,
            .target_port = 0,
        };

        var have_listen_port = false;
        var have_target_address = false;
        var have_target_port = false;

        var src_zones_list = std.array_list.Managed([]const u8).init(allocator);
        defer src_zones_list.deinit();
        errdefer {
            for (src_zones_list.items) |z| allocator.free(z);
        }

        var dest_zones_list = std.array_list.Managed([]const u8).init(allocator);
        defer dest_zones_list.deinit();
        errdefer {
            for (dest_zones_list.items) |z| allocator.free(z);
        }

        var port_mappings_list = std.array_list.Managed(types.PortMapping).init(allocator);
        defer port_mappings_list.deinit();
        errdefer {
            for (port_mappings_list.items) |*pm| pm.deinit(allocator);
        }

        if (obj.get("remark")) |v| {
            const s = try parseJsonString(v);
            project.remark = try types.dupeIfNonEmpty(allocator, s);
        }

        if (obj.get("src_zone")) |v| {
            try parseJsonZones(allocator, v, &src_zones_list);
        }

        if (obj.get("dest_zone")) |v| {
            try parseJsonZones(allocator, v, &dest_zones_list);
        }

        if (obj.get("family")) |v| {
            const s = try parseJsonString(v);
            project.family = try types.parseFamily(s);
        }

        if (obj.get("protocol")) |v| {
            const s = try parseJsonString(v);
            project.protocol = try types.parseProtocol(s);
        }

        if (obj.get("listen_port")) |v| {
            project.listen_port = try parseJsonPort(v);
            have_listen_port = true;
        }

        if (obj.get("reuseaddr")) |v| {
            project.reuseaddr = try parseJsonBool(v);
        }

        if (obj.get("target_address")) |v| {
            const s = try parseJsonString(v);
            const trimmed = std.mem.trim(u8, s, " \t\r\n");
            if (trimmed.len == 0) return types.ConfigError.InvalidValue;
            project.target_address = try allocator.dupe(u8, trimmed);
            have_target_address = true;
        }

        if (obj.get("target_port")) |v| {
            project.target_port = try parseJsonPort(v);
            have_target_port = true;
        }

        if (obj.get("open_firewall_port")) |v| {
            project.open_firewall_port = try parseJsonBool(v);
        }

        if (obj.get("add_firewall_forward")) |v| {
            project.add_firewall_forward = try parseJsonBool(v);
        }

        if (obj.get("enable_app_forward")) |v| {
            project.enable_app_forward = try parseJsonBool(v);
        }

        // 解析 port_mappings 数组
        if (obj.get("port_mappings")) |v| {
            if (v != .array) return types.ConfigError.InvalidValue;

            for (v.array.items) |mapping_item| {
                if (mapping_item != .object) return types.ConfigError.InvalidValue;
                const mapping_obj = mapping_item.object;

                var port_mapping = types.PortMapping{
                    .listen_port = undefined,
                    .target_port = undefined,
                };

                var have_listen = false;
                var have_target = false;

                if (mapping_obj.get("listen_port")) |port_v| {
                    port_mapping.listen_port = try parseJsonPortString(port_v, allocator);
                    have_listen = true;
                }

                if (mapping_obj.get("target_port")) |port_v| {
                    port_mapping.target_port = try parseJsonPortString(port_v, allocator);
                    have_target = true;
                }

                if (mapping_obj.get("protocol")) |proto_v| {
                    const s = try parseJsonString(proto_v);
                    port_mapping.protocol = try types.parseProtocol(s);
                }

                // 解析 FRPC 转发
                if (mapping_obj.get("frpc")) |frpc_v| {
                    port_mapping.frpc = try parseJsonFrpcForwards(allocator, frpc_v);
                }

                if (!have_listen or !have_target) {
                    if (have_listen) allocator.free(port_mapping.listen_port);
                    if (have_target) allocator.free(port_mapping.target_port);
                    return types.ConfigError.MissingField;
                }

                try port_mappings_list.append(port_mapping);
            }
        }

        // 验证配置：单端口模式或多端口模式二选一
        const has_single_port = have_listen_port and have_target_port;
        const has_port_mappings = port_mappings_list.items.len > 0;

        if (!have_target_address) {
            if (project.remark.len != 0) allocator.free(project.remark);
            return types.ConfigError.MissingField;
        }

        if (has_single_port == has_port_mappings) {
            // 两者都有或都没有都是错误
            if (have_target_address) allocator.free(project.target_address);
            if (project.remark.len != 0) allocator.free(project.remark);
            for (port_mappings_list.items) |*pm| pm.deinit(allocator);
            return types.ConfigError.InvalidValue;
        }

        if (src_zones_list.items.len != 0) {
            project.src_zones = try src_zones_list.toOwnedSlice();
        }
        if (dest_zones_list.items.len != 0) {
            project.dest_zones = try dest_zones_list.toOwnedSlice();
        }

        if (port_mappings_list.items.len != 0) {
            project.port_mappings = try port_mappings_list.toOwnedSlice();
        }

        try list.append(project);
    }

    // 解析 FRPC 节点配置
    var frpc_nodes = std.StringHashMap(types.FrpcNode).init(allocator);
    errdefer {
        var it = frpc_nodes.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        frpc_nodes.deinit();
    }

    if (root == .object) {
        if (root.object.get("frpc_nodes")) |frpc_value| {
            if (frpc_value == .object) {
                var node_it = frpc_value.object.iterator();
                while (node_it.next()) |entry| {
                    const node_name = entry.key_ptr.*;
                    const node_obj = entry.value_ptr.*;

                    if (node_obj != .object) continue;

                    var frpc_node = types.FrpcNode{
                        .enabled = true,
                        .server = undefined,
                        .port = 0,
                        .use_encryption = true,
                        .use_compression = true,
                    };

                    var have_server = false;
                    var have_port = false;

                    if (node_obj.object.get("server")) |v| {
                        const s = try parseJsonString(v);
                        const trimmed = std.mem.trim(u8, s, " \t\r\n");
                        if (trimmed.len == 0) continue;
                        frpc_node.server = try allocator.dupe(u8, trimmed);
                        have_server = true;
                    }

                    if (node_obj.object.get("port")) |v| {
                        frpc_node.port = try parseJsonPort(v);
                        have_port = true;
                    }

                    if (node_obj.object.get("token")) |v| {
                        const s = try parseJsonString(v);
                        frpc_node.token = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (node_obj.object.get("use_encryption")) |v| {
                        frpc_node.use_encryption = try parseJsonBool(v);
                    }

                    if (node_obj.object.get("use_compression")) |v| {
                        frpc_node.use_compression = try parseJsonBool(v);
                    }

                    if (node_obj.object.get("log_level")) |v| {
                        const s = try parseJsonString(v);
                        frpc_node.log_level = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (node_obj.object.get("enabled")) |v| {
                        frpc_node.enabled = try parseJsonBool(v);
                    }

                    if (!have_server or !have_port) {
                        if (have_server) allocator.free(frpc_node.server);
                        if (frpc_node.token.len != 0) allocator.free(frpc_node.token);
                        if (frpc_node.log_level.len != 0 and !std.mem.eql(u8, frpc_node.log_level, "info")) allocator.free(frpc_node.log_level);
                        continue;
                    }

                    const key = try allocator.dupe(u8, node_name);
                    try frpc_nodes.put(key, frpc_node);
                }
            }
        }
    }

    // 解析 FRPS 节点配置
    var frps_nodes = std.StringHashMap(types.FrpsNode).init(allocator);
    errdefer {
        var it = frps_nodes.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        frps_nodes.deinit();
    }

    if (root == .object) {
        if (root.object.get("frps_nodes")) |frps_value| {
            if (frps_value == .object) {
                var node_it = frps_value.object.iterator();
                while (node_it.next()) |entry| {
                    const node_name = entry.key_ptr.*;
                    const node_obj = entry.value_ptr.*;

                    if (node_obj != .object) continue;

                    var frps_node = types.FrpsNode{
                        .enabled = true,
                        .port = 0,
                        .token = "",
                        .log_level = "info",
                        .allow_ports = "",
                        .bind_addr = "",
                        .max_pool_count = 5,
                        .max_ports_per_client = 0,
                        .tcp_mux = true,
                        .udp_mux = true,
                        .kcp_mux = true,
                        .dashboard_addr = "",
                        .dashboard_user = "",
                        .dashboard_pwd = "",
                    };

                    var have_port = false;

                    if (node_obj.object.get("port")) |v| {
                        frps_node.port = try parseJsonPort(v);
                        have_port = true;
                    }

                    if (node_obj.object.get("token")) |v| {
                        const s = try parseJsonString(v);
                        frps_node.token = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (node_obj.object.get("log_level")) |v| {
                        const s = try parseJsonString(v);
                        frps_node.log_level = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (node_obj.object.get("allow_ports")) |v| {
                        const s = try parseJsonString(v);
                        frps_node.allow_ports = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (node_obj.object.get("bind_addr")) |v| {
                        const s = try parseJsonString(v);
                        frps_node.bind_addr = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (node_obj.object.get("max_pool_count")) |v| {
                        frps_node.max_pool_count = switch (v) {
                            .integer => |i| @intCast(i),
                            .string => |s| std.fmt.parseUnsigned(u32, s, 10) catch 5,
                            else => 5,
                        };
                    }

                    if (node_obj.object.get("max_ports_per_client")) |v| {
                        frps_node.max_ports_per_client = switch (v) {
                            .integer => |i| @intCast(i),
                            .string => |s| std.fmt.parseUnsigned(u32, s, 10) catch 0,
                            else => 0,
                        };
                    }

                    if (node_obj.object.get("tcp_mux")) |v| {
                        frps_node.tcp_mux = try parseJsonBool(v);
                    }

                    if (node_obj.object.get("udp_mux")) |v| {
                        frps_node.udp_mux = try parseJsonBool(v);
                    }

                    if (node_obj.object.get("kcp_mux")) |v| {
                        frps_node.kcp_mux = try parseJsonBool(v);
                    }

                    if (node_obj.object.get("dashboard_addr")) |v| {
                        const s = try parseJsonString(v);
                        frps_node.dashboard_addr = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (node_obj.object.get("dashboard_user")) |v| {
                        const s = try parseJsonString(v);
                        frps_node.dashboard_user = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (node_obj.object.get("dashboard_pwd")) |v| {
                        const s = try parseJsonString(v);
                        frps_node.dashboard_pwd = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (node_obj.object.get("enabled")) |v| {
                        frps_node.enabled = try parseJsonBool(v);
                    }

                    if (!have_port) {
                        if (frps_node.token.len != 0) allocator.free(frps_node.token);
                        if (frps_node.log_level.len != 0 and !std.mem.eql(u8, frps_node.log_level, "info")) allocator.free(frps_node.log_level);
                        if (frps_node.allow_ports.len != 0) allocator.free(frps_node.allow_ports);
                        if (frps_node.bind_addr.len != 0) allocator.free(frps_node.bind_addr);
                        if (frps_node.dashboard_addr.len != 0) allocator.free(frps_node.dashboard_addr);
                        if (frps_node.dashboard_user.len != 0) allocator.free(frps_node.dashboard_user);
                        if (frps_node.dashboard_pwd.len != 0) allocator.free(frps_node.dashboard_pwd);
                        continue;
                    }

                    const key = try allocator.dupe(u8, node_name);
                    try frps_nodes.put(key, frps_node);
                }
            }
        }
    }

    // 解析 DDNS 配置
    var ddns_list = std.array_list.Managed(types.DdnsConfig).init(allocator);
    errdefer {
        for (ddns_list.items) |*d| d.deinit(allocator);
        ddns_list.deinit();
    }

    if (root == .object) {
        if (root.object.get("ddns")) |ddns_value| {
            if (ddns_value == .array) {
                for (ddns_value.array.items) |item| {
                    if (item != .object) continue;
                    const obj = item.object;

                    var ddns_cfg = types.DdnsConfig{
                        .enabled = true,
                        .name = undefined,
                        .dns_provider = undefined,
                    };

                    var have_name = false;
                    var have_provider = false;

                    // 必填字段
                    if (obj.get("name")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.name = try types.dupeIfNonEmpty(allocator, s);
                        have_name = ddns_cfg.name.len > 0;
                    }

                    if (obj.get("dns_provider")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.dns_provider = try types.dupeIfNonEmpty(allocator, s);
                        have_provider = ddns_cfg.dns_provider.len > 0;
                    }

                    // 可选字段
                    if (obj.get("dns_id")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.dns_id = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (obj.get("dns_secret")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.dns_secret = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (obj.get("dns_ext_param")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.dns_ext_param = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (obj.get("ttl")) |v| {
                        ddns_cfg.ttl = switch (v) {
                            .integer => |i| @intCast(i),
                            .string => |s| std.fmt.parseUnsigned(u32, s, 10) catch 3600,
                            else => 3600,
                        };
                    }

                    // IPv4 配置
                    if (obj.get("ipv4_enable")) |v| {
                        ddns_cfg.ipv4.enable = try parseJsonBool(v);
                    }

                    if (obj.get("ipv4_get_type")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.ipv4.get_type = try types.DdnsIpGetType.fromString(s);
                    }

                    if (obj.get("ipv4_url")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.ipv4.url = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (obj.get("ipv4_net_interface")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.ipv4.net_interface = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (obj.get("ipv4_cmd")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.ipv4.cmd = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (obj.get("ipv4_domains")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.ipv4.domains = try types.dupeIfNonEmpty(allocator, s);
                    }

                    // IPv6 配置
                    if (obj.get("ipv6_enable")) |v| {
                        ddns_cfg.ipv6.enable = try parseJsonBool(v);
                    }

                    if (obj.get("ipv6_get_type")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.ipv6.get_type = try types.DdnsIpGetType.fromString(s);
                    }

                    if (obj.get("ipv6_url")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.ipv6.url = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (obj.get("ipv6_net_interface")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.ipv6.net_interface = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (obj.get("ipv6_cmd")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.ipv6.cmd = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (obj.get("ipv6_reg")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.ipv6.reg = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (obj.get("ipv6_domains")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.ipv6.domains = try types.dupeIfNonEmpty(allocator, s);
                    }

                    // 其他配置
                    if (obj.get("not_allow_wan_access")) |v| {
                        ddns_cfg.not_allow_wan_access = try parseJsonBool(v);
                    }

                    if (obj.get("username")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.username = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (obj.get("password")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.password = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (obj.get("webhook_url")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.webhook_url = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (obj.get("webhook_body")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.webhook_body = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (obj.get("webhook_headers")) |v| {
                        const s = try parseJsonString(v);
                        ddns_cfg.webhook_headers = try types.dupeIfNonEmpty(allocator, s);
                    }

                    if (obj.get("enabled")) |v| {
                        ddns_cfg.enabled = try parseJsonBool(v);
                    }

                    // 验证必填字段
                    if (!have_name or !have_provider) {
                        ddns_cfg.deinit(allocator);
                        continue;
                    }

                    try ddns_list.append(ddns_cfg);
                }
            }
        }
    }

    return .{ .projects = try list.toOwnedSlice(), .frpc_nodes = frpc_nodes, .frps_nodes = frps_nodes, .ddns_configs = try ddns_list.toOwnedSlice() };
}
