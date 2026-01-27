const std = @import("std");
const uci = @import("../uci/mod.zig");
const types = @import("types.zig");
const helper = @import("helper.zig");
fn appendZoneString(list: *std.array_list.Managed([]const u8), allocator: std.mem.Allocator, s: []const u8) !void {
    const trimmed = std.mem.trim(u8, s, " \t\r\n");
    if (trimmed.len == 0) return;
    try list.append(try allocator.dupe(u8, trimmed));
}

fn parseProjectFromSection(allocator: std.mem.Allocator, sec: uci.UciSection) !types.Project {
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

    var opt_it = sec.options();
    while (opt_it.next()) |opt| {
        const opt_name = uci.cStr(opt.name());

        const is_src_zone = std.mem.eql(u8, opt_name, "src_zone") or std.mem.eql(u8, opt_name, "source_zone") or std.mem.eql(u8, opt_name, "srcZone") or std.mem.eql(u8, opt_name, "src-zone") or std.mem.eql(u8, opt_name, "源区域") or std.mem.eql(u8, opt_name, "来源区域");
        const is_dest_zone = std.mem.eql(u8, opt_name, "dest_zone") or std.mem.eql(u8, opt_name, "destination_zone") or std.mem.eql(u8, opt_name, "dst_zone") or std.mem.eql(u8, opt_name, "destZone") or std.mem.eql(u8, opt_name, "dest-zone") or std.mem.eql(u8, opt_name, "目标区域");

        if (is_src_zone or is_dest_zone) {
            if (opt.isString()) {
                const opt_val = uci.cStr(opt.getString());
                if (is_src_zone) {
                    try appendZoneString(&src_zones_list, allocator, opt_val);
                } else {
                    try appendZoneString(&dest_zones_list, allocator, opt_val);
                }
            } else if (opt.isList()) {
                var val_it = opt.values();
                while (val_it.next()) |val| {
                    const s = uci.cStr(val);
                    if (is_src_zone) {
                        try appendZoneString(&src_zones_list, allocator, s);
                    } else {
                        try appendZoneString(&dest_zones_list, allocator, s);
                    }
                }
            } else {
                return types.ConfigError.InvalidValue;
            }
            continue;
        }

        if (!opt.isString()) continue;
        const opt_val = uci.cStr(opt.getString());

        if (std.mem.eql(u8, opt_name, "enabled") or std.mem.eql(u8, opt_name, "enable") or std.mem.eql(u8, opt_name, "启用")) {
            project.enabled = try types.parseBool(opt_val);
        } else if (std.mem.eql(u8, opt_name, "remark") or std.mem.eql(u8, opt_name, "note") or std.mem.eql(u8, opt_name, "备注")) {
            project.remark = try types.dupeIfNonEmpty(allocator, opt_val);
        } else if (std.mem.eql(u8, opt_name, "family") or std.mem.eql(u8, opt_name, "addr_family") or std.mem.eql(u8, opt_name, "地址族限制")) {
            project.family = try types.parseFamily(opt_val);
        } else if (std.mem.eql(u8, opt_name, "protocol") or std.mem.eql(u8, opt_name, "proto") or std.mem.eql(u8, opt_name, "协议")) {
            project.protocol = try types.parseProtocol(opt_val);
        } else if (std.mem.eql(u8, opt_name, "listen_port") or std.mem.eql(u8, opt_name, "src_port") or std.mem.eql(u8, opt_name, "监听端口")) {
            project.listen_port = try types.parsePort(opt_val);
            have_listen_port = true;
        } else if (std.mem.eql(u8, opt_name, "reuseaddr") or std.mem.eql(u8, opt_name, "reuse") or std.mem.eql(u8, opt_name, "reuse_addr") or std.mem.eql(u8, opt_name, "绑定到本地端口")) {
            project.reuseaddr = try types.parseBool(opt_val);
        } else if (std.mem.eql(u8, opt_name, "target_address") or std.mem.eql(u8, opt_name, "target_addr") or std.mem.eql(u8, opt_name, "dst_ip") or std.mem.eql(u8, opt_name, "目标地址")) {
            const trimmed = std.mem.trim(u8, opt_val, " \t\r\n");
            if (trimmed.len == 0) return types.ConfigError.InvalidValue;
            project.target_address = try allocator.dupe(u8, trimmed);
            have_target_address = true;
        } else if (std.mem.eql(u8, opt_name, "target_port") or std.mem.eql(u8, opt_name, "dst_port") or std.mem.eql(u8, opt_name, "目标端口")) {
            project.target_port = try types.parsePort(opt_val);
            have_target_port = true;
        } else if (std.mem.eql(u8, opt_name, "open_firewall_port") or std.mem.eql(u8, opt_name, "firewall_open") or std.mem.eql(u8, opt_name, "打开防火墙端口")) {
            project.open_firewall_port = try types.parseBool(opt_val);
        } else if (std.mem.eql(u8, opt_name, "add_firewall_forward") or std.mem.eql(u8, opt_name, "firewall_forward") or std.mem.eql(u8, opt_name, "添加防火墙转发")) {
            project.add_firewall_forward = try types.parseBool(opt_val);
        } else if (std.mem.eql(u8, opt_name, "enable_app_forward") or std.mem.eql(u8, opt_name, "app_forward") or std.mem.eql(u8, opt_name, "启用应用层转发")) {
            project.enable_app_forward = try types.parseBool(opt_val);
        } else if (std.mem.eql(u8, opt_name, "enable_stats") or std.mem.eql(u8, opt_name, "stats") or std.mem.eql(u8, opt_name, "启用统计")) {
            project.enable_stats = try types.parseBool(opt_val);
        }
    }

    // Handle port_mapping option (list of custom format strings)
    var opt_it2 = sec.options();
    while (opt_it2.next()) |opt| {
        const opt_name = uci.cStr(opt.name());

        if (std.mem.eql(u8, opt_name, "port_mapping")) {
            if (opt.isList()) {
                var val_it = opt.values();
                while (val_it.next()) |val| {
                    const s = uci.cStr(val);
                    const mapping = helper.parsePortMapping(allocator, s) catch continue;
                    try port_mappings_list.append(mapping);
                }
            } else if (opt.isString()) {
                const opt_val = uci.cStr(opt.getString());
                const mapping = helper.parsePortMapping(allocator, opt_val) catch continue;
                try port_mappings_list.append(mapping);
            }
        }
    }

    if (port_mappings_list.items.len > 0) {
        project.port_mappings = try port_mappings_list.toOwnedSlice();
    }

    // target_address 是必需的
    if (!have_target_address) {
        if (project.remark.len != 0) allocator.free(project.remark);
        return types.ConfigError.MissingField;
    }

    if (src_zones_list.items.len != 0) {
        project.src_zones = try src_zones_list.toOwnedSlice();
    }
    if (dest_zones_list.items.len != 0) {
        project.dest_zones = try dest_zones_list.toOwnedSlice();
    }

    return project;
}

/// Load projects from a UCI config package (e.g. `/etc/config/portweaver`).
///
/// Expected schema (one section per project):
///   config project 'name'
///     option remark '...'
///     option target_address '192.168.1.2'
///     option listen_port '3389'      # 单端口模式
///     option target_port '3389'      # 单端口模式
///     option protocol 'tcp'          # 单端口模式
///     list port_mapping '8080-8090:80-90/udp'  # 多端口模式
///     list port_mapping '443:8443/tcp'         # 多端口模式
pub fn loadFromUci(allocator: std.mem.Allocator, ctx: uci.UciContext, package_name: [*c]const u8) !types.Config {
    var pkg = try ctx.load(package_name);
    if (pkg.isNull()) return types.ConfigError.MissingField;
    defer pkg.unload() catch {};

    var list = std.array_list.Managed(types.Project).init(allocator);
    errdefer {
        for (list.items) |*p| p.deinit(allocator);
        list.deinit();
    }

    var sec_it = uci.sections(pkg);
    while (sec_it.next()) |sec| {
        const sec_type = uci.cStr(sec.sectionType());
        if (!(std.mem.eql(u8, sec_type, "project") or std.mem.eql(u8, sec_type, "rule"))) continue;

        var project = try parseProjectFromSection(allocator, sec);

        // 验证配置有效性
        if (!project.isValid()) {
            project.deinit(allocator);
            return types.ConfigError.InvalidValue;
        }

        try list.append(project);
    }

    // Parse FRP nodes from UCI config
    var frp_nodes = std.StringHashMap(types.FrpNode).init(allocator);
    errdefer {
        var it = frp_nodes.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.deinit(allocator);
        }
        frp_nodes.deinit();
    }

    var frp_sec_it = uci.sections(pkg);
    while (frp_sec_it.next()) |sec| {
        const sec_type = uci.cStr(sec.sectionType());
        if (!std.mem.eql(u8, sec_type, "frp_node")) continue;

        var frp_node = types.FrpNode{
            .server = undefined,
            .port = 0,
            .token = &.{},
            .log_level = &.{},
        };
        var node_name: []const u8 = "";
        var have_server = false;
        var have_port = false;

        // Get node name from section name or 'name' option
        const sec_name = uci.cStr(sec.name());
        if (sec_name.len > 0) {
            node_name = sec_name;
        }

        var opt_it = sec.options();
        while (opt_it.next()) |opt| {
            const opt_name = uci.cStr(opt.name());
            if (!opt.isString()) continue;
            const opt_val = uci.cStr(opt.getString());

            if (std.mem.eql(u8, opt_name, "name")) {
                node_name = opt_val;
            } else if (std.mem.eql(u8, opt_name, "server") or std.mem.eql(u8, opt_name, "address") or std.mem.eql(u8, opt_name, "host")) {
                const trimmed = std.mem.trim(u8, opt_val, " \t\r\n");
                if (trimmed.len == 0) continue;
                frp_node.server = try allocator.dupe(u8, trimmed);
                have_server = true;
            } else if (std.mem.eql(u8, opt_name, "port")) {
                frp_node.port = try types.parsePort(opt_val);
                have_port = true;
            } else if (std.mem.eql(u8, opt_name, "token") or std.mem.eql(u8, opt_name, "auth_token")) {
                frp_node.token = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "log_level") or std.mem.eql(u8, opt_name, "loglevel")) {
                frp_node.log_level = try types.dupeIfNonEmpty(allocator, opt_val);
            }
        }

        // Validate FRP node
        if (node_name.len == 0 or !have_server or !have_port) {
            if (have_server) allocator.free(frp_node.server);
            if (frp_node.token.len != 0) allocator.free(frp_node.token);
            if (frp_node.log_level.len != 0) allocator.free(frp_node.log_level);
            continue;
        }

        const node_name_owned = try allocator.dupe(u8, node_name);
        errdefer allocator.free(node_name_owned);

        try frp_nodes.put(node_name_owned, frp_node);
    }

    // Parse frp_nodes list from project sections
    var sec_it3 = uci.sections(pkg);
    while (sec_it3.next()) |sec| {
        const sec_type = uci.cStr(sec.sectionType());
        if (!(std.mem.eql(u8, sec_type, "project") or std.mem.eql(u8, sec_type, "rule"))) continue;

        // Find the corresponding project
        var project_idx: ?usize = null;
        const sec_name = uci.cStr(sec.name());
        for (list.items, 0..) |*proj, idx| {
            // Match by section name or order (this is simplified)
            _ = proj;
            _ = sec_name;
            project_idx = idx;
            break;
        }

        if (project_idx == null) continue;

        var frp_list = std.array_list.Managed(types.FrpForward).init(allocator);
        defer frp_list.deinit();
        errdefer {
            for (frp_list.items) |*f| f.deinit(allocator);
        }

        var opt_it4 = sec.options();
        while (opt_it4.next()) |opt| {
            const opt_name = uci.cStr(opt.name());
            if (!std.mem.eql(u8, opt_name, "frp_nodes") and !std.mem.eql(u8, opt_name, "frp")) continue;

            if (opt.isList()) {
                var val_it = opt.values();
                while (val_it.next()) |val| {
                    const s = uci.cStr(val);
                    const fwd = helper.parseFrpForwardString(allocator, s) catch continue;
                    try frp_list.append(fwd);
                }
            } else if (opt.isString()) {
                const opt_val = uci.cStr(opt.getString());
                const fwd = helper.parseFrpForwardString(allocator, opt_val) catch continue;
                try frp_list.append(fwd);
            }
        }

        // Assign FRP forwards to the project's first port mapping or create a default one
        if (frp_list.items.len > 0) {
            if (list.items[project_idx.?].port_mappings.len > 0) {
                list.items[project_idx.?].port_mappings[0].frp = try frp_list.toOwnedSlice();
            } else {
                // Create a default port mapping if none exists (mirror single-port mode)
                const listen_str = try std.fmt.allocPrint(allocator, "{d}", .{list.items[project_idx.?].listen_port});
                errdefer allocator.free(listen_str);
                const target_str = try std.fmt.allocPrint(allocator, "{d}", .{list.items[project_idx.?].target_port});
                errdefer allocator.free(target_str);

                const owned_frp = try frp_list.toOwnedSlice();
                errdefer {
                    for (owned_frp) |*f| f.deinit(allocator);
                    allocator.free(owned_frp);
                }

                const default_mapping = types.PortMapping{
                    .listen_port = listen_str,
                    .target_port = target_str,
                    .protocol = list.items[project_idx.?].protocol,
                    .frp = owned_frp,
                };

                const owned_slice = try allocator.alloc(types.PortMapping, 1);
                owned_slice[0] = default_mapping;
                list.items[project_idx.?].port_mappings = owned_slice;
            }
        }
    }

    // Parse DDNS configs from UCI
    var ddns_list = std.array_list.Managed(types.DdnsConfig).init(allocator);
    errdefer {
        for (ddns_list.items) |*d| d.deinit(allocator);
        ddns_list.deinit();
    }

    var ddns_sec_it = uci.sections(pkg);
    while (ddns_sec_it.next()) |sec| {
        const sec_type = uci.cStr(sec.sectionType());
        if (!std.mem.eql(u8, sec_type, "ddns")) continue;

        var ddns_cfg = types.DdnsConfig{
            .name = undefined,
            .dns_provider = undefined,
        };
        var have_name = false;
        var have_provider = false;

        // Get name from section name or 'name' option
        const sec_name = uci.cStr(sec.name());
        if (sec_name.len > 0) {
            ddns_cfg.name = try allocator.dupe(u8, sec_name);
            have_name = true;
        }

        var opt_it = sec.options();
        while (opt_it.next()) |opt| {
            const opt_name = uci.cStr(opt.name());
            if (!opt.isString()) continue;
            const opt_val = uci.cStr(opt.getString());

            if (std.mem.eql(u8, opt_name, "name")) {
                if (have_name) allocator.free(ddns_cfg.name);
                ddns_cfg.name = try allocator.dupe(u8, opt_val);
                have_name = true;
            } else if (std.mem.eql(u8, opt_name, "dns_provider")) {
                ddns_cfg.dns_provider = try allocator.dupe(u8, opt_val);
                have_provider = true;
            } else if (std.mem.eql(u8, opt_name, "dns_id")) {
                ddns_cfg.dns_id = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "dns_secret")) {
                ddns_cfg.dns_secret = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "dns_ext_param")) {
                ddns_cfg.dns_ext_param = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "ttl")) {
                ddns_cfg.ttl = std.fmt.parseUnsigned(u32, std.mem.trim(u8, opt_val, " \t\r\n"), 10) catch 3600;
            } else if (std.mem.eql(u8, opt_name, "ipv4_enable")) {
                ddns_cfg.ipv4.enable = try types.parseBool(opt_val);
            } else if (std.mem.eql(u8, opt_name, "ipv4_get_type")) {
                ddns_cfg.ipv4.get_type = try types.DdnsIpGetType.fromString(opt_val);
            } else if (std.mem.eql(u8, opt_name, "ipv4_url")) {
                ddns_cfg.ipv4.url = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "ipv4_net_interface")) {
                ddns_cfg.ipv4.net_interface = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "ipv4_cmd")) {
                ddns_cfg.ipv4.cmd = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "ipv4_domains")) {
                ddns_cfg.ipv4.domains = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "ipv6_enable")) {
                ddns_cfg.ipv6.enable = try types.parseBool(opt_val);
            } else if (std.mem.eql(u8, opt_name, "ipv6_get_type")) {
                ddns_cfg.ipv6.get_type = try types.DdnsIpGetType.fromString(opt_val);
            } else if (std.mem.eql(u8, opt_name, "ipv6_url")) {
                ddns_cfg.ipv6.url = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "ipv6_net_interface")) {
                ddns_cfg.ipv6.net_interface = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "ipv6_cmd")) {
                ddns_cfg.ipv6.cmd = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "ipv6_reg")) {
                ddns_cfg.ipv6.reg = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "ipv6_domains")) {
                ddns_cfg.ipv6.domains = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "not_allow_wan_access")) {
                ddns_cfg.not_allow_wan_access = try types.parseBool(opt_val);
            } else if (std.mem.eql(u8, opt_name, "username")) {
                ddns_cfg.username = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "password")) {
                ddns_cfg.password = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "webhook_url")) {
                ddns_cfg.webhook_url = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "webhook_body")) {
                ddns_cfg.webhook_body = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "webhook_headers")) {
                ddns_cfg.webhook_headers = try types.dupeIfNonEmpty(allocator, opt_val);
            }
        }

        // Validate required fields
        if (!have_name or !have_provider) {
            if (have_name) allocator.free(ddns_cfg.name);
            if (have_provider) allocator.free(ddns_cfg.dns_provider);
            continue;
        }

        try ddns_list.append(ddns_cfg);
    }

    return .{ .projects = try list.toOwnedSlice(), .frp_nodes = frp_nodes, .ddns_configs = try ddns_list.toOwnedSlice() };
}
