const std = @import("std");
const uci = @import("../uci/mod.zig");
const types = @import("types.zig");
const helper = @import("helper.zig");
const file_log = @import("../file_log.zig");
const build_options = @import("build_options");
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

    var detect_protocols_list = std.array_list.Managed([]const u8).init(allocator);
    defer detect_protocols_list.deinit();
    errdefer {
        for (detect_protocols_list.items) |p| allocator.free(p);
    }

    var allowed_protocols_list = std.array_list.Managed([]const u8).init(allocator);
    defer allowed_protocols_list.deinit();
    errdefer {
        for (allowed_protocols_list.items) |p| allocator.free(p);
    }

    var tls_allowed_snis_list = std.array_list.Managed([]const u8).init(allocator);
    defer tls_allowed_snis_list.deinit();
    errdefer {
        for (tls_allowed_snis_list.items) |s| allocator.free(s);
    }

    var port_mappings_list = std.array_list.Managed(types.PortMapping).init(allocator);
    defer port_mappings_list.deinit();
    errdefer {
        for (port_mappings_list.items) |*pm| pm.deinit(allocator);
    }

    var opt_it = sec.options();
    while (opt_it.next()) |opt| {
        const opt_name = uci.cStr(opt.name());

        const is_src_zone = std.mem.eql(u8, opt_name, "src_zone");
        const is_dest_zone = std.mem.eql(u8, opt_name, "dest_zone");

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

        const is_detect_protocols = std.mem.eql(u8, opt_name, "detect_protocols");
        const is_allowed_protocols = std.mem.eql(u8, opt_name, "allowed_protocols");
        const is_tls_allowed_snis = std.mem.eql(u8, opt_name, "tls_allowed_snis");

        if (is_detect_protocols or is_allowed_protocols or is_tls_allowed_snis) {
            if (opt.isString()) {
                const opt_val = uci.cStr(opt.getString());
                if (is_detect_protocols) {
                    try appendZoneString(&detect_protocols_list, allocator, opt_val);
                } else if (is_allowed_protocols) {
                    try appendZoneString(&allowed_protocols_list, allocator, opt_val);
                } else {
                    try appendZoneString(&tls_allowed_snis_list, allocator, opt_val);
                }
            } else if (opt.isList()) {
                var val_it = opt.values();
                while (val_it.next()) |val| {
                    const s = uci.cStr(val);
                    if (is_detect_protocols) {
                        try appendZoneString(&detect_protocols_list, allocator, s);
                    } else if (is_allowed_protocols) {
                        try appendZoneString(&allowed_protocols_list, allocator, s);
                    } else {
                        try appendZoneString(&tls_allowed_snis_list, allocator, s);
                    }
                }
            } else {
                return types.ConfigError.InvalidValue;
            }
            continue;
        }

        if (!opt.isString()) continue;
        const opt_val = uci.cStr(opt.getString());

        if (std.mem.eql(u8, opt_name, "enabled")) {
            project.enabled = try types.parseBool(opt_val);
        } else if (std.mem.eql(u8, opt_name, "remark")) {
            project.remark = try types.dupeIfNonEmpty(allocator, opt_val);
        } else if (std.mem.eql(u8, opt_name, "family")) {
            project.family = try types.parseFamily(opt_val);
        } else if (std.mem.eql(u8, opt_name, "protocol")) {
            project.protocol = try types.parseProtocol(opt_val);
        } else if (std.mem.eql(u8, opt_name, "listen_port")) {
            project.listen_port = try types.parsePort(opt_val);
            have_listen_port = true;
        } else if (std.mem.eql(u8, opt_name, "reuseaddr")) {
            project.reuseaddr = try types.parseBool(opt_val);
        } else if (std.mem.eql(u8, opt_name, "target_address")) {
            const trimmed = std.mem.trim(u8, opt_val, " \t\r\n");
            if (trimmed.len == 0) return types.ConfigError.InvalidValue;
            project.target_address = try allocator.dupe(u8, trimmed);
            have_target_address = true;
        } else if (std.mem.eql(u8, opt_name, "target_port")) {
            project.target_port = try types.parsePort(opt_val);
            have_target_port = true;
        } else if (std.mem.eql(u8, opt_name, "open_firewall_port")) {
            project.open_firewall_port = try types.parseBool(opt_val);
        } else if (std.mem.eql(u8, opt_name, "add_firewall_forward")) {
            project.add_firewall_forward = try types.parseBool(opt_val);
        } else if (std.mem.eql(u8, opt_name, "preserve_source_ip")) {
            project.preserve_source_ip = try types.parseBool(opt_val);
        } else if (std.mem.eql(u8, opt_name, "enable_app_forward")) {
            project.enable_app_forward = try types.parseBool(opt_val);
        } else if (std.mem.eql(u8, opt_name, "enable_app_stats")) {
            project.enable_app_stats = try types.parseBool(opt_val);
        } else if (std.mem.eql(u8, opt_name, "enable_firewall_stats")) {
            project.enable_firewall_stats = try types.parseBool(opt_val);
        } else if (std.mem.eql(u8, opt_name, "app_forward_loop_mode")) {
            project.app_forward_loop_mode = try types.parseLoopMode(opt_val);
        } else if (std.mem.eql(u8, opt_name, "connect_timeout_ms")) {
            const trimmed = std.mem.trim(u8, opt_val, " \t\r\n");
            if (trimmed.len != 0) {
                project.connect_timeout_ms = std.fmt.parseUnsigned(u32, trimmed, 10) catch return types.ConfigError.InvalidValue;
            }
        } else if (std.mem.eql(u8, opt_name, "max_connections")) {
            const trimmed = std.mem.trim(u8, opt_val, " \t\r\n");
            if (trimmed.len != 0) {
                project.max_connections = std.fmt.parseUnsigned(u32, trimmed, 10) catch return types.ConfigError.InvalidValue;
            }
        } else if (std.mem.eql(u8, opt_name, "enable_wol")) {
            project.enable_wol = try types.parseBool(opt_val);
        } else if (std.mem.eql(u8, opt_name, "wol_trigger_mode")) {
            project.wol_trigger_mode = try types.parseWolTriggerMode(opt_val);
        } else if (std.mem.eql(u8, opt_name, "wol_target")) {
            project.wol_target = try types.dupeIfNonEmpty(allocator, opt_val);
        } else if (std.mem.eql(u8, opt_name, "enable_protocol_filter")) {
            project.enable_protocol_filter = try types.parseBool(opt_val);
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
                    const mapping = try helper.parsePortMapping(allocator, s);
                    try port_mappings_list.append(mapping);
                }
            } else if (opt.isString()) {
                const opt_val = uci.cStr(opt.getString());
                const mapping = try helper.parsePortMapping(allocator, opt_val);
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
    if (detect_protocols_list.items.len != 0) {
        project.detect_protocols = try detect_protocols_list.toOwnedSlice();
    }

    if (allowed_protocols_list.items.len != 0) {
        project.allowed_protocols = try allowed_protocols_list.toOwnedSlice();
    }
    if (tls_allowed_snis_list.items.len != 0) {
        project.tls_allowed_snis = try tls_allowed_snis_list.toOwnedSlice();
    }

    // Store the UCI section name for index-independent status matching
    const sec_name = uci.cStr(sec.name());
    if (sec_name.len > 0) {
        project.section_name = try allocator.dupe(u8, sec_name);
    }

    return project;
}

fn findProject(projects: []const types.Project, name: []const u8) ?types.Project {
    for (projects) |project| {
        if (std.mem.eql(u8, project.section_name, name)) return project;
    }
    return null;
}

fn parseRatholeClientNode(allocator: std.mem.Allocator, sec: uci.UciSection) !struct { name: []const u8, node: types.RatholeClientNode } {
    var name = uci.cStr(sec.name());
    var node = types.RatholeClientNode{ .remote_addr = "" };
    errdefer node.deinit(allocator);

    var opt_it = sec.options();
    while (opt_it.next()) |opt| {
        if (!opt.isString()) continue;
        const option_name = uci.cStr(opt.name());
        const value = uci.cStr(opt.getString());
        if (std.mem.eql(u8, option_name, "name")) {
            name = value;
        } else if (std.mem.eql(u8, option_name, "enabled")) {
            node.enabled = try types.parseBool(value);
        } else if (std.mem.eql(u8, option_name, "remote_addr")) {
            if (node.remote_addr.len != 0) allocator.free(node.remote_addr);
            node.remote_addr = try types.dupeIfNonEmpty(allocator, value);
        } else if (std.mem.eql(u8, option_name, "default_token")) {
            if (node.default_token.len != 0) allocator.free(node.default_token);
            node.default_token = try types.dupeIfNonEmpty(allocator, value);
        } else if (std.mem.eql(u8, option_name, "transport")) {
            node.transport = try types.RatholeTransport.fromString(value);
        } else if (std.mem.eql(u8, option_name, "noise_local_private_key")) {
            if (node.noise_local_private_key.len != 0) allocator.free(node.noise_local_private_key);
            node.noise_local_private_key = try types.dupeIfNonEmpty(allocator, value);
        } else if (std.mem.eql(u8, option_name, "noise_remote_public_key")) {
            if (node.noise_remote_public_key.len != 0) allocator.free(node.noise_remote_public_key);
            node.noise_remote_public_key = try types.dupeIfNonEmpty(allocator, value);
        }
    }
    if (name.len == 0 or node.remote_addr.len == 0) return types.ConfigError.MissingField;
    return .{ .name = name, .node = node };
}

fn parseRatholeServerNode(allocator: std.mem.Allocator, sec: uci.UciSection) !struct { name: []const u8, node: types.RatholeServerNode } {
    var name = uci.cStr(sec.name());
    var node = types.RatholeServerNode{ .bind_addr = "" };
    errdefer node.deinit(allocator);

    var opt_it = sec.options();
    while (opt_it.next()) |opt| {
        if (!opt.isString()) continue;
        const option_name = uci.cStr(opt.name());
        const value = uci.cStr(opt.getString());
        if (std.mem.eql(u8, option_name, "name")) {
            name = value;
        } else if (std.mem.eql(u8, option_name, "enabled")) {
            node.enabled = try types.parseBool(value);
        } else if (std.mem.eql(u8, option_name, "bind_addr")) {
            if (node.bind_addr.len != 0) allocator.free(node.bind_addr);
            node.bind_addr = try types.dupeIfNonEmpty(allocator, value);
        } else if (std.mem.eql(u8, option_name, "default_token")) {
            if (node.default_token.len != 0) allocator.free(node.default_token);
            node.default_token = try types.dupeIfNonEmpty(allocator, value);
        } else if (std.mem.eql(u8, option_name, "transport")) {
            node.transport = try types.RatholeTransport.fromString(value);
        } else if (std.mem.eql(u8, option_name, "noise_local_private_key")) {
            if (node.noise_local_private_key.len != 0) allocator.free(node.noise_local_private_key);
            node.noise_local_private_key = try types.dupeIfNonEmpty(allocator, value);
        } else if (std.mem.eql(u8, option_name, "noise_remote_public_key")) {
            if (node.noise_remote_public_key.len != 0) allocator.free(node.noise_remote_public_key);
            node.noise_remote_public_key = try types.dupeIfNonEmpty(allocator, value);
        }
    }
    if (name.len == 0 or node.bind_addr.len == 0) return types.ConfigError.MissingField;
    return .{ .name = name, .node = node };
}

fn parseRatholeClientService(allocator: std.mem.Allocator, sec: uci.UciSection, projects: []const types.Project) !types.RatholeClientService {
    var node_name: []const u8 = "";
    var service_name: []const u8 = uci.cStr(sec.name());
    var project_name: []const u8 = "";
    var local_address: []const u8 = "";
    var local_port: u16 = 0;
    var project_target_port: ?u16 = null;
    var service = types.RatholeClientService{ .node_name = "", .service_name = "", .local_address = "", .local_port = 0 };
    errdefer service.deinit(allocator);

    var opt_it = sec.options();
    while (opt_it.next()) |opt| {
        if (!opt.isString()) continue;
        const option_name = uci.cStr(opt.name());
        const value = uci.cStr(opt.getString());
        if (std.mem.eql(u8, option_name, "name") or std.mem.eql(u8, option_name, "service_name")) service_name = value else if (std.mem.eql(u8, option_name, "node")) node_name = value else if (std.mem.eql(u8, option_name, "enabled")) service.enabled = try types.parseBool(value) else if (std.mem.eql(u8, option_name, "protocol")) service.protocol = try types.RatholeServiceProtocol.fromString(value) else if (std.mem.eql(u8, option_name, "token")) service.token = try types.dupeIfNonEmpty(allocator, value) else if (std.mem.eql(u8, option_name, "local_address")) local_address = value else if (std.mem.eql(u8, option_name, "local_port")) local_port = try types.parsePort(value) else if (std.mem.eql(u8, option_name, "project")) project_name = value else if (std.mem.eql(u8, option_name, "project_target_port")) project_target_port = try types.parsePort(value);
    }

    if (node_name.len == 0 or service_name.len == 0) return types.ConfigError.MissingField;
    if (project_name.len != 0) {
        if (local_address.len != 0 or local_port != 0) return types.ConfigError.InvalidValue;
        const project = findProject(projects, project_name) orelse return types.ConfigError.InvalidValue;
        service.local_address = try allocator.dupe(u8, project.target_address);
        service.local_port = project_target_port orelse if (project.port_mappings.len == 0) project.target_port else return types.ConfigError.MissingField;
        service.project_name = try allocator.dupe(u8, project_name);
    } else {
        if (local_address.len == 0 or local_port == 0) return types.ConfigError.MissingField;
        service.local_address = try allocator.dupe(u8, std.mem.trim(u8, local_address, " \t\r\n"));
        service.local_port = local_port;
    }
    service.node_name = try allocator.dupe(u8, std.mem.trim(u8, node_name, " \t\r\n"));
    service.service_name = try allocator.dupe(u8, std.mem.trim(u8, service_name, " \t\r\n"));
    return service;
}

fn parseRatholeServerService(allocator: std.mem.Allocator, sec: uci.UciSection) !types.RatholeServerService {
    var node_name: []const u8 = "";
    var service_name: []const u8 = uci.cStr(sec.name());
    var bind_address: []const u8 = "";
    var bind_port: u16 = 0;
    var service = types.RatholeServerService{ .node_name = "", .service_name = "", .bind_address = "", .bind_port = 0 };
    errdefer service.deinit(allocator);

    var opt_it = sec.options();
    while (opt_it.next()) |opt| {
        if (!opt.isString()) continue;
        const option_name = uci.cStr(opt.name());
        const value = uci.cStr(opt.getString());
        if (std.mem.eql(u8, option_name, "name") or std.mem.eql(u8, option_name, "service_name")) service_name = value else if (std.mem.eql(u8, option_name, "node")) node_name = value else if (std.mem.eql(u8, option_name, "enabled")) service.enabled = try types.parseBool(value) else if (std.mem.eql(u8, option_name, "protocol")) service.protocol = try types.RatholeServiceProtocol.fromString(value) else if (std.mem.eql(u8, option_name, "token")) service.token = try types.dupeIfNonEmpty(allocator, value) else if (std.mem.eql(u8, option_name, "bind_address")) bind_address = value else if (std.mem.eql(u8, option_name, "bind_port")) bind_port = try types.parsePort(value);
    }
    if (node_name.len == 0 or service_name.len == 0 or bind_address.len == 0 or bind_port == 0) return types.ConfigError.MissingField;
    service.node_name = try allocator.dupe(u8, std.mem.trim(u8, node_name, " \t\r\n"));
    service.service_name = try allocator.dupe(u8, std.mem.trim(u8, service_name, " \t\r\n"));
    service.bind_address = try allocator.dupe(u8, std.mem.trim(u8, bind_address, " \t\r\n"));
    service.bind_port = bind_port;
    return service;
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

    var log_config = try file_log.defaultLogConfig(allocator);
    errdefer log_config.deinit(allocator);
    var app_forward_loop_mode: types.LoopMode = .per_project;
    var use_nftables: bool = false;
    var frps_config_mode: types.FrpConfigMode = .builtin;
    var frps_config_format: types.FrpConfigFormat = .toml;
    var frps_config_path: []const u8 = "";
    errdefer if (frps_config_path.len != 0) allocator.free(frps_config_path);
    var frps_config_content: []const u8 = "";
    errdefer if (frps_config_content.len != 0) allocator.free(frps_config_content);
    var frpc_config_mode: types.FrpConfigMode = .builtin;
    var frpc_config_format: types.FrpConfigFormat = .toml;
    var frpc_config_path: []const u8 = "";
    errdefer if (frpc_config_path.len != 0) allocator.free(frpc_config_path);
    var frpc_config_content: []const u8 = "";
    errdefer if (frpc_config_content.len != 0) allocator.free(frpc_config_content);
    var frp_config_root: ?[]const u8 = null;
    errdefer if (frp_config_root) |root| allocator.free(root);

    var global_sec_it = uci.sections(pkg);
    while (global_sec_it.next()) |sec| {
        const sec_type = uci.cStr(sec.sectionType());

        if (!std.mem.eql(u8, sec_type, "global")) continue;

        var opt_it = sec.options();
        while (opt_it.next()) |opt| {
            if (!opt.isString()) continue;
            const opt_name = uci.cStr(opt.name());
            const opt_val = uci.cStr(opt.getString());

            if (std.mem.eql(u8, opt_name, "log_enabled")) {
                log_config.enabled = try types.parseBool(opt_val);
            } else if (std.mem.eql(u8, opt_name, "log_file")) {
                const new_path = try types.dupeIfNonEmpty(allocator, opt_val);
                if (new_path.len != 0) {
                    allocator.free(log_config.file_path);
                    log_config.file_path = new_path;
                }
            } else if (std.mem.eql(u8, opt_name, "max_log_size")) {
                const size_kb = std.fmt.parseUnsigned(usize, std.mem.trim(u8, opt_val, " \t\r\n"), 10) catch 1024;
                log_config.max_size = size_kb * 1024;
            } else if (std.mem.eql(u8, opt_name, "max_log_files")) {
                log_config.max_files = std.fmt.parseUnsigned(usize, std.mem.trim(u8, opt_val, " \t\r\n"), 10) catch 3;
            } else if (std.mem.eql(u8, opt_name, "format")) {
                log_config.format = file_log.LogFormat.fromString(opt_val) orelse .plain;
            } else if (std.mem.eql(u8, opt_name, "app_forward_loop_mode")) {
                app_forward_loop_mode = try types.parseLoopMode(opt_val);
            } else if (std.mem.eql(u8, opt_name, "use_nftables")) {
                use_nftables = try types.parseBool(opt_val);
            } else if (std.mem.eql(u8, opt_name, "frps_config_mode")) {
                frps_config_mode = try types.FrpConfigMode.fromString(opt_val);
            } else if (std.mem.eql(u8, opt_name, "frps_config_format")) {
                frps_config_format = try types.FrpConfigFormat.fromString(opt_val);
            } else if (std.mem.eql(u8, opt_name, "frps_config_path")) {
                const path = try types.dupeIfNonEmpty(allocator, opt_val);
                if (frps_config_path.len != 0) allocator.free(frps_config_path);
                frps_config_path = path;
            } else if (std.mem.eql(u8, opt_name, "frps_config_content")) {
                const content = try types.dupeIfNonEmpty(allocator, opt_val);
                if (frps_config_content.len != 0) allocator.free(frps_config_content);
                frps_config_content = content;
            } else if (std.mem.eql(u8, opt_name, "frpc_config_mode")) {
                frpc_config_mode = try types.FrpConfigMode.fromString(opt_val);
            } else if (std.mem.eql(u8, opt_name, "frpc_config_format")) {
                frpc_config_format = try types.FrpConfigFormat.fromString(opt_val);
            } else if (std.mem.eql(u8, opt_name, "frpc_config_path")) {
                const path = try types.dupeIfNonEmpty(allocator, opt_val);
                if (frpc_config_path.len != 0) allocator.free(frpc_config_path);
                frpc_config_path = path;
            } else if (std.mem.eql(u8, opt_name, "frpc_config_content")) {
                const content = try types.dupeIfNonEmpty(allocator, opt_val);
                if (frpc_config_content.len != 0) allocator.free(frpc_config_content);
                frpc_config_content = content;
            } else if (std.mem.eql(u8, opt_name, "frp_config_root")) {
                const root = try types.dupeIfNonEmpty(allocator, opt_val);
                if (frp_config_root) |old_root| allocator.free(old_root);
                frp_config_root = if (root.len == 0) null else root;
            }
        }
        break;
    }

    switch (frps_config_mode) {
        .builtin => {},
        .external_file => {
            if (std.mem.trim(u8, frps_config_path, " \t\r\n").len == 0) {
                return types.ConfigError.MissingField;
            }
        },
        .external_uci => {
            if (std.mem.trim(u8, frps_config_content, " \t\r\n").len == 0) {
                return types.ConfigError.MissingField;
            }
        },
    }
    switch (frpc_config_mode) {
        .builtin => {},
        .external_file => if (std.mem.trim(u8, frpc_config_path, " \t\r\n").len == 0) return types.ConfigError.MissingField,
        .external_uci => if (std.mem.trim(u8, frpc_config_content, " \t\r\n").len == 0) return types.ConfigError.MissingField,
    }
    if (frp_config_root) |root| {
        if (!std.fs.path.isAbsolute(root) or std.mem.eql(u8, root, "/")) return types.ConfigError.InvalidValue;
    }

    var list = std.array_list.Managed(types.Project).init(allocator);
    errdefer {
        for (list.items) |*p| p.deinit(allocator);
        list.deinit();
    }

    var sec_it = uci.sections(pkg);
    while (sec_it.next()) |sec| {
        const sec_type = uci.cStr(sec.sectionType());
        if (!std.mem.eql(u8, sec_type, "project")) continue;

        var project = parseProjectFromSection(allocator, sec) catch |err| {
            std.log.err("Failed to parse project section '{s}': {any}. Skipping this project.", .{ uci.cStr(sec.name()), err });
            continue;
        };

        // 验证配置有效性
        if (!project.isValid()) {
            std.log.err("Project '{s}' ({s}) is invalid (must configure either single port or port mappings). Disabling this project.", .{ project.remark, uci.cStr(sec.name()) });
            project.enabled = false;
        }

        try list.append(project);
    }

    var rathole_client_nodes = std.StringHashMap(types.RatholeClientNode).init(allocator);
    errdefer {
        var it = rathole_client_nodes.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        rathole_client_nodes.deinit();
    }
    var rathole_client_node_sections = uci.sections(pkg);
    while (rathole_client_node_sections.next()) |sec| {
        if (!std.mem.eql(u8, uci.cStr(sec.sectionType()), "rathole_client_node")) continue;
        const parsed_node = try parseRatholeClientNode(allocator, sec);
        const key = try allocator.dupe(u8, parsed_node.name);
        errdefer allocator.free(key);
        if (rathole_client_nodes.contains(key)) return types.ConfigError.InvalidValue;
        try rathole_client_nodes.put(key, parsed_node.node);
    }

    var rathole_server_nodes = std.StringHashMap(types.RatholeServerNode).init(allocator);
    errdefer {
        var it = rathole_server_nodes.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        rathole_server_nodes.deinit();
    }
    var rathole_server_node_sections = uci.sections(pkg);
    while (rathole_server_node_sections.next()) |sec| {
        if (!std.mem.eql(u8, uci.cStr(sec.sectionType()), "rathole_server_node")) continue;
        const parsed_node = try parseRatholeServerNode(allocator, sec);
        const key = try allocator.dupe(u8, parsed_node.name);
        errdefer allocator.free(key);
        if (rathole_server_nodes.contains(key)) return types.ConfigError.InvalidValue;
        try rathole_server_nodes.put(key, parsed_node.node);
    }

    var rathole_client_services_list = std.array_list.Managed(types.RatholeClientService).init(allocator);
    defer rathole_client_services_list.deinit();
    errdefer for (rathole_client_services_list.items) |*service| service.deinit(allocator);
    var rathole_client_service_sections = uci.sections(pkg);
    while (rathole_client_service_sections.next()) |sec| {
        if (!std.mem.eql(u8, uci.cStr(sec.sectionType()), "rathole_client_service")) continue;
        try rathole_client_services_list.append(try parseRatholeClientService(allocator, sec, list.items));
    }

    var rathole_server_services_list = std.array_list.Managed(types.RatholeServerService).init(allocator);
    defer rathole_server_services_list.deinit();
    errdefer for (rathole_server_services_list.items) |*service| service.deinit(allocator);
    var rathole_server_service_sections = uci.sections(pkg);
    while (rathole_server_service_sections.next()) |sec| {
        if (!std.mem.eql(u8, uci.cStr(sec.sectionType()), "rathole_server_service")) continue;
        try rathole_server_services_list.append(try parseRatholeServerService(allocator, sec));
    }

    // Parse WOL targets from UCI config
    var wol_targets = std.StringHashMap(types.WolTarget).init(allocator);
    errdefer {
        var it = wol_targets.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        wol_targets.deinit();
    }

    var wol_sec_it = uci.sections(pkg);
    while (wol_sec_it.next()) |sec| {
        const sec_type = uci.cStr(sec.sectionType());
        if (!std.mem.eql(u8, sec_type, "wol_target")) continue;

        var wol_target = types.WolTarget{
            .enabled = true,
            .mac_addresses = &.{},
            .cooldown_ms = 30000,
        };
        var target_name: []const u8 = "";
        var mac_addresses_list = std.array_list.Managed([]const u8).init(allocator);
        defer mac_addresses_list.deinit();
        errdefer {
            for (mac_addresses_list.items) |m| allocator.free(m);
        }

        // Get target name from section name or 'name' option
        const sec_name = uci.cStr(sec.name());
        if (sec_name.len > 0) {
            target_name = sec_name;
        }

        var opt_it = sec.options();
        while (opt_it.next()) |opt| {
            const opt_name = uci.cStr(opt.name());
            if (std.mem.eql(u8, opt_name, "mac_addresses") or std.mem.eql(u8, opt_name, "mac")) {
                if (opt.isString()) {
                    const opt_val = uci.cStr(opt.getString());
                    try appendZoneString(&mac_addresses_list, allocator, opt_val);
                } else if (opt.isList()) {
                    var val_it = opt.values();
                    while (val_it.next()) |val| {
                        const s = uci.cStr(val);
                        try appendZoneString(&mac_addresses_list, allocator, s);
                    }
                }
                continue;
            }

            if (!opt.isString()) continue;
            const opt_val = uci.cStr(opt.getString());

            if (std.mem.eql(u8, opt_name, "name")) {
                target_name = opt_val;
            } else if (std.mem.eql(u8, opt_name, "enabled")) {
                wol_target.enabled = try types.parseBool(opt_val);
            } else if (std.mem.eql(u8, opt_name, "log_enabled")) {
                wol_target.log_enabled = try types.parseBool(opt_val);
            } else if (std.mem.eql(u8, opt_name, "cooldown_ms")) {
                const cd_trimmed = std.mem.trim(u8, opt_val, " \t\r\n");
                if (cd_trimmed.len != 0) {
                    wol_target.cooldown_ms = std.fmt.parseUnsigned(u64, cd_trimmed, 10) catch return types.ConfigError.InvalidValue;
                }
            } else if (std.mem.eql(u8, opt_name, "wake_delay_ms")) {
                const trimmed = std.mem.trim(u8, opt_val, " \t\r\n");
                if (trimmed.len != 0) wol_target.wake_delay_ms = std.fmt.parseUnsigned(u64, trimmed, 10) catch return types.ConfigError.InvalidValue;
            } else if (std.mem.eql(u8, opt_name, "retry_interval_ms")) {
                const trimmed = std.mem.trim(u8, opt_val, " \t\r\n");
                if (trimmed.len != 0) wol_target.retry_interval_ms = std.fmt.parseUnsigned(u64, trimmed, 10) catch return types.ConfigError.InvalidValue;
            } else if (std.mem.eql(u8, opt_name, "retry_window_ms")) {
                const trimmed = std.mem.trim(u8, opt_val, " \t\r\n");
                if (trimmed.len != 0) wol_target.retry_window_ms = std.fmt.parseUnsigned(u64, trimmed, 10) catch return types.ConfigError.InvalidValue;
            }
        }

        if (mac_addresses_list.items.len > 0) {
            wol_target.mac_addresses = try mac_addresses_list.toOwnedSlice();
        }

        if (target_name.len == 0) {
            wol_target.deinit(allocator);
            continue;
        }

        const target_name_owned = try allocator.dupe(u8, target_name);
        errdefer allocator.free(target_name_owned);

        if (wol_targets.contains(target_name_owned)) {
            wol_target.deinit(allocator);
            return types.ConfigError.InvalidValue;
        }
        try wol_targets.put(target_name_owned, wol_target);
    }

    // Parse FRPC nodes from UCI config
    var frpc_nodes = std.StringHashMap(types.FrpcNode).init(allocator);
    errdefer {
        var it = frpc_nodes.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        frpc_nodes.deinit();
    }

    var frp_sec_it = uci.sections(pkg);
    while (frp_sec_it.next()) |sec| {
        const sec_type = uci.cStr(sec.sectionType());
        if (!std.mem.eql(u8, sec_type, "frpc_node")) continue;

        var frpc_node = types.FrpcNode{
            .enabled = true,
            .server = undefined,
            .port = 0,
            .token = &.{},
            .log_level = &.{},
            .use_encryption = true,
            .use_compression = true,
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
            } else if (std.mem.eql(u8, opt_name, "server")) {
                const trimmed = std.mem.trim(u8, opt_val, " \t\r\n");
                if (trimmed.len == 0) continue;
                frpc_node.server = try allocator.dupe(u8, trimmed);
                have_server = true;
            } else if (std.mem.eql(u8, opt_name, "port")) {
                frpc_node.port = try types.parsePort(opt_val);
                have_port = true;
            } else if (std.mem.eql(u8, opt_name, "token")) {
                frpc_node.token = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "log_level")) {
                frpc_node.log_level = try types.dupeIfNonEmpty(allocator, opt_val);
            } else if (std.mem.eql(u8, opt_name, "use_encryption")) {
                frpc_node.use_encryption = try types.parseBool(opt_val);
            } else if (std.mem.eql(u8, opt_name, "use_compression")) {
                frpc_node.use_compression = try types.parseBool(opt_val);
            } else if (std.mem.eql(u8, opt_name, "enabled")) {
                frpc_node.enabled = try types.parseBool(opt_val);
            }
        }

        // Validate FRPC node
        if (node_name.len == 0 or !have_server or !have_port) {
            if (have_server) allocator.free(frpc_node.server);
            if (frpc_node.token.len != 0) allocator.free(frpc_node.token);
            if (frpc_node.log_level.len != 0) allocator.free(frpc_node.log_level);
            continue;
        }

        const node_name_owned = try allocator.dupe(u8, node_name);
        errdefer allocator.free(node_name_owned);

        try frpc_nodes.put(node_name_owned, frpc_node);
    }

    // Parse frp_nodes list from project sections
    var sec_it3 = uci.sections(pkg);
    while (sec_it3.next()) |sec| {
        const sec_type = uci.cStr(sec.sectionType());
        if (!std.mem.eql(u8, sec_type, "project")) continue;

        // Find the corresponding project
        var project_idx: ?usize = null;
        const sec_name = uci.cStr(sec.name());
        for (list.items, 0..) |*proj, idx| {
            if (sec_name.len > 0 and std.mem.eql(u8, proj.section_name, sec_name)) {
                project_idx = idx;
                break;
            }
        }

        if (project_idx == null) continue;

        var frpc_list = std.array_list.Managed(types.FrpcForward).init(allocator);
        defer frpc_list.deinit();
        errdefer {
            for (frpc_list.items) |*f| f.deinit(allocator);
        }

        var opt_it4 = sec.options();
        while (opt_it4.next()) |opt| {
            const opt_name = uci.cStr(opt.name());
            if (!std.mem.eql(u8, opt_name, "frpc_nodes")) continue;

            if (opt.isList()) {
                var val_it = opt.values();
                while (val_it.next()) |val| {
                    const s = uci.cStr(val);
                    const fwd = helper.parseFrpcForwardString(allocator, s) catch continue;
                    try frpc_list.append(fwd);
                }
            } else if (opt.isString()) {
                const opt_val = uci.cStr(opt.getString());
                const fwd = helper.parseFrpcForwardString(allocator, opt_val) catch continue;
                try frpc_list.append(fwd);
            }
        }

        // Assign FRPC forwards to the project's first port mapping or create a default one
        if (frpc_list.items.len > 0) {
            if (list.items[project_idx.?].port_mappings.len > 0) {
                list.items[project_idx.?].port_mappings[0].frpc = try frpc_list.toOwnedSlice();
            } else {
                // Create a default port mapping if none exists (mirror single-port mode)
                const listen_str = try std.fmt.allocPrint(allocator, "{d}", .{list.items[project_idx.?].listen_port});
                errdefer allocator.free(listen_str);
                const target_str = try std.fmt.allocPrint(allocator, "{d}", .{list.items[project_idx.?].target_port});
                errdefer allocator.free(target_str);

                const owned_frpc = try frpc_list.toOwnedSlice();
                errdefer {
                    for (owned_frpc) |*f| f.deinit(allocator);
                    allocator.free(owned_frpc);
                }

                const default_mapping = types.PortMapping{
                    .listen_port = listen_str,
                    .target_port = target_str,
                    .protocol = list.items[project_idx.?].protocol,
                    .frpc = owned_frpc,
                };

                const owned_slice = try allocator.alloc(types.PortMapping, 1);
                owned_slice[0] = default_mapping;
                list.items[project_idx.?].port_mappings = owned_slice;
            }
        }
    }

    // Parse FRPS nodes from UCI config
    var frps_nodes = std.StringHashMap(types.FrpsNode).init(allocator);
    errdefer {
        var it = frps_nodes.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        frps_nodes.deinit();
    }

    var frps_sec_it = uci.sections(pkg);
    while (frps_sec_it.next()) |sec| {
        const sec_type = uci.cStr(sec.sectionType());
        if (!std.mem.eql(u8, sec_type, "frps_node")) continue;

        var frps_node = types.FrpsNode{
            .enabled = true,
            .bind_port = null,
            .auth_token = null,
            .log_level = null,
            .allow_ports = null,
            .bind_addr = null,
            .max_pool_count = null,
            .max_ports_per_client = null,
            .tcp_mux = null,
            .dashboard_addr = null,
            .dashboard_port = null,
            .dashboard_user = null,
            .dashboard_pwd = null,
        };
        var node_name: []const u8 = "";

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
            } else if (std.mem.eql(u8, opt_name, "bind_port") or std.mem.eql(u8, opt_name, "port")) {
                // Support both "bind_port" (canonical) and "port" (alias) for FRPS server port
                frps_node.bind_port = try types.parsePort(opt_val);
            } else if (std.mem.eql(u8, opt_name, "auth_token") or std.mem.eql(u8, opt_name, "token")) {
                // Support both "auth_token" (canonical) and "token" (alias)
                const trimmed = std.mem.trim(u8, opt_val, " \t\r\n");
                if (trimmed.len > 0) frps_node.auth_token = try allocator.dupe(u8, trimmed);
            } else if (std.mem.eql(u8, opt_name, "log_level")) {
                const trimmed = std.mem.trim(u8, opt_val, " \t\r\n");
                if (trimmed.len > 0) frps_node.log_level = try allocator.dupe(u8, trimmed);
            } else if (std.mem.eql(u8, opt_name, "allow_ports")) {
                const trimmed = std.mem.trim(u8, opt_val, " \t\r\n");
                if (trimmed.len > 0) frps_node.allow_ports = try allocator.dupe(u8, trimmed);
            } else if (std.mem.eql(u8, opt_name, "bind_addr")) {
                const trimmed = std.mem.trim(u8, opt_val, " \t\r\n");
                if (trimmed.len > 0) frps_node.bind_addr = try allocator.dupe(u8, trimmed);
            } else if (std.mem.eql(u8, opt_name, "max_pool_count")) {
                frps_node.max_pool_count = std.fmt.parseUnsigned(u32, std.mem.trim(u8, opt_val, " \t\r\n"), 10) catch null;
            } else if (std.mem.eql(u8, opt_name, "max_ports_per_client")) {
                frps_node.max_ports_per_client = std.fmt.parseUnsigned(u32, std.mem.trim(u8, opt_val, " \t\r\n"), 10) catch null;
            } else if (std.mem.eql(u8, opt_name, "tcp_mux")) {
                frps_node.tcp_mux = try types.parseBool(opt_val);
            } else if (std.mem.eql(u8, opt_name, "dashboard_addr")) {
                const trimmed = std.mem.trim(u8, opt_val, " \t\r\n");
                if (trimmed.len > 0) frps_node.dashboard_addr = try allocator.dupe(u8, trimmed);
            } else if (std.mem.eql(u8, opt_name, "dashboard_port")) {
                frps_node.dashboard_port = std.fmt.parseUnsigned(u16, std.mem.trim(u8, opt_val, " \t\r\n"), 10) catch null;
            } else if (std.mem.eql(u8, opt_name, "dashboard_user")) {
                const trimmed = std.mem.trim(u8, opt_val, " \t\r\n");
                if (trimmed.len > 0) frps_node.dashboard_user = try allocator.dupe(u8, trimmed);
            } else if (std.mem.eql(u8, opt_name, "dashboard_pwd")) {
                const trimmed = std.mem.trim(u8, opt_val, " \t\r\n");
                if (trimmed.len > 0) frps_node.dashboard_pwd = try allocator.dupe(u8, trimmed);
            } else if (std.mem.eql(u8, opt_name, "enabled")) {
                frps_node.enabled = try types.parseBool(opt_val);
            }
        }

        // Validate FRPS node - only node_name is required
        if (node_name.len == 0) {
            frps_node.deinit(allocator);
            continue;
        }

        const node_name_owned = try allocator.dupe(u8, node_name);
        errdefer allocator.free(node_name_owned);

        try frps_nodes.put(node_name_owned, frps_node);
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
            .enabled = true,
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
            } else if (std.mem.eql(u8, opt_name, "enabled")) {
                ddns_cfg.enabled = try types.parseBool(opt_val);
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

    const projects = try list.toOwnedSlice();
    errdefer {
        for (projects) |*project| project.deinit(allocator);
        allocator.free(projects);
    }
    const ddns_configs = try ddns_list.toOwnedSlice();
    errdefer {
        for (ddns_configs) |*ddns| ddns.deinit(allocator);
        allocator.free(ddns_configs);
    }
    const rathole_client_services = try rathole_client_services_list.toOwnedSlice();
    errdefer {
        for (rathole_client_services) |*service| service.deinit(allocator);
        allocator.free(rathole_client_services);
    }
    const rathole_server_services = try rathole_server_services_list.toOwnedSlice();
    errdefer {
        for (rathole_server_services) |*service| service.deinit(allocator);
        allocator.free(rathole_server_services);
    }

    var cfg = types.Config{
        .log_config = log_config,
        .app_forward_loop_mode = app_forward_loop_mode,
        .use_nftables = use_nftables,
        .frps_config_mode = frps_config_mode,
        .frps_config_format = frps_config_format,
        .frps_config_path = frps_config_path,
        .frps_config_content = frps_config_content,
        .frpc_config_mode = frpc_config_mode,
        .frpc_config_format = frpc_config_format,
        .frpc_config_path = frpc_config_path,
        .frpc_config_content = frpc_config_content,
        .frp_config_root = frp_config_root,
        .projects = projects,
        .frpc_nodes = frpc_nodes,
        .frps_nodes = frps_nodes,
        .rathole_client_nodes = rathole_client_nodes,
        .rathole_client_services = rathole_client_services,
        .rathole_server_nodes = rathole_server_nodes,
        .rathole_server_services = rathole_server_services,
        .wol_targets = wol_targets,
        .ddns_configs = ddns_configs,
    };
    errdefer cfg.deinit(allocator);

    helper.validateGlobalConfig(&cfg) catch |err| {
        std.log.err("Global configuration validation error: {any}", .{err});
        return err;
    };

    for (cfg.projects, 0..) |*project, idx| {
        helper.validateProject(project, &cfg) catch |err| {
            std.log.err("Project {d} ('{s}') configuration error: {any}. Disabling this project so remaining projects and services can continue.", .{ idx + 1, project.remark, err });
            project.enabled = false;
        };
    }

    helper.validateFeatureAvailability(&cfg, build_options.wol_mode) catch |err| {
        std.log.err("Feature availability validation error: {any}", .{err});
        return err;
    };
    cfg.resolveWolTargets();
    return cfg;
}
