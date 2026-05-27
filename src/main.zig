const std = @import("std");
const build_options = @import("build_options");
const config = @import("config/mod.zig");
const app_forward = @import("impl/app_forward.zig");
const frpc_forward = if (build_options.frpc_mode) @import("impl/frpc_forward.zig") else struct {};
const ddns_manager = if (build_options.ddns_mode) @import("impl/ddns_manager.zig") else struct {};
const frps_forward = if (build_options.frps_mode) @import("impl/frps_forward.zig") else struct {};
const libfrpc = if (build_options.frpc_mode) @import("impl/frpc/libfrpc.zig") else struct {};
const libfrps = if (build_options.frps_mode) @import("impl/frps/libfrps.zig") else struct {};
const project_status = @import("impl/project_status.zig");
const ubus_server = if (build_options.ubus_mode) @import("ubus/server.zig") else void;
// 仅在 UCI 模式下导入 UCI 相关模块
const firewall = if (build_options.uci_mode) @import("impl/uci_firewall.zig") else void;
const nft_firewall = if (build_options.nftables_mode) @import("impl/nft_firewall.zig") else void;
const nftables = if (build_options.nftables_mode) @import("nftables/mod.zig") else void;
const uci = if (build_options.uci_mode) @import("uci/mod.zig") else void;
const event_log = @import("event_log.zig");
const process_lock = @import("process_lock.zig");
const file_log = @import("file_log.zig");
const compat = @import("compat.zig");

var global_log_level: std.log.Level = .info;

pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = myLogFn,
};

fn myLogFn(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@intFromEnum(level) > @intFromEnum(global_log_level)) return;

    std.debug.print("[" ++ level.asText() ++ "] " ++ format ++ "\n", args);

    if (file_log.getGlobalFileLogger()) |logger| {
        logger.log(level, scope, format, args);
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    errdefer {
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpErrorReturnTrace(trace);
        }
    }

    // Ensure single instance ownership before starting services.
    try process_lock.ensureSingleInstance(allocator);
    defer process_lock.cleanup();

    // Initialize event logger
    event_log.initGlobal(allocator);
    defer event_log.deinitGlobal();

    // 加载配置
    var result = try loadConfig(allocator, args);
    defer result.deinit(allocator);

    if (result.log_config.enabled) {
        file_log.initGlobalFileLogger(allocator, result.log_config);
    }
    defer file_log.deinitGlobalFileLogger();

    const cfg = &result;

    @import("impl/app_forward/uv.zig").printVersion();
    std.log.info("PortWeaver starting with {d} project(s)...", .{cfg.projects.len});
    if (build_options.frpc_mode) {
        std.log.info("FRPC client mode enabled (build flag)", .{});
    }
    if (build_options.frps_mode) {
        std.log.info("FRPS server mode enabled (build flag)", .{});
    }
    if (build_options.nftables_mode) {
        std.log.info("nftables mode enabled (build flag)", .{});
    }

    var handles = try std.array_list.Managed(project_status.ProjectHandle).initCapacity(allocator, cfg.projects.len);
    defer {
        if (build_options.ubus_mode) {
            ubus_server.stop();
        }
        project_status.stopAll(&handles);
        handles.deinit();
        if (build_options.frpc_mode) {
            frpc_forward.stopAll();
            libfrpc.cleanup();
        }
        if (build_options.ddns_mode) {
            ddns_manager.deinit(allocator);
        }
        if (build_options.frps_mode) {
            frps_forward.stopAll();
            libfrps.cleanup();
        }
    }

    // 应用配置并启动服务
    const has_app_forward = try applyConfig(allocator, &handles, cfg);

    if (build_options.ubus_mode) {
        ubus_server.start(allocator, &handles) catch |err| {
            std.log.warn("Failed to start ubus server: {any}", .{err});
        };
    }

    std.log.info("PortWeaver started successfully.", .{});

    // 保持程序运行（如果有应用层转发或 UBUS 服务）
    if (has_app_forward or build_options.ubus_mode) {
        const service_type = if (has_app_forward) "Application layer forwarding" else "UBUS server";
        std.log.info("{s} is running. Press Ctrl+C to stop.\n", .{service_type});

        while (true) {
            if (process_lock.shouldExitForTakeover()) {
                std.log.info("PortWeaver takeover requested. Stopping services cleanly...", .{});
                break;
            }

            compat.sleepNanos(100 * std.time.ns_per_ms);
        }
    }
}
/// 根据编译选项和命令行参数加载配置
fn loadConfig(allocator: std.mem.Allocator, args: []const []const u8) !config.Config {
    if (build_options.uci_mode) {
        // UCI 模式：直接从 UCI 加载配置
        std.log.info("Loading configuration from UCI...", .{});
        var uci_ctx = try uci.UciContext.alloc();
        defer uci_ctx.free();
        return config.loadFromUci(allocator, uci_ctx, "portweaver");
    } else {
        // JSON 模式：需要通过 -c 参数指定配置文件
        const config_file = try parseConfigFile(args);
        std.log.info("Loading configuration from JSON file: {s}", .{config_file});
        return config.loadFromJsonFile(allocator, config_file);
    }
}

/// 解析命令行参数中的配置文件路径
fn parseConfigFile(args: []const []const u8) ![]const u8 {
    for (args[1..], 1..) |arg, i| {
        if (std.mem.eql(u8, arg, "-c")) {
            if (i + 1 < args.len) {
                return args[i + 1];
            }
            std.log.err("-c option requires a config file path", .{});
            return error.MissingConfigFile;
        }
    }

    // 如果没有指定配置文件，使用默认路径
    std.log.info("No config file specified, using default: config.json", .{});
    return "config.json";
}
fn setupProject(allocator: std.mem.Allocator, id: usize, handles: *std.array_list.Managed(project_status.ProjectHandle), project: config.Project) !void {
    const handle: project_status.ProjectHandle = .init(allocator, id, project);
    try handles.append(handle);

    if (!project.enabled) {
        handles.items[handles.items.len - 1].setDisabled();
        std.log.info("Project {d} ({s}) is disabled, skipping.", .{ id + 1, project.remark });
        return;
    }

    // 应用层端口转发将在所有handle添加完成后统一启动
    if (project.enable_app_forward) {
        std.log.debug("  Will start application layer forwarding...", .{});
    }
}
/// 应用配置：设置防火墙规则并启动应用层转发
fn applyConfig(allocator: std.mem.Allocator, handles: *std.array_list.Managed(project_status.ProjectHandle), cfg: *const config.Config) !bool {
    // 设置所有项目
    for (cfg.projects, 0..) |project, i| {
        setupProject(allocator, i, handles, project) catch |err| {
            std.log.err("Failed to setup project {d} ({s}): {any}", .{ i + 1, project.remark, err });
            continue;
        };
    }

    // 防火墙规则：根据配置选择后端
    if (build_options.nftables_mode and cfg.use_nftables) {
        // 使用 nftables 后端
        applyNftablesRules(allocator, cfg.projects) catch |err| {
            std.log.warn("Failed to apply nftables rules: {any}", .{err});
        };
    } else if (build_options.uci_mode) {
        // 使用 OpenWrt fw4 后端（默认）
        try applyFirewallRules(allocator, cfg.projects);
    }

    // 启动 DDNS 服务（如果启用）
    if (build_options.ddns_mode) {
        std.log.info("Applying DDNS configuration...", .{});
        ddns_manager.applyConfig(allocator, cfg.ddns_configs) catch |err| {
            std.log.warn("Failed to apply DDNS configuration: {any}", .{err});
        };
    }

    // 启动 FRPS 服务（如果启用）
    if (build_options.frps_mode) {
        std.log.info("Starting FRPS servers...", .{});
        var frps_it = cfg.frps_nodes.iterator();

        while (frps_it.next()) |entry| {
            const node_name = entry.key_ptr.*;
            const node = entry.value_ptr.*;
            if (node.enabled) {
                frps_forward.startServer(allocator, node_name, node) catch |err| {
                    std.log.warn("Failed to start FRPS server {s}: {any}", .{ node_name, err });
                };
            }
        }
    }

    // 所有handle添加完成后，启动线程
    // 这样可以确保handles数组不会在线程运行时重新分配
    return try startForwardingThreads(allocator, handles, &cfg.frpc_nodes);
}

/// 配置防火墙规则（仅 UCI 模式）
fn applyFirewallRules(allocator: std.mem.Allocator, projects: []const config.Project) !void {
    var uci_ctx = try uci.UciContext.alloc();
    defer uci_ctx.free();

    // 删除旧的规则
    std.log.info("Clearing old firewall rules...", .{});
    firewall.clearFirewallRules(uci_ctx, allocator) catch |err| {
        std.log.warn("Failed to clear old firewall rules: {any}", .{err});
    };

    // 应用新规则
    for (projects, 0..) |project, i| {
        if (!project.enabled) continue;

        std.log.info("Applying project {d}: {s}", .{ i + 1, project.remark });
        logProjectConfig(project);

        // 应用防火墙规则
        // 注意：即使启用统计模式，应用层转发仍需要 ACCEPT 规则来放通端口
        // applyFirewallRulesForProject 会根据配置标志智能决定需要哪些规则
        std.log.debug("  Applying firewall rules...", .{});
        firewall.applyFirewallRulesForProject(uci_ctx, allocator, project) catch |err| {
            std.log.warn("Failed to apply firewall rules for project {d}: {any}", .{ i + 1, err });
        };
    }

    // 重新加载防火墙配置
    std.log.info("Reloading firewall...", .{});
    firewall.reloadFirewall(allocator) catch |err| {
        std.log.warn("Failed to reload firewall: {any}", .{err});
    };
}

/// 配置 nftables 规则（仅 nftables 模式）
fn applyNftablesRules(allocator: std.mem.Allocator, projects: []const config.Project) !void {
    if (!nftables.isLoaded()) {
        std.log.warn("libnftables not available, skipping nftables rules", .{});
        return;
    }

    var ctx = try nftables.NftablesContext.init(allocator);
    defer ctx.deinit();

    // Setup table and chains
    std.log.info("Setting up nftables table...", .{});
    nft_firewall.setupTable(&ctx) catch |err| {
        std.log.warn("Failed to setup nftables table: {any}", .{err});
        return;
    };

    // Clear old rules
    std.log.info("Clearing old nftables rules...", .{});
    nft_firewall.clearRules(&ctx) catch |err| {
        std.log.warn("Failed to clear old nftables rules: {any}", .{err});
    };

    // Apply new rules
    for (projects, 0..) |project, i| {
        if (!project.enabled) continue;

        std.log.info("Applying nftables rules for project {d}: {s}", .{ i + 1, project.remark });
        nft_firewall.applyRulesForProject(&ctx, allocator, project) catch |err| {
            std.log.warn("Failed to apply nftables rules for project {d}: {any}", .{ i + 1, err });
        };
    }

    std.log.info("nftables rules applied successfully.", .{});
}

/// 记录项目配置信息
fn logProjectConfig(project: config.Project) void {
    if (project.port_mappings.len > 0) {
        std.log.debug("  Mode: Port Mappings ({d} mapping(s))", .{project.port_mappings.len});
        std.log.debug("  Target: {s}", .{project.target_address});
    } else {
        std.log.debug("  Mode: Single Port", .{});
        std.log.debug("  Listen: :{d} -> Target: {s}:{d}", .{
            project.listen_port,
            project.target_address,
            project.target_port,
        });
    }
}

/// 启动所有转发线程
fn startForwardingThreads(
    allocator: std.mem.Allocator,
    handles: *std.array_list.Managed(project_status.ProjectHandle),
    frpc_nodes: *const std.StringHashMap(config.FrpcNode),
) !bool {
    std.log.info("Starting forwarding threads...", .{});
    var has_app_forward = false;

    for (handles.items) |*handle| {
        if (!handle.cfg.enabled) {
            continue;
        }
        if (handle.cfg.enable_app_forward) {
            has_app_forward = true;
        }
        startForwarding(allocator, handle, frpc_nodes);
    }
    if (build_options.frpc_mode) {
        frpc_forward.flushAllClients();
    }
    return has_app_forward;
}

/// 启动转发
fn startForwarding(
    allocator: std.mem.Allocator,
    handle: *project_status.ProjectHandle,
    frpc_nodes: *const std.StringHashMap(config.FrpcNode),
) void {
    std.log.info("[Thread] Starting forwarding for project {d} ({s}), app_forward={}, stats={}", .{ handle.id + 1, handle.cfg.remark, handle.cfg.enable_app_forward, handle.cfg.enable_stats });
    // 启动应用层转发
    if (handle.cfg.enable_app_forward) {
        app_forward.startForwarding(allocator, handle) catch |err| {
            std.log.err("Failed to start forwarding for project {d} ({s}): {any}", .{ handle.id + 1, handle.cfg.remark, err });
            if (compat.isDebugBuild()) {
                if (@errorReturnTrace()) |trace| {
                    std.debug.dumpErrorReturnTrace(trace);
                }
            }
        };
    }
    // 启动 FRPC 转发（如果启用）
    if (build_options.frpc_mode) {
        frpc_forward.startForwarding(allocator, handle, frpc_nodes) catch |err| {
            std.log.err("Failed to start FRPC forwarding for project {d} ({s}): {any}", .{ handle.id + 1, handle.cfg.remark, err });
            if (compat.isDebugBuild()) {
                if (@errorReturnTrace()) |trace| {
                    std.debug.dumpErrorReturnTrace(trace);
                }
            }
        };
    }
}
