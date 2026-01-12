const std = @import("std");
const build_options = @import("build_options");
const config = @import("config/mod.zig");
const app_forward = @import("impl/app_forward.zig");
const frp_forward = if (build_options.frpc_mode) @import("impl/frp_forward.zig") else struct {};
const project_status = @import("impl/project_status.zig");
const builtin = @import("builtin");
const ubus_server = if (build_options.ubus_mode) @import("ubus/server.zig") else void;
// 仅在 UCI 模式下导入 UCI 相关模块
const firewall = if (build_options.uci_mode) @import("impl/uci_firewall.zig") else void;
const uci = if (build_options.uci_mode) @import("uci/mod.zig") else void;
pub fn main() !void {
    const GPAType = std.heap.GeneralPurposeAllocator(.{});
    var gpa: ?GPAType = null;
    // 默认使用 c_allocator
    var allocator: std.mem.Allocator = std.heap.c_allocator;
    // Debug 模式下覆盖为 GPA
    defer if (gpa) |*g| {
        // 检查内存泄漏
        if (g.deinit() == .leak) {
            @panic("Memory leak detected!");
        }
    };
    if (builtin.mode == .Debug) {
        gpa = GPAType{};
        allocator = gpa.?.allocator();
    }
    // 解析命令行参数
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // 加载配置
    var cfg = try loadConfig(allocator, args);

    @import("impl/app_forward/uv.zig").printVersion();
    std.log.debug("PortWeaver starting with {d} project(s)...", .{cfg.projects.len});

    var handles: std.array_list.Managed(project_status.ProjectHandle) = .init(allocator);
    defer {
        project_status.stopAll(&handles);
        if (build_options.frpc_mode) {
            frp_forward.stopAll();
        }
        // Clean up config after stopping all threads
        cfg.deinit(allocator);
    }
    // 预分配容量以避免重新分配
    try handles.ensureTotalCapacity(cfg.projects.len);

    // 应用配置并启动服务
    const has_app_forward = try applyConfig(allocator, &handles, cfg);
    if (build_options.ubus_mode) {
        ubus_server.start(allocator, handles) catch |err| {
            std.log.debug("Warning: Failed to start ubus server: {any}", .{err});
        };
    }
    std.log.debug("PortWeaver started successfully.", .{});
    // 如果有应用层转发，保持程序运行
    if (has_app_forward) {
        std.log.info("Application layer forwarding is running. Press Ctrl+C to stop.\n", .{});
        while (true) {
            std.Thread.sleep(std.time.ns_per_s);
        }
    } else if (build_options.ubus_mode) {
        // 如果只有 UBUS 模式，保持程序运行
        std.log.info("UBUS server is running. Press Ctrl+C to stop.\n", .{});
        while (true) {
            std.Thread.sleep(std.time.ns_per_s);
        }
    }
}
/// 根据编译选项和命令行参数加载配置
fn loadConfig(allocator: std.mem.Allocator, args: []const []const u8) !config.Config {
    if (build_options.uci_mode) {
        // UCI 模式：直接从 UCI 加载配置
        std.log.debug("Loading configuration from UCI...", .{});
        // Allocate UCI context
        var uci_ctx = try uci.UciContext.alloc();
        defer uci_ctx.free();
        return try config.loadFromUci(allocator, uci_ctx, "portweaver");
    } else {
        // JSON 模式：需要通过 -c 参数指定配置文件
        const config_file = try parseConfigFile(args);
        std.log.debug("Loading configuration from JSON file: {s}", .{config_file});
        return try config.loadFromJsonFile(allocator, config_file);
    }
}

/// 解析命令行参数中的配置文件路径
fn parseConfigFile(args: []const []const u8) ![]const u8 {
    var i: usize = 1; // 跳过程序名称
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "-c")) {
            if (i + 1 < args.len) {
                return args[i + 1];
            } else {
                std.log.debug("Error: -c option requires a config file path", .{});
                return error.MissingConfigFile;
            }
        }
    }

    // 如果没有指定配置文件，使用默认路径
    std.log.debug("No config file specified, using default: config.json", .{});
    return "config.json";
}
fn setupProject(allocator: std.mem.Allocator, id: usize, handles: *std.array_list.Managed(project_status.ProjectHandle), project: config.Project) !void {
    var handle: project_status.ProjectHandle = .init(allocator, id, project);
    handles.append(handle) catch |err| {
        std.log.debug("Error: Failed to append project handles: {any}", .{err});
        return err;
    };
    if (!project.enabled) {
        handle.setDisabled();
        std.log.debug("Project {d} ({s}) is disabled, skipping.", .{ id + 1, project.remark });
        return;
    }
    // 应用层端口转发将在所有handle添加完成后统一启动
    if (project.enable_app_forward) {
        std.log.debug("  Will start application layer forwarding...", .{});
    }
}
/// 应用配置：设置防火墙规则并启动应用层转发
fn applyConfig(allocator: std.mem.Allocator, handles: *std.array_list.Managed(project_status.ProjectHandle), cfg: config.Config) !bool {

    // 初始化 UCI 上下文（如果需要配置防火墙）
    if (build_options.uci_mode) {
        var uci_ctx = try uci.UciContext.alloc();
        defer uci_ctx.free();

        // 删除旧的规则
        std.log.debug("Clearing old firewall rules...", .{});
        firewall.clearFirewallRules(uci_ctx, allocator) catch |err| {
            std.log.debug("Warning: Failed to clear old firewall rules: {any}", .{err});
        };
        for (cfg.projects, 0..) |project, i| {
            // 启动应用层端口转发
            setupProject(allocator, i, handles, project) catch |err| {
                std.log.debug("Error: Failed to setup project: {any}", .{err});
            };

            if (!project.enabled) {
                continue;
            }
            std.log.debug("Applying project {d}: {s}", .{ i + 1, project.remark });
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

            // 应用防火墙规则（统计模式下跳过）
            if (project.enable_stats) {
                std.log.debug("  Statistics enabled - skipping firewall forward rules (mutually exclusive)", .{});
            } else {
                std.log.debug("  Applying firewall rules...", .{});
                firewall.applyFirewallRulesForProject(uci_ctx, allocator, project) catch |err| {
                    std.log.debug("Warning: Failed to apply firewall rules: {any}", .{err});
                };
            }
        }

        // 重新加载防火墙配置
        std.log.debug("Reloading firewall...", .{});
        firewall.reloadFirewall(allocator) catch |err| {
            std.log.debug("Warning: Failed to reload firewall: {any}", .{err});
        };
    } else {
        // JSON 模式：只启动应用层转发
        for (cfg.projects, 0..) |project, i| {
            setupProject(allocator, i, handles, project) catch |err| {
                std.log.debug("Error: Failed to setup project: {any}", .{err});
            };
        }
    }

    // 所有handle添加完成后，启动线程
    // 这样可以确保handles数组不会在线程运行时重新分配
    std.log.debug("Starting forwarding threads...", .{});
    var has_app_forward = false;
    for (handles.items) |*handle| {
        if (!handle.cfg.enabled) {
            continue;
        }
        if (handle.cfg.enable_app_forward) {
            std.log.debug("  Launching thread for project {d} ({s})...", .{ handle.id, handle.cfg.remark });
            const thread = std.Thread.spawn(.{}, startForwardingThread, .{
                allocator,
                handle,
                &cfg.frp_nodes,
            }) catch |err| {
                std.log.debug("Error: Failed to spawn forwarding thread: {any}", .{err});
                continue;
            };
            thread.detach();
            has_app_forward = true;
        }
    }

    return has_app_forward;
}

/// 在独立线程中启动转发
fn startForwardingThread(
    allocator: std.mem.Allocator,
    handle: *project_status.ProjectHandle,
    frp_nodes: *const std.StringHashMap(config.FrpNode),
) void {
    std.log.debug("[FORWARDING_THREAD] Starting for project {d} ({s}), enable_app_forward={}, enable_stats={}", .{ handle.id, handle.cfg.remark, handle.cfg.enable_app_forward, handle.cfg.enable_stats });
    app_forward.startForwarding(allocator, handle) catch |err| {
        std.log.debug("Error: Failed to start forwarding for {s}: {any}", .{ handle.cfg.remark, err });
        if (builtin.mode == .Debug) {
            if (@errorReturnTrace()) |trace| {
                std.debug.dumpStackTrace(trace.*);
            }
        }
    };

    if (build_options.frpc_mode) {
        frp_forward.startForwarding(allocator, handle, frp_nodes) catch |err| {
            std.log.debug("Error: Failed to start FRP forwarding for {s}: {any}", .{ handle.cfg.remark, err });
        };
    }
}
