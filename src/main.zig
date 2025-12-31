const std = @import("std");
const build_options = @import("build_options");
const config = @import("config/mod.zig");
const app_forward = @import("impl/app_forward.zig");
const builtin = @import("builtin");
const Io = std.Io;
// 仅在 UCI 模式下导入 UCI 相关模块
const firewall = if (build_options.uci_mode) @import("impl/uci_firewall.zig") else void;
const uci = if (build_options.uci_mode) @import("uci/mod.zig") else void;
pub fn test1() !void {
    const network = @import("impl/network.zig");

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // get the name of the server
    var args_iter = try std.process.argsWithAllocator(allocator);
    defer args_iter.deinit();

    _ = args_iter.next() orelse return error.MissingArgument;

    // const server_name = args_iter.next() orelse "Server Name";

    // Create a UDP socket
    try network.init();
    defer network.deinit();
    var sock = try network.Socket.create(.ipv4, .udp);
    defer sock.close();

    const endpoint = network.EndPoint{
        .address = network.Address{
            .ipv4 = network.Address.IPv4.any,
        },
        .port = 8080,
    };

    // Setup the readloop
    std.debug.print("Sending UDP messages to multicast address {f}\n", .{endpoint});
    var threaded: Io.Threaded = .init_single_threaded;
    // var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    while (true) {
        try sock.bind(endpoint);
        // try sock.listen(endpoint);
        // _ = try sock.sendTo(endpoint, server_name);
        io.sleep(std.Io.Duration.fromSeconds(1), .awake) catch {};
    }
}
pub fn main() !void {
    try test1();

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
    var threaded: Io.Threaded = .init_single_threaded;
    // var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    // 解析命令行参数
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // 加载配置
    var cfg = try loadConfig(io, allocator, args);
    defer cfg.deinit(allocator);

    std.debug.print("PortWeaver starting with {d} project(s)...\n", .{cfg.projects.len});

    // 应用配置并启动服务
    const has_app_forward = try applyConfig(io, allocator, cfg);
    std.debug.print("PortWeaver started successfully.\n", .{});
    // 如果有应用层转发，保持程序运行
    if (has_app_forward) {
        std.log.info("Application layer forwarding is running. Press Ctrl+C to stop.\n", .{});
        while (true) {
            io.sleep(std.Io.Duration.fromSeconds(1), .awake) catch {};
        }
    }
}
/// 根据编译选项和命令行参数加载配置
fn loadConfig(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !config.Config {
    if (build_options.uci_mode) {
        // UCI 模式：直接从 UCI 加载配置
        std.debug.print("Loading configuration from UCI...\n", .{});
        // Allocate UCI context
        var uci_ctx = try uci.UciContext.alloc();
        defer uci_ctx.free();
        return try config.loadFromUci(allocator, uci_ctx, "portweaver");
    } else {
        // JSON 模式：需要通过 -c 参数指定配置文件
        const config_file = try parseConfigFile(args);
        std.debug.print("Loading configuration from JSON file: {s}\n", .{config_file});
        return try config.loadFromJsonFile(io, allocator, config_file);
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
                std.debug.print("Error: -c option requires a config file path\n", .{});
                return error.MissingConfigFile;
            }
        }
    }

    // 如果没有指定配置文件，使用默认路径
    std.debug.print("No config file specified, using default: config.json\n", .{});
    return "config.json";
}

/// 应用配置：设置防火墙规则并启动应用层转发
fn applyConfig(io: Io, allocator: std.mem.Allocator, cfg: config.Config) !bool {
    var has_app_forward = false;

    // 初始化 UCI 上下文（如果需要配置防火墙）
    if (build_options.uci_mode) {
        var uci_ctx = try uci.UciContext.alloc();
        defer uci_ctx.free();

        // 删除旧的规则
        std.debug.print("Clearing old firewall rules...\n", .{});
        firewall.clearFirewallRules(uci_ctx, allocator) catch |err| {
            std.debug.print("Warning: Failed to clear old firewall rules: {any}\n", .{err});
        };
        for (cfg.projects, 0..) |project, i| {
            if (!project.enabled) {
                std.debug.print("Project {d} ({s}) is disabled, skipping.\n", .{ i + 1, project.remark });
                continue;
            }

            std.debug.print("Applying project {d}: {s}\n", .{ i + 1, project.remark });
            if (project.port_mappings.len > 0) {
                std.debug.print("  Mode: Port Mappings ({d} mapping(s))\n", .{project.port_mappings.len});
                std.debug.print("  Target: {s}\n", .{project.target_address});
            } else {
                std.debug.print("  Mode: Single Port\n", .{});
                std.debug.print("  Listen: :{d} -> Target: {s}:{d}\n", .{
                    project.listen_port,
                    project.target_address,
                    project.target_port,
                });
            }

            // 应用防火墙规则
            std.debug.print("  Applying firewall rules...\n", .{});
            firewall.applyFirewallRulesForProject(uci_ctx, allocator, project) catch |err| {
                std.debug.print("Warning: Failed to apply firewall rules: {any}\n", .{err});
            };

            // 启动应用层端口转发（如果启用）
            if (project.enable_app_forward) {
                has_app_forward = true;
                std.debug.print("  Starting application layer forwarding...\n", .{});

                // 为每个项目创建独立线程
                const thread = std.Thread.spawn(.{}, startForwardingThread, .{
                    io,
                    allocator,
                    project,
                }) catch |err| {
                    std.debug.print("Error: Failed to spawn forwarding thread: {any}\n", .{err});
                    continue;
                };
                thread.detach();
            }
        }
        // 重新加载防火墙配置
        std.debug.print("Reloading firewall...\n", .{});
        firewall.reloadFirewall(io, allocator) catch |err| {
            std.debug.print("Warning: Failed to reload firewall: {any}\n", .{err});
        };
    } else {
        // JSON 模式：只启动应用层转发
        for (cfg.projects, 0..) |project, i| {
            if (!project.enabled) {
                std.debug.print("Project {d} ({s}) is disabled, skipping.\n", .{ i + 1, project.remark });
                continue;
            }

            std.debug.print("Applying project {d}: {s}\n", .{ i + 1, project.remark });
            if (project.port_mappings.len > 0) {
                std.debug.print("  Mode: Port Mappings ({d} mapping(s))\n", .{project.port_mappings.len});
                std.debug.print("  Target: {s}\n", .{project.target_address});
            } else {
                std.debug.print("  Mode: Single Port\n", .{});
                std.debug.print("  Listen: :{d} -> Target: {s}:{d}\n", .{
                    project.listen_port,
                    project.target_address,
                    project.target_port,
                });
            }

            // 启动应用层端口转发（如果启用）
            if (project.enable_app_forward) {
                has_app_forward = true;
                std.debug.print("  Starting application layer forwarding...\n", .{});

                // 为每个项目创建独立线程
                const thread = std.Thread.spawn(.{}, startForwardingThread, .{
                    io,
                    allocator,
                    project,
                }) catch |err| {
                    std.debug.print("Error: Failed to spawn forwarding thread: {any}\n", .{err});
                    continue;
                };
                thread.detach();
            }
        }
    }

    if (has_app_forward) {
        return true;
    }
    return false;
}

/// 在独立线程中启动转发
fn startForwardingThread(io: Io, allocator: std.mem.Allocator, project: config.Project) void {
    app_forward.startForwarding(io, allocator, project) catch |err| {
        std.debug.print("Error: Failed to start forwarding for {s}: {any}\n", .{ project.remark, err });
        const trace = @errorReturnTrace();
        if (trace) |t| {
            std.debug.dumpStackTrace(t);
        } else {
            std.debug.print("No error return trace available (build may have tracing disabled).\n", .{});
        }
    };
}

// test "test" {}
