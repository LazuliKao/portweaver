const std = @import("std");
const build_options = @import("build_options");
const config = @import("config/mod.zig");
const firewall = @import("impl/uci_firewall.zig");
const app_forward = @import("impl/app_forward.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 解析命令行参数
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    // 加载配置
    const cfg = try loadConfig(allocator, args);
    defer cfg.deinit(allocator);

    std.debug.print("PortWeaver starting with {d} project(s)...\n", .{cfg.projects.len});

    // 应用配置并启动服务
    try applyConfig(allocator, cfg);

    std.debug.print("PortWeaver started successfully.\n", .{});
}

/// 根据编译选项和命令行参数加载配置
fn loadConfig(allocator: std.mem.Allocator, args: []const []const u8) !config.Config {
    if (build_options.enable_json) {
        // JSON 模式：需要通过 -c 参数指定配置文件
        const config_file = try parseConfigFile(args);
        std.debug.print("Loading configuration from JSON file: {s}\n", .{config_file});
        return try config.loadFromJsonFile(allocator, config_file);
    } else {
        // UCI 模式：直接从 UCI 加载配置
        std.debug.print("Loading configuration from UCI...\n", .{});
        return try config.loadFromUci(allocator);
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
fn applyConfig(allocator: std.mem.Allocator, cfg: config.Config) !void {
    for (cfg.projects, 0..) |project, i| {
        if (!project.enabled) {
            std.debug.print("Project {d} ({s}) is disabled, skipping.\n", .{ i + 1, project.remark });
            continue;
        }

        std.debug.print("Applying project {d}: {s}\n", .{ i + 1, project.remark });
        std.debug.print("  Listen: :{d} -> Target: {s}:{d}\n", .{
            project.listen_port,
            project.target_address,
            project.target_port,
        });

        // 应用防火墙规则
        if (!build_options.enable_json) {
            // UCI 模式下重新加载防火墙
            if (i == cfg.projects.len - 1) {
                // 只在最后一个项目后重新加载防火墙
                firewall.reloadFirewall(allocator) catch |err| {
                    std.debug.print("Warning: Failed to reload firewall: {}\n", .{err});
                };
            }
        }

        // 启动应用层端口转发（如果启用）
        if (project.enable_app_forward) {
            std.debug.print("  Starting application layer forwarding...\n", .{});
            // TODO: 实现应用层转发的实际启动逻辑
            // 这里需要启动独立的转发线程或异步任务
        }
    }
}
