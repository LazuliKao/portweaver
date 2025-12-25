// 应用层端口转发使用示例
// 编译后可以直接运行此文件来测试端口转发功能

const std = @import("std");
const config = @import("config/mod.zig");
const app_forward = @import("impl/app_forward.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== PortWeaver 应用层端口转发示例 ===\n\n", .{});

    // 从命令行参数或配置文件加载配置
    // 这里演示手动创建配置
    try runTcpExample(allocator);
}

/// TCP 转发示例
fn runTcpExample(allocator: std.mem.Allocator) !void {
    std.debug.print("启动 TCP 转发示例...\n", .{});
    std.debug.print("监听端口: 8080 -> 目标: 127.0.0.1:80\n", .{});
    std.debug.print("你可以通过访问 http://127.0.0.1:8080 来测试\n\n", .{});

    const tcp_project = config.Project{
        .remark = "TCP Forward Example",
        .listen_port = 8080,
        .target_address = "127.0.0.1",
        .target_port = 80,
        .protocol = .tcp,
        .family = .any,
        .enable_app_forward = true,
        .open_firewall_port = false,
        .add_firewall_forward = false,
    };

    // 启动转发（这会阻塞）
    try app_forward.startForwarding(allocator, tcp_project);
}

/// UDP 转发示例
fn runUdpExample(allocator: std.mem.Allocator) !void {
    std.debug.print("启动 UDP 转发示例...\n", .{});
    std.debug.print("监听端口: 5353 -> 目标: 8.8.8.8:53\n", .{});
    std.debug.print("你可以使用 nslookup 命令测试: nslookup google.com 127.0.0.1 -port=5353\n\n", .{});

    const udp_project = config.Project{
        .remark = "UDP Forward Example - DNS",
        .listen_port = 5353,
        .target_address = "8.8.8.8",
        .target_port = 53,
        .protocol = .udp,
        .family = .ipv4,
        .enable_app_forward = true,
        .open_firewall_port = false,
        .add_firewall_forward = false,
    };

    try app_forward.startForwarding(allocator, udp_project);
}

/// 从 JSON 配置文件加载并运行多个转发项目
fn runFromConfig(allocator: std.mem.Allocator, config_file: []const u8) !void {
    std.debug.print("从配置文件加载: {s}\n\n", .{config_file});

    // 加载配置
    var cfg = try config.loadFromJsonFile(allocator, config_file);
    defer cfg.deinit(allocator);

    std.debug.print("加载了 {d} 个转发项目\n", .{cfg.projects.len});

    // 为每个启用应用层转发的项目创建线程
    var threads = std.ArrayList(std.Thread).init(allocator);
    defer {
        for (threads.items) |thread| {
            thread.join();
        }
        threads.deinit();
    }

    for (cfg.projects) |project| {
        if (project.enable_app_forward) {
            std.debug.print("启动转发: {s}\n", .{project.remark});

            const thread = try std.Thread.spawn(.{}, startProjectForward, .{
                allocator,
                project,
            });
            try threads.append(thread);
        }
    }

    // 等待所有线程
    std.debug.print("\n所有转发服务已启动，按 Ctrl+C 停止\n", .{});
}

fn startProjectForward(allocator: std.mem.Allocator, project: config.Project) void {
    app_forward.startForwarding(allocator, project) catch |err| {
        std.debug.print("转发错误 ({s}): {}\n", .{ project.remark, err });
    };
}
