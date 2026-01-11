const std = @import("std");
const libfrp = @import("libfrp.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== FRP Client Example ===\n", .{});

    // 获取版本信息
    const version = try libfrp.getVersion(allocator);
    defer allocator.free(version);
    std.debug.print("FRP Version: {s}\n\n", .{version});

    // 创建 FRP 客户端
    // 注意：这里使用示例配置，实际使用时需要替换为真实的 FRP 服务器地址
    var client = try libfrp.FrpClient.init(
        allocator,
        "frp.example.com", // FRP 服务器地址
        7000, // FRP 服务器端口
        "your_token_here", // 认证 token（可选）
    );
    defer client.deinit();

    std.debug.print("✓ FRP Client created\n", .{});

    // 添加 TCP 代理 - 将本地 SSH 服务映射到远程端口
    try client.addTcpProxy(
        "ssh_proxy", // 代理名称
        "127.0.0.1", // 本地 IP
        22, // 本地端口 (SSH)
        6000, // 远程端口
    );
    std.debug.print("✓ TCP proxy added: ssh (127.0.0.1:22 -> remote:6000)\n", .{});

    // 添加 UDP 代理 - 将本地 DNS 服务映射到远程端口
    try client.addUdpProxy(
        "dns_proxy", // 代理名称
        "127.0.0.1", // 本地 IP
        53, // 本地端口 (DNS)
        6053, // 远程端口
    );
    std.debug.print("✓ UDP proxy added: dns (127.0.0.1:53 -> remote:6053)\n", .{});

    // 添加更多 TCP 代理示例
    try client.addTcpProxy("web_proxy", "127.0.0.1", 80, 8080);
    std.debug.print("✓ TCP proxy added: web (127.0.0.1:80 -> remote:8080)\n", .{});

    try client.addTcpProxy("https_proxy", "127.0.0.1", 443, 8443);
    std.debug.print("✓ TCP proxy added: https (127.0.0.1:443 -> remote:8443)\n\n", .{});

    // 启动客户端
    std.debug.print("Starting FRP client...\n", .{});
    try client.start();
    std.debug.print("✓ FRP Client started successfully!\n\n", .{});

    std.debug.print("Press Ctrl+C to stop...\n", .{});

    // 保持运行状态
    // 在实际应用中，这里应该等待某个信号或事件
    std.Thread.sleep(60 * std.time.ns_per_s);

    // 停止客户端
    std.debug.print("\nStopping FRP client...\n", .{});
    try client.stop();
    std.debug.print("✓ FRP Client stopped\n", .{});

    // 清理所有资源
    libfrp.cleanup();
    std.debug.print("✓ Cleanup completed\n", .{});
}
