# 应用层端口转发功能

## 概述

PortWeaver 现在支持纯 Zig 实现的应用层端口转发功能，类似于 socat 工具。这个功能使用 Zig 的标准网络库，可以在应用层转发 TCP 和 UDP 流量。

## 功能特性

- ✅ **TCP 转发**：支持 TCP 连接的端口转发，自动处理多个并发连接
- ✅ **UDP 转发**：支持 UDP 数据报的端口转发
- ✅ **双向转发**：自动处理双向数据流
- ✅ **多协议支持**：可同时转发 TCP 和 UDP（protocol: "both"）
- ✅ **IPv4/IPv6**：支持 IPv4、IPv6 或同时支持两者
- ✅ **并发连接**：每个 TCP 连接在独立线程中处理

## 配置选项

在配置文件中，为每个项目添加 `enable_app_forward` 字段来启用应用层转发：

```json
{
  "projects": [
    {
      "remark": "TCP转发示例",
      "listen_port": 8080,
      "target_address": "127.0.0.1",
      "target_port": 80,
      "protocol": "tcp",
      "family": "any",
      "enable_app_forward": true
    }
  ]
}
```

### 配置字段说明

| 字段 | 类型 | 说明 | 示例 |
|------|------|------|------|
| `remark` | string | 备注说明 | "HTTP转发" |
| `listen_port` | number | 监听端口（1-65535） | 8080 |
| `target_address` | string | 目标地址（IP或域名） | "127.0.0.1" |
| `target_port` | number | 目标端口 | 80 |
| `protocol` | string | 协议类型 | "tcp", "udp", "both" |
| `family` | string | 地址族 | "any", "ipv4", "ipv6" |
| `enable_app_forward` | boolean | **启用应用层转发** | true/false |

## 使用示例

### 1. TCP 端口转发

将本地 8080 端口转发到 127.0.0.1:80：

```json
{
  "remark": "HTTP转发",
  "listen_port": 8080,
  "target_address": "127.0.0.1",
  "target_port": 80,
  "protocol": "tcp",
  "enable_app_forward": true
}
```

### 2. UDP 端口转发

将本地 5353 端口转发到 Google DNS (8.8.8.8:53)：

```json
{
  "remark": "DNS转发",
  "listen_port": 5353,
  "target_address": "8.8.8.8",
  "target_port": 53,
  "protocol": "udp",
  "enable_app_forward": true
}
```

### 3. TCP + UDP 同时转发

同时转发 TCP 和 UDP 流量：

```json
{
  "remark": "游戏服务器转发",
  "listen_port": 9000,
  "target_address": "game.server.com",
  "target_port": 9000,
  "protocol": "both",
  "enable_app_forward": true
}
```

### 4. IPv6 转发

仅监听 IPv6：

```json
{
  "remark": "IPv6转发",
  "listen_port": 8080,
  "target_address": "::1",
  "target_port": 80,
  "protocol": "tcp",
  "family": "ipv6",
  "enable_app_forward": true
}
```

## 与防火墙规则的区别

| 特性 | 应用层转发 | 防火墙转发 |
|------|------------|------------|
| 实现方式 | Zig 网络库 | 系统防火墙（iptables/nftables） |
| 性能 | 中等（应用层） | 高（内核层） |
| 跨平台 | 是 | 否（依赖特定防火墙） |
| 调试 | 容易（日志详细） | 困难 |
| 资源占用 | 较高 | 较低 |
| 适用场景 | 开发/测试/小流量 | 生产环境/大流量 |

## 工作原理

### TCP 转发

1. 在指定端口上监听 TCP 连接
2. 接受客户端连接
3. 为每个连接创建到目标服务器的连接
4. 启动两个线程分别处理双向数据转发
5. 当任一方关闭连接时，清理资源

### UDP 转发

1. 在指定端口上绑定 UDP socket
2. 接收来自客户端的数据报
3. 转发到目标服务器
4. 保存客户端地址以便回复
5. 处理来自目标服务器的响应（如需要）

## 代码集成

在你的代码中使用应用层转发：

```zig
const app_forward = @import("impl/app_forward.zig");
const config = @import("config/mod.zig");

// 创建项目配置
const project = config.Project{
    .listen_port = 8080,
    .target_address = "127.0.0.1",
    .target_port = 80,
    .protocol = .tcp,
    .enable_app_forward = true,
    // ... 其他字段
};

// 启动转发（会阻塞当前线程）
try app_forward.startForwarding(allocator, project);
```

## 高级用法

### 在后台线程中运行

```zig
const thread = try std.Thread.spawn(.{}, app_forward.startForwarding, .{
    allocator,
    project,
});
thread.detach();
```

### 组合使用防火墙规则

你可以同时启用应用层转发和防火墙规则：

```json
{
  "remark": "混合模式",
  "listen_port": 8080,
  "target_address": "192.168.1.100",
  "target_port": 80,
  "protocol": "tcp",
  "enable_app_forward": true,
  "open_firewall_port": true,
  "add_firewall_forward": false
}
```

## 日志输出

应用层转发会输出详细的日志信息：

```
[TCP] Listening on port 8080, forwarding to 127.0.0.1:80
[TCP] New connection from 127.0.0.1:52341
[TCP] Connected to target 127.0.0.1:80
[UDP] Listening on port 5353, forwarding to 8.8.8.8:53
[UDP] Forwarded 32 bytes from 127.0.0.1:54123 to 8.8.8.8:53
```

## 性能考虑

- **缓冲区大小**：默认为 8192 字节，在 `app_forward.zig` 中的 `BUFFER_SIZE` 常量可调整
- **并发连接**：TCP 转发为每个连接创建独立线程，注意系统线程限制
- **内存使用**：每个活动连接占用约 16KB（两个缓冲区）
- **CPU 使用**：数据拷贝在用户空间进行，CPU 占用相对较高

## 故障排查

### 端口已被占用
```
[TCP] Accept error: error.AddressInUse
```
解决：更换监听端口或停止占用该端口的程序

### 无法连接到目标
```
[TCP] Failed to connect to target 192.168.1.100:80: error.ConnectionRefused
```
解决：检查目标地址和端口是否正确，目标服务是否运行

### 权限不足
在 Linux 上监听 1024 以下的端口需要 root 权限

## 限制

- UDP 转发目前是单向的（客户端→目标），不处理目标的响应
- 不支持连接池或连接复用
- 不支持 SSL/TLS 解密
- 不支持协议转换（如 HTTP→HTTPS）

## 未来改进

- [ ] UDP 双向转发支持
- [ ] 连接池和复用
- [ ] 流量统计和监控
- [ ] 速率限制
- [ ] 连接超时配置
- [ ] SSL/TLS 支持

## 参考

- 类似工具：socat, netcat, rinetd
- Zig 网络编程：https://ziglang.org/documentation/master/std/#std.net
