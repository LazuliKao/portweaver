# PortWeaver

[English](README.md) | [中文](README_zh.md)

高性能端口转发统一管理引擎，基于 Zig 构建，适用于 OpenWrt。

---

## 概述

PortWeaver 是一个为 OpenWrt 设计的高性能端口转发统一管理引擎，使用 Zig 编写。它将内核级 NAT 转发与可选的用户态转发（基于 libuv）、FRP 隧道和动态 DNS 结合在一起，全部静态链接到单个二进制文件中。

## 功能特性

- **TCP/UDP 端口转发** — 通过 iptables/nftables 的内核级 NAT 转发
- **应用层转发** — 基于 libuv 的用户态转发，支持 TCP + UDP，独立线程
- **端口范围映射** — 例如 8080-8090 映射到 9080-9090，自动扩展
- **FRP 客户端 (frpc)** — 可选，静态链接 Go 库，`-Dfrpc=true`
- **FRP 服务端 (frps)** — 可选，静态链接 Go 库，`-Dfrps=true`
- **DDNS** — 可选，支持 24 个 DNS 提供商，`-Dddns=true`
- **UCI 配置** — 可选，`-Duci=true`，从 `/etc/config/portweaver` 读取
- **UCI 防火墙** — 自动管理 ACCEPT + DNAT/重定向规则
- **流量统计** — 每项目字节计数器，支持 `enable_app_stats`（应用层）和 `enable_firewall_stats`（nftables 内核计数器）
- **源 IP 保留** — `preserve_source_ip` 选项用于透明代理
- **IPv4/IPv6/双栈** — 支持 IPv6 监听转发到 IPv4 目标（应用层转发）

### DDNS 支持的提供商

alidns, aliesa, tencentcloud, trafficroute, dnspod, dnsla, cloudflare, huaweicloud, callback, baiducloud, porkbun, godaddy, namecheap, namesilo, vercel, dynadot, dynv6, spaceship, nowcn, eranet, gcore, edgeone, nsone, name_com

## 快速开始

### 最小 JSON 配置

```json
{
    "$schema": "https://github.com/LazuliKao/portweaver/raw/refs/heads/main/docs/portweaver-config.schema.json",
    "projects": [
        {
            "remark": "HTTP 转发",
            "target_address": "127.0.0.1",
            "listen_port": 8080,
            "target_port": 80,
            "protocol": "tcp",
            "family": "any",
            "enable_app_forward": true,
            "open_firewall_port": false,
            "add_firewall_forward": false
        }
    ]
}
```

完整配置示例请参考 [docs/example_config.json](docs/example_config.json)。

## 编译

### 基础构建

```bash
# 默认构建
zig build

# 调试构建
zig build -Doptimize=Debug

# 针对嵌入式优化（ReleaseSmall）
zig build -Doptimize=ReleaseSmall
```

### 功能标志

```bash
zig build -Duci=true        # 启用 UCI 配置支持
zig build -Dubus=true       # 启用 UBUS RPC 服务器
zig build -Dfrpc=true       # 启用 FRP 客户端
zig build -Dfrps=true       # 启用 FRP 服务端
zig build -Dddns=true       # 启用 DDNS 支持
```

多个功能标志可以组合使用：

```bash
zig build -Dfrpc=true -Dfrps=true -Dddns=true -Dubus=true
```

### 测试与格式化

```bash
# 运行所有测试
zig build test

# 格式化源码
zig fmt src/
```

## 命令行用法

```
portweaver [选项]
  -c <路径>    JSON 配置文件路径（默认：config.json）
               仅在非 UCI 构建中使用。
```

## 架构

```
                    ┌─────────────────────────────────────┐
                    │          PortWeaver 后端              │
                    │         (Zig + 静态链接 Go 库)        │
                    └──────────────┬──────────────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         │                         │                         │
    ┌────▼────┐             ┌──────▼──────┐           ┌──────▼──────┐
    │  配置    │             │   主循环     │           │  UBUS RPC   │
    │  系统    │             │ (100ms 轮询) │           │   服务器    │
    │ UCI/JSON │             │              │           │  (可选)     │
    └────┬────┘             └──────┬──────┘           └─────────────┘
         │                         │
    ┌────▼────┐             ┌──────▼──────┐
    │ 防火墙  │             │   项目       │
    │  规则   │             │  (句柄)      │
    │ (UCI)   │             └──────┬──────┘
    └─────────┘                    │
                    ┌──────────────┼──────────────┐
                    │              │              │
              ┌─────▼─────┐ ┌─────▼─────┐ ┌─────▼─────┐
              │ 内核 NAT  │ │ 应用层    │ │    FRP    │
              │   转发    │ │   转发    │ │ (客户端/  │
              │(iptables) │ │  (libuv)  │ │ 服务端)   │
              └───────────┘ └───────────┘ └───────────┘
                                                    │
                                              ┌─────▼─────┐
                                              │   DDNS    │
                                              └───────────┘
```

## 启动流程

1. `ensureSingleInstance()` — 获取 PID 文件锁（Unix）或命名互斥体（Windows）；优雅接管，5 秒延迟
2. `event_log.initGlobal()` — 初始化线程安全的事件环形缓冲区（容量 20）
3. `loadConfig()` — 根据编译标志解析 JSON 文件或加载 UCI 配置
4. `file_log.initGlobalFileLogger()` — 启动可选的滚动文件日志
5. `setupProject()` — 为每个已启用的项目创建 ProjectHandle
6. `applyConfig()` — 应用 UCI 防火墙规则，启动 DDNS 实例，启动 FRPS 服务器
7. `startForwardingThreads()` — 为每个项目生成每端口的 TCP/UDP 转发线程
8. 主循环：每 100ms 睡眠间隔轮询 `shouldExitForTakeover()`；在接管信号时干净退出

## UBUS RPC API

使用 `-Dubus=true` 编译时启用。

| 方法 | 参数 | 描述 |
|------|------|------|
| `get_status` | - | 获取整体引擎状态 |
| `get_full_status` | - | 获取包含所有子系统信息的详细状态 |
| `list_projects` | - | 列出所有已配置的项目 |
| `set_enabled` | `(id, enabled)` | 按 ID 启用/禁用项目 |
| `get_events` | - | 获取最近的事件日志条目 |
| `get_frp_status` | - | 获取 FRP 客户端+服务端的组合状态 |
| `get_frpc_info` | `(id)` | 获取 FRP 客户端项目信息 |
| `get_frpc_proxy_stats` | `(id)` | 获取 FRP 客户端代理统计 |
| `clear_frpc_logs` | `(id)` | 清除 FRP 客户端日志 |
| `get_frps_info` | `(id)` | 获取 FRP 服务端项目信息 |
| `get_frps_proxy_stats` | `(id)` | 获取 FRP 服务端代理统计 |
| `clear_frps_logs` | `(id)` | 清除 FRP 服务端日志 |
| `get_ddns_global_status` | - | 获取所有 DDNS 实例状态 |
| `get_ddns_status` | - | 获取 DDNS 状态摘要 |
| `get_ddns_info` | `(name)` | 获取特定 DDNS 配置信息 |
| `clear_ddns_logs` | `(name)` | 清除特定 DDNS 日志 |

## 配置

### 配置字段

每条"项目"包含以下字段：

| 字段 | 描述 |
|------|------|
| `remark` | 备注名称 |
| `family` | 地址族：`any` / `ipv4` / `ipv6` |
| `protocol` | 协议：`tcp` / `udp` / `both` |
| `listen_port` | 监听端口（支持范围，如 `8080-8090`） |
| `target_address` | 目标地址 |
| `target_port` | 目标端口（支持范围） |
| `enable_app_forward` | 启用应用层转发（基于 libuv） |
| `open_firewall_port` | 打开防火墙端口 |
| `add_firewall_forward` | 添加防火墙转发规则 |
| `src_zone` | 源区域（默认：wan） |
| `dest_zone` | 目标区域（默认：lan） |
| `preserve_source_ip` | 源 IP 保留（用于透明代理） |
| `enable_app_stats` | 启用应用层流量统计（仅当 `enable_app_forward=true` 时有效） |
| `enable_firewall_stats` | 启用防火墙流量统计（nftables 内核计数器，仅 nftables 后端） |
| `port_mappings` | 端口范围映射数组（详见下方） |

### 端口范围映射

支持将一段端口范围映射到另一段端口范围。详细文档请参考 [docs/PORT_MAPPINGS.md](docs/PORT_MAPPINGS.md)。

```json
{
    "listen_port": "8080-8090",
    "target_port": "9080-9090",
    "protocol": "tcp"
}
```

### 应用层转发

基于 libuv 的用户态 TCP/UDP 转发，无需依赖系统防火墙。详细文档请参考 [docs/APP_FORWARD.md](docs/APP_FORWARD.md)。

在配置中设置 `"enable_app_forward": true` 即可启用。

### UCI 配置

使用 `-Duci=true` 编译时，从 `/etc/config/portweaver` 读取配置：

```uci
config project 'rdp'
    option remark 'Windows RDP'
    option family 'IPv4'
    option protocol 'TCP'
    option listen_port '3389'
    option target_address '192.168.1.100'
    option target_port '3389'
    option open_firewall_port '1'
    option add_firewall_forward '1'
```

### FRP 客户端配置

```json
{
  "frpc_nodes": {
    "node1": {
      "enabled": true,
      "server": "1.2.3.4",
      "port": 7000,
      "token": "your_token",
      "log_level": "info",
      "use_encryption": true,
      "use_compression": true
    }
  }
}
```

### FRP 服务端配置

使用 `-Dfrps=true` 编译时启用：

```json
{
  "frps_nodes": {
    "server1": {
      "enabled": true,
      "port": 7000,
      "token": "your_token",
      "log_level": "info",
      "allow_ports": "10000-20000",
      "bind_addr": "0.0.0.0",
      "tcp_mux": true,
      "udp_mux": true,
      "kcp_mux": true,
      "dashboard_addr": "0.0.0.0",
      "dashboard_user": "admin",
      "dashboard_pwd": "admin"
    }
  }
}
```

### DDNS 配置

使用 `-Dddns=true` 编译时启用：

```json
{
  "ddns": [
    {
      "name": "cloudflare-home",
      "dns_provider": "cloudflare",
      "dns_id": "",
      "dns_secret": "your_cloudflare_token",
      "ttl": 3600,
      "ipv4_enable": true,
      "ipv4_get_type": "url",
      "ipv4_url": "https://api.ipify.org",
      "ipv4_domains": "home.example.com",
      "ipv6_enable": false,
      "not_allow_wan_access": true
    }
  ]
}
```

## 文档

- [docs/APP_FORWARD.md](docs/APP_FORWARD.md) — 应用层转发完整文档
- [docs/PORT_MAPPINGS.md](docs/PORT_MAPPINGS.md) — 端口范围映射文档
- [docs/portweaver-config.schema.json](docs/portweaver-config.schema.json) — JSON 配置 schema

## 许可证

[GPL-3.0](LICENSE)
