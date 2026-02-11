const std = @import("std");

pub const ConfigError = error{
    MissingField,
    InvalidValue,
    UnsupportedFeature,
    JsonParseError,
};

pub const AddressFamily = enum {
    any,
    ipv4,
    ipv6,
};

pub const Protocol = enum {
    both,
    tcp,
    udp,
};

/// FRP 节点配置
pub const FrpcNode = struct {
    /// 是否启用此规则
    enabled: bool = true,
    server: []const u8,
    port: u16,
    token: []const u8 = "",
    log_level: []const u8 = "info",
    use_encryption: bool = true,
    use_compression: bool = true,

    pub fn deinit(self: *FrpcNode, allocator: std.mem.Allocator) void {
        allocator.free(self.server);
        if (self.token.len != 0) allocator.free(self.token);
        if (self.log_level.len != 0) allocator.free(self.log_level);
        self.* = undefined;
    }
};

/// FRP 服务器节点配置
pub const FrpsNode = struct {
    /// 是否启用此规则
    enabled: bool = true,
    port: u16,
    token: []const u8 = "",
    log_level: []const u8 = "info",
    allow_ports: []const u8 = "",
    bind_addr: []const u8 = "",
    max_pool_count: u32 = 5,
    max_ports_per_client: u32 = 0,
    tcp_mux: bool = true,
    udp_mux: bool = true,
    kcp_mux: bool = true,
    dashboard_addr: []const u8 = "",
    dashboard_user: []const u8 = "",
    dashboard_pwd: []const u8 = "",

    pub fn deinit(self: *FrpsNode, allocator: std.mem.Allocator) void {
        if (self.token.len != 0) allocator.free(self.token);
        if (self.log_level.len != 0) allocator.free(self.log_level);
        if (self.allow_ports.len != 0) allocator.free(self.allow_ports);
        if (self.bind_addr.len != 0) allocator.free(self.bind_addr);
        if (self.dashboard_addr.len != 0) allocator.free(self.dashboard_addr);
        if (self.dashboard_user.len != 0) allocator.free(self.dashboard_user);
        if (self.dashboard_pwd.len != 0) allocator.free(self.dashboard_pwd);
        self.* = undefined;
    }
};

/// FRP 转发配置（节点名称:远程端口）
pub const FrpcForward = struct {
    /// 节点名称
    node_name: []const u8,
    /// 远程端口
    remote_port: u16,

    pub fn deinit(self: *FrpcForward, allocator: std.mem.Allocator) void {
        allocator.free(self.node_name);
        self.* = undefined;
    }
};

/// 端口映射：单个监听端口到单个目标端口的映射
pub const PortMapping = struct {
    /// 监听端口（支持范围如 "8080-8090" 或单个端口如 "8080"）
    listen_port: []const u8,
    /// 目标端口（支持范围如 "80-90" 或单个端口如 "80"）
    target_port: []const u8,
    /// 协议: TCP+UDP / TCP / UDP
    protocol: Protocol = .tcp,
    /// FRP 转发列表
    frpc: []FrpcForward = &[_]FrpcForward{},

    pub fn deinit(self: *PortMapping, allocator: std.mem.Allocator) void {
        allocator.free(self.listen_port);
        allocator.free(self.target_port);
        if (self.frpc.len != 0) {
            for (self.frpc) |*f| f.deinit(allocator);
            allocator.free(self.frpc);
        }
        self.* = undefined;
    }
};

/// One port-forwarding project/rule.
pub const Project = struct {
    /// 是否启用此规则
    enabled: bool = true,
    /// 备注
    remark: []const u8 = "",
    /// 防火墙来源 zones（用于转发/DNAT 时的 src）
    /// 为空表示使用默认值（通常为 "wan"）
    src_zones: []const []const u8 = &[_][]const u8{},
    /// 防火墙目标 zones（用于转发/DNAT 时的 dest）
    /// 为空表示使用默认值（通常为 "lan"）
    dest_zones: []const []const u8 = &[_][]const u8{},
    /// 地址族限制: IPv4 和 IPv6 / IPv4 / IPv6
    family: AddressFamily = .any,
    /// 协议: TCP+UDP / TCP / UDP （仅在使用单端口模式时有效）
    protocol: Protocol = .both,
    /// 监听端口（单端口模式，与 port_mappings 互斥）
    listen_port: u16,
    /// 目标地址
    target_address: []const u8,
    /// 目标端口（单端口模式，与 port_mappings 互斥）
    target_port: u16,
    /// 端口映射列表（多端口/范围端口模式，与 listen_port/target_port 互斥）
    port_mappings: []PortMapping = &[_]PortMapping{},
    /// 打开防火墙端口
    open_firewall_port: bool = true,
    /// 添加防火墙转发
    add_firewall_forward: bool = true,
    /// 保留源 IP (仅当 add_firewall_forward=true 时有效)
    /// 当启用时,只添加 redirect 规则而不添加 NAT 规则,保留源 IP 地址
    preserve_source_ip: bool = false,
    /// 启用应用层端口转发(使用 Zig 网络库实现,类似 socat)
    enable_app_forward: bool = false,
    /// reuseaddr 绑定到本地端口
    reuseaddr: bool = true,
    /// 启用流量统计（仅当 enable_app_forward=true 时有效）
    /// 注意：启用统计后无法使用防火墙转发（add_firewall_forward 会被强制禁用）
    enable_stats: bool = false,

    pub fn deinit(self: *Project, allocator: std.mem.Allocator) void {
        if (self.remark.len != 0) allocator.free(self.remark);
        if (self.src_zones.len != 0) {
            for (self.src_zones) |z| allocator.free(z);
            allocator.free(self.src_zones);
        }
        if (self.dest_zones.len != 0) {
            for (self.dest_zones) |z| allocator.free(z);
            allocator.free(self.dest_zones);
        }
        allocator.free(self.target_address);
        if (self.port_mappings.len != 0) {
            for (self.port_mappings) |*pm| pm.deinit(allocator);
            allocator.free(self.port_mappings);
        }
        self.* = undefined;
    }

    /// 检查配置是否有效（单端口模式和多端口模式不能同时使用）
    pub fn isValid(self: *const Project) bool {
        const has_single_port = self.listen_port != 0 and self.target_port != 0;
        const has_port_mappings = self.port_mappings.len > 0;
        // 必须恰好选择一种模式
        return (has_single_port and !has_port_mappings) or (!has_single_port and has_port_mappings);
    }
};

/// DDNS IP 获取方式
pub const DdnsIpGetType = enum {
    url,
    net_interface,
    cmd,

    pub fn fromString(s: []const u8) !DdnsIpGetType {
        const trimmed = std.mem.trim(u8, s, " \t\r\n");
        if (eqlIgnoreCase(trimmed, "url")) return .url;
        if (eqlIgnoreCase(trimmed, "net_interface") or eqlIgnoreCase(trimmed, "netInterface")) return .net_interface;
        if (eqlIgnoreCase(trimmed, "cmd") or eqlIgnoreCase(trimmed, "command")) return .cmd;
        return ConfigError.InvalidValue;
    }

    pub fn toString(self: DdnsIpGetType) []const u8 {
        return switch (self) {
            .url => "url",
            .net_interface => "netInterface",
            .cmd => "cmd",
        };
    }
};

/// DDNS IPv4 配置
pub const DdnsIpv4Config = struct {
    enable: bool = true,
    get_type: DdnsIpGetType = .url,
    url: []const u8 = "",
    net_interface: []const u8 = "",
    cmd: []const u8 = "",
    domains: []const u8 = "",

    pub fn deinit(self: *DdnsIpv4Config, allocator: std.mem.Allocator) void {
        if (self.url.len != 0) allocator.free(self.url);
        if (self.net_interface.len != 0) allocator.free(self.net_interface);
        if (self.cmd.len != 0) allocator.free(self.cmd);
        if (self.domains.len != 0) allocator.free(self.domains);
        self.* = undefined;
    }
};

/// DDNS IPv6 配置
pub const DdnsIpv6Config = struct {
    enable: bool = false,
    get_type: DdnsIpGetType = .url,
    url: []const u8 = "",
    net_interface: []const u8 = "",
    cmd: []const u8 = "",
    reg: []const u8 = "",
    domains: []const u8 = "",

    pub fn deinit(self: *DdnsIpv6Config, allocator: std.mem.Allocator) void {
        if (self.url.len != 0) allocator.free(self.url);
        if (self.net_interface.len != 0) allocator.free(self.net_interface);
        if (self.cmd.len != 0) allocator.free(self.cmd);
        if (self.reg.len != 0) allocator.free(self.reg);
        if (self.domains.len != 0) allocator.free(self.domains);
        self.* = undefined;
    }
};

/// DDNS 配置
pub const DdnsConfig = struct {
    /// 是否启用此规则
    enabled: bool = true,
    /// 配置名称（用于显示和标识）
    name: []const u8,
    /// DNS 提供商
    dns_provider: []const u8,
    /// DNS ID（某些提供商需要）
    dns_id: []const u8 = "",
    /// DNS Secret/Token
    dns_secret: []const u8 = "",
    /// DNS 扩展参数（如 Vercel 的 Team ID）
    dns_ext_param: []const u8 = "",
    /// TTL（秒）
    ttl: u32 = 3600,
    /// IPv4 配置
    ipv4: DdnsIpv4Config = .{},
    /// IPv6 配置
    ipv6: DdnsIpv6Config = .{},
    /// 禁止从 WAN 访问
    not_allow_wan_access: bool = true,
    /// 用户名（某些提供商需要）
    username: []const u8 = "",
    /// 密码（某些提供商需要）
    password: []const u8 = "",
    /// Webhook URL
    webhook_url: []const u8 = "",
    /// Webhook 请求体
    webhook_body: []const u8 = "",
    /// Webhook 请求头
    webhook_headers: []const u8 = "",

    pub fn deinit(self: *DdnsConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.dns_provider);
        if (self.dns_id.len != 0) allocator.free(self.dns_id);
        if (self.dns_secret.len != 0) allocator.free(self.dns_secret);
        if (self.dns_ext_param.len != 0) allocator.free(self.dns_ext_param);
        self.ipv4.deinit(allocator);
        self.ipv6.deinit(allocator);
        if (self.username.len != 0) allocator.free(self.username);
        if (self.password.len != 0) allocator.free(self.password);
        if (self.webhook_url.len != 0) allocator.free(self.webhook_url);
        if (self.webhook_body.len != 0) allocator.free(self.webhook_body);
        if (self.webhook_headers.len != 0) allocator.free(self.webhook_headers);
        self.* = undefined;
    }
};

pub const Config = struct {
    projects: []Project,
    /// FRPC 节点配置（key 为节点名称）
    frpc_nodes: std.StringHashMap(FrpcNode),
    /// FRPS 节点配置（key 为节点名称）
    frps_nodes: std.StringHashMap(FrpsNode),
    /// DDNS 配置列表
    ddns_configs: []DdnsConfig,

    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        for (self.projects) |*p| p.deinit(allocator);
        allocator.free(self.projects);

        var it = self.frpc_nodes.iterator();
        while (it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        self.frpc_nodes.deinit();

        var frps_it = self.frps_nodes.iterator();
        while (frps_it.next()) |entry| {
            allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(allocator);
        }
        self.frps_nodes.deinit();

        for (self.ddns_configs) |*d| d.deinit(allocator);
        allocator.free(self.ddns_configs);

        self.* = undefined;
    }
};

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

pub fn parseBool(val: []const u8) !bool {
    const trimmed = std.mem.trim(u8, val, " \t\r\n");
    if (trimmed.len == 0) return false;

    if (eqlIgnoreCase(trimmed, "1") or eqlIgnoreCase(trimmed, "true") or eqlIgnoreCase(trimmed, "yes") or eqlIgnoreCase(trimmed, "on") or eqlIgnoreCase(trimmed, "enabled")) return true;
    if (eqlIgnoreCase(trimmed, "0") or eqlIgnoreCase(trimmed, "false") or eqlIgnoreCase(trimmed, "no") or eqlIgnoreCase(trimmed, "off") or eqlIgnoreCase(trimmed, "disabled")) return false;

    return ConfigError.InvalidValue;
}

pub fn parsePort(val: []const u8) !u16 {
    const trimmed = std.mem.trim(u8, val, " \t\r\n");
    const port_u32 = std.fmt.parseUnsigned(u32, trimmed, 10) catch return ConfigError.InvalidValue;
    if (port_u32 == 0 or port_u32 > 65535) return ConfigError.InvalidValue;
    return @intCast(port_u32);
}

/// 验证端口字符串（可以是单个端口如 "8080" 或端口范围如 "8080-8090"）
pub fn validatePortString(val: []const u8) !void {
    const trimmed = std.mem.trim(u8, val, " \t\r\n");
    if (trimmed.len == 0) return ConfigError.InvalidValue;

    // 检查是否是端口范围
    if (std.mem.indexOf(u8, trimmed, "-")) |dash_pos| {
        if (dash_pos == 0 or dash_pos == trimmed.len - 1) return ConfigError.InvalidValue;

        const start_str = trimmed[0..dash_pos];
        const end_str = trimmed[dash_pos + 1 ..];

        const start_port = try parsePort(start_str);
        const end_port = try parsePort(end_str);

        if (start_port >= end_port) return ConfigError.InvalidValue;
    } else {
        // 单个端口
        _ = try parsePort(trimmed);
    }
}

pub fn parseFamily(val: []const u8) !AddressFamily {
    const trimmed = std.mem.trim(u8, val, " \t\r\n");

    if (trimmed.len == 0) return .any;
    if (eqlIgnoreCase(trimmed, "any") or eqlIgnoreCase(trimmed, "all") or eqlIgnoreCase(trimmed, "both") or eqlIgnoreCase(trimmed, "ipv4+ipv6") or eqlIgnoreCase(trimmed, "ipv4_and_ipv6") or eqlIgnoreCase(trimmed, "IPv4 和 IPv6") or eqlIgnoreCase(trimmed, "IPv4和IPv6")) return .any;
    if (eqlIgnoreCase(trimmed, "ipv4") or eqlIgnoreCase(trimmed, "IPv4")) return .ipv4;
    if (eqlIgnoreCase(trimmed, "ipv6") or eqlIgnoreCase(trimmed, "IPv6")) return .ipv6;

    return ConfigError.InvalidValue;
}

pub fn parseProtocol(val: []const u8) !Protocol {
    const trimmed = std.mem.trim(u8, val, " \t\r\n");

    if (trimmed.len == 0) return .both;
    if (eqlIgnoreCase(trimmed, "both") or eqlIgnoreCase(trimmed, "tcp+udp") or eqlIgnoreCase(trimmed, "all") or eqlIgnoreCase(trimmed, "TCP+UDP") or eqlIgnoreCase(trimmed, "tcpudp") or eqlIgnoreCase(trimmed, "TCP和UDP") or eqlIgnoreCase(trimmed, "TCP 与 UDP") or eqlIgnoreCase(trimmed, "TCP 和 UDP")) return .both;
    if (eqlIgnoreCase(trimmed, "tcp") or eqlIgnoreCase(trimmed, "TCP")) return .tcp;
    if (eqlIgnoreCase(trimmed, "udp") or eqlIgnoreCase(trimmed, "UDP")) return .udp;

    return ConfigError.InvalidValue;
}

pub fn dupeIfNonEmpty(allocator: std.mem.Allocator, s: []const u8) ![]const u8 {
    if (s.len == 0) return "";
    return allocator.dupe(u8, s);
}

test "config: parse bool" {
    try std.testing.expect(try parseBool("1"));
    try std.testing.expect(try parseBool("true"));
    try std.testing.expect(!(try parseBool("0")));
    try std.testing.expect(!(try parseBool("false")));
}

test "config: parse enums" {
    try std.testing.expectEqual(AddressFamily.any, try parseFamily("IPv4 和 IPv6"));
    try std.testing.expectEqual(AddressFamily.ipv4, try parseFamily("ipv4"));
    try std.testing.expectEqual(Protocol.both, try parseProtocol("TCP+UDP"));
    try std.testing.expectEqual(Protocol.tcp, try parseProtocol("tcp"));
}
