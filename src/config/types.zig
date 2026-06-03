const std = @import("std");
const file_log = @import("../file_log.zig");

pub const ConfigError = error{
    MissingField,
    InvalidValue,
    UnsupportedFeature,
    JsonParseError,
    ValidationFailed,
};

// ── Validation error context ────────────────────────────────────────────

pub const ErrorType = enum {
    missing_field,
    wrong_type,
    out_of_range,
    invalid_format,
    empty_value,
    enum_value_invalid,
    range_mismatch,
    conflict,
};

pub const ValidationError = struct {
    field_path: []const u8,
    error_type: ErrorType,
    expected: []const u8,
    actual: []const u8,
    message: []const u8,

    pub fn format(self: ValidationError, writer: anytype) !void {
        try writer.print("  {s}: {s}", .{ self.field_path, self.message });
        if (self.expected.len > 0) try writer.print(" (expected {s}", .{self.expected});
        if (self.actual.len > 0) try writer.print(", got '{s}'", .{self.actual});
        if (self.expected.len > 0) try writer.writeAll(")");
    }
};

/// Collects multiple validation errors during JSON config parsing.
/// Uses an arena so callers do not need to free individual error strings.
pub const ErrorCollector = struct {
    arena: std.heap.ArenaAllocator,
    errors: std.ArrayList(ValidationError),
    alloc: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) ErrorCollector {
        return .{
            .arena = std.heap.ArenaAllocator.init(allocator),
            .errors = .empty,
            .alloc = allocator,
        };
    }

    pub fn deinit(self: *ErrorCollector) void {
        self.errors.deinit(self.alloc);
        self.arena.deinit();
    }

    pub fn hasErrors(self: *const ErrorCollector) bool {
        return self.errors.items.len > 0;
    }

    /// Add a validation error with pre-built strings (already in arena or comptime).
    pub fn add(
        self: *ErrorCollector,
        field_path: []const u8,
        error_type: ErrorType,
        expected: []const u8,
        actual: []const u8,
        message: []const u8,
    ) void {
        self.errors.append(self.alloc, .{
            .field_path = field_path,
            .error_type = error_type,
            .expected = expected,
            .actual = actual,
            .message = message,
        }) catch |err| {
            std.log.warn("ErrorCollector: failed to append validation error: {}", .{err});
        };
    }

    /// Convenience: format `actual` from a runtime value.
    pub fn addFmt(
        self: *ErrorCollector,
        field_path: []const u8,
        error_type: ErrorType,
        expected: []const u8,
        comptime actual_fmt: []const u8,
        actual_args: anytype,
        message: []const u8,
    ) void {
        const actual_str = std.fmt.allocPrint(self.arena.allocator(), actual_fmt, actual_args) catch "";
        self.add(field_path, error_type, expected, actual_str, message);
    }

    /// Build a "field.path[idx].child" string inside the arena.
    pub fn fieldPath(self: *ErrorCollector, comptime fmt: []const u8, args: anytype) []const u8 {
        return std.fmt.allocPrint(self.arena.allocator(), fmt, args) catch "<oom>";
    }

    /// Format a human-readable report (caller owns the returned slice).
    pub fn formatReport(self: *const ErrorCollector, allocator: std.mem.Allocator) ![]const u8 {
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(allocator);
        const header = try std.fmt.allocPrint(allocator, "Configuration has {d} error(s):\n", .{self.errors.items.len});
        defer allocator.free(header);
        try buf.appendSlice(allocator, header);
        for (self.errors.items) |e| {
            const line = try std.fmt.allocPrint(allocator, "{f}\n", .{e});
            defer allocator.free(line);
            try buf.appendSlice(allocator, line);
        }
        return buf.toOwnedSlice(allocator);
    }
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

pub const LoopMode = enum {
    per_listener,
    per_project,
    global,
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

    pub fn eql(a: @This(), b: @This()) bool {
        return a.enabled == b.enabled and
            std.mem.eql(u8, a.server, b.server) and
            a.port == b.port and
            std.mem.eql(u8, a.token, b.token) and
            std.mem.eql(u8, a.log_level, b.log_level) and
            a.use_encryption == b.use_encryption and
            a.use_compression == b.use_compression;
    }
};

/// FRP 服务器节点配置
/// 字段命名与 FRP v1 ServerConfig 保持一致
pub const FrpsNode = struct {
    /// 是否启用此规则
    enabled: bool = true,

    // === ServerConfig fields ===
    /// 服务器监听端口 (FRP v1: BindPort, default: 7000)
    bind_port: ?u16 = null,
    /// 服务器绑定地址 (FRP v1: BindAddr, default: "0.0.0.0")
    bind_addr: ?[]const u8 = null,
    /// 认证令牌 (FRP v1: Auth.Token)
    auth_token: ?[]const u8 = null,
    /// 日志级别: trace, debug, info, warn, error (FRP v1: Log.Level)
    log_level: ?[]const u8 = null,
    /// 允许的端口范围，如 "10000-20000" 或 "8080,8081,8082" (FRP v1: AllowPorts)
    allow_ports: ?[]const u8 = null,

    // === ServerTransportConfig fields (flattened) ===
    /// 连接池大小 (FRP v1: Transport.MaxPoolCount, default: 5)
    max_pool_count: ?u32 = null,
    /// 每个客户端最大端口数，0表示无限制 (FRP v1: MaxPortsPerClient)
    max_ports_per_client: ?u32 = null,
    /// TCP 多路复用 (FRP v1: Transport.TCPMux, default: true)
    tcp_mux: ?bool = null,

    // === WebServerConfig fields (flattened) ===
    /// Dashboard/管理界面地址 (FRP v1: WebServer.Addr)
    dashboard_addr: ?[]const u8 = null,
    /// Dashboard/管理界面端口 (FRP v1: WebServer.Port)
    dashboard_port: ?u16 = null,
    /// Dashboard 用户名 (FRP v1: WebServer.User)
    dashboard_user: ?[]const u8 = null,
    /// Dashboard 密码 (FRP v1: WebServer.Password)
    dashboard_pwd: ?[]const u8 = null,

    pub fn deinit(self: *FrpsNode, allocator: std.mem.Allocator) void {
        if (self.auth_token) |s| allocator.free(s);
        if (self.log_level) |s| allocator.free(s);
        if (self.allow_ports) |s| allocator.free(s);
        if (self.bind_addr) |s| allocator.free(s);
        if (self.dashboard_addr) |s| allocator.free(s);
        if (self.dashboard_user) |s| allocator.free(s);
        if (self.dashboard_pwd) |s| allocator.free(s);
        self.* = undefined;
    }

    fn eqlOptionalSlices(a: ?[]const u8, b: ?[]const u8) bool {
        if (a == null and b == null) return true;
        if (a == null or b == null) return false;
        return std.mem.eql(u8, a.?, b.?);
    }

    pub fn eql(a: @This(), b: @This()) bool {
        return a.enabled == b.enabled and
            a.bind_port == b.bind_port and
            eqlOptionalSlices(a.bind_addr, b.bind_addr) and
            eqlOptionalSlices(a.auth_token, b.auth_token) and
            eqlOptionalSlices(a.log_level, b.log_level) and
            eqlOptionalSlices(a.allow_ports, b.allow_ports) and
            a.max_pool_count == b.max_pool_count and
            a.max_ports_per_client == b.max_ports_per_client and
            a.tcp_mux == b.tcp_mux and
            eqlOptionalSlices(a.dashboard_addr, b.dashboard_addr) and
            a.dashboard_port == b.dashboard_port and
            eqlOptionalSlices(a.dashboard_user, b.dashboard_user) and
            eqlOptionalSlices(a.dashboard_pwd, b.dashboard_pwd);
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
    pub fn eql(a: @This(), b: @This()) bool {
        return std.mem.eql(u8, a.node_name, b.node_name) and
            a.remote_port == b.remote_port;
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

    fn eqlSlice(comptime T: type, a: []const T, b: []const T) bool {
        if (a.len != b.len) return false;
        for (a, b) |ea, eb| {
            if (!ea.eql(eb)) return false;
        }
        return true;
    }

    pub fn eql(a: @This(), b: @This()) bool {
        return std.mem.eql(u8, a.listen_port, b.listen_port) and
            std.mem.eql(u8, a.target_port, b.target_port) and
            a.protocol == b.protocol and
            eqlSlice(FrpcForward, a.frpc, b.frpc);
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
    /// 启用应用层转发流量统计（仅当 enable_app_forward=true 时有效）
    /// 由 libuv forwarder 在用户态统计字节数和活跃会话数
    enable_app_stats: bool = false,
    /// 启用防火墙转发流量统计（仅当使用 nftables 后端时有效）
    /// 通过 nftables named counter 在内核层统计，开销极低
    /// 与 enable_app_stats 独立，两者可同时开启（数据相加）
    /// 注意：UCI/fw4 防火墙模式不支持此功能
    enable_firewall_stats: bool = false,
    /// Application-forward loop sharing override. Null inherits Config.app_forward_loop_mode.
    app_forward_loop_mode: ?LoopMode = null,
    /// TCP connect timeout in milliseconds. Null = no timeout (OS default, typically 60-120s).
    connect_timeout_ms: ?u32 = null,
    /// Maximum concurrent connections per listener. Null = unlimited.
    max_connections: ?u32 = null,
    /// 启用 Wake-on-LAN 功能
    enable_wol: bool = false,
    /// 需要检测的协议名称列表
    detect_protocols: []const []const u8 = &[_][]const u8{},
    /// 目标设备的 MAC 地址列表（用于 WoL 唤醒）
    wol_mac_addresses: []const []const u8 = &[_][]const u8{},
    /// WoL 魔术包发送冷却时间（毫秒）
    wol_cooldown_ms: u64 = 30000,
    /// 启用协议过滤（拒绝不匹配的协议）
    enable_protocol_filter: bool = false,
    /// 允许的协议列表（当协议过滤启用时）
    allowed_protocols: []const []const u8 = &[_][]const u8{},
    /// 允许的 TLS SNI 列表（仅当 enable_protocol_filter=true 且 allowed_protocols 包含 tls 时有效）
    /// 支持通配符如 "*.example.com"
    tls_allowed_snis: []const []const u8 = &[_][]const u8{},
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
        if (self.detect_protocols.len != 0) {
            for (self.detect_protocols) |p| allocator.free(p);
            allocator.free(self.detect_protocols);
        }
        if (self.wol_mac_addresses.len != 0) {
            for (self.wol_mac_addresses) |m| allocator.free(m);
            allocator.free(self.wol_mac_addresses);
        }
        if (self.allowed_protocols.len != 0) {
            for (self.allowed_protocols) |p| allocator.free(p);
            allocator.free(self.allowed_protocols);
        }
        if (self.tls_allowed_snis.len != 0) {
            for (self.tls_allowed_snis) |s| allocator.free(s);
            allocator.free(self.tls_allowed_snis);
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

    pub fn effectiveAppForwardLoopMode(self: *const Project, default_mode: LoopMode) LoopMode {
        return self.app_forward_loop_mode orelse default_mode;
    }

    fn eqlStringSlices(a: []const []const u8, b: []const []const u8) bool {
        if (a.len != b.len) return false;
        for (a, b) |sa, sb| {
            if (!std.mem.eql(u8, sa, sb)) return false;
        }
        return true;
    }

    pub fn eql(a: @This(), b: @This()) bool {
        return a.enabled == b.enabled and
            eqlStringSlices(a.src_zones, b.src_zones) and
            eqlStringSlices(a.dest_zones, b.dest_zones) and
            a.family == b.family and
            a.protocol == b.protocol and
            a.listen_port == b.listen_port and
            std.mem.eql(u8, a.target_address, b.target_address) and
            a.target_port == b.target_port and
            PortMapping.eqlSlice(PortMapping, a.port_mappings, b.port_mappings) and
            a.open_firewall_port == b.open_firewall_port and
            a.add_firewall_forward == b.add_firewall_forward and
            a.preserve_source_ip == b.preserve_source_ip and
            a.enable_app_forward == b.enable_app_forward and
            a.reuseaddr == b.reuseaddr and
            a.enable_app_stats == b.enable_app_stats and
            a.enable_firewall_stats == b.enable_firewall_stats and
            a.app_forward_loop_mode == b.app_forward_loop_mode and
            a.connect_timeout_ms == b.connect_timeout_ms and
            a.max_connections == b.max_connections and
            a.enable_wol == b.enable_wol and
            eqlStringSlices(a.detect_protocols, b.detect_protocols) and
            eqlStringSlices(a.wol_mac_addresses, b.wol_mac_addresses) and
            a.wol_cooldown_ms == b.wol_cooldown_ms and
            a.enable_protocol_filter == b.enable_protocol_filter and
            eqlStringSlices(a.allowed_protocols, b.allowed_protocols) and
            eqlStringSlices(a.tls_allowed_snis, b.tls_allowed_snis);
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

    pub fn eql(a: @This(), b: @This()) bool {
        return a.enable == b.enable and
            a.get_type == b.get_type and
            std.mem.eql(u8, a.url, b.url) and
            std.mem.eql(u8, a.net_interface, b.net_interface) and
            std.mem.eql(u8, a.cmd, b.cmd) and
            std.mem.eql(u8, a.domains, b.domains);
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

    pub fn eql(a: @This(), b: @This()) bool {
        return a.enable == b.enable and
            a.get_type == b.get_type and
            std.mem.eql(u8, a.url, b.url) and
            std.mem.eql(u8, a.net_interface, b.net_interface) and
            std.mem.eql(u8, a.cmd, b.cmd) and
            std.mem.eql(u8, a.reg, b.reg) and
            std.mem.eql(u8, a.domains, b.domains);
    }
};

/// DDNS 配置
pub const DdnsConfig = struct {
    /// 是否启用此规则
    enabled: bool = true,
    /// 配置名称（用于显示和标识）
    name: []const u8 = "",
    /// DNS 提供商
    dns_provider: []const u8 = "",
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
        if (self.name.len != 0) allocator.free(self.name);
        if (self.dns_provider.len != 0) allocator.free(self.dns_provider);
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

    pub fn eql(a: @This(), b: @This()) bool {
        return a.enabled == b.enabled and
            std.mem.eql(u8, a.name, b.name) and
            std.mem.eql(u8, a.dns_provider, b.dns_provider) and
            std.mem.eql(u8, a.dns_id, b.dns_id) and
            std.mem.eql(u8, a.dns_secret, b.dns_secret) and
            std.mem.eql(u8, a.dns_ext_param, b.dns_ext_param) and
            a.ttl == b.ttl and
            a.ipv4.eql(b.ipv4) and
            a.ipv6.eql(b.ipv6) and
            a.not_allow_wan_access == b.not_allow_wan_access and
            std.mem.eql(u8, a.username, b.username) and
            std.mem.eql(u8, a.password, b.password) and
            std.mem.eql(u8, a.webhook_url, b.webhook_url) and
            std.mem.eql(u8, a.webhook_body, b.webhook_body) and
            std.mem.eql(u8, a.webhook_headers, b.webhook_headers);
    }
};

pub const Config = struct {
    app_forward_loop_mode: LoopMode = .per_project,
    /// 是否使用 nftables 作为防火墙后端（默认使用 OpenWrt fw4）
    use_nftables: bool = false,
    /// JSON 模式下是否启用配置文件监听自动重载（默认关闭）
    watch: bool = false,
    log_config: file_log.LogConfig,
    projects: []Project,
    /// FRPC 节点配置（key 为节点名称）
    frpc_nodes: std.StringHashMap(FrpcNode),
    /// FRPS 节点配置（key 为节点名称）
    frps_nodes: std.StringHashMap(FrpsNode),
    /// DDNS 配置列表
    ddns_configs: []DdnsConfig,

    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        self.log_config.deinit(allocator);

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

    fn eqlNodeHashMap(comptime V: type, a: std.StringHashMap(V), b: std.StringHashMap(V)) bool {
        if (a.count() != b.count()) return false;
        var it = a.iterator();
        while (it.next()) |entry| {
            const other_val = b.get(entry.key_ptr.*) orelse return false;
            if (!entry.value_ptr.eql(other_val)) return false;
        }
        return true;
    }

    pub fn eql(a: @This(), b: @This()) bool {
        return a.app_forward_loop_mode == b.app_forward_loop_mode and
            a.use_nftables == b.use_nftables and
            a.watch == b.watch and
            a.log_config.eql(b.log_config) and
            PortMapping.eqlSlice(Project, a.projects, b.projects) and
            eqlNodeHashMap(FrpcNode, a.frpc_nodes, b.frpc_nodes) and
            eqlNodeHashMap(FrpsNode, a.frps_nodes, b.frps_nodes) and
            PortMapping.eqlSlice(DdnsConfig, a.ddns_configs, b.ddns_configs);
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

pub fn parseLoopMode(val: []const u8) !LoopMode {
    const trimmed = std.mem.trim(u8, val, " \t\r\n");
    if (trimmed.len == 0) return .per_project;
    if (eqlIgnoreCase(trimmed, "per_listener") or eqlIgnoreCase(trimmed, "per-listener")) return .per_listener;
    if (eqlIgnoreCase(trimmed, "per_project") or eqlIgnoreCase(trimmed, "per-project")) return .per_project;
    if (eqlIgnoreCase(trimmed, "global")) return .global;
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

test "config: parse app forward loop mode" {
    try std.testing.expectEqual(LoopMode.per_listener, try parseLoopMode("per_listener"));
    try std.testing.expectEqual(LoopMode.per_project, try parseLoopMode("per_project"));
    try std.testing.expectEqual(LoopMode.global, try parseLoopMode("global"));
    try std.testing.expectError(ConfigError.InvalidValue, parseLoopMode("bad_mode"));
}

test "config: app forward loop mode defaults and effective override" {
    const config = Config{
        .log_config = undefined,
        .projects = &[_]Project{},
        .frpc_nodes = undefined,
        .frps_nodes = undefined,
        .ddns_configs = &[_]DdnsConfig{},
    };
    const inherited = Project{
        .listen_port = 1000,
        .target_address = "127.0.0.1",
        .target_port = 2000,
    };
    const overridden = Project{
        .listen_port = 1001,
        .target_address = "127.0.0.1",
        .target_port = 2001,
        .app_forward_loop_mode = .per_listener,
    };

    try std.testing.expectEqual(LoopMode.per_project, config.app_forward_loop_mode);
    try std.testing.expectEqual(LoopMode.per_project, inherited.effectiveAppForwardLoopMode(config.app_forward_loop_mode));
    try std.testing.expectEqual(LoopMode.per_listener, overridden.effectiveAppForwardLoopMode(config.app_forward_loop_mode));
}

test "config: eql methods" {
    // FrpcNode
    const node_a = FrpcNode{ .server = "frp.example.com", .port = 7000, .token = "tok123" };
    const node_b = FrpcNode{ .server = "frp.example.com", .port = 7000, .token = "tok123" };
    const node_c = FrpcNode{ .server = "frp.example.com", .port = 7001, .token = "tok123" };
    try std.testing.expect(node_a.eql(node_b));
    try std.testing.expect(!node_a.eql(node_c));

    // FrpsNode
    const frps_a = FrpsNode{ .bind_port = 7000, .bind_addr = "0.0.0.0", .auth_token = "secret" };
    const frps_b = FrpsNode{ .bind_port = 7000, .bind_addr = "0.0.0.0", .auth_token = "secret" };
    const frps_c = FrpsNode{ .bind_port = 7000 };
    try std.testing.expect(frps_a.eql(frps_b));
    try std.testing.expect(!frps_a.eql(frps_c));

    // FrpcForward
    const fwd_a = FrpcForward{ .node_name = "node1", .remote_port = 8080 };
    const fwd_b = FrpcForward{ .node_name = "node1", .remote_port = 8080 };
    const fwd_c = FrpcForward{ .node_name = "node2", .remote_port = 8080 };
    try std.testing.expect(fwd_a.eql(fwd_b));
    try std.testing.expect(!fwd_a.eql(fwd_c));

    // PortMapping
    const pm_a = PortMapping{ .listen_port = "8080", .target_port = "80" };
    const pm_b = PortMapping{ .listen_port = "8080", .target_port = "80" };
    const pm_c = PortMapping{ .listen_port = "8081", .target_port = "80" };
    try std.testing.expect(pm_a.eql(pm_b));
    try std.testing.expect(!pm_a.eql(pm_c));

    // PortMapping with frpc slice
    var frpc_d = [_]FrpcForward{fwd_a};
    var frpc_e = [_]FrpcForward{fwd_b};
    var frpc_f = [_]FrpcForward{fwd_c};
    const pm_d = PortMapping{ .listen_port = "8080", .target_port = "80", .frpc = &frpc_d };
    const pm_e = PortMapping{ .listen_port = "8080", .target_port = "80", .frpc = &frpc_e };
    const pm_f = PortMapping{ .listen_port = "8080", .target_port = "80", .frpc = &frpc_f };
    try std.testing.expect(pm_d.eql(pm_e));
    try std.testing.expect(!pm_d.eql(pm_f));

    // Project (excludes remark)
    const proj_a = Project{ .listen_port = 1000, .target_address = "192.168.1.1", .target_port = 80, .remark = "first" };
    const proj_b = Project{ .listen_port = 1000, .target_address = "192.168.1.1", .target_port = 80, .remark = "second" };
    const proj_c = Project{ .listen_port = 1001, .target_address = "192.168.1.1", .target_port = 80, .remark = "first" };
    try std.testing.expect(proj_a.eql(proj_b)); // remark differs but is ignored
    try std.testing.expect(!proj_a.eql(proj_c));

    // DdnsIpv4Config
    const ipv4_a = DdnsIpv4Config{ .url = "https://api.ipify.org", .domains = "a.com" };
    const ipv4_b = DdnsIpv4Config{ .url = "https://api.ipify.org", .domains = "a.com" };
    const ipv4_c = DdnsIpv4Config{ .url = "https://other.com", .domains = "a.com" };
    try std.testing.expect(ipv4_a.eql(ipv4_b));
    try std.testing.expect(!ipv4_a.eql(ipv4_c));

    // DdnsIpv6Config
    const ipv6_a = DdnsIpv6Config{ .enable = true, .url = "https://6.ipify.io", .domains = "b.com" };
    const ipv6_b = DdnsIpv6Config{ .enable = true, .url = "https://6.ipify.io", .domains = "b.com" };
    const ipv6_c = DdnsIpv6Config{ .enable = false, .url = "https://6.ipify.io", .domains = "b.com" };
    try std.testing.expect(ipv6_a.eql(ipv6_b));
    try std.testing.expect(!ipv6_a.eql(ipv6_c));

    // DdnsConfig (nested ipv4/ipv6)
    const ddns_a = DdnsConfig{
        .name = "myddns",
        .dns_provider = "cloudflare",
        .ttl = 300,
        .ipv4 = ipv4_a,
        .ipv6 = ipv6_a,
    };
    const ddns_b = DdnsConfig{
        .name = "myddns",
        .dns_provider = "cloudflare",
        .ttl = 300,
        .ipv4 = ipv4_b,
        .ipv6 = ipv6_b,
    };
    const ddns_c = DdnsConfig{
        .name = "myddns",
        .dns_provider = "cloudflare",
        .ttl = 600,
        .ipv4 = ipv4_a,
        .ipv6 = ipv6_a,
    };
    try std.testing.expect(ddns_a.eql(ddns_b));
    try std.testing.expect(!ddns_a.eql(ddns_c));
}

test "config: Config.eql with hashmaps" {
    const allocator = std.testing.allocator;

    var frpc_a = std.StringHashMap(FrpcNode).init(allocator);
    try frpc_a.put("node1", FrpcNode{ .server = "frp.example.com", .port = 7000 });
    var frps_a = std.StringHashMap(FrpsNode).init(allocator);
    try frps_a.put("srv1", FrpsNode{ .bind_port = 7000 });

    var frpc_b = std.StringHashMap(FrpcNode).init(allocator);
    try frpc_b.put("node1", FrpcNode{ .server = "frp.example.com", .port = 7000 });
    var frps_b = std.StringHashMap(FrpsNode).init(allocator);
    try frps_b.put("srv1", FrpsNode{ .bind_port = 7000 });

    var frpc_c = std.StringHashMap(FrpcNode).init(allocator);
    try frpc_c.put("node1", FrpcNode{ .server = "frp.example.com", .port = 9999 });
    var frps_c = std.StringHashMap(FrpsNode).init(allocator);
    try frps_c.put("srv1", FrpsNode{ .bind_port = 7000 });

    var cfg_a = Config{
        .log_config = .{ .file_path = "/tmp/test.log" },
        .projects = &[_]Project{},
        .frpc_nodes = frpc_a,
        .frps_nodes = frps_a,
        .ddns_configs = &[_]DdnsConfig{},
    };
    var cfg_b = Config{
        .log_config = .{ .file_path = "/tmp/test.log" },
        .projects = &[_]Project{},
        .frpc_nodes = frpc_b,
        .frps_nodes = frps_b,
        .ddns_configs = &[_]DdnsConfig{},
    };
    var cfg_c = Config{
        .log_config = .{ .file_path = "/tmp/test.log" },
        .projects = &[_]Project{},
        .frpc_nodes = frpc_c,
        .frps_nodes = frps_c,
        .ddns_configs = &[_]DdnsConfig{},
    };

    try std.testing.expect(cfg_a.eql(cfg_b));
    try std.testing.expect(!cfg_a.eql(cfg_c));

    // Clean up HashMap internals (keys are comptime literals, no free needed)
    cfg_a.frpc_nodes.deinit();
    cfg_a.frps_nodes.deinit();
    cfg_b.frpc_nodes.deinit();
    cfg_b.frps_nodes.deinit();
    cfg_c.frpc_nodes.deinit();
    cfg_c.frps_nodes.deinit();
}
