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

/// One port-forwarding project/rule.
pub const Project = struct {
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
    /// 协议: TCP+UDP / TCP / UDP
    protocol: Protocol = .both,
    /// 监听端口
    listen_port: u16,
    /// reuseaddr 绑定到本地端口
    reuseaddr: bool = false,
    /// 目标地址
    target_address: []const u8,
    /// 目标端口
    target_port: u16,
    /// 打开防火墙端口
    open_firewall_port: bool = false,
    /// 添加防火墙转发
    add_firewall_forward: bool = false,
    /// 启用应用层端口转发（使用 Zig 网络库实现，类似 socat）
    enable_app_forward: bool = false,

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
        self.* = undefined;
    }
};

pub const Config = struct {
    projects: []Project,

    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        for (self.projects) |*p| p.deinit(allocator);
        allocator.free(self.projects);
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
    if (eqlIgnoreCase(trimmed, "both") or eqlIgnoreCase(trimmed, "tcp+udp") or eqlIgnoreCase(trimmed, "TCP+UDP") or eqlIgnoreCase(trimmed, "tcpudp") or eqlIgnoreCase(trimmed, "TCP和UDP") or eqlIgnoreCase(trimmed, "TCP 与 UDP") or eqlIgnoreCase(trimmed, "TCP 和 UDP")) return .both;
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
