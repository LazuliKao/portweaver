const std = @import("std");
const uci = @import("uci.zig");
const build_options = @import("build_options");

pub const ConfigError = error{
    MissingField,
    InvalidValue,
    UnsupportedFeature,
    JsonParseError,
};

pub const Provider = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        load: *const fn (ctx: *anyopaque, allocator: std.mem.Allocator) anyerror!Config,
    };

    pub fn load(self: Provider, allocator: std.mem.Allocator) !Config {
        return self.vtable.load(self.ctx, allocator);
    }
};

pub const UciProvider = struct {
    ctx: uci.UciContext,
    package_name: [*c]const u8,

    pub fn asProvider(self: *UciProvider) Provider {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn loadErased(ctx_ptr: *anyopaque, allocator: std.mem.Allocator) anyerror!Config {
        const self: *UciProvider = @ptrCast(@alignCast(ctx_ptr));
        return loadFromUci(allocator, self.ctx, self.package_name);
    }

    const vtable = Provider.VTable{ .load = loadErased };
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
///
/// This maps to a UCI section:
///   config project|rule '<name>'
/// and its options.
pub const Project = struct {
    /// 备注
    remark: []const u8 = "",
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

    pub fn deinit(self: *Project, allocator: std.mem.Allocator) void {
        if (self.remark.len != 0) allocator.free(self.remark);
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

fn parseBool(val: []const u8) !bool {
    const trimmed = std.mem.trim(u8, val, " \t\r\n");
    if (trimmed.len == 0) return false;

    if (eqlIgnoreCase(trimmed, "1") or eqlIgnoreCase(trimmed, "true") or eqlIgnoreCase(trimmed, "yes") or eqlIgnoreCase(trimmed, "on") or eqlIgnoreCase(trimmed, "enabled")) return true;
    if (eqlIgnoreCase(trimmed, "0") or eqlIgnoreCase(trimmed, "false") or eqlIgnoreCase(trimmed, "no") or eqlIgnoreCase(trimmed, "off") or eqlIgnoreCase(trimmed, "disabled")) return false;

    return ConfigError.InvalidValue;
}

fn parsePort(val: []const u8) !u16 {
    const trimmed = std.mem.trim(u8, val, " \t\r\n");
    const port_u32 = std.fmt.parseUnsigned(u32, trimmed, 10) catch return ConfigError.InvalidValue;
    if (port_u32 == 0 or port_u32 > 65535) return ConfigError.InvalidValue;
    return @intCast(port_u32);
}

fn parseFamily(val: []const u8) !AddressFamily {
    const trimmed = std.mem.trim(u8, val, " \t\r\n");

    if (trimmed.len == 0) return .any;
    if (eqlIgnoreCase(trimmed, "any") or eqlIgnoreCase(trimmed, "all") or eqlIgnoreCase(trimmed, "both") or eqlIgnoreCase(trimmed, "ipv4+ipv6") or eqlIgnoreCase(trimmed, "ipv4_and_ipv6") or eqlIgnoreCase(trimmed, "IPv4 和 IPv6") or eqlIgnoreCase(trimmed, "IPv4和IPv6")) return .any;
    if (eqlIgnoreCase(trimmed, "ipv4") or eqlIgnoreCase(trimmed, "IPv4")) return .ipv4;
    if (eqlIgnoreCase(trimmed, "ipv6") or eqlIgnoreCase(trimmed, "IPv6")) return .ipv6;

    return ConfigError.InvalidValue;
}

fn parseProtocol(val: []const u8) !Protocol {
    const trimmed = std.mem.trim(u8, val, " \t\r\n");

    if (trimmed.len == 0) return .both;
    if (eqlIgnoreCase(trimmed, "both") or eqlIgnoreCase(trimmed, "tcp+udp") or eqlIgnoreCase(trimmed, "TCP+UDP") or eqlIgnoreCase(trimmed, "tcpudp") or eqlIgnoreCase(trimmed, "TCP和UDP") or eqlIgnoreCase(trimmed, "TCP 与 UDP") or eqlIgnoreCase(trimmed, "TCP 和 UDP")) return .both;
    if (eqlIgnoreCase(trimmed, "tcp") or eqlIgnoreCase(trimmed, "TCP")) return .tcp;
    if (eqlIgnoreCase(trimmed, "udp") or eqlIgnoreCase(trimmed, "UDP")) return .udp;

    return ConfigError.InvalidValue;
}

fn dupeIfNonEmpty(allocator: std.mem.Allocator, s: []const u8) ![]const u8 {
    if (s.len == 0) return "";
    return allocator.dupe(u8, s);
}

fn parseProjectFromSection(allocator: std.mem.Allocator, sec: uci.UciSection) !Project {
    var project = Project{
        .listen_port = 0,
        .target_address = undefined,
        .target_port = 0,
    };

    var have_listen_port = false;
    var have_target_address = false;
    var have_target_port = false;

    var opt_it = sec.options();
    while (opt_it.next()) |opt| {
        const opt_name = uci.cStr(opt.name());
        if (!opt.isString()) continue;
        const opt_val = uci.cStr(opt.getString());

        if (std.mem.eql(u8, opt_name, "remark") or std.mem.eql(u8, opt_name, "note") or std.mem.eql(u8, opt_name, "备注")) {
            project.remark = try dupeIfNonEmpty(allocator, opt_val);
        } else if (std.mem.eql(u8, opt_name, "family") or std.mem.eql(u8, opt_name, "addr_family") or std.mem.eql(u8, opt_name, "地址族限制")) {
            project.family = try parseFamily(opt_val);
        } else if (std.mem.eql(u8, opt_name, "protocol") or std.mem.eql(u8, opt_name, "proto") or std.mem.eql(u8, opt_name, "协议")) {
            project.protocol = try parseProtocol(opt_val);
        } else if (std.mem.eql(u8, opt_name, "listen_port") or std.mem.eql(u8, opt_name, "src_port") or std.mem.eql(u8, opt_name, "监听端口")) {
            project.listen_port = try parsePort(opt_val);
            have_listen_port = true;
        } else if (std.mem.eql(u8, opt_name, "reuseaddr") or std.mem.eql(u8, opt_name, "reuse") or std.mem.eql(u8, opt_name, "reuse_addr") or std.mem.eql(u8, opt_name, "绑定到本地端口")) {
            project.reuseaddr = try parseBool(opt_val);
        } else if (std.mem.eql(u8, opt_name, "target_address") or std.mem.eql(u8, opt_name, "target_addr") or std.mem.eql(u8, opt_name, "dst_ip") or std.mem.eql(u8, opt_name, "目标地址")) {
            const trimmed = std.mem.trim(u8, opt_val, " \t\r\n");
            if (trimmed.len == 0) return ConfigError.InvalidValue;
            project.target_address = try allocator.dupe(u8, trimmed);
            have_target_address = true;
        } else if (std.mem.eql(u8, opt_name, "target_port") or std.mem.eql(u8, opt_name, "dst_port") or std.mem.eql(u8, opt_name, "目标端口")) {
            project.target_port = try parsePort(opt_val);
            have_target_port = true;
        } else if (std.mem.eql(u8, opt_name, "open_firewall_port") or std.mem.eql(u8, opt_name, "firewall_open") or std.mem.eql(u8, opt_name, "打开防火墙端口")) {
            project.open_firewall_port = try parseBool(opt_val);
        } else if (std.mem.eql(u8, opt_name, "add_firewall_forward") or std.mem.eql(u8, opt_name, "firewall_forward") or std.mem.eql(u8, opt_name, "添加防火墙转发")) {
            project.add_firewall_forward = try parseBool(opt_val);
        }
    }

    if (!have_listen_port or !have_target_address or !have_target_port) {
        if (have_target_address) allocator.free(project.target_address);
        if (project.remark.len != 0) allocator.free(project.remark);
        return ConfigError.MissingField;
    }

    return project;
}

/// Load projects from a UCI config package (e.g. `/etc/config/portweaver`).
///
/// Expected schema (one section per project):
///   config project 'name'
///     option remark '...'
///     option family 'any|ipv4|ipv6'
///     option protocol 'both|tcp|udp'
///     option listen_port '3389'
///     option reuseaddr '1'
///     option target_address '192.168.1.2'
///     option target_port '3389'
///     option open_firewall_port '1'
///     option add_firewall_forward '1'
pub fn loadFromUci(allocator: std.mem.Allocator, ctx: uci.UciContext, package_name: [*c]const u8) !Config {
    var pkg = try ctx.load(package_name);
    if (pkg.isNull()) return ConfigError.MissingField;
    defer pkg.unload() catch {};

    var list = std.ArrayList(Project).init(allocator);
    errdefer {
        for (list.items) |*p| p.deinit(allocator);
        list.deinit();
    }

    var sec_it = uci.sections(pkg);
    while (sec_it.next()) |sec| {
        const sec_type = uci.cStr(sec.sectionType());
        if (!(std.mem.eql(u8, sec_type, "project") or std.mem.eql(u8, sec_type, "rule"))) continue;

        const project = try parseProjectFromSection(allocator, sec);
        try list.append(project);
    }

    return .{ .projects = try list.toOwnedSlice() };
}

pub const JsonProvider = if (build_options.enable_json) struct {
    path: []const u8,

    pub fn asProvider(self: *JsonProvider) Provider {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn loadErased(ctx_ptr: *anyopaque, allocator: std.mem.Allocator) anyerror!Config {
        const self: *JsonProvider = @ptrCast(@alignCast(ctx_ptr));
        return loadFromJsonFile(allocator, self.path);
    }

    const vtable = Provider.VTable{ .load = loadErased };
} else struct {
    path: []const u8,

    pub fn asProvider(self: *JsonProvider) Provider {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn loadErased(_: *anyopaque, _: std.mem.Allocator) anyerror!Config {
        return ConfigError.UnsupportedFeature;
    }

    const vtable = Provider.VTable{ .load = loadErased };
};

pub fn loadFromProvider(allocator: std.mem.Allocator, provider: Provider) !Config {
    return provider.load(allocator);
}

fn jsonGet(obj: std.json.ObjectMap, key: []const u8) ?std.json.Value {
    return obj.get(key);
}

fn jsonGetAliased(obj: std.json.ObjectMap, keys: []const []const u8) ?std.json.Value {
    for (keys) |k| {
        if (obj.get(k)) |v| return v;
    }
    return null;
}

fn parseJsonBool(v: std.json.Value) !bool {
    return switch (v) {
        .bool => |b| b,
        .integer => |i| i != 0,
        .string => |s| try parseBool(s),
        else => ConfigError.InvalidValue,
    };
}

fn parseJsonPort(v: std.json.Value) !u16 {
    return switch (v) {
        .integer => |i| {
            if (i <= 0 or i > 65535) return ConfigError.InvalidValue;
            return @intCast(i);
        },
        .string => |s| try parsePort(s),
        else => ConfigError.InvalidValue,
    };
}

fn parseJsonString(v: std.json.Value) ![]const u8 {
    return switch (v) {
        .string => |s| s,
        else => ConfigError.InvalidValue,
    };
}

pub fn loadFromJsonFile(allocator: std.mem.Allocator, path: []const u8) !Config {
    if (!build_options.enable_json) return ConfigError.UnsupportedFeature;

    const json_text = std.fs.cwd().readFileAlloc(allocator, path, 1 << 20) catch return ConfigError.JsonParseError;
    defer allocator.free(json_text);

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json_text, .{}) catch return ConfigError.JsonParseError;
    defer parsed.deinit();

    var list = std.ArrayList(Project).init(allocator);
    errdefer {
        for (list.items) |*p| p.deinit(allocator);
        list.deinit();
    }

    const root = parsed.value;
    const projects_value: std.json.Value = switch (root) {
        .array => root,
        .object => |o| jsonGetAliased(o, &.{ "projects", "items", "rules" }) orelse return ConfigError.MissingField,
        else => return ConfigError.InvalidValue,
    };

    if (projects_value != .array) return ConfigError.InvalidValue;

    for (projects_value.array.items) |item| {
        if (item != .object) return ConfigError.InvalidValue;
        const obj = item.object;

        var project = Project{
            .listen_port = 0,
            .target_address = undefined,
            .target_port = 0,
        };

        var have_listen_port = false;
        var have_target_address = false;
        var have_target_port = false;

        if (jsonGetAliased(obj, &.{ "remark", "note", "备注" })) |v| {
            const s = try parseJsonString(v);
            project.remark = try dupeIfNonEmpty(allocator, s);
        }

        if (jsonGetAliased(obj, &.{ "family", "addr_family", "地址族限制" })) |v| {
            const s = try parseJsonString(v);
            project.family = try parseFamily(s);
        }

        if (jsonGetAliased(obj, &.{ "protocol", "proto", "协议" })) |v| {
            const s = try parseJsonString(v);
            project.protocol = try parseProtocol(s);
        }

        if (jsonGetAliased(obj, &.{ "listen_port", "src_port", "监听端口" })) |v| {
            project.listen_port = try parseJsonPort(v);
            have_listen_port = true;
        }

        if (jsonGetAliased(obj, &.{ "reuseaddr", "reuse", "reuse_addr", "绑定到本地端口" })) |v| {
            project.reuseaddr = try parseJsonBool(v);
        }

        if (jsonGetAliased(obj, &.{ "target_address", "target_addr", "dst_ip", "目标地址" })) |v| {
            const s = try parseJsonString(v);
            const trimmed = std.mem.trim(u8, s, " \t\r\n");
            if (trimmed.len == 0) return ConfigError.InvalidValue;
            project.target_address = try allocator.dupe(u8, trimmed);
            have_target_address = true;
        }

        if (jsonGetAliased(obj, &.{ "target_port", "dst_port", "目标端口" })) |v| {
            project.target_port = try parseJsonPort(v);
            have_target_port = true;
        }

        if (jsonGetAliased(obj, &.{ "open_firewall_port", "firewall_open", "打开防火墙端口" })) |v| {
            project.open_firewall_port = try parseJsonBool(v);
        }

        if (jsonGetAliased(obj, &.{ "add_firewall_forward", "firewall_forward", "添加防火墙转发" })) |v| {
            project.add_firewall_forward = try parseJsonBool(v);
        }

        if (!have_listen_port or !have_target_address or !have_target_port) {
            if (have_target_address) allocator.free(project.target_address);
            if (project.remark.len != 0) allocator.free(project.remark);
            return ConfigError.MissingField;
        }

        try list.append(project);
    }

    return .{ .projects = try list.toOwnedSlice() };
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

test "config: provider abstraction (uci) compiles" {
    // This test only checks the vtable wiring compiles.
    // It does not call into libuci or require OpenWrt runtime.
    const fake_ctx = uci.UciContext{ .ctx = null };
    var p = UciProvider{ .ctx = fake_ctx, .package_name = "portweaver" };
    _ = p.asProvider();
}
