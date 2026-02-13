const std = @import("std");
const c = @cImport({
    @cInclude(if (@import("builtin").os.tag == .windows) "golibs.h" else "libgolibs.h");
});

pub const DdnsError = error{
    InitFailed,
    CreateInstanceFailed,
    SetConfigFailed,
    AddDomainFailed,
    RemoveDomainFailed,
    ClearDomainsFailed,
    UpdateFailed,
    StartFailed,
    StopFailed,
    DestroyFailed,
    InvalidInstanceID,
    UnsupportedProvider,
};

pub const LogLevel = enum(c_int) {
    debug = 0,
    info = 1,
    warn = 2,
    err = 3,
};

pub const LogCallback = *const fn (instance_id: i32, level: LogLevel, message: []const u8) void;

var global_log_callback: ?LogCallback = null;

fn logCallbackBridge(instance_id: c_int, level: c_int, message: [*c]const u8) callconv(.C) void {
    if (global_log_callback) |callback| {
        const msg_len = std.mem.len(message);
        const msg_slice = message[0..msg_len];
        const log_level: LogLevel = @enumFromInt(level);
        callback(@intCast(instance_id), log_level, msg_slice);
    }
}

pub fn setLogCallback(callback: ?LogCallback) void {
    global_log_callback = callback;
    if (callback != null) {
        c.DdnsSetLogCallback(logCallbackBridge);
    } else {
        c.DdnsSetLogCallback(null);
    }
}

pub const DnsProvider = enum {
    alidns,
    aliesa,
    tencentcloud,
    trafficroute,
    dnspod,
    dnsla,
    cloudflare,
    huaweicloud,
    callback,
    baiducloud,
    porkbun,
    godaddy,
    namecheap,
    namesilo,
    vercel,
    dynadot,
    dynv6,
    spaceship,
    nowcn,
    eranet,
    gcore,
    edgeone,
    nsone,
    name_com,

    pub fn toString(self: DnsProvider) []const u8 {
        return switch (self) {
            .alidns => "alidns",
            .aliesa => "aliesa",
            .tencentcloud => "tencentcloud",
            .trafficroute => "trafficroute",
            .dnspod => "dnspod",
            .dnsla => "dnsla",
            .cloudflare => "cloudflare",
            .huaweicloud => "huaweicloud",
            .callback => "callback",
            .baiducloud => "baiducloud",
            .porkbun => "porkbun",
            .godaddy => "godaddy",
            .namecheap => "namecheap",
            .namesilo => "namesilo",
            .vercel => "vercel",
            .dynadot => "dynadot",
            .dynv6 => "dynv6",
            .spaceship => "spaceship",
            .nowcn => "nowcn",
            .eranet => "eranet",
            .gcore => "gcore",
            .edgeone => "edgeone",
            .nsone => "nsone",
            .name_com => "name_com",
        };
    }

    pub fn fromString(str: []const u8) !DnsProvider {
        if (std.mem.eql(u8, str, "alidns")) return .alidns;
        if (std.mem.eql(u8, str, "aliesa")) return .aliesa;
        if (std.mem.eql(u8, str, "tencentcloud")) return .tencentcloud;
        if (std.mem.eql(u8, str, "trafficroute")) return .trafficroute;
        if (std.mem.eql(u8, str, "dnspod")) return .dnspod;
        if (std.mem.eql(u8, str, "dnsla")) return .dnsla;
        if (std.mem.eql(u8, str, "cloudflare")) return .cloudflare;
        if (std.mem.eql(u8, str, "huaweicloud")) return .huaweicloud;
        if (std.mem.eql(u8, str, "callback")) return .callback;
        if (std.mem.eql(u8, str, "baiducloud")) return .baiducloud;
        if (std.mem.eql(u8, str, "porkbun")) return .porkbun;
        if (std.mem.eql(u8, str, "godaddy")) return .godaddy;
        if (std.mem.eql(u8, str, "namecheap")) return .namecheap;
        if (std.mem.eql(u8, str, "namesilo")) return .namesilo;
        if (std.mem.eql(u8, str, "vercel")) return .vercel;
        if (std.mem.eql(u8, str, "dynadot")) return .dynadot;
        if (std.mem.eql(u8, str, "dynv6")) return .dynv6;
        if (std.mem.eql(u8, str, "spaceship")) return .spaceship;
        if (std.mem.eql(u8, str, "nowcn")) return .nowcn;
        if (std.mem.eql(u8, str, "eranet")) return .eranet;
        if (std.mem.eql(u8, str, "gcore")) return .gcore;
        if (std.mem.eql(u8, str, "edgeone")) return .edgeone;
        if (std.mem.eql(u8, str, "nsone")) return .nsone;
        if (std.mem.eql(u8, str, "name_com")) return .name_com;
        return DdnsError.UnsupportedProvider;
    }
};

pub const DomainConfig = struct {
    domain_name: []const u8,
    sub_domain: ?[]const u8 = null,
    ipv4_enabled: bool = true,
    ipv6_enabled: bool = false,
};

pub const DdnsStatusResponse = struct {
    status: []const u8,
    last_error: []const u8,
    logs: [][]const u8,
};

pub const DdnsInstance = struct {
    id: c_int,
    allocator: std.mem.Allocator,
    provider: DnsProvider,
    is_running: bool,

    pub fn init(allocator: std.mem.Allocator, provider: DnsProvider) !DdnsInstance {
        _ = c.DdnsInit();

        const provider_str = provider.toString();
        const c_provider = try allocator.dupeZ(u8, provider_str);
        defer allocator.free(c_provider);

        const instance_id = c.DdnsCreateInstance(c_provider.ptr);
        if (instance_id < 0) {
            return if (instance_id == -2) DdnsError.UnsupportedProvider else DdnsError.CreateInstanceFailed;
        }

        const instance = DdnsInstance{
            .id = instance_id,
            .allocator = allocator,
            .provider = provider,
            .is_running = false,
        };

        _ = c.DdnsSetProviderName(instance_id, c_provider.ptr);

        return instance;
    }

    pub fn setCredentials(self: *DdnsInstance, id: ?[]const u8, secret: ?[]const u8) !void {
        var c_id: ?[:0]u8 = null;
        var c_secret: ?[:0]u8 = null;

        if (id) |i| {
            c_id = try self.allocator.dupeZ(u8, i);
        }
        defer if (c_id) |ci| self.allocator.free(ci);

        if (secret) |s| {
            c_secret = try self.allocator.dupeZ(u8, s);
        }
        defer if (c_secret) |cs| self.allocator.free(cs);

        const result = c.DdnsSetCredentials(
            self.id,
            if (c_id) |ci| ci.ptr else null,
            if (c_secret) |cs| cs.ptr else null,
        );

        if (result < 0) {
            return DdnsError.SetConfigFailed;
        }
    }

    pub fn setExtParam(self: *DdnsInstance, ext_param: ?[]const u8) !void {
        if (ext_param) |ep| {
            const c_ext = try self.allocator.dupeZ(u8, ep);
            defer self.allocator.free(c_ext);
            const result = c.DdnsSetExtParam(self.id, c_ext.ptr);
            if (result < 0) {
                return DdnsError.SetConfigFailed;
            }
        } else {
            const result = c.DdnsSetExtParam(self.id, null);
            if (result < 0) {
                return DdnsError.SetConfigFailed;
            }
        }
    }

    pub fn addDomain(self: *DdnsInstance, config: DomainConfig) !void {
        const c_domain = try self.allocator.dupeZ(u8, config.domain_name);
        defer self.allocator.free(c_domain);

        var c_subdomain: ?[:0]u8 = null;
        if (config.sub_domain) |sub| {
            c_subdomain = try self.allocator.dupeZ(u8, sub);
        }
        defer if (c_subdomain) |cs| self.allocator.free(cs);

        const result = c.DdnsAddDomain(
            self.id,
            c_domain.ptr,
            if (c_subdomain) |cs| cs.ptr else null,
            if (config.ipv4_enabled) 1 else 0,
            if (config.ipv6_enabled) 1 else 0,
        );

        if (result < 0) {
            return DdnsError.AddDomainFailed;
        }
    }

    pub fn removeDomain(self: *DdnsInstance, domain_name: []const u8, sub_domain: ?[]const u8) !void {
        const c_domain = try self.allocator.dupeZ(u8, domain_name);
        defer self.allocator.free(c_domain);

        var c_subdomain: ?[:0]u8 = null;
        if (sub_domain) |sub| {
            c_subdomain = try self.allocator.dupeZ(u8, sub);
        }
        defer if (c_subdomain) |cs| self.allocator.free(cs);

        const result = c.DdnsRemoveDomain(
            self.id,
            c_domain.ptr,
            if (c_subdomain) |cs| cs.ptr else null,
        );

        if (result < 0) {
            return DdnsError.RemoveDomainFailed;
        }
    }

    pub fn clearDomains(self: *DdnsInstance) !void {
        const result = c.DdnsClearDomains(self.id);
        if (result < 0) {
            return DdnsError.ClearDomainsFailed;
        }
    }

    pub fn setIPv4Address(self: *DdnsInstance, ipv4_addr: []const u8) !void {
        const c_addr = try self.allocator.dupeZ(u8, ipv4_addr);
        defer self.allocator.free(c_addr);

        const result = c.DdnsSetIPv4Address(self.id, c_addr.ptr);
        if (result < 0) {
            return DdnsError.SetConfigFailed;
        }
    }

    pub fn setIPv4GetType(self: *DdnsInstance, get_type: []const u8) !void {
        const c_type = try self.allocator.dupeZ(u8, get_type);
        defer self.allocator.free(c_type);

        const result = c.DdnsSetIPv4GetType(self.id, c_type.ptr);
        if (result < 0) {
            return DdnsError.SetConfigFailed;
        }
    }

    pub fn setIPv6Address(self: *DdnsInstance, ipv6_addr: []const u8) !void {
        const c_addr = try self.allocator.dupeZ(u8, ipv6_addr);
        defer self.allocator.free(c_addr);

        const result = c.DdnsSetIPv6Address(self.id, c_addr.ptr);
        if (result < 0) {
            return DdnsError.SetConfigFailed;
        }
    }

    pub fn setIPv6GetType(self: *DdnsInstance, get_type: []const u8) !void {
        const c_type = try self.allocator.dupeZ(u8, get_type);
        defer self.allocator.free(c_type);

        const result = c.DdnsSetIPv6GetType(self.id, c_type.ptr);
        if (result < 0) {
            return DdnsError.SetConfigFailed;
        }
    }

    pub fn updateOnce(self: *DdnsInstance) !void {
        const result = c.DdnsUpdateOnce(self.id);
        if (result < 0) {
            return DdnsError.UpdateFailed;
        }
    }

    pub fn startAutoUpdate(self: *DdnsInstance, interval_seconds: u32) !void {
        const result = c.DdnsStartAutoUpdate(self.id, @intCast(interval_seconds));
        if (result < 0) {
            return if (result == -3) DdnsError.StartFailed else DdnsError.InvalidInstanceID;
        }
        self.is_running = true;
    }

    pub fn stopAutoUpdate(self: *DdnsInstance) !void {
        const result = c.DdnsStopAutoUpdate(self.id);
        if (result < 0) {
            return DdnsError.StopFailed;
        }
        self.is_running = false;
    }

    pub fn getStatusAndLogs(self: *DdnsInstance) !DdnsStatusResponse {
        const json_str = c.DdnsGetStatusAndLogs(self.id);
        if (json_str == null) {
            return DdnsError.InvalidInstanceID;
        }
        defer c.DdnsFreeString(json_str);

        const json_slice = std.mem.span(json_str);
        const parsed = try std.json.parseFromSlice(DdnsStatusResponse, self.allocator, json_slice, .{});
        defer parsed.deinit();

        // Deep copy to avoid dependency on parsed data
        var response = parsed.value;
        response.status = try self.allocator.dupe(u8, response.status);
        response.last_error = try self.allocator.dupe(u8, response.last_error);
        response.logs = try self.allocator.dupe([]const u8, response.logs);
        for (response.logs) |*log| {
            log.* = try self.allocator.dupe(u8, log.*);
        }

        return response;
    }

    pub fn clearLogs(self: *DdnsInstance) void {
        c.DdnsClearLogs(self.id);
    }

    pub fn deinit(self: *DdnsInstance) void {
        if (self.is_running) {
            _ = c.DdnsStopAutoUpdate(self.id);
        }
        _ = c.DdnsDestroyInstance(self.id);
    }
};

/// Get the DDNS library version
pub fn getVersion(allocator: std.mem.Allocator) !?[]const u8 {
    const c_version = c.DdnsGetVersion();
    if (c_version) |cv| {
        defer c.DdnsFreeString(cv);
        const len = std.mem.len(cv);
        return try allocator.dupe(u8, cv[0..len]);
    } else {
        return null;
    }
}

pub fn cleanup() void {
    c.DdnsCleanup();
}
