const std = @import("std");
const c = @cImport({
    @cInclude(if (@import("builtin").os.tag == .windows) "golibs.h" else "libgolibs.h");
});

pub const FrpsError = error{
    InitFailed,
    CreateServerFailed,
    StartFailed,
    StopFailed,
    DestroyFailed,
    InvalidServerError,
};

var frps_initialized: bool = false;
var frps_init_lock: std.Thread.Mutex = .{};

fn ensureFrpsInit() !void {
    frps_init_lock.lock();
    defer frps_init_lock.unlock();

    if (frps_initialized) return;

    c.FrpsInit();
    frps_initialized = true;
}

pub const FrpsServer = struct {
    id: c_int,
    allocator: std.mem.Allocator,

    pub const Config = struct {
        // === ServerConfig fields ===
        bind_addr: ?[]const u8 = null,
        bind_port: ?u16 = null,
        auth_token: ?[]const u8 = null,
        // === WebServerConfig fields (flattened) ===
        dashboard_addr: ?[]const u8 = null,
        dashboard_port: ?u16 = null,
        dashboard_user: ?[]const u8 = null,
        dashboard_pwd: ?[]const u8 = null,
        // === LogConfig fields ===
        log_level: ?[]const u8 = null,
        // === ServerTransportConfig fields (flattened) ===
        max_pool_count: ?u32 = null,
        max_ports_per_client: ?u32 = null,
        tcp_mux: ?bool = null,
        // === Access control ===
        allow_ports: ?[]const u8 = null,
    };

    // Keep consistent with Go struct definition
    const CFrpsConfig = extern struct {
        server_name: ?[*:0]const u8,
        bind_addr: ?[*:0]const u8,
        bind_port: ?*c_int,
        auth_token: ?[*:0]const u8,
        dashboard_addr: ?[*:0]const u8,
        dashboard_port: ?*c_int,
        dashboard_user: ?[*:0]const u8,
        dashboard_pwd: ?[*:0]const u8,
        log_level: ?[*:0]const u8,
        max_pool_count: ?*c_int,
        max_ports_per_client: ?*c_int,
        tcp_mux: ?*bool,
        allow_ports: ?[*:0]const u8,
    };

    // Override the C import signature manually since the header might not be updated yet
    extern fn FrpsCreateServer(config: *const CFrpsConfig) c_int;

    pub fn init(allocator: std.mem.Allocator, config: Config, server_name: []const u8) !FrpsServer {
        try ensureFrpsInit();

        // Helper to duplicate string to C string
        const toCString = struct {
            fn call(alloc: std.mem.Allocator, str: ?[]const u8) !?[*:0]const u8 {
                if (str) |s| {
                    return try alloc.dupeZ(u8, s);
                }
                return null;
            }
        }.call;

        // Prepare C config struct
        const c_name = try toCString(allocator, server_name);
        errdefer if (c_name) |p| allocator.free(std.mem.span(p));

        const c_bind_addr = try toCString(allocator, config.bind_addr);
        errdefer if (c_bind_addr) |p| allocator.free(std.mem.span(p));

        const c_token = try toCString(allocator, config.auth_token);
        errdefer if (c_token) |p| allocator.free(std.mem.span(p));

        const c_dash_addr = try toCString(allocator, config.dashboard_addr);
        errdefer if (c_dash_addr) |p| allocator.free(std.mem.span(p));

        const c_dash_user = try toCString(allocator, config.dashboard_user);
        errdefer if (c_dash_user) |p| allocator.free(std.mem.span(p));

        const c_dash_pwd = try toCString(allocator, config.dashboard_pwd);
        errdefer if (c_dash_pwd) |p| allocator.free(std.mem.span(p));

        const c_log_level = try toCString(allocator, config.log_level);
        errdefer if (c_log_level) |p| allocator.free(std.mem.span(p));

        const c_allow_ports = try toCString(allocator, config.allow_ports);
        errdefer if (c_allow_ports) |p| allocator.free(std.mem.span(p));

        // Allocate space for optional integer/bool values
        var bind_port_val: c_int = undefined;
        var dash_port_val: c_int = undefined;
        var max_pool_val: c_int = undefined;
        var max_ports_val: c_int = undefined;
        var tcp_mux_val: bool = undefined;

        const c_config = CFrpsConfig{
            .server_name = c_name,
            .bind_addr = c_bind_addr,
            .bind_port = if (config.bind_port) |p| blk: {
                bind_port_val = @intCast(p);
                break :blk &bind_port_val;
            } else null,
            .auth_token = c_token,
            .dashboard_addr = c_dash_addr,
            .dashboard_port = if (config.dashboard_port) |p| blk: {
                dash_port_val = @intCast(p);
                break :blk &dash_port_val;
            } else null,
            .dashboard_user = c_dash_user,
            .dashboard_pwd = c_dash_pwd,
            .log_level = c_log_level,
            .max_pool_count = if (config.max_pool_count) |p| blk: {
                max_pool_val = @intCast(p);
                break :blk &max_pool_val;
            } else null,
            .max_ports_per_client = if (config.max_ports_per_client) |p| blk: {
                max_ports_val = @intCast(p);
                break :blk &max_ports_val;
            } else null,
            .tcp_mux = if (config.tcp_mux) |p| blk: {
                tcp_mux_val = p;
                break :blk &tcp_mux_val;
            } else null,
            .allow_ports = c_allow_ports,
        };

        const server_id = FrpsCreateServer(&c_config);

        // Cleanup C strings
        if (c_name) |p| allocator.free(std.mem.span(p));
        if (c_bind_addr) |p| allocator.free(std.mem.span(p));
        if (c_token) |p| allocator.free(std.mem.span(p));
        if (c_dash_addr) |p| allocator.free(std.mem.span(p));
        if (c_dash_user) |p| allocator.free(std.mem.span(p));
        if (c_dash_pwd) |p| allocator.free(std.mem.span(p));
        if (c_log_level) |p| allocator.free(std.mem.span(p));
        if (c_allow_ports) |p| allocator.free(std.mem.span(p));

        if (server_id < 0) {
            return FrpsError.CreateServerFailed;
        }

        return FrpsServer{
            .id = server_id,
            .allocator = allocator,
        };
    }

    pub fn start(self: *FrpsServer) !void {
        const result = c.FrpsStartServer(self.id);
        if (result < 0) {
            return FrpsError.StartFailed;
        }
    }

    pub fn stop(self: *FrpsServer) !void {
        const result = c.FrpsStopServer(self.id);
        if (result < 0) {
            return FrpsError.StopFailed;
        }
    }

    pub fn deinit(self: *FrpsServer) void {
        _ = c.FrpsDestroyServer(self.id);
    }

    pub fn getStatus(self: *FrpsServer, allocator: std.mem.Allocator) ![]const u8 {
        const c_status = c.FrpsGetStatus(self.id);
        defer c.FrpsFreeString(c_status);

        const len = std.mem.len(c_status);
        return try allocator.dupe(u8, c_status[0..len]);
    }

    pub fn getLogs(self: *FrpsServer, allocator: std.mem.Allocator) ![]const u8 {
        const c_logs = c.FrpsGetLogs(self.id);
        defer c.FrpsFreeString(c_logs);

        const len = std.mem.len(c_logs);
        return try allocator.dupe(u8, c_logs[0..len]);
    }

    pub fn clearLogs(self: *FrpsServer) void {
        c.FrpsClearLogs(self.id);
    }
};

pub fn getVersion(allocator: std.mem.Allocator) ![]const u8 {
    const c_version = c.FrpsGetVersion();
    defer c.FrpsFreeString(c_version);

    const len = std.mem.len(c_version);
    return try allocator.dupe(u8, c_version[0..len]);
}

pub const ServerStats = struct {
    status: []const u8,
    last_error: []const u8,
    client_count: usize,
    proxy_count: usize,
    server_count: usize,
};

pub fn getServerStats(allocator: std.mem.Allocator) !ServerStats {
    const c_stats = c.FrpsGetServerStats();
    defer c.FrpsFreeString(c_stats);

    const len = std.mem.len(c_stats);
    const json_str = c_stats[0..len];

    return parseServerStatsJson(allocator, json_str);
}

fn parseServerStatsJson(allocator: std.mem.Allocator, json: []const u8) !ServerStats {
    var status: []const u8 = "unknown";
    var last_error: []const u8 = "";
    var client_count: usize = 0;
    var proxy_count: usize = 0;
    var server_count: usize = 0;

    if (std.mem.indexOf(u8, json, "\"status\":\"")) |start| {
        const value_start = start + 10;
        if (std.mem.indexOfPos(u8, json, value_start, "\"")) |end| {
            status = json[value_start..end];
        }
    }

    if (std.mem.indexOf(u8, json, "\"last_error\":\"")) |start| {
        const value_start = start + 14;
        if (std.mem.indexOfPos(u8, json, value_start, "\"")) |end| {
            last_error = json[value_start..end];
        }
    }

    if (std.mem.indexOf(u8, json, "\"client_count\":")) |start| {
        const value_start = start + 15;
        if (std.mem.indexOfPos(u8, json, value_start, ",")) |end| {
            const num_str = json[value_start..end];
            client_count = std.fmt.parseInt(usize, num_str, 10) catch 0;
        } else if (std.mem.indexOfPos(u8, json, value_start, "}")) |end| {
            const num_str = json[value_start..end];
            client_count = std.fmt.parseInt(usize, num_str, 10) catch 0;
        }
    }

    if (std.mem.indexOf(u8, json, "\"proxy_count\":")) |start| {
        const value_start = start + 14;
        if (std.mem.indexOfPos(u8, json, value_start, ",")) |end| {
            const num_str = json[value_start..end];
            proxy_count = std.fmt.parseInt(usize, num_str, 10) catch 0;
        } else if (std.mem.indexOfPos(u8, json, value_start, "}")) |end| {
            const num_str = json[value_start..end];
            proxy_count = std.fmt.parseInt(usize, num_str, 10) catch 0;
        }
    }

    if (std.mem.indexOf(u8, json, "\"server_count\":")) |start| {
        const value_start = start + 15;
        if (std.mem.indexOfPos(u8, json, value_start, ",")) |end| {
            const num_str = json[value_start..end];
            server_count = std.fmt.parseInt(usize, num_str, 10) catch 0;
        } else if (std.mem.indexOfPos(u8, json, value_start, "}")) |end| {
            const num_str = json[value_start..end];
            server_count = std.fmt.parseInt(usize, num_str, 10) catch 0;
        }
    }

    return ServerStats{
        .status = try allocator.dupe(u8, status),
        .last_error = try allocator.dupe(u8, last_error),
        .client_count = client_count,
        .proxy_count = proxy_count,
        .server_count = server_count,
    };
}

pub fn cleanup() void {
    c.FrpsCleanup();
}
