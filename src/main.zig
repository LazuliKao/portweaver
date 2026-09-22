const std = @import("std");
const build_options = @import("build_options");
const rathole_enabled = build_options.rathole_client_mode or build_options.rathole_server_mode;
const config = @import("config/mod.zig");
const ubus_server = if (build_options.ubus_mode) @import("ubus/server.zig") else void;
const uci = if (build_options.uci_mode) @import("uci/mod.zig") else void;
const event_log = @import("event_log.zig");
const process_lock = @import("process_lock.zig");
const file_log = @import("file_log.zig");
const reload = @import("reload.zig");
const RuntimeController = @import("runtime_controller.zig").RuntimeController;
const libddns = if (build_options.ddns_mode) @import("impl/ddns/libddns.zig") else struct {};
const wol = if (build_options.wol_mode) @import("impl/wol.zig") else struct {};

fn handleSighup(_: std.posix.SIG) callconv(.c) void {
    process_lock.requestReload();
}
var global_log_level: std.log.Level = .info;

pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = myLogFn,
};

fn myLogFn(
    comptime level: std.log.Level,
    comptime scope: @EnumLiteral(),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@intFromEnum(level) > @intFromEnum(global_log_level)) return;

    std.debug.print("[" ++ level.asText() ++ "] " ++ format ++ "\n", args);

    file_log.logToFile(level, scope, format, args);
}

const VersionInfo = struct {
    version: []const u8 = "1.0.0",
    uci_mode: bool = build_options.uci_mode,
    ubus_mode: bool = build_options.ubus_mode,
    frpc_mode: bool = build_options.frpc_mode,
    frps_mode: bool = build_options.frps_mode,
    rathole_client_mode: bool = build_options.rathole_client_mode,
    rathole_server_mode: bool = build_options.rathole_server_mode,
    ddns_mode: bool = build_options.ddns_mode,
    nftables_mode: bool = build_options.nftables_mode,
    wol_mode: bool = build_options.wol_mode,
    forward_backend: []const u8 = @tagName(build_options.forward_backend),
    frp_version: ?[]const u8,
    ddns_version: ?[]const u8,
    backend_version: []const u8,
};

fn handleVersionCommand(allocator: std.mem.Allocator, json_mode: bool) !void {
    var frp_version: ?[]const u8 = null;
    defer if (frp_version) |v| allocator.free(v);

    if (build_options.frpc_mode) {
        const libfrpc_impl = @import("impl/frpc/libfrpc.zig");
        frp_version = libfrpc_impl.getVersion(allocator) catch |err| blk: {
            std.log.warn("Failed to get FRPC version: {any}", .{err});
            break :blk null;
        };
    } else if (build_options.frps_mode) {
        const libfrps_impl = @import("impl/frps/libfrps.zig");
        frp_version = libfrps_impl.getVersion(allocator) catch |err| blk: {
            std.log.warn("Failed to get FRPS version: {any}", .{err});
            break :blk null;
        };
    }

    var ddns_version: ?[]const u8 = null;
    defer if (ddns_version) |v| allocator.free(v);

    if (build_options.ddns_mode) {
        ddns_version = libddns.getVersion(allocator) catch |err| blk: {
            std.log.warn("Failed to get DDNS version: {any}", .{err});
            break :blk null;
        };
    }

    const backend_runtime = @import("impl/app_forward/forwarder_runtime.zig");
    const backend_version = backend_runtime.backendVersion();

    const io = std.Options.debug_io;
    const stdout_file = std.Io.File.stdout();
    var write_buf: [4096]u8 = undefined;
    var stdout_writer = stdout_file.writer(io, &write_buf);
    const writer = &stdout_writer.interface;

    if (json_mode) {
        const info = VersionInfo{
            .frp_version = frp_version,
            .ddns_version = ddns_version,
            .backend_version = backend_version,
        };
        try writer.print("{f}", .{std.json.fmt(info, .{})});
        try writer.writeByte('\n');
    } else {
        try writer.print("PortWeaver version: 1.0.0\n", .{});
        try writer.print("  Forwarding backend: {s} ({s})\n", .{ @tagName(build_options.forward_backend), backend_version });
        if (frp_version) |v| {
            try writer.print("  FRP version: {s}\n", .{v});
        }
        if (ddns_version) |v| {
            try writer.print("  DDNS version: {s}\n", .{v});
        }
        try writer.print("  Features: uci={any}, ubus={any}, frpc={any}, frps={any}, ddns={any}, nftables={any}, wol={any}\n", .{
            build_options.uci_mode,
            build_options.ubus_mode,
            build_options.frpc_mode,
            build_options.frps_mode,
            build_options.ddns_mode,
            build_options.nftables_mode,
            build_options.wol_mode,
        });
    }
    try stdout_writer.flush();
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len >= 2 and std.mem.eql(u8, args[1], "version")) {
        const json_mode = args.len >= 3 and std.mem.eql(u8, args[2], "--json");
        try handleVersionCommand(allocator, json_mode);
        return;
    }
    errdefer {
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpErrorReturnTrace(trace);
        }
    }

    // Ensure single instance ownership before starting services.
    try process_lock.ensureSingleInstance(allocator);
    defer process_lock.cleanup();

    // Initialize event logger
    event_log.initGlobal(allocator);
    defer event_log.deinitGlobal();

    if (build_options.wol_mode) {
        try wol.initGlobal(allocator);
    }
    defer if (build_options.wol_mode) wol.deinitGlobal();

    // 注册 SIGHUP 信号处理器（非 Windows）
    if (@import("builtin").os.tag != .windows) {
        const act = std.posix.Sigaction{
            .handler = .{ .handler = handleSighup },
            .mask = std.mem.zeroes(std.posix.sigset_t),
            .flags = 0,
        };
        std.posix.sigaction(std.posix.SIG.HUP, &act, null);
    }

    // Determine config source for initial load and future reloads
    const cfg_source: reload.ConfigSource = if (build_options.uci_mode) .uci else .json;
    const cfg_path: ?[]const u8 = if (build_options.uci_mode) null else parseConfigFile(args) catch |err| {
        std.log.err("Failed to parse config file argument: {any}", .{err});
        return err;
    };

    // 加载配置
    const result = try loadConfigFrom(allocator, cfg_source, cfg_path);

    defer file_log.deinitGlobalFileLogger();

    // RuntimeController takes ownership of the live config and every project
    // handle. Reload and UBUS only receive its explicit APIs.
    var runtime = try RuntimeController.init(allocator, result);
    defer runtime.deinit();

    reload.init(allocator, &runtime, cfg_source, cfg_path);
    defer reload.deinit();

    @import("impl/app_forward/forwarder_runtime.zig").logBackendVersion();
    std.log.info("PortWeaver starting with {d} project(s)...", .{runtime.projectCount()});
    if (build_options.frpc_mode) {
        std.log.info("FRPC client mode enabled (build flag)", .{});
    }
    if (build_options.frps_mode) {
        std.log.info("FRPS server mode enabled (build flag)", .{});
    }
    if (build_options.nftables_mode) {
        std.log.info("nftables mode enabled (build flag)", .{});
    }

    // 应用配置并启动服务
    const has_app_forward = try runtime.start();

    if (build_options.ubus_mode) {
        ubus_server.start(allocator, &runtime) catch |err| {
            std.log.warn("Failed to start ubus server: {any}", .{err});
        };
        defer ubus_server.stop();
    }

    std.log.info("PortWeaver started successfully.", .{});

    // 保持程序运行（如果有应用层转发或 UBUS 服务）
    if (has_app_forward or build_options.ubus_mode or rathole_enabled) {
        const service_type = if (has_app_forward) "Application layer forwarding" else "UBUS server";
        std.log.info("{s} is running. Press Ctrl+C to stop.\n", .{service_type});

        while (true) {
            const event = process_lock.waitForEvent();
            switch (event) {
                .shutdown => {
                    if (process_lock.shouldExitForTakeover()) {
                        std.log.info("PortWeaver takeover requested. Stopping services cleanly...", .{});
                    }
                    break;
                },
                .reload => {
                    std.log.info("Configuration reload requested...", .{});
                    reload.apply();
                },
            }
        }
    }
}
/// 根据配置源类型加载配置
fn loadConfigFrom(allocator: std.mem.Allocator, source: reload.ConfigSource, path: ?[]const u8) !config.Config {
    if (build_options.uci_mode and source == .uci) {
        std.log.info("Loading configuration from UCI...", .{});
        var uci_ctx = try uci.UciContext.alloc();
        defer uci_ctx.free();
        return config.loadFromUci(allocator, uci_ctx, "portweaver");
    } else if (source == .json) {
        const config_file = path orelse "config.json";
        std.log.info("Loading configuration from JSON file: {s}", .{config_file});
        return config.loadFromJsonFile(allocator, config_file);
    } else {
        return config.ConfigError.UnsupportedFeature;
    }
}

/// 解析命令行参数中的配置文件路径
fn parseConfigFile(args: []const []const u8) ![]const u8 {
    for (args[1..], 1..) |arg, i| {
        if (std.mem.eql(u8, arg, "-c")) {
            if (i + 1 < args.len) {
                return args[i + 1];
            }
            std.log.err("-c option requires a config file path", .{});
            return error.MissingConfigFile;
        }
    }

    // 如果没有指定配置文件，使用默认路径
    std.log.info("No config file specified, using default: config.json", .{});
    return "config.json";
}
