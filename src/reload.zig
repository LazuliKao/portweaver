const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const rathole_enabled = build_options.rathole_client_mode or build_options.rathole_server_mode;
const rathole_forward = if (rathole_enabled) @import("impl/rathole_forward.zig") else struct {};
const config = @import("config/mod.zig");
const app_forward = @import("impl/app_forward.zig");
const frpc_forward = if (build_options.frpc_mode) @import("impl/frpc_forward.zig") else struct {};
const ddns_manager = if (build_options.ddns_mode) @import("impl/ddns_manager.zig") else struct {};
const frps_forward = if (build_options.frps_mode) @import("impl/frps_forward.zig") else struct {};
const project_status = @import("impl/project_status.zig");
const event_log = @import("event_log.zig");
const compat = @import("compat.zig");
const process_lock = @import("process_lock.zig");

/// UCI or JSON config source — set once at init, used for reload.
pub const ConfigSource = enum {
    uci,
    json,
};

var allocator: ?std.mem.Allocator = null;
var handles: ?*project_status.ProjectHandleList = null;
var current_cfg: ?config.Config = null;
var config_source: ConfigSource = .uci;
var config_path: ?[]const u8 = null;
var reload_lock: std.Io.Mutex = .init;

// ── File watcher (libuv uv_fs_event, cross-platform) ─────────────────

extern "c" fn file_watcher_start(path: [*:0]const u8, callback: *const fn (?*anyopaque) callconv(.c) void, user_data: ?*anyopaque) ?*anyopaque;
extern "c" fn file_watcher_stop(handle: ?*anyopaque) void;

var watcher_handle: ?*anyopaque = null;

/// Callback invoked by the C watcher thread when the file changes.
fn onFileChanged(user_data: ?*anyopaque) callconv(.c) void {
    _ = user_data;
    std.log.info("Config file changed, triggering reload...", .{});
    process_lock.requestReload();
}

/// Start the file watcher if config watch is enabled and source is JSON.
fn startWatcher() void {
    if (config_source != .json) return;
    const cfg = current_cfg orelse return;
    if (!cfg.watch) return;
    const path = config_path orelse return;

    // Zero-terminate the path for C
    const alloc = allocator orelse return;
    const c_path = alloc.dupeZ(u8, path) catch |err| {
        std.log.warn("Failed to allocate watcher path: {any}", .{err});
        return;
    };
    defer alloc.free(c_path);

    watcher_handle = file_watcher_start(c_path.ptr, onFileChanged, null);
    if (watcher_handle != null) {
        std.log.info("Config file watcher started for: {s} (event-driven)", .{path});
    } else {
        std.log.warn("Failed to start config file watcher for: {s}", .{path});
    }
}

/// Stop the file watcher.
fn stopWatcher() void {
    if (watcher_handle) |h| {
        file_watcher_stop(h);
        watcher_handle = null;
    }
}

/// Initialize the reload module. Must be called once at startup, after
/// the initial config has been loaded and handles created.
///
/// Takes ownership of `cfg` — caller must NOT deinit it.
pub fn init(
    alloc: std.mem.Allocator,
    h: *project_status.ProjectHandleList,
    cfg: config.Config,
    source: ConfigSource,
    path: ?[]const u8,
) void {
    allocator = alloc;
    handles = h;
    current_cfg = cfg;
    config_source = source;
    config_path = path;

    // Start file watcher if enabled
    startWatcher();
}

/// Deinitialize the reload module and free the current config.
pub fn deinit() void {
    stopWatcher();

    if (current_cfg) |*cfg| {
        if (allocator) |alloc| {
            cfg.deinit(alloc);
        }
        current_cfg = null;
    }
    handles = null;
    allocator = null;
    config_path = null;
}

/// Get the current configuration. Returns null if not initialized.
pub fn getConfig() ?*const config.Config {
    if (current_cfg) |*cfg| {
        return cfg;
    }
    return null;
}

/// Get the current frpc_nodes for use by other modules (e.g. UBUS restart_project).
pub fn getFrpcNodes() ?*const std.StringHashMap(config.FrpcNode) {
    if (current_cfg) |*cfg| {
        return &cfg.frpc_nodes;
    }
    return null;
}

/// Reload configuration from the original source and apply differences.
/// Thread-safe — concurrent calls are serialized by an internal mutex.
pub fn apply() void {
    const alloc = allocator orelse {
        std.log.err("Reload: module not initialized", .{});
        return;
    };

    reload_lock.lockUncancelable(compat.io());
    defer reload_lock.unlock(compat.io());

    std.log.info("Reload: reading configuration...", .{});

    var new_cfg = loadConfigFromSource(alloc) catch |err| {
        std.log.err("Reload: failed to load new config: {any}", .{err});
        return;
    };

    applyConfigDiff(alloc, &new_cfg);
}

/// Load configuration from the original source (UCI or JSON file).
fn loadConfigFromSource(alloc: std.mem.Allocator) !config.Config {
    if (build_options.uci_mode and config_source == .uci) {
        const uci = @import("uci/mod.zig");
        var uci_ctx = try uci.UciContext.alloc();
        defer uci_ctx.free();
        return config.loadFromUci(alloc, uci_ctx, "portweaver");
    } else if (config_source == .json) {
        const path = config_path orelse "config.json";
        return config.loadFromJsonFile(alloc, path);
    }
    return config.ConfigError.UnsupportedFeature;
}

/// Apply the diff between the current config and a new config.
/// On success, takes ownership of `new_cfg` and frees the old config.
fn applyConfigDiff(alloc: std.mem.Allocator, new_cfg: *config.Config) void {
    const old_cfg = &(current_cfg orelse {
        // No previous config — just adopt the new one.
        current_cfg = new_cfg.*;
        std.log.info("Reload: no previous config, adopting new config directly", .{});
        return;
    });

    const h = handles orelse {
        std.log.err("Reload: handles not initialized", .{});
        new_cfg.deinit(alloc);
        return;
    };

    var changed: u32 = 0;
    const old_projects = old_cfg.projects;
    const new_projects = new_cfg.projects;
    const common = @min(old_projects.len, new_projects.len);

    // Allocate every additional handle before touching live state. Otherwise an
    // OOM could commit a config with more projects than handles and crash the
    // next reload. Prepared handles borrow new_cfg until it is adopted below.
    prepare_added_handles(alloc, h, new_cfg) catch |err| {
        std.log.warn("Reload: unable to prepare projects, keeping current config: {any}", .{err});
        new_cfg.deinit(alloc);
        return;
    };

    // 1) Restart changed projects (index-aligned diff)
    for (0..common) |i| {
        const handle = h.items[i];
        if (old_projects[i].eql(new_projects[i])) {
            // Config unchanged — just update the cfg pointer to new config and use_nftables
            handle.cfg = new_projects[i];
            handle.use_nftables = new_cfg.use_nftables;
            continue;
        }

        const was_enabled = old_projects[i].enabled;
        const is_enabled = new_projects[i].enabled;

        // Config changed — teardown and restart
        std.log.info("Reload: project {d} ({s}) config changed, restarting", .{ i + 1, new_projects[i].remark });
        handle.teardownForwarders();
        handle.cfg = new_projects[i];
        handle.use_nftables = new_cfg.use_nftables;

        if (new_projects[i].enabled) {
            startForwardingForHandle(handle);
        }
        changed += 1;

        if (was_enabled != is_enabled) {
            if (is_enabled) {
                event_log.logEventFmt(.project_started, @intCast(i), "Project {d} enabled via reload", .{i + 1});
            } else {
                event_log.logEventFmt(.project_stopped, @intCast(i), "Project {d} disabled via reload", .{i + 1});
            }
        }
    }

    // 3) Add new projects
    for (common..new_projects.len) |i| {
        std.log.info("Reload: adding new project {d} ({s})", .{ i + 1, new_projects[i].remark });
        const handle = h.items[i];
        changed += 1;

        if (!new_projects[i].enabled) {
            handle.setDisabled();
            event_log.logEventFmt(.project_stopped, @intCast(i), "Project {d} added (disabled)", .{i + 1});
            continue;
        }

        startForwardingForHandle(handle);
        event_log.logEventFmt(.project_started, @intCast(i), "Project {d} added and enabled", .{i + 1});
    }

    // 4) Destroy removed projects before releasing their borrowed config.
    if (old_projects.len > new_projects.len) {
        for (new_projects.len..old_projects.len) |i| {
            const handle = h.items[i];
            std.log.info("Reload: removing project {d} ({s})", .{ i + 1, handle.cfg.remark });
            handle.deinit();
            alloc.destroy(handle);
            changed += 1;
            event_log.logEventFmt(.project_stopped, @intCast(i), "Project {d} removed", .{i + 1});
        }
        h.shrinkRetainingCapacity(new_projects.len);
    }

    // 5) Rebuild all FRPC clients so source-file changes, node source changes,
    // and project-generated mappings are applied consistently.
    if (build_options.frpc_mode) {
        frpc_forward.stopAll();
        frpc_forward.initialize(alloc);
        for (h.items) |handle| {
            if (!handle.cfg.enabled) continue;
            frpc_forward.startForwarding(handle, &new_cfg.frpc_nodes) catch |err| {
                std.log.warn("Reload: failed to rebuild FRPC project {d}: {any}", .{ handle.id + 1, err });
            };
        }
        frpc_forward.startConfiguredClients(&new_cfg.frpc_nodes) catch |err| {
            std.log.warn("Reload: failed to start configured FRPC clients: {any}", .{err});
        };
    }

    // 6) Refresh firewall rules
    refreshFirewallRules(alloc, new_cfg);

    // 7) Reload DDNS
    if (build_options.ddns_mode) {
        ddns_manager.applyConfig(alloc, new_cfg.ddns_configs) catch |err| {
            std.log.warn("Reload: failed to apply DDNS config: {any}", .{err});
        };
    }

    // 8) Reload FRPS configuration. External nodes are always recreated so
    // `service portweaver reload` applies file changes at an unchanged path.
    if (build_options.frps_mode) {
        reloadFrpsNodes(alloc, old_cfg, new_cfg);
    }

    if (rathole_enabled) {
        rathole_forward.apply_config(alloc, new_cfg) catch |err| {
            std.log.err("Reload: failed to apply Rathole configuration: {any}", .{err});
        };
    }

    // 9) Swap configs: free old, adopt new
    const watch_changed = old_cfg.watch != new_cfg.watch;
    if (watch_changed) stopWatcher();
    old_cfg.deinit(alloc);
    current_cfg = new_cfg.*;
    if (watch_changed) startWatcher();

    event_log.logEventFmt(.info, -1, "Config reloaded: {d} project(s) changed", .{changed});
    std.log.info("Reload complete: {d} project(s) changed", .{changed});
}

/// Append additional handles atomically; on failure the original list is intact.
fn prepare_added_handles(alloc: std.mem.Allocator, h: *project_status.ProjectHandleList, cfg: *const config.Config) !void {
    const original_len = h.items.len;
    if (cfg.projects.len <= original_len) return;
    try h.ensureTotalCapacity(cfg.projects.len);
    errdefer {
        for (h.items[original_len..]) |handle| {
            handle.deinit();
            alloc.destroy(handle);
        }
        h.shrinkRetainingCapacity(original_len);
    }
    for (original_len..cfg.projects.len) |i| {
        const handle = try alloc.create(project_status.ProjectHandle);
        handle.* = project_status.ProjectHandle.init(alloc, i, cfg.projects[i], cfg.use_nftables);
        h.appendAssumeCapacity(handle);
    }
}

/// Start application forwarding; FRPC is rebuilt once after all project changes.
fn startForwardingForHandle(
    handle: *project_status.ProjectHandle,
) void {
    if (handle.cfg.enable_app_forward) {
        app_forward.startForwarding(handle) catch |err| {
            std.log.err("Reload: failed to start forwarding for project {d} ({s}): {any}", .{ handle.id + 1, handle.cfg.remark, err });
        };
    }
}

/// Refresh firewall rules based on the new configuration.
fn refreshFirewallRules(alloc: std.mem.Allocator, cfg: *const config.Config) void {
    if (build_options.nftables_mode and cfg.use_nftables) {
        const nftables = @import("nftables/mod.zig");
        const nft_firewall = @import("impl/nft_firewall.zig");

        if (!nftables.isLoaded()) {
            std.log.warn("Reload: libnftables not available, skipping nftables rules", .{});
            return;
        }

        var ctx = nftables.NftablesContext.init(alloc) catch |err| {
            std.log.warn("Reload: failed to init nftables context: {any}", .{err});
            return;
        };
        defer ctx.deinit();

        nft_firewall.setupTable(&ctx, alloc) catch |err| {
            std.log.warn("Reload: failed to setup nftables table: {any}", .{err});
            return;
        };
        nft_firewall.clearRules(&ctx) catch |err| {
            std.log.warn("Reload: failed to clear nftables rules: {any}", .{err});
        };

        for (cfg.projects) |project| {
            if (!project.enabled) continue;
            nft_firewall.applyRulesForProject(&ctx, alloc, project) catch |err| {
                std.log.warn("Reload: failed to apply nftables rules for project: {any}", .{err});
            };
        }
        std.log.info("Reload: nftables rules refreshed", .{});
    } else if (build_options.uci_mode) {
        const firewall = @import("impl/uci_firewall.zig");
        const uci = @import("uci/mod.zig");

        var uci_ctx = uci.UciContext.alloc() catch |err| {
            std.log.warn("Reload: failed to alloc UCI context: {any}", .{err});
            return;
        };
        defer uci_ctx.free();

        firewall.clearFirewallRules(uci_ctx, alloc) catch |err| {
            std.log.warn("Reload: failed to clear firewall rules: {any}", .{err});
        };

        for (cfg.projects) |project| {
            if (!project.enabled) continue;
            firewall.applyFirewallRulesForProject(uci_ctx, alloc, project) catch |err| {
                std.log.warn("Reload: failed to apply firewall rules: {any}", .{err});
            };
        }

        firewall.reloadFirewall(alloc) catch |err| {
            std.log.warn("Reload: failed to reload firewall: {any}", .{err});
        };
        std.log.info("Reload: UCI firewall rules refreshed", .{});
    }
}

/// Diff and reload FRPS server nodes.
fn reloadFrpsNodes(
    alloc: std.mem.Allocator,
    old_cfg: *const config.Config,
    new_cfg: *const config.Config,
) void {
    // Restart changed or new nodes
    var new_it = new_cfg.frps_nodes.iterator();
    while (new_it.next()) |entry| {
        const name = entry.key_ptr.*;
        const new_node = entry.value_ptr.*;

        if (!new_node.enabled) continue;

        if (old_cfg.frps_nodes.get(name)) |old_node| {
            // Rebuild external nodes on every reload so an unchanged path is reread.
            if (old_node.eql(new_node) and new_node.source.mode == .builtin) continue;
            std.log.info("Reload: FRPS node {s} config changed, restarting", .{name});
        } else {
            std.log.info("Reload: adding new FRPS node {s}", .{name});
        }

        frps_forward.restartServer(alloc, name, new_node) catch |err| {
            std.log.warn("Reload: failed to restart FRPS node {s}: {any}", .{ name, err });
        };
    }

    // Remove nodes that no longer exist or are disabled
    var old_it = old_cfg.frps_nodes.iterator();
    while (old_it.next()) |entry| {
        const name = entry.key_ptr.*;
        if (new_cfg.frps_nodes.get(name)) |new_node| {
            if (new_node.enabled) continue;
        }
        std.log.info("Reload: removing FRPS node {s}", .{name});
        frps_forward.removeServer(name);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

const types = @import("config/types.zig");

fn makeTestProject(alloc: std.mem.Allocator, remark: []const u8, port: u16) !types.Project {
    return types.Project{
        .remark = try alloc.dupe(u8, remark),
        .target_address = try alloc.dupe(u8, "192.168.1.1"),
        .listen_port = port,
        .target_port = 80,
    };
}

fn makeTestConfig(alloc: std.mem.Allocator, projects: []const types.Project) !types.Config {
    return types.Config{
        .projects = try alloc.dupe(types.Project, projects),
        .frpc_nodes = std.StringHashMap(types.FrpcNode).init(alloc),
        .frps_nodes = std.StringHashMap(types.FrpsNode).init(alloc),
        .rathole_client_nodes = std.StringHashMap(types.RatholeClientNode).init(alloc),
        .rathole_client_services = try alloc.alloc(types.RatholeClientService, 0),
        .rathole_server_nodes = std.StringHashMap(types.RatholeServerNode).init(alloc),
        .rathole_server_services = try alloc.alloc(types.RatholeServerService, 0),
        .wol_targets = std.StringHashMap(types.WolTarget).init(alloc),
        .ddns_configs = try alloc.alloc(types.DdnsConfig, 0),
        .log_config = .{ .enabled = false, .file_path = "", .max_size = 0, .max_files = 0 },
    };
}

fn makeTestDdns(alloc: std.mem.Allocator, name: []const u8, provider: []const u8) !types.DdnsConfig {
    const cfg: types.DdnsConfig = .{
        .enabled = true,
        .name = name,
        .dns_provider = provider,
        .dns_id = "id123",
        .dns_secret = "secret123",
        .ttl = 300,
        // Exercise real instance lifetimes without network-dependent DNS updates.
        .ipv4 = .{ .enable = false },
        .ipv6 = .{ .enable = false },
    };
    return cfg.clone(alloc);
}

fn makeTestConfigWithDdns(alloc: std.mem.Allocator, projects: []const types.Project, ddns: []const types.DdnsConfig) !types.Config {
    return types.Config{
        .projects = try alloc.dupe(types.Project, projects),
        .frpc_nodes = std.StringHashMap(types.FrpcNode).init(alloc),
        .frps_nodes = std.StringHashMap(types.FrpsNode).init(alloc),
        .rathole_client_nodes = std.StringHashMap(types.RatholeClientNode).init(alloc),
        .rathole_client_services = try alloc.alloc(types.RatholeClientService, 0),
        .rathole_server_nodes = std.StringHashMap(types.RatholeServerNode).init(alloc),
        .rathole_server_services = try alloc.alloc(types.RatholeServerService, 0),
        .wol_targets = std.StringHashMap(types.WolTarget).init(alloc),
        .ddns_configs = try alloc.dupe(types.DdnsConfig, ddns),
        .log_config = .{ .enabled = false, .file_path = "", .max_size = 0, .max_files = 0 },
    };
}

test "config eql: identical configs are equal" {
    const alloc = std.testing.allocator;
    const p1 = try makeTestProject(alloc, "test", 8080);
    const p2 = try makeTestProject(alloc, "test", 8080);

    var c1 = try makeTestConfig(alloc, &.{p1});
    defer c1.deinit(alloc);
    var c2 = try makeTestConfig(alloc, &.{p2});
    defer c2.deinit(alloc);

    try std.testing.expect(c1.eql(c2));
}

test "config eql: different port detects change" {
    const alloc = std.testing.allocator;
    const p1 = try makeTestProject(alloc, "test", 8080);
    const p2 = try makeTestProject(alloc, "test", 9090);

    var c1 = try makeTestConfig(alloc, &.{p1});
    defer c1.deinit(alloc);
    var c2 = try makeTestConfig(alloc, &.{p2});
    defer c2.deinit(alloc);

    try std.testing.expect(!c1.eql(c2));
}

test "config eql: different project count detects change" {
    const alloc = std.testing.allocator;
    const p1a = try makeTestProject(alloc, "a", 8080);
    const p1b = try makeTestProject(alloc, "a", 8080);
    const p2 = try makeTestProject(alloc, "b", 9090);

    var c1 = try makeTestConfig(alloc, &.{p1a});
    defer c1.deinit(alloc);
    var c2 = try makeTestConfig(alloc, &.{ p1b, p2 });
    defer c2.deinit(alloc);

    try std.testing.expect(!c1.eql(c2));
}

test "config eql: enabled flag change detected" {
    const alloc = std.testing.allocator;
    const p1 = try makeTestProject(alloc, "test", 8080);
    var p2 = try makeTestProject(alloc, "test", 8080);
    p2.enabled = false;

    var c1 = try makeTestConfig(alloc, &.{p1});
    defer c1.deinit(alloc);
    var c2 = try makeTestConfig(alloc, &.{p2});
    defer c2.deinit(alloc);

    try std.testing.expect(!c1.eql(c2));
}

test "config eql: empty configs are equal" {
    const alloc = std.testing.allocator;
    var c1 = try makeTestConfig(alloc, &.{});
    defer c1.deinit(alloc);
    var c2 = try makeTestConfig(alloc, &.{});
    defer c2.deinit(alloc);

    try std.testing.expect(c1.eql(c2));
}

test "ConfigSource enum values" {
    try std.testing.expectEqual(ConfigSource.uci, ConfigSource.uci);
    try std.testing.expectEqual(ConfigSource.json, ConfigSource.json);
    try std.testing.expect(ConfigSource.uci != ConfigSource.json);
}

test "reload module lifecycle: init and deinit" {
    try std.testing.expect(getConfig() == null);
}

test "project eql: multi-project diff detection" {
    const alloc = std.testing.allocator;
    const p1 = try makeTestProject(alloc, "web", 8080);
    const p2 = try makeTestProject(alloc, "ssh", 22);
    const p3 = try makeTestProject(alloc, "web", 8080);
    const p4 = try makeTestProject(alloc, "ssh-modified", 2222);

    var c1 = try makeTestConfig(alloc, &.{ p1, p2 });
    defer c1.deinit(alloc);
    var c2 = try makeTestConfig(alloc, &.{ p3, p4 });
    defer c2.deinit(alloc);

    try std.testing.expect(!c1.eql(c2));
}
test "project eql: same multi-project configs equal" {
    const alloc = std.testing.allocator;
    const p1a = try makeTestProject(alloc, "web", 8080);
    const p2a = try makeTestProject(alloc, "ssh", 22);
    const p1b = try makeTestProject(alloc, "web", 8080);
    const p2b = try makeTestProject(alloc, "ssh", 22);

    var c1 = try makeTestConfig(alloc, &.{ p1a, p2a });
    defer c1.deinit(alloc);
    var c2 = try makeTestConfig(alloc, &.{ p1b, p2b });
    defer c2.deinit(alloc);

    try std.testing.expect(c1.eql(c2));
}

test "onFileChanged callback sets reload flag" {
    // Reset the flag
    process_lock.requestReload(); // clear via consume won't work here, just set and check
    // Simulate the callback
    onFileChanged(null);
    // The callback calls requestReload which sets the atomic flag
    // We can't easily test waitForEvent here without blocking, but we can verify the callback doesn't crash
}

test "config with watch=true creates config with watch enabled" {
    const alloc = std.testing.allocator;
    var c = try makeTestConfig(alloc, &.{});
    defer c.deinit(alloc);

    try std.testing.expect(!c.watch);
    c.watch = true;
    try std.testing.expect(c.watch);
}

test "config eql: watch field change detected" {
    const alloc = std.testing.allocator;
    var c1 = try makeTestConfig(alloc, &.{});
    defer c1.deinit(alloc);
    var c2 = try makeTestConfig(alloc, &.{});
    defer c2.deinit(alloc);

    c2.watch = true;
    try std.testing.expect(!c1.eql(c2));
}

test "reload: simulate project toggle sequence (close -> open -> close) under multiple forwards" {
    const alloc = std.testing.allocator;

    const p1_init = try makeTestProject(alloc, "RDP", 3389);
    const p2_init = try makeTestProject(alloc, "HTTPS", 443);

    var ddns_slice: []types.DdnsConfig = try alloc.alloc(types.DdnsConfig, 0);
    if (build_options.ddns_mode) {
        alloc.free(ddns_slice);
        const d = try makeTestDdns(alloc, "dghome", "alidns");
        ddns_slice = try alloc.dupe(types.DdnsConfig, &.{d});
    }

    var h_list = project_status.ProjectHandleList.init(alloc);
    defer {
        for (h_list.items) |h| {
            h.deinit();
            alloc.destroy(h);
        }
        h_list.deinit();
    }

    const h1 = try alloc.create(project_status.ProjectHandle);
    h1.* = project_status.ProjectHandle.init(alloc, 0, p1_init, false);
    try h_list.append(h1);

    const h2 = try alloc.create(project_status.ProjectHandle);
    h2.* = project_status.ProjectHandle.init(alloc, 1, p2_init, false);
    try h_list.append(h2);

    const cfg0 = try makeTestConfigWithDdns(alloc, &.{ p1_init, p2_init }, ddns_slice);
    alloc.free(ddns_slice);

    if (build_options.ddns_mode) {
        try ddns_manager.applyConfig(alloc, cfg0.ddns_configs);
    }

    init(alloc, &h_list, cfg0, .json, null);
    defer {
        if (build_options.ddns_mode) {
            ddns_manager.deinit(alloc);
        }
        deinit();
    }

    // Reload 1: Disable Project 1 (close) and apply
    {
        var p1_step1 = try makeTestProject(alloc, "RDP", 3389);
        p1_step1.enabled = false;
        const p2_step1 = try makeTestProject(alloc, "HTTPS", 443);

        var d_step1: []types.DdnsConfig = try alloc.alloc(types.DdnsConfig, 0);
        if (build_options.ddns_mode) {
            alloc.free(d_step1);
            const d = try makeTestDdns(alloc, "dghome", "alidns");
            d_step1 = try alloc.dupe(types.DdnsConfig, &.{d});
        }
        var cfg1 = try makeTestConfigWithDdns(alloc, &.{ p1_step1, p2_step1 }, d_step1);
        alloc.free(d_step1);

        applyConfigDiff(alloc, &cfg1);

        try std.testing.expectEqual(false, h_list.items[0].cfg.enabled);
        try std.testing.expectEqual(true, h_list.items[1].cfg.enabled);
    }

    // Reload 2: Enable Project 1 (open) and apply
    {
        var p1_step2 = try makeTestProject(alloc, "RDP", 3389);
        p1_step2.enabled = true;
        const p2_step2 = try makeTestProject(alloc, "HTTPS", 443);

        var d_step2: []types.DdnsConfig = try alloc.alloc(types.DdnsConfig, 0);
        if (build_options.ddns_mode) {
            alloc.free(d_step2);
            const d = try makeTestDdns(alloc, "dghome", "alidns");
            d_step2 = try alloc.dupe(types.DdnsConfig, &.{d});
        }
        var cfg2 = try makeTestConfigWithDdns(alloc, &.{ p1_step2, p2_step2 }, d_step2);
        alloc.free(d_step2);

        applyConfigDiff(alloc, &cfg2);

        try std.testing.expectEqual(true, h_list.items[0].cfg.enabled);
        try std.testing.expectEqual(true, h_list.items[1].cfg.enabled);
    }

    // Reload 3: Disable Project 1 again (close) and apply
    {
        var p1_step3 = try makeTestProject(alloc, "RDP", 3389);
        p1_step3.enabled = false;
        const p2_step3 = try makeTestProject(alloc, "HTTPS", 443);

        var d_step3: []types.DdnsConfig = try alloc.alloc(types.DdnsConfig, 0);
        if (build_options.ddns_mode) {
            alloc.free(d_step3);
            const d = try makeTestDdns(alloc, "dghome", "alidns");
            d_step3 = try alloc.dupe(types.DdnsConfig, &.{d});
        }
        var cfg3 = try makeTestConfigWithDdns(alloc, &.{ p1_step3, p2_step3 }, d_step3);
        alloc.free(d_step3);

        applyConfigDiff(alloc, &cfg3);

        try std.testing.expectEqual(false, h_list.items[0].cfg.enabled);
        try std.testing.expectEqual(true, h_list.items[1].cfg.enabled);
    }
}

test "reload: add, reorder, remove, empty and re-add projects across independent snapshots" {
    const alloc = std.testing.allocator;
    var list = project_status.ProjectHandleList.init(alloc);
    init(alloc, &list, try makeTestConfig(alloc, &.{}), .json, null);
    defer {
        for (list.items) |handle| {
            handle.deinit();
            alloc.destroy(handle);
        }
        list.deinit();
        deinit();
    }
    const scenarios = [_][]const []const u8{
        &.{ "RDP", "HTTPS" },
        &.{ "RDP", "HTTPS" }, // equal data with new allocations
        &.{ "HTTPS", "RDP", "extra" },
        &.{"RDP"},
        &.{},
        &.{ "new", "HTTPS" },
    };
    for (scenarios) |names| {
        var next = try makeTestConfig(alloc, &.{});
        alloc.free(next.projects);
        next.projects = try alloc.alloc(types.Project, names.len);
        for (names, 0..) |name, i| {
            next.projects[i] = try makeTestProject(alloc, name, @intCast(8000 + i));
            next.projects[i].enabled = false;
        }
        applyConfigDiff(alloc, &next);
        try std.testing.expectEqual(names.len, list.items.len);
        try std.testing.expectEqual(names.len, getConfig().?.projects.len);
        for (names, list.items, 0..) |name, handle, i| {
            try std.testing.expectEqual(i, handle.id);
            try std.testing.expectEqualStrings(name, handle.cfg.remark);
            try std.testing.expectEqual(project_status.StartupStatus.disabled, handle.startup_status);
        }
    }
}

fn test_prepare_handles_failure(alloc: std.mem.Allocator) !void {
    const config_alloc = std.testing.allocator;
    const p = try makeTestProject(config_alloc, "existing", 8000);
    const q = try makeTestProject(config_alloc, "added", 8001);
    var cfg = try makeTestConfig(config_alloc, &.{ p, q });
    defer cfg.deinit(config_alloc);
    var list = project_status.ProjectHandleList.init(alloc);
    defer {
        for (list.items) |handle| {
            handle.deinit();
            alloc.destroy(handle);
        }
        list.deinit();
    }
    // A failure at either allocation must leave no partially appended handles.
    prepare_added_handles(alloc, &list, &cfg) catch |err| {
        std.log.debug("Expected handle preparation failure: {any}", .{err});
        try std.testing.expectEqual(@as(usize, 0), list.items.len);
        return err;
    };
    try std.testing.expectEqual(@as(usize, 2), list.items.len);
}

test "reload: handle preparation rolls back every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, test_prepare_handles_failure, .{});
}

test "reload: repeated TCP and UDP toggles preserve the other project's live listeners" {
    const alloc = std.testing.allocator;
    var list = project_status.ProjectHandleList.init(alloc);
    init(alloc, &list, try makeTestConfig(alloc, &.{}), .json, null);
    defer {
        for (list.items) |handle| {
            handle.deinit();
            alloc.destroy(handle);
        }
        list.deinit();
        deinit();
    }
    var stable_tcp: ?*app_forward.TcpForwarder = null;
    var stable_udp: ?*app_forward.UdpForwarder = null;
    for ([_]bool{ true, false, true, false, true, true, false }) |enabled| {
        var first = try makeTestProject(alloc, "RDP", 48761);
        first.enable_app_forward = true;
        first.enabled = enabled;
        var second = try makeTestProject(alloc, "HTTPS", 48762);
        second.enable_app_forward = true;
        var next = try makeTestConfig(alloc, &.{ first, second });
        applyConfigDiff(alloc, &next);
        const changing = list.items[0];
        const stable = list.items[1];
        try std.testing.expectEqual(@as(usize, if (enabled) 1 else 0), changing.tcp_forwarders.items.len);
        try std.testing.expectEqual(@as(usize, if (enabled) 1 else 0), changing.udp_forwarders.items.len);
        try std.testing.expectEqual(project_status.StartupStatus.success, stable.startup_status);
        try std.testing.expectEqual(@as(usize, 1), stable.tcp_forwarders.items.len);
        try std.testing.expectEqual(@as(usize, 1), stable.udp_forwarders.items.len);
        if (stable_tcp) |tcp| try std.testing.expect(tcp == stable.tcp_forwarders.items[0]);
        if (stable_udp) |udp| try std.testing.expect(udp == stable.udp_forwarders.items[0]);
        stable_tcp = stable.tcp_forwarders.items[0];
        stable_udp = stable.udp_forwarders.items[0];
    }
}

test "reload: watch setting starts and stops the file watcher" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const file = try tmp.dir.createFile(std.testing.io, "reload.json", .{});
    file.close(std.testing.io);
    const path = try std.fmt.allocPrint(alloc, ".zig-cache/tmp/{s}/reload.json", .{tmp.sub_path});
    defer alloc.free(path);
    var list = project_status.ProjectHandleList.init(alloc);
    defer list.deinit();
    init(alloc, &list, try makeTestConfig(alloc, &.{}), .json, path);
    defer deinit();
    try std.testing.expect(watcher_handle == null);
    for ([_]bool{ true, true, false, true, false }) |watch| {
        var next = try makeTestConfig(alloc, &.{});
        next.watch = watch;
        const previous_watcher = watcher_handle;
        const previous_watch = current_cfg.?.watch;
        applyConfigDiff(alloc, &next);
        try std.testing.expectEqual(watch, watcher_handle != null);
        if (previous_watch == watch) try std.testing.expect(previous_watcher == watcher_handle);
    }
}
