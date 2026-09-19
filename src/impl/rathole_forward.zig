const std = @import("std");
const options = @import("build_options");
const config = @import("../config/types.zig");
const compat = @import("../compat.zig");
const lib = @import("librathole.zig");
const config_file = @import("frp_config_file.zig");

pub const Mode = enum { client, server };
pub const Status = struct {
    id: i32,
    name: []const u8,
    mode: []const u8,
    state: []const u8,
    last_error: []const u8,
};
const Holder = struct { name: []const u8, mode: Mode, instance: lib.Instance };
// The lock protects lifecycle operations and RPC reads. Names are owned by owner.
var lock: std.Io.Mutex = .init;
var instances: std.ArrayList(Holder) = .empty;
var owner: ?std.mem.Allocator = null;

fn quoted(writer: *std.Io.Writer, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        0...8, 11, 12, 14...31, 127 => try writer.print("\\u{X:0>4}", .{@as(u16, byte)}),
        else => try writer.writeByte(byte),
    };
    try writer.writeByte('"');
}

fn field(writer: *std.Io.Writer, key: []const u8, value: []const u8) !void {
    try writer.print("{s} = ", .{key});
    try quoted(writer, value);
    try writer.writeByte('\n');
}

/// Returns owned TOML; caller frees with allocator. No secrets are logged.
pub fn render_config(allocator: std.mem.Allocator, comptime mode: Mode, name: []const u8, node: anytype, services: anytype) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const writer = &output.writer;
    const section = @tagName(mode);
    try writer.print("[{s}]\n", .{section});
    if (mode == .client) try field(writer, "remote_addr", node.remote_addr) else try field(writer, "bind_addr", node.bind_addr);
    if (node.default_token.len > 0) try field(writer, "default_token", node.default_token);
    try writer.print("[{s}.transport]\n", .{section});
    try field(writer, "type", @tagName(node.transport));
    if (node.transport == .noise) {
        try writer.print("[{s}.transport.noise]\n", .{section});
        if (node.noise_local_private_key.len > 0) try field(writer, "local_private_key", node.noise_local_private_key);
        if (node.noise_remote_public_key.len > 0) try field(writer, "remote_public_key", node.noise_remote_public_key);
    }
    try writer.print("[{s}.services]\n", .{section});
    for (services) |service| {
        if (!service.enabled or !std.mem.eql(u8, service.node_name, name)) continue;
        if (service.token.len == 0 and node.default_token.len == 0) return error.MissingServiceToken;
        try writer.print("[{s}.services.", .{section});
        try quoted(writer, service.service_name);
        try writer.writeAll("]\n");
        try field(writer, "type", @tagName(service.protocol));
        if (service.token.len > 0) try field(writer, "token", service.token);
        const address = if (mode == .client) service.local_address else service.bind_address;
        const port = if (mode == .client) service.local_port else service.bind_port;
        const ipv6 = std.mem.indexOfScalar(u8, address, ':') != null and !std.mem.startsWith(u8, address, "[");
        const endpoint = if (ipv6) try std.fmt.allocPrint(allocator, "[{s}]:{d}", .{ address, port }) else try std.fmt.allocPrint(allocator, "{s}:{d}", .{ address, port });
        defer allocator.free(endpoint);
        try field(writer, if (mode == .client) "local_addr" else "bind_addr", endpoint);
    }
    return allocator.dupe(u8, output.written());
}

pub fn validate_toml_path(path: []const u8) !void {
    if (!std.mem.endsWith(u8, path, ".toml")) return error.InvalidArgument;
}

fn node_toml(allocator: std.mem.Allocator, comptime mode: Mode, root: []const u8, name: []const u8, node: anytype, services: anytype) ![]u8 {
    return switch (node.source.mode) {
        .builtin => render_config(allocator, mode, name, node, services),
        .external_file => blk: {
            try validate_toml_path(node.source.path);
            break :blk config_file.read(allocator, root, node.source.path);
        },
        .external_uci => allocator.dupe(u8, node.source.content),
    };
}

/// Validates TOML using the embedded Rathole parser. Detailed parser errors
/// require a future upstream FFI API.
pub fn validate_toml(allocator: std.mem.Allocator, mode: Mode, content: []const u8) !void {
    try config_file.validateContent(content);
    var instance = if (mode == .client)
        try lib.Instance.initClient(allocator, content, "validation")
    else
        try lib.Instance.initServer(allocator, content, "validation");
    defer instance.deinit();
}

fn start_node(allocator: std.mem.Allocator, comptime mode: Mode, root: []const u8, name: []const u8, node: anytype, services: anytype) !void {
    const toml = try node_toml(allocator, mode, root, name, node, services);
    defer allocator.free(toml);
    const owned_name = try allocator.dupe(u8, name);
    errdefer allocator.free(owned_name);
    var instance = if (mode == .client) try lib.Instance.initClient(allocator, toml, name) else try lib.Instance.initServer(allocator, toml, name);
    errdefer instance.deinit();
    try instance.start();
    try instances.append(allocator, .{ .name = owned_name, .mode = mode, .instance = instance });
}

fn stop_locked() void {
    if (owner) |allocator| {
        var index = instances.items.len;
        while (index > 0) {
            index -= 1;
            instances.items[index].instance.deinit();
            allocator.free(instances.items[index].name);
        }
        instances.deinit(allocator);
        instances = .empty;
        owner = null;
    }
}

/// Rebuilds only Rathole instances; callers serialize this with config reload.
pub fn apply_config(allocator: std.mem.Allocator, cfg: *const config.Config) !void {
    lock.lockUncancelable(compat.io());
    defer lock.unlock(compat.io());
    stop_locked();
    owner = allocator;
    errdefer stop_locked();
    if (options.rathole_server_mode) {
        var iterator = cfg.rathole_server_nodes.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.enabled) try start_node(allocator, .server, cfg.frpConfigRoot(), entry.key_ptr.*, entry.value_ptr.*, cfg.rathole_server_services);
        }
    }
    if (options.rathole_client_mode) {
        var iterator = cfg.rathole_client_nodes.iterator();
        while (iterator.next()) |entry| {
            if (entry.value_ptr.enabled) try start_node(allocator, .client, cfg.frpConfigRoot(), entry.key_ptr.*, entry.value_ptr.*, cfg.rathole_client_services);
        }
    }
}

pub fn stop_all() void {
    lock.lockUncancelable(compat.io());
    defer lock.unlock(compat.io());
    stop_locked();
}

/// Caller owns returned JSON. Running denotes task lifecycle, not connectivity.
pub fn get_status(allocator: std.mem.Allocator) ![]u8 {
    lock.lockUncancelable(compat.io());
    defer lock.unlock(compat.io());
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try output.writer.writeByte('[');
    for (instances.items, 0..) |*holder, index| {
        if (index != 0) try output.writer.writeByte(',');
        const status = try holder.instance.getStatus(allocator);
        defer allocator.free(status);
        try output.writer.writeAll(status);
    }
    try output.writer.writeByte(']');
    return allocator.dupe(u8, output.written());
}

/// Returned strings belong to allocator. Intended for a request-scoped arena.
pub fn get_info(allocator: std.mem.Allocator, mode: Mode, name: []const u8) !struct { status: []const u8, last_error: []const u8, logs: []const []const u8 } {
    lock.lockUncancelable(compat.io());
    defer lock.unlock(compat.io());
    for (instances.items) |*holder| {
        if (holder.mode != mode or !std.mem.eql(u8, holder.name, name)) continue;
        const json = try holder.instance.getStatus(allocator);
        defer allocator.free(json);
        const parsed = try std.json.parseFromSlice(Status, allocator, json, .{});
        defer parsed.deinit();
        const text = try holder.instance.getLogs(allocator);
        defer allocator.free(text);
        var logs: std.ArrayList([]const u8) = .empty;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| {
            if (line.len != 0) try logs.append(allocator, try allocator.dupe(u8, line));
        }
        return .{
            .status = try allocator.dupe(u8, parsed.value.state),
            .last_error = try allocator.dupe(u8, parsed.value.last_error),
            .logs = try logs.toOwnedSlice(allocator),
        };
    }
    return .{ .status = "stopped", .last_error = "", .logs = &.{} };
}

pub fn clear_logs(mode: Mode, name: []const u8) !void {
    lock.lockUncancelable(compat.io());
    defer lock.unlock(compat.io());
    for (instances.items) |*holder| {
        if (holder.mode == mode and std.mem.eql(u8, holder.name, name)) {
            holder.instance.clearLogs();
            return;
        }
    }
    return error.NotFound;
}

test "TOML quoting prevents service names creating sections" {
    var output: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try quoted(&output.writer, "a\"\n[b]\\");
    try std.testing.expectEqualStrings("\"a\\\"\\n[b]\\\\\"", output.written());
}

test "embedded client accepts generated TOML and repeated lifecycle" {
    const allocator = std.testing.allocator;
    defer lib.cleanup();
    const node = config.RatholeClientNode{ .remote_addr = "127.0.0.1:1", .default_token = "test-token" };
    const services = [_]config.RatholeClientService{.{
        .node_name = "test",
        .service_name = "quoted.\"service",
        .local_address = "::1",
        .local_port = 8080,
    }};
    const toml = try render_config(allocator, .client, "test", node, &services);
    defer allocator.free(toml);
    var instance = try lib.Instance.initClient(allocator, toml, "test");
    defer instance.deinit();
    for (0..3) |_| {
        try instance.start();
        try instance.stop();
        const status = try instance.getStatus(allocator);
        defer allocator.free(status);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, status, .{});
        defer parsed.deinit();
        try std.testing.expectEqualStrings("stopped", parsed.value.object.get("state").?.string);
    }
}
