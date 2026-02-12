const std = @import("std");
const types = @import("types.zig");
const helper = @import("helper.zig");

// ── JSON value helpers ──────────────────────────────────────────────────

fn jsonValueTypeName(v: std.json.Value) []const u8 {
    return switch (v) {
        .null => "null",
        .bool => "boolean",
        .integer => "integer",
        .float => "float",
        .string => "string",
        .array => "array",
        .object => "object",
        .number_string => "number_string",
    };
}

// ── Parsing helpers (operate on arena allocator) ────────────────────────

fn parseJsonBool(v: std.json.Value, field: []const u8, ec: *types.ErrorCollector) ?bool {
    return switch (v) {
        .bool => |b| b,
        .integer => |i| i != 0,
        .string => |s| types.parseBool(s) catch {
            ec.addFmt(field, .enum_value_invalid, "true/false/1/0/yes/no", "{s}", .{s}, "invalid boolean string");
            return null;
        },
        else => {
            ec.add(field, .wrong_type, "boolean, integer, or string", jsonValueTypeName(v), "cannot convert to boolean");
            return null;
        },
    };
}

fn parseJsonPort(v: std.json.Value, field: []const u8, ec: *types.ErrorCollector) ?u16 {
    return switch (v) {
        .integer => |i| {
            if (i <= 0 or i > 65535) {
                ec.addFmt(field, .out_of_range, "1-65535", "{d}", .{i}, "port out of range");
                return null;
            }
            return @intCast(i);
        },
        .string => |s| types.parsePort(s) catch {
            ec.addFmt(field, .invalid_format, "integer 1-65535", "{s}", .{s}, "invalid port value");
            return null;
        },
        else => {
            ec.add(field, .wrong_type, "integer or string", jsonValueTypeName(v), "cannot parse as port");
            return null;
        },
    };
}

fn parseJsonString(v: std.json.Value, field: []const u8, ec: *types.ErrorCollector) ?[]const u8 {
    return switch (v) {
        .string => |s| s,
        else => {
            ec.add(field, .wrong_type, "string", jsonValueTypeName(v), "expected a string value");
            return null;
        },
    };
}

/// Parse a port string that may be an integer JSON value or a string (possibly a range).
/// Returns an arena-duped string (needed because integer -> string conversion allocates).
fn parseJsonPortString(v: std.json.Value, arena: std.mem.Allocator, field: []const u8, ec: *types.ErrorCollector) ?[]const u8 {
    switch (v) {
        .integer => |i| {
            if (i <= 0 or i > 65535) {
                ec.addFmt(field, .out_of_range, "1-65535", "{d}", .{i}, "port out of range");
                return null;
            }
            const result = std.fmt.allocPrint(arena, "{d}", .{i}) catch return null;
            types.validatePortString(result) catch {
                ec.addFmt(field, .invalid_format, "port or port-range", "{s}", .{result}, "invalid port string");
                return null;
            };
            return result;
        },
        .string => |str| {
            const trimmed = std.mem.trim(u8, str, " \t\r\n");
            types.validatePortString(trimmed) catch {
                ec.addFmt(field, .invalid_format, "port or port-range (e.g. 8080 or 8080-8090)", "{s}", .{trimmed}, "invalid port string");
                return null;
            };
            return arena.dupe(u8, trimmed) catch return null;
        },
        else => {
            ec.add(field, .wrong_type, "integer or string", jsonValueTypeName(v), "cannot parse as port string");
            return null;
        },
    }
}

fn appendZoneString(list: *std.ArrayList([]const u8), arena: std.mem.Allocator, s: []const u8) !void {
    const trimmed = std.mem.trim(u8, s, " \t\r\n");
    if (trimmed.len == 0) return;
    try list.append(arena, try arena.dupe(u8, trimmed));
}

fn parseJsonZones(
    arena: std.mem.Allocator,
    v: std.json.Value,
    out: *std.ArrayList([]const u8),
    field: []const u8,
    ec: *types.ErrorCollector,
) void {
    switch (v) {
        .string => |s| appendZoneString(out, arena, s) catch {},
        .array => |a| {
            for (a.items, 0..) |item, i| {
                const f = ec.fieldPath("{s}[{d}]", .{ field, i });
                const s = parseJsonString(item, f, ec) orelse continue;
                appendZoneString(out, arena, s) catch {};
            }
        },
        else => ec.add(field, .wrong_type, "string or array of strings", jsonValueTypeName(v), "invalid zones value"),
    }
}

fn parseJsonFrpcForwards(
    arena: std.mem.Allocator,
    v: std.json.Value,
    field: []const u8,
    ec: *types.ErrorCollector,
) ?[]types.FrpcForward {
    var list: std.ArrayList(types.FrpcForward) = .empty;

    switch (v) {
        .string => |s| {
            const fwd = helper.parseFrpcForwardString(arena, s) catch {
                ec.addFmt(field, .invalid_format, "node:port", "{s}", .{s}, "invalid FRPC forward string");
                return null;
            };
            list.append(arena, fwd) catch return null;
        },
        .array => |a| {
            for (a.items, 0..) |item, i| {
                const f = ec.fieldPath("{s}[{d}]", .{ field, i });
                const fwd: types.FrpcForward = switch (item) {
                    .string => |s| helper.parseFrpcForwardString(arena, s) catch {
                        ec.addFmt(f, .invalid_format, "node:port", "{s}", .{s}, "invalid FRPC forward string");
                        continue;
                    },
                    .object => |obj| blk: {
                        const node_name_v = obj.get("node_name") orelse {
                            ec.add(ec.fieldPath("{s}.node_name", .{f}), .missing_field, "", "", "required field missing");
                            continue;
                        };
                        const remote_port_v = obj.get("remote_port") orelse {
                            ec.add(ec.fieldPath("{s}.remote_port", .{f}), .missing_field, "", "", "required field missing");
                            continue;
                        };
                        const node_name_str = parseJsonString(node_name_v, ec.fieldPath("{s}.node_name", .{f}), ec) orelse continue;
                        const remote_port = parseJsonPort(remote_port_v, ec.fieldPath("{s}.remote_port", .{f}), ec) orelse continue;
                        break :blk .{
                            .node_name = arena.dupe(u8, std.mem.trim(u8, node_name_str, " \t\r\n")) catch continue,
                            .remote_port = remote_port,
                        };
                    },
                    else => {
                        ec.add(f, .wrong_type, "string or object", jsonValueTypeName(item), "invalid FRPC forward entry");
                        continue;
                    },
                };
                list.append(arena, fwd) catch {};
            }
        },
        else => {
            ec.add(field, .wrong_type, "string or array", jsonValueTypeName(v), "invalid FRPC forwards value");
            return null;
        },
    }

    return list.toOwnedSlice(arena) catch null;
}

// ── Helper: dupe non-empty trimmed string into arena ────────────────────

fn dupeTrimmed(arena: std.mem.Allocator, s: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, s, " \t\r\n");
    if (trimmed.len == 0) return "";
    return arena.dupe(u8, trimmed) catch "";
}

// ── Main loader ─────────────────────────────────────────────────────────

/// Load and parse a JSON configuration file.
///
/// All returned data is owned by the caller's `allocator`.
/// On validation errors the function returns `ConfigError.ValidationFailed`
/// and logs the error report via `std.log.err`.
/// Use `loadFromJsonFileWithErrors` to programmatically access the errors.
pub fn loadFromJsonFile(allocator: std.mem.Allocator, path: []const u8) !types.Config {
    var ec = types.ErrorCollector.init(allocator);
    defer ec.deinit();
    return loadFromJsonFileWithErrors(allocator, path, &ec) catch |err| {
        if (err == types.ConfigError.ValidationFailed) {
            if (ec.formatReport(allocator)) |report| {
                defer allocator.free(report);
                std.log.err("{s}", .{report});
            } else |_| {}
        }
        return err;
    };
}

/// Same as `loadFromJsonFile` but populates `ec` with detailed validation
/// errors.  The caller keeps ownership of `ec` and must call `ec.deinit()`.
pub fn loadFromJsonFileWithErrors(allocator: std.mem.Allocator, path: []const u8, ec: *types.ErrorCollector) !types.Config {
    // All intermediate + final config data is allocated through an arena.
    // Config.deinit (unchanged) still frees everything because the arena's
    // child allocator forwards to the parent allocator.
    // We use the caller's allocator directly so that Config.deinit works.
    const a = allocator;

    std.fs.cwd().access(path, .{}) catch |err| {
        std.log.debug("File not found: {s}", .{path});
        return err;
    };
    const json_text = std.fs.cwd().readFileAlloc(a, path, 1 << 20) catch return types.ConfigError.JsonParseError;
    defer a.free(json_text);

    const parsed = std.json.parseFromSlice(std.json.Value, a, json_text, .{}) catch return types.ConfigError.JsonParseError;
    defer parsed.deinit();

    // ── Projects ────────────────────────────────────────────────────────
    const root = parsed.value;
    const projects_value: std.json.Value = switch (root) {
        .array => root,
        .object => |o| o.get("projects") orelse {
            ec.add("(root)", .missing_field, "", "", "'projects' key is required in root object");
            return types.ConfigError.ValidationFailed;
        },
        else => {
            ec.add("(root)", .wrong_type, "array or object", jsonValueTypeName(root), "root must be an array of projects or an object with a 'projects' key");
            return types.ConfigError.ValidationFailed;
        },
    };

    if (projects_value != .array) {
        ec.add("projects", .wrong_type, "array", jsonValueTypeName(projects_value), "'projects' must be an array");
        return types.ConfigError.ValidationFailed;
    }

    var list: std.ArrayList(types.Project) = .empty;
    errdefer {
        for (list.items) |*p| p.deinit(a);
        list.deinit(a);
    }

    for (projects_value.array.items, 0..) |item, idx| {
        const prefix = ec.fieldPath("projects[{d}]", .{idx});
        if (item != .object) {
            ec.add(prefix, .wrong_type, "object", jsonValueTypeName(item), "project entry must be an object");
            continue;
        }
        const obj = item.object;

        var project = types.Project{
            .listen_port = 0,
            .target_address = "",
            .target_port = 0,
        };
        var project_has_allocs = false;

        var have_listen_port = false;
        var have_target_address = false;
        var have_target_port = false;

        var src_zones_list: std.ArrayList([]const u8) = .empty;
        defer src_zones_list.deinit(a);
        errdefer for (src_zones_list.items) |z| a.free(z);

        var dest_zones_list: std.ArrayList([]const u8) = .empty;
        defer dest_zones_list.deinit(a);
        errdefer for (dest_zones_list.items) |z| a.free(z);

        var port_mappings_list: std.ArrayList(types.PortMapping) = .empty;
        defer port_mappings_list.deinit(a);
        errdefer for (port_mappings_list.items) |*pm| pm.deinit(a);

        if (obj.get("enabled")) |v| {
            if (parseJsonBool(v, ec.fieldPath("{s}.enabled", .{prefix}), ec)) |b| project.enabled = b;
        }

        if (obj.get("remark")) |v| {
            if (parseJsonString(v, ec.fieldPath("{s}.remark", .{prefix}), ec)) |s| {
                project.remark = types.dupeIfNonEmpty(a, s) catch "";
                if (project.remark.len > 0) project_has_allocs = true;
            }
        }

        if (obj.get("src_zone")) |v| {
            parseJsonZones(a, v, &src_zones_list, ec.fieldPath("{s}.src_zone", .{prefix}), ec);
        }

        if (obj.get("dest_zone")) |v| {
            parseJsonZones(a, v, &dest_zones_list, ec.fieldPath("{s}.dest_zone", .{prefix}), ec);
        }

        if (obj.get("family")) |v| {
            if (parseJsonString(v, ec.fieldPath("{s}.family", .{prefix}), ec)) |s| {
                project.family = types.parseFamily(s) catch blk: {
                    ec.addFmt(ec.fieldPath("{s}.family", .{prefix}), .enum_value_invalid, "any/ipv4/ipv6", "{s}", .{s}, "invalid address family");
                    break :blk .any;
                };
            }
        }

        if (obj.get("protocol")) |v| {
            if (parseJsonString(v, ec.fieldPath("{s}.protocol", .{prefix}), ec)) |s| {
                project.protocol = types.parseProtocol(s) catch blk: {
                    ec.addFmt(ec.fieldPath("{s}.protocol", .{prefix}), .enum_value_invalid, "tcp/udp/both", "{s}", .{s}, "invalid protocol value");
                    break :blk .both;
                };
            }
        }

        if (obj.get("listen_port")) |v| {
            if (parseJsonPort(v, ec.fieldPath("{s}.listen_port", .{prefix}), ec)) |p| {
                project.listen_port = p;
                have_listen_port = true;
            }
        }

        if (obj.get("reuseaddr")) |v| {
            if (parseJsonBool(v, ec.fieldPath("{s}.reuseaddr", .{prefix}), ec)) |b| project.reuseaddr = b;
        }

        if (obj.get("target_address")) |v| {
            if (parseJsonString(v, ec.fieldPath("{s}.target_address", .{prefix}), ec)) |s| {
                const trimmed = std.mem.trim(u8, s, " \t\r\n");
                if (trimmed.len == 0) {
                    ec.add(ec.fieldPath("{s}.target_address", .{prefix}), .empty_value, "non-empty string", "", "target address cannot be empty");
                } else {
                    project.target_address = a.dupe(u8, trimmed) catch "";
                    if (project.target_address.len > 0) {
                        have_target_address = true;
                        project_has_allocs = true;
                    }
                }
            }
        }

        if (obj.get("target_port")) |v| {
            if (parseJsonPort(v, ec.fieldPath("{s}.target_port", .{prefix}), ec)) |p| {
                project.target_port = p;
                have_target_port = true;
            }
        }

        if (obj.get("open_firewall_port")) |v| {
            if (parseJsonBool(v, ec.fieldPath("{s}.open_firewall_port", .{prefix}), ec)) |b| project.open_firewall_port = b;
        }

        if (obj.get("add_firewall_forward")) |v| {
            if (parseJsonBool(v, ec.fieldPath("{s}.add_firewall_forward", .{prefix}), ec)) |b| project.add_firewall_forward = b;
        }

        if (obj.get("preserve_source_ip")) |v| {
            if (parseJsonBool(v, ec.fieldPath("{s}.preserve_source_ip", .{prefix}), ec)) |b| project.preserve_source_ip = b;
        }

        if (obj.get("enable_app_forward")) |v| {
            if (parseJsonBool(v, ec.fieldPath("{s}.enable_app_forward", .{prefix}), ec)) |b| project.enable_app_forward = b;
        }

        if (obj.get("enable_stats")) |v| {
            if (parseJsonBool(v, ec.fieldPath("{s}.enable_stats", .{prefix}), ec)) |b| project.enable_stats = b;
        }

        // ── port_mappings ──
        if (obj.get("port_mappings")) |v| {
            if (v != .array) {
                ec.add(ec.fieldPath("{s}.port_mappings", .{prefix}), .wrong_type, "array", jsonValueTypeName(v), "port_mappings must be an array");
            } else {
                for (v.array.items, 0..) |mapping_item, mi| {
                    const mp = ec.fieldPath("{s}.port_mappings[{d}]", .{ prefix, mi });
                    if (mapping_item != .object) {
                        ec.add(mp, .wrong_type, "object", jsonValueTypeName(mapping_item), "port mapping entry must be an object");
                        continue;
                    }
                    const mapping_obj = mapping_item.object;

                    const m_listen = mapping_obj.get("listen_port") orelse {
                        ec.add(ec.fieldPath("{s}.listen_port", .{mp}), .missing_field, "", "", "required field missing");
                        continue;
                    };
                    const m_target = mapping_obj.get("target_port") orelse {
                        ec.add(ec.fieldPath("{s}.target_port", .{mp}), .missing_field, "", "", "required field missing");
                        continue;
                    };

                    const listen_str = parseJsonPortString(m_listen, a, ec.fieldPath("{s}.listen_port", .{mp}), ec) orelse continue;
                    const target_str = parseJsonPortString(m_target, a, ec.fieldPath("{s}.target_port", .{mp}), ec) orelse continue;

                    var pm = types.PortMapping{
                        .listen_port = listen_str,
                        .target_port = target_str,
                    };

                    if (mapping_obj.get("protocol")) |proto_v| {
                        if (parseJsonString(proto_v, ec.fieldPath("{s}.protocol", .{mp}), ec)) |s| {
                            pm.protocol = types.parseProtocol(s) catch blk: {
                                ec.addFmt(ec.fieldPath("{s}.protocol", .{mp}), .enum_value_invalid, "tcp/udp/both", "{s}", .{s}, "invalid protocol");
                                break :blk .tcp;
                            };
                        }
                    }

                    if (mapping_obj.get("frpc")) |frpc_v| {
                        if (parseJsonFrpcForwards(a, frpc_v, ec.fieldPath("{s}.frpc", .{mp}), ec)) |fwds| {
                            pm.frpc = fwds;
                        }
                    }

                    port_mappings_list.append(a, pm) catch {};
                }
            }
        }

        // ── Validation ──
        const has_single_port = have_listen_port and have_target_port;
        const has_port_mappings = port_mappings_list.items.len > 0;

        if (!have_target_address) {
            ec.add(ec.fieldPath("{s}.target_address", .{prefix}), .missing_field, "", "", "required field missing");
        }

        if (has_single_port and has_port_mappings) {
            ec.add(prefix, .conflict, "listen_port/target_port OR port_mappings", "", "cannot specify both single-port and port_mappings modes");
        } else if (!has_single_port and !has_port_mappings) {
            ec.add(prefix, .missing_field, "listen_port+target_port or port_mappings", "", "must specify either single-port (listen_port+target_port) or port_mappings");
        }

        // Skip this project if critical data is missing
        if (!have_target_address or (has_single_port == has_port_mappings)) {
            // Clean up what we allocated for this project
            if (project_has_allocs) {
                if (project.remark.len != 0) a.free(project.remark);
                if (have_target_address) a.free(project.target_address);
            }
            for (src_zones_list.items) |z| a.free(z);
            for (dest_zones_list.items) |z| a.free(z);
            for (port_mappings_list.items) |*pm| pm.deinit(a);
            // Clear lists so errdefer doesn't double-free
            src_zones_list.clearRetainingCapacity();
            dest_zones_list.clearRetainingCapacity();
            port_mappings_list.clearRetainingCapacity();
            continue;
        }

        if (src_zones_list.items.len != 0) {
            project.src_zones = src_zones_list.toOwnedSlice(a) catch &[_][]const u8{};
        }
        if (dest_zones_list.items.len != 0) {
            project.dest_zones = dest_zones_list.toOwnedSlice(a) catch &[_][]const u8{};
        }
        if (port_mappings_list.items.len != 0) {
            project.port_mappings = port_mappings_list.toOwnedSlice(a) catch &[_]types.PortMapping{};
        }

        list.append(a, project) catch {};
    }

    // ── FRPC nodes ──────────────────────────────────────────────────────
    var frpc_nodes = std.StringHashMap(types.FrpcNode).init(a);
    errdefer {
        var it = frpc_nodes.iterator();
        while (it.next()) |entry| {
            a.free(entry.key_ptr.*);
            entry.value_ptr.deinit(a);
        }
        frpc_nodes.deinit();
    }

    if (root == .object) {
        if (root.object.get("frpc_nodes")) |frpc_value| {
            if (frpc_value == .object) {
                var node_it = frpc_value.object.iterator();
                while (node_it.next()) |entry| {
                    const node_name = entry.key_ptr.*;
                    const node_obj = entry.value_ptr.*;
                    const np = ec.fieldPath("frpc_nodes.{s}", .{node_name});

                    if (node_obj != .object) continue;

                    var frpc_node = types.FrpcNode{
                        .enabled = true,
                        .server = undefined,
                        .port = 0,
                        .log_level = "",
                    };
                    var have_server = false;
                    var have_port = false;

                    if (node_obj.object.get("server")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.server", .{np}), ec)) |s| {
                            const trimmed = std.mem.trim(u8, s, " \t\r\n");
                            if (trimmed.len == 0) {
                                ec.add(ec.fieldPath("{s}.server", .{np}), .empty_value, "non-empty string", "", "server cannot be empty");
                            } else {
                                frpc_node.server = a.dupe(u8, trimmed) catch continue;
                                have_server = true;
                            }
                        }
                    }

                    if (node_obj.object.get("port")) |v| {
                        if (parseJsonPort(v, ec.fieldPath("{s}.port", .{np}), ec)) |p| {
                            frpc_node.port = p;
                            have_port = true;
                        }
                    }

                    if (node_obj.object.get("token")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.token", .{np}), ec)) |s|
                            frpc_node.token = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (node_obj.object.get("use_encryption")) |v| {
                        if (parseJsonBool(v, ec.fieldPath("{s}.use_encryption", .{np}), ec)) |b| frpc_node.use_encryption = b;
                    }
                    if (node_obj.object.get("use_compression")) |v| {
                        if (parseJsonBool(v, ec.fieldPath("{s}.use_compression", .{np}), ec)) |b| frpc_node.use_compression = b;
                    }
                    if (node_obj.object.get("log_level")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.log_level", .{np}), ec)) |s|
                            frpc_node.log_level = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (node_obj.object.get("enabled")) |v| {
                        if (parseJsonBool(v, ec.fieldPath("{s}.enabled", .{np}), ec)) |b| frpc_node.enabled = b;
                    }

                    if (!have_server) ec.add(ec.fieldPath("{s}.server", .{np}), .missing_field, "", "", "required field missing");
                    if (!have_port) ec.add(ec.fieldPath("{s}.port", .{np}), .missing_field, "", "", "required field missing");
                    if (!have_server or !have_port) {
                        // Clean up partial node
                        if (have_server) a.free(frpc_node.server);
                        if (frpc_node.token.len != 0) a.free(frpc_node.token);
                        if (frpc_node.log_level.len != 0) a.free(frpc_node.log_level);
                        continue;
                    }

                    const key = a.dupe(u8, node_name) catch continue;
                    frpc_nodes.put(key, frpc_node) catch {};
                }
            }
        }
    }

    // ── FRPS nodes ──────────────────────────────────────────────────────
    var frps_nodes = std.StringHashMap(types.FrpsNode).init(a);
    errdefer {
        var it = frps_nodes.iterator();
        while (it.next()) |entry| {
            a.free(entry.key_ptr.*);
            entry.value_ptr.deinit(a);
        }
        frps_nodes.deinit();
    }

    if (root == .object) {
        if (root.object.get("frps_nodes")) |frps_value| {
            if (frps_value == .object) {
                var node_it = frps_value.object.iterator();
                while (node_it.next()) |entry| {
                    const node_name = entry.key_ptr.*;
                    const node_obj = entry.value_ptr.*;
                    const np = ec.fieldPath("frps_nodes.{s}", .{node_name});

                    if (node_obj != .object) continue;

                    var frps_node = types.FrpsNode{
                        .enabled = true,
                        .port = 0,
                        .log_level = "",
                    };
                    var have_port = false;

                    if (node_obj.object.get("port")) |v| {
                        if (parseJsonPort(v, ec.fieldPath("{s}.port", .{np}), ec)) |p| {
                            frps_node.port = p;
                            have_port = true;
                        }
                    }
                    if (node_obj.object.get("token")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.token", .{np}), ec)) |s|
                            frps_node.token = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (node_obj.object.get("log_level")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.log_level", .{np}), ec)) |s|
                            frps_node.log_level = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (node_obj.object.get("allow_ports")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.allow_ports", .{np}), ec)) |s|
                            frps_node.allow_ports = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (node_obj.object.get("bind_addr")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.bind_addr", .{np}), ec)) |s|
                            frps_node.bind_addr = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (node_obj.object.get("max_pool_count")) |v| {
                        frps_node.max_pool_count = switch (v) {
                            .integer => |i| @intCast(i),
                            .string => |s| std.fmt.parseUnsigned(u32, s, 10) catch 5,
                            else => 5,
                        };
                    }
                    if (node_obj.object.get("max_ports_per_client")) |v| {
                        frps_node.max_ports_per_client = switch (v) {
                            .integer => |i| @intCast(i),
                            .string => |s| std.fmt.parseUnsigned(u32, s, 10) catch 0,
                            else => 0,
                        };
                    }
                    if (node_obj.object.get("tcp_mux")) |v| {
                        if (parseJsonBool(v, ec.fieldPath("{s}.tcp_mux", .{np}), ec)) |b| frps_node.tcp_mux = b;
                    }
                    if (node_obj.object.get("udp_mux")) |v| {
                        if (parseJsonBool(v, ec.fieldPath("{s}.udp_mux", .{np}), ec)) |b| frps_node.udp_mux = b;
                    }
                    if (node_obj.object.get("kcp_mux")) |v| {
                        if (parseJsonBool(v, ec.fieldPath("{s}.kcp_mux", .{np}), ec)) |b| frps_node.kcp_mux = b;
                    }
                    if (node_obj.object.get("dashboard_addr")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.dashboard_addr", .{np}), ec)) |s|
                            frps_node.dashboard_addr = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (node_obj.object.get("dashboard_user")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.dashboard_user", .{np}), ec)) |s|
                            frps_node.dashboard_user = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (node_obj.object.get("dashboard_pwd")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.dashboard_pwd", .{np}), ec)) |s|
                            frps_node.dashboard_pwd = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (node_obj.object.get("enabled")) |v| {
                        if (parseJsonBool(v, ec.fieldPath("{s}.enabled", .{np}), ec)) |b| frps_node.enabled = b;
                    }

                    if (!have_port) {
                        ec.add(ec.fieldPath("{s}.port", .{np}), .missing_field, "", "", "required field missing");
                        // Clean up partial node
                        if (frps_node.token.len != 0) a.free(frps_node.token);
                        if (frps_node.log_level.len != 0) a.free(frps_node.log_level);
                        if (frps_node.allow_ports.len != 0) a.free(frps_node.allow_ports);
                        if (frps_node.bind_addr.len != 0) a.free(frps_node.bind_addr);
                        if (frps_node.dashboard_addr.len != 0) a.free(frps_node.dashboard_addr);
                        if (frps_node.dashboard_user.len != 0) a.free(frps_node.dashboard_user);
                        if (frps_node.dashboard_pwd.len != 0) a.free(frps_node.dashboard_pwd);
                        continue;
                    }

                    const key = a.dupe(u8, node_name) catch continue;
                    frps_nodes.put(key, frps_node) catch {};
                }
            }
        }
    }

    // ── DDNS configs ────────────────────────────────────────────────────
    var ddns_list: std.ArrayList(types.DdnsConfig) = .empty;
    errdefer {
        for (ddns_list.items) |*d| d.deinit(a);
        ddns_list.deinit(a);
    }

    if (root == .object) {
        if (root.object.get("ddns")) |ddns_value| {
            if (ddns_value == .array) {
                for (ddns_value.array.items, 0..) |item, di| {
                    const dp = ec.fieldPath("ddns[{d}]", .{di});
                    if (item != .object) continue;
                    const obj = item.object;

                    var ddns_cfg = types.DdnsConfig{
                        .enabled = true,
                        .name = undefined,
                        .dns_provider = undefined,
                    };
                    var have_name = false;
                    var have_provider = false;

                    if (obj.get("name")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.name", .{dp}), ec)) |s| {
                            ddns_cfg.name = types.dupeIfNonEmpty(a, s) catch "";
                            have_name = ddns_cfg.name.len > 0;
                        }
                    }
                    if (obj.get("dns_provider")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.dns_provider", .{dp}), ec)) |s| {
                            ddns_cfg.dns_provider = types.dupeIfNonEmpty(a, s) catch "";
                            have_provider = ddns_cfg.dns_provider.len > 0;
                        }
                    }

                    if (obj.get("dns_id")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.dns_id", .{dp}), ec)) |s|
                            ddns_cfg.dns_id = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (obj.get("dns_secret")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.dns_secret", .{dp}), ec)) |s|
                            ddns_cfg.dns_secret = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (obj.get("dns_ext_param")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.dns_ext_param", .{dp}), ec)) |s|
                            ddns_cfg.dns_ext_param = types.dupeIfNonEmpty(a, s) catch "";
                    }

                    if (obj.get("ttl")) |v| {
                        ddns_cfg.ttl = switch (v) {
                            .integer => |i| @intCast(i),
                            .string => |s| std.fmt.parseUnsigned(u32, s, 10) catch 3600,
                            else => 3600,
                        };
                    }

                    // IPv4 config
                    if (obj.get("ipv4_enable")) |v| {
                        if (parseJsonBool(v, ec.fieldPath("{s}.ipv4_enable", .{dp}), ec)) |b| ddns_cfg.ipv4.enable = b;
                    }
                    if (obj.get("ipv4_get_type")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.ipv4_get_type", .{dp}), ec)) |s| {
                            ddns_cfg.ipv4.get_type = types.DdnsIpGetType.fromString(s) catch blk: {
                                ec.addFmt(ec.fieldPath("{s}.ipv4_get_type", .{dp}), .enum_value_invalid, "url/net_interface/cmd", "{s}", .{s}, "invalid IP get type");
                                break :blk .url;
                            };
                        }
                    }
                    if (obj.get("ipv4_url")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.ipv4_url", .{dp}), ec)) |s|
                            ddns_cfg.ipv4.url = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (obj.get("ipv4_net_interface")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.ipv4_net_interface", .{dp}), ec)) |s|
                            ddns_cfg.ipv4.net_interface = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (obj.get("ipv4_cmd")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.ipv4_cmd", .{dp}), ec)) |s|
                            ddns_cfg.ipv4.cmd = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (obj.get("ipv4_domains")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.ipv4_domains", .{dp}), ec)) |s|
                            ddns_cfg.ipv4.domains = types.dupeIfNonEmpty(a, s) catch "";
                    }

                    // IPv6 config
                    if (obj.get("ipv6_enable")) |v| {
                        if (parseJsonBool(v, ec.fieldPath("{s}.ipv6_enable", .{dp}), ec)) |b| ddns_cfg.ipv6.enable = b;
                    }
                    if (obj.get("ipv6_get_type")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.ipv6_get_type", .{dp}), ec)) |s| {
                            ddns_cfg.ipv6.get_type = types.DdnsIpGetType.fromString(s) catch blk: {
                                ec.addFmt(ec.fieldPath("{s}.ipv6_get_type", .{dp}), .enum_value_invalid, "url/net_interface/cmd", "{s}", .{s}, "invalid IP get type");
                                break :blk .url;
                            };
                        }
                    }
                    if (obj.get("ipv6_url")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.ipv6_url", .{dp}), ec)) |s|
                            ddns_cfg.ipv6.url = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (obj.get("ipv6_net_interface")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.ipv6_net_interface", .{dp}), ec)) |s|
                            ddns_cfg.ipv6.net_interface = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (obj.get("ipv6_cmd")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.ipv6_cmd", .{dp}), ec)) |s|
                            ddns_cfg.ipv6.cmd = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (obj.get("ipv6_reg")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.ipv6_reg", .{dp}), ec)) |s|
                            ddns_cfg.ipv6.reg = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (obj.get("ipv6_domains")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.ipv6_domains", .{dp}), ec)) |s|
                            ddns_cfg.ipv6.domains = types.dupeIfNonEmpty(a, s) catch "";
                    }

                    // Other optional fields
                    if (obj.get("not_allow_wan_access")) |v| {
                        if (parseJsonBool(v, ec.fieldPath("{s}.not_allow_wan_access", .{dp}), ec)) |b| ddns_cfg.not_allow_wan_access = b;
                    }
                    if (obj.get("username")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.username", .{dp}), ec)) |s|
                            ddns_cfg.username = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (obj.get("password")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.password", .{dp}), ec)) |s|
                            ddns_cfg.password = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (obj.get("webhook_url")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.webhook_url", .{dp}), ec)) |s|
                            ddns_cfg.webhook_url = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (obj.get("webhook_body")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.webhook_body", .{dp}), ec)) |s|
                            ddns_cfg.webhook_body = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (obj.get("webhook_headers")) |v| {
                        if (parseJsonString(v, ec.fieldPath("{s}.webhook_headers", .{dp}), ec)) |s|
                            ddns_cfg.webhook_headers = types.dupeIfNonEmpty(a, s) catch "";
                    }
                    if (obj.get("enabled")) |v| {
                        if (parseJsonBool(v, ec.fieldPath("{s}.enabled", .{dp}), ec)) |b| ddns_cfg.enabled = b;
                    }

                    if (!have_name) ec.add(ec.fieldPath("{s}.name", .{dp}), .missing_field, "", "", "required field missing");
                    if (!have_provider) ec.add(ec.fieldPath("{s}.dns_provider", .{dp}), .missing_field, "", "", "required field missing");
                    if (!have_name or !have_provider) {
                        ddns_cfg.deinit(a);
                        continue;
                    }

                    ddns_list.append(a, ddns_cfg) catch {};
                }
            }
        }
    }

    // ── Final check ─────────────────────────────────────────────────────
    if (ec.hasErrors()) {
        // errdefer blocks above will clean up list, frpc_nodes, frps_nodes, ddns_list
        return types.ConfigError.ValidationFailed;
    }

    return .{
        .projects = list.toOwnedSlice(a) catch return error.OutOfMemory,
        .frpc_nodes = frpc_nodes,
        .frps_nodes = frps_nodes,
        .ddns_configs = ddns_list.toOwnedSlice(a) catch return error.OutOfMemory,
    };
}

// ═══════════════════════════════════════════════════════════════════════
//                              TESTS
// ═══════════════════════════════════════════════════════════════════════

const testing = std.testing;

/// Write `content` to a temporary file and return its absolute path.
fn writeTmpJson(alloc: std.mem.Allocator, content: []const u8) ![]const u8 {
    const tmp = testing.tmpDir(.{});
    const dir = tmp.dir;
    dir.writeFile(.{ .sub_path = "test.json", .data = content }) catch return error.TestFailed;
    return dir.realpathAlloc(alloc, "test.json");
}

// ── Normal-case tests ───────────────────────────────────────────────────

test "json: minimal valid config" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{
        \\  "projects": [{
        \\    "remark": "echo",
        \\    "target_address": "127.0.0.1",
        \\    "listen_port": 8080,
        \\    "target_port": 80,
        \\    "protocol": "tcp",
        \\    "family": "any",
        \\    "enable_app_forward": true
        \\  }]
        \\}
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();

    var cfg = try loadFromJsonFileWithErrors(alloc, path, &ec);
    defer cfg.deinit(alloc);

    try testing.expect(!ec.hasErrors());
    try testing.expectEqual(@as(usize, 1), cfg.projects.len);
    try testing.expectEqualStrings("echo", cfg.projects[0].remark);
    try testing.expectEqual(@as(u16, 8080), cfg.projects[0].listen_port);
    try testing.expectEqual(@as(u16, 80), cfg.projects[0].target_port);
    try testing.expectEqual(types.Protocol.tcp, cfg.projects[0].protocol);
    try testing.expect(cfg.projects[0].enable_app_forward);
}

test "json: multiple projects" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{
        \\  "projects": [
        \\    {"target_address": "10.0.0.1", "listen_port": 1000, "target_port": 2000, "family": "ipv4", "protocol": "tcp"},
        \\    {"target_address": "::1",       "listen_port": 3000, "target_port": 4000, "family": "ipv6", "protocol": "udp"}
        \\  ]
        \\}
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    var cfg = try loadFromJsonFileWithErrors(alloc, path, &ec);
    defer cfg.deinit(alloc);

    try testing.expect(!ec.hasErrors());
    try testing.expectEqual(@as(usize, 2), cfg.projects.len);
    try testing.expectEqual(types.AddressFamily.ipv4, cfg.projects[0].family);
    try testing.expectEqual(types.AddressFamily.ipv6, cfg.projects[1].family);
    try testing.expectEqual(types.Protocol.udp, cfg.projects[1].protocol);
}

test "json: port mappings" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{
        \\  "projects": [{
        \\    "target_address": "192.168.1.1",
        \\    "port_mappings": [
        \\      {"listen_port": "8080-8085", "target_port": "80-85", "protocol": "tcp"},
        \\      {"listen_port": 9090,        "target_port": 90,      "protocol": "udp"}
        \\    ]
        \\  }]
        \\}
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    var cfg = try loadFromJsonFileWithErrors(alloc, path, &ec);
    defer cfg.deinit(alloc);

    try testing.expect(!ec.hasErrors());
    try testing.expectEqual(@as(usize, 2), cfg.projects[0].port_mappings.len);
    try testing.expectEqualStrings("8080-8085", cfg.projects[0].port_mappings[0].listen_port);
    try testing.expectEqualStrings("80-85", cfg.projects[0].port_mappings[0].target_port);
}

test "json: boolean as integer and string" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{
        \\  "projects": [{
        \\    "target_address": "127.0.0.1",
        \\    "listen_port": 80,
        \\    "target_port": 80,
        \\    "enable_app_forward": 1,
        \\    "open_firewall_port": 0,
        \\    "add_firewall_forward": "yes"
        \\  }]
        \\}
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    var cfg = try loadFromJsonFileWithErrors(alloc, path, &ec);
    defer cfg.deinit(alloc);

    try testing.expect(!ec.hasErrors());
    try testing.expect(cfg.projects[0].enable_app_forward);
    try testing.expect(!cfg.projects[0].open_firewall_port);
    try testing.expect(cfg.projects[0].add_firewall_forward);
}

test "json: frpc nodes" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{
        \\  "projects": [{"target_address": "127.0.0.1", "listen_port": 80, "target_port": 80}],
        \\  "frpc_nodes": {"n1": {"server": "1.2.3.4", "port": 7000, "token": "abc"}}
        \\}
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    var cfg = try loadFromJsonFileWithErrors(alloc, path, &ec);
    defer cfg.deinit(alloc);

    try testing.expect(!ec.hasErrors());
    try testing.expectEqual(@as(u32, 1), cfg.frpc_nodes.count());
    const n1 = cfg.frpc_nodes.get("n1").?;
    try testing.expectEqualStrings("1.2.3.4", n1.server);
    try testing.expectEqual(@as(u16, 7000), n1.port);
}

test "json: empty projects array" {
    const alloc = testing.allocator;
    const json_str = "{\"projects\": []}";
    const path = try writeTmpJson(alloc, json_str);
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    var cfg = try loadFromJsonFileWithErrors(alloc, path, &ec);
    defer cfg.deinit(alloc);

    try testing.expect(!ec.hasErrors());
    try testing.expectEqual(@as(usize, 0), cfg.projects.len);
}

test "json: port boundary 1 and 65535" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{
        \\  "projects": [
        \\    {"target_address": "127.0.0.1", "listen_port": 1,     "target_port": 1},
        \\    {"target_address": "127.0.0.1", "listen_port": 65535, "target_port": 65535}
        \\  ]
        \\}
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    var cfg = try loadFromJsonFileWithErrors(alloc, path, &ec);
    defer cfg.deinit(alloc);

    try testing.expect(!ec.hasErrors());
    try testing.expectEqual(@as(u16, 1), cfg.projects[0].listen_port);
    try testing.expectEqual(@as(u16, 65535), cfg.projects[1].listen_port);
}

test "json: root array shorthand" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\[{"target_address": "127.0.0.1", "listen_port": 80, "target_port": 80}]
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    var cfg = try loadFromJsonFileWithErrors(alloc, path, &ec);
    defer cfg.deinit(alloc);

    try testing.expect(!ec.hasErrors());
    try testing.expectEqual(@as(usize, 1), cfg.projects.len);
}

// ── Error-case tests ────────────────────────────────────────────────────

test "json: malformed JSON" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc, "{ invalid json }}}");
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    try testing.expectError(types.ConfigError.JsonParseError, loadFromJsonFileWithErrors(alloc, path, &ec));
}

test "json: missing target_address" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{"projects": [{"listen_port": 80, "target_port": 80}]}
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    try testing.expectError(types.ConfigError.ValidationFailed, loadFromJsonFileWithErrors(alloc, path, &ec));
    try testing.expect(ec.hasErrors());

    var found = false;
    for (ec.errors.items) |e| {
        if (std.mem.indexOf(u8, e.field_path, "target_address") != null) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "json: port out of range" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{"projects": [{"target_address": "127.0.0.1", "listen_port": 70000, "target_port": 80}]}
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    try testing.expectError(types.ConfigError.ValidationFailed, loadFromJsonFileWithErrors(alloc, path, &ec));

    var found = false;
    for (ec.errors.items) |e| {
        if (std.mem.indexOf(u8, e.field_path, "listen_port") != null and e.error_type == .out_of_range) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "json: invalid protocol" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{"projects": [{"target_address": "127.0.0.1", "listen_port": 80, "target_port": 80, "protocol": "http"}]}
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    try testing.expectError(types.ConfigError.ValidationFailed, loadFromJsonFileWithErrors(alloc, path, &ec));

    var found = false;
    for (ec.errors.items) |e| {
        if (std.mem.indexOf(u8, e.field_path, "protocol") != null and e.error_type == .enum_value_invalid) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "json: empty target_address" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{"projects": [{"target_address": "", "listen_port": 80, "target_port": 80}]}
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    try testing.expectError(types.ConfigError.ValidationFailed, loadFromJsonFileWithErrors(alloc, path, &ec));
    try testing.expect(ec.hasErrors());
}

test "json: single-port and port_mappings conflict" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{"projects": [{"target_address": "127.0.0.1", "listen_port": 80, "target_port": 80, "port_mappings": [{"listen_port": 90, "target_port": 90}]}]}
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    try testing.expectError(types.ConfigError.ValidationFailed, loadFromJsonFileWithErrors(alloc, path, &ec));

    var found = false;
    for (ec.errors.items) |e| {
        if (e.error_type == .conflict) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "json: missing port_mapping required fields" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{"projects": [{"target_address": "127.0.0.1", "port_mappings": [{"listen_port": 80}]}]}
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    try testing.expectError(types.ConfigError.ValidationFailed, loadFromJsonFileWithErrors(alloc, path, &ec));
    try testing.expect(ec.hasErrors());
}

test "json: multiple errors from multiple projects" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{
        \\  "projects": [
        \\    {"listen_port": -1, "target_port": 80, "target_address": "127.0.0.1"},
        \\    {"listen_port": 80, "target_port": 80, "target_address": "", "protocol": "ftp"},
        \\    {"listen_port": 80, "target_port": 80, "family": "ipv7", "target_address": "1.1.1.1"}
        \\  ]
        \\}
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    try testing.expectError(types.ConfigError.ValidationFailed, loadFromJsonFileWithErrors(alloc, path, &ec));
    try testing.expect(ec.errors.items.len >= 3);
}

test "json: error report formatting" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{"projects": [{"listen_port": 70000, "target_port": 80, "target_address": "127.0.0.1"}]}
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    _ = loadFromJsonFileWithErrors(alloc, path, &ec) catch {};

    const report = try ec.formatReport(alloc);
    defer alloc.free(report);
    try testing.expect(report.len > 0);
    try testing.expect(std.mem.indexOf(u8, report, "error") != null);
}

// ── Memory safety tests ─────────────────────────────────────────────────

test "json: no leak on successful load" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{"projects": [{"remark": "leak test", "target_address": "127.0.0.1", "listen_port": 80, "target_port": 80}]}
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    var cfg = try loadFromJsonFileWithErrors(alloc, path, &ec);
    defer cfg.deinit(alloc);
}

test "json: no leak on validation error" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{"projects": [{"listen_port": 70000, "target_port": 80, "target_address": "127.0.0.1"}]}
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    _ = loadFromJsonFileWithErrors(alloc, path, &ec) catch {};
}

test "json: no leak on malformed JSON" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc, "{{{bad");
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    _ = loadFromJsonFileWithErrors(alloc, path, &ec) catch {};
}

test "json: repeated load/free (no double-free)" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{
        \\  "projects": [{"target_address": "127.0.0.1", "listen_port": 80, "target_port": 80, "remark": "cycle"}],
        \\  "frpc_nodes": {"n1": {"server": "1.1.1.1", "port": 7000}}
        \\}
    );
    defer alloc.free(path);

    for (0..5) |_| {
        var ec = types.ErrorCollector.init(alloc);
        defer ec.deinit();
        var cfg = try loadFromJsonFileWithErrors(alloc, path, &ec);
        cfg.deinit(alloc);
    }
}

test "json: no leak with partial parse (valid + invalid)" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{
        \\  "projects": [
        \\    {"target_address": "127.0.0.1", "listen_port": 80, "target_port": 80},
        \\    {"target_address": "127.0.0.1", "listen_port": -999, "target_port": 80}
        \\  ]
        \\}
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    _ = loadFromJsonFileWithErrors(alloc, path, &ec) catch {};
}

test "json: complex config no leak" {
    const alloc = testing.allocator;
    const path = try writeTmpJson(alloc,
        \\{
        \\  "projects": [{
        \\    "remark": "full",
        \\    "target_address": "10.0.0.1",
        \\    "port_mappings": [
        \\      {"listen_port": "8080-8085", "target_port": "80-85", "protocol": "tcp"},
        \\      {"listen_port": 9090, "target_port": 90}
        \\    ],
        \\    "family": "ipv4",
        \\    "src_zone": ["wan", "lan"],
        \\    "dest_zone": "lan",
        \\    "enable_app_forward": true
        \\  }],
        \\  "frpc_nodes": {
        \\    "node1": {"server": "1.2.3.4", "port": 7000, "token": "s3cret"},
        \\    "node2": {"server": "5.6.7.8", "port": 7001}
        \\  },
        \\  "frps_nodes": {
        \\    "srv1": {"port": 7000, "token": "tk", "bind_addr": "0.0.0.0"}
        \\  },
        \\  "ddns": [{
        \\    "name": "test", "dns_provider": "cloudflare",
        \\    "dns_secret": "token123", "ipv4_enable": true, "ipv4_domains": "example.com"
        \\  }]
        \\}
    );
    defer alloc.free(path);

    var ec = types.ErrorCollector.init(alloc);
    defer ec.deinit();
    var cfg = try loadFromJsonFileWithErrors(alloc, path, &ec);
    defer cfg.deinit(alloc);

    try testing.expect(!ec.hasErrors());
    try testing.expectEqual(@as(usize, 1), cfg.projects.len);
    try testing.expectEqual(@as(u32, 2), cfg.frpc_nodes.count());
    try testing.expectEqual(@as(u32, 1), cfg.frps_nodes.count());
    try testing.expectEqual(@as(usize, 1), cfg.ddns_configs.len);
}
