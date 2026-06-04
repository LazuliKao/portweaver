const std = @import("std");
const nft = @import("../nftables/mod.zig");
const types = @import("../config/types.zig");

const NFT_TABLE = "inet portweaver";

fn runCommandLogged(ctx: anytype, cmd: [*:0]const u8) !void {
    ctx.runCommand(cmd) catch |err| {
        if (ctx.getErrorMsg()) |msg| {
            std.log.err("failed to run nft command `{s}`: {s}", .{ std.mem.span(cmd), msg });
        } else {
            std.log.err("failed to run nft command `{s}`: {}", .{ std.mem.span(cmd), err });
        }
        return err;
    };
}

fn familyInputMatch(family: ?types.AddressFamily) []const u8 {
    return switch (family orelse .any) {
        .any => "",
        .ipv4 => " ip saddr 0.0.0.0/0",
        .ipv6 => " ip6 saddr ::/0",
    };
}

fn familyAddrKeyword(family: ?types.AddressFamily) []const u8 {
    return switch (family orelse .ipv4) {
        .any => "ip",
        .ipv4 => "ip",
        .ipv6 => "ip6",
    };
}

fn dnatTargetSpec(
    allocator: std.mem.Allocator,
    family: ?types.AddressFamily,
    dest_ip: []const u8,
    dest_port: []const u8,
) ![:0]u8 {
    return switch (family orelse .ipv4) {
        .any, .ipv4 => std.fmt.allocPrintSentinel(
            allocator,
            "dnat ip to {s}:{s}",
            .{ dest_ip, dest_port },
            0,
        ),
        .ipv6 => std.fmt.allocPrintSentinel(
            allocator,
            "dnat ip6 to [{s}]:{s}",
            .{ dest_ip, dest_port },
            0,
        ),
    };
}

fn addAcceptRulesForProtocolFamily(
    ctx: anytype,
    allocator: std.mem.Allocator,
    proto: []const u8,
    port_str: []const u8,
    remark: []const u8,
    family: types.AddressFamily,
    enable_firewall_stats: bool,
) !void {
    switch (family) {
        .any => {
            try addAcceptRule(ctx, allocator, proto, port_str, remark, .ipv4, enable_firewall_stats);
            try addAcceptRule(ctx, allocator, proto, port_str, remark, .ipv6, enable_firewall_stats);
        },
        .ipv4, .ipv6 => try addAcceptRule(ctx, allocator, proto, port_str, remark, family, enable_firewall_stats),
    }
}

fn addRedirectRulesForProtocolFamily(
    ctx: anytype,
    allocator: std.mem.Allocator,
    src_zone: []const u8,
    proto: []const u8,
    listen_port: []const u8,
    dest_zone: []const u8,
    dest_ip: []const u8,
    dest_port: []const u8,
    remark: []const u8,
    family: types.AddressFamily,
    preserve_source_ip: bool,
    enable_firewall_stats: bool,
) !void {
    switch (family) {
        .any => {
            try addRedirectRule(ctx, allocator, src_zone, proto, listen_port, dest_zone, dest_ip, dest_port, remark, .ipv4, preserve_source_ip, enable_firewall_stats);
            try addRedirectRule(ctx, allocator, src_zone, proto, listen_port, dest_zone, dest_ip, dest_port, remark, .ipv6, preserve_source_ip, enable_firewall_stats);
        },
        .ipv4, .ipv6 => try addRedirectRule(ctx, allocator, src_zone, proto, listen_port, dest_zone, dest_ip, dest_port, remark, family, preserve_source_ip, enable_firewall_stats),
    }
}

fn addExpandedAcceptRules(
    ctx: anytype,
    allocator: std.mem.Allocator,
    protocol: types.Protocol,
    port_str: []const u8,
    remark: []const u8,
    family: types.AddressFamily,
    enable_firewall_stats: bool,
) !void {
    switch (protocol) {
        .tcp => try addAcceptRulesForProtocolFamily(ctx, allocator, "tcp", port_str, remark, family, enable_firewall_stats),
        .udp => try addAcceptRulesForProtocolFamily(ctx, allocator, "udp", port_str, remark, family, enable_firewall_stats),
        .both => {
            try addAcceptRulesForProtocolFamily(ctx, allocator, "tcp", port_str, remark, family, enable_firewall_stats);
            try addAcceptRulesForProtocolFamily(ctx, allocator, "udp", port_str, remark, family, enable_firewall_stats);
        },
    }
}

fn addExpandedRedirectRules(
    ctx: anytype,
    allocator: std.mem.Allocator,
    src_zone: []const u8,
    protocol: types.Protocol,
    listen_port: []const u8,
    dest_zone: []const u8,
    dest_ip: []const u8,
    dest_port: []const u8,
    remark: []const u8,
    family: types.AddressFamily,
    preserve_source_ip: bool,
    enable_firewall_stats: bool,
) !void {
    switch (protocol) {
        .tcp => try addRedirectRulesForProtocolFamily(ctx, allocator, src_zone, "tcp", listen_port, dest_zone, dest_ip, dest_port, remark, family, preserve_source_ip, enable_firewall_stats),
        .udp => try addRedirectRulesForProtocolFamily(ctx, allocator, src_zone, "udp", listen_port, dest_zone, dest_ip, dest_port, remark, family, preserve_source_ip, enable_firewall_stats),
        .both => {
            try addRedirectRulesForProtocolFamily(ctx, allocator, src_zone, "tcp", listen_port, dest_zone, dest_ip, dest_port, remark, family, preserve_source_ip, enable_firewall_stats);
            try addRedirectRulesForProtocolFamily(ctx, allocator, src_zone, "udp", listen_port, dest_zone, dest_ip, dest_port, remark, family, preserve_source_ip, enable_firewall_stats);
        },
    }
}

/// Adds an ACCEPT rule to the input chain.
/// When enable_firewall_stats is true, injects a named counter for traffic accounting.
pub fn addAcceptRule(
    ctx: anytype,
    allocator: std.mem.Allocator,
    proto: []const u8,
    port_str: []const u8,
    remark: []const u8,
    family: ?types.AddressFamily,
    enable_firewall_stats: bool,
) !void {
    const family_str = switch (family orelse .any) {
        .any => "any",
        .ipv4 => "ipv4",
        .ipv6 => "ipv6",
    };
    std.log.info("[NFT] ACCEPT {s}/{s} dport {s} ({s})", .{ proto, family_str, port_str, remark });

    const cmd = if (enable_firewall_stats)
        try std.fmt.allocPrintSentinel(
            allocator,
            "add rule {s} input{s} {s} dport {s} counter name \"pw_{s}_{s}_accept\" accept comment \"PORTWEAVER_{s}_{s}_{s}\"",
            .{ NFT_TABLE, familyInputMatch(family), proto, port_str, port_str, proto, port_str, proto, remark },
            0,
        )
    else
        try std.fmt.allocPrintSentinel(
            allocator,
            "add rule {s} input{s} {s} dport {s} accept comment \"PORTWEAVER_{s}_{s}_{s}\"",
            .{ NFT_TABLE, familyInputMatch(family), proto, port_str, port_str, proto, remark },
            0,
        );
    defer allocator.free(cmd);

    try runCommandLogged(ctx, cmd);
}

/// Adds a NAT (srcnat) rule used when preserve_source_ip is enabled.
/// When enable_firewall_stats is true, injects a named counter for traffic accounting.
pub fn addNatRule(
    ctx: anytype,
    allocator: std.mem.Allocator,
    src_zone: []const u8,
    proto: []const u8,
    listen_port: []const u8,
    dest_ip: []const u8,
    dest_port: []const u8,
    remark: []const u8,
    family: ?types.AddressFamily,
    enable_firewall_stats: bool,
) !void {
    std.log.info("[NFT] SRCNAT {s} dport {s} -> {s}:{s} (preserve-src-ip, remark={s})", .{ proto, listen_port, dest_ip, dest_port, remark });
    const addr_keyword = familyAddrKeyword(family);
    const cmd = if (enable_firewall_stats)
        try std.fmt.allocPrintSentinel(
            allocator,
            "add rule {s} srcnat oifname \"{s}\" {s} dport {s} {s} daddr {s} {s} dport {s} counter name \"pw_{s}_{s}_srcnat\" accept comment \"PORTWEAVER_{s}_{s}_{s}\"",
            .{ NFT_TABLE, src_zone, proto, listen_port, addr_keyword, dest_ip, proto, dest_port, listen_port, proto, listen_port, proto, remark },
            0,
        )
    else
        try std.fmt.allocPrintSentinel(
            allocator,
            "add rule {s} srcnat oifname \"{s}\" {s} dport {s} {s} daddr {s} {s} dport {s} accept comment \"PORTWEAVER_{s}_{s}_{s}\"",
            .{ NFT_TABLE, src_zone, proto, listen_port, addr_keyword, dest_ip, proto, dest_port, listen_port, proto, remark },
            0,
        );
    defer allocator.free(cmd);

    try runCommandLogged(ctx, cmd);
}

/// Adds a DNAT rule and optional NAT (srcnat) rule.
/// When enable_firewall_stats is true, injects named counters for traffic accounting.
pub fn addRedirectRule(
    ctx: anytype,
    allocator: std.mem.Allocator,
    src_zone: []const u8,
    proto: []const u8,
    listen_port: []const u8,
    dest_zone: []const u8,
    dest_ip: []const u8,
    dest_port: []const u8,
    remark: []const u8,
    family: ?types.AddressFamily,
    preserve_source_ip: bool,
    enable_firewall_stats: bool,
) !void {
    _ = dest_zone;

    std.log.info("[NFT] DNAT {s} iif={s} dport {s} -> {s}:{s} (remark={s})", .{ proto, src_zone, listen_port, dest_ip, dest_port, remark });

    if (preserve_source_ip) {
        try addNatRule(ctx, allocator, src_zone, proto, listen_port, dest_ip, dest_port, remark, family, enable_firewall_stats);
    }

    const dnat_spec = try dnatTargetSpec(allocator, family, dest_ip, dest_port);
    defer allocator.free(dnat_spec);

    const cmd = if (enable_firewall_stats)
        try std.fmt.allocPrintSentinel(
            allocator,
            "add rule {s} dstnat iifname \"{s}\" {s} dport {s} counter name \"pw_{s}_{s}_dstnat\" {s} comment \"PORTWEAVER_{s}_{s}_{s}\"",
            .{ NFT_TABLE, src_zone, proto, listen_port, listen_port, proto, dnat_spec, listen_port, proto, remark },
            0,
        )
    else
        try std.fmt.allocPrintSentinel(
            allocator,
            "add rule {s} dstnat iifname \"{s}\" {s} dport {s} {s} comment \"PORTWEAVER_{s}_{s}_{s}\"",
            .{ NFT_TABLE, src_zone, proto, listen_port, dnat_spec, listen_port, proto, remark },
            0,
        );
    defer allocator.free(cmd);

    try runCommandLogged(ctx, cmd);
}

/// Applies nftables rules for a project using the same decision logic as the UCI firewall backend.
pub fn applyRulesForProject(
    ctx: anytype,
    allocator: std.mem.Allocator,
    project: types.Project,
) !void {
    const should_add_forward = project.add_firewall_forward;

    if (project.port_mappings.len > 0) {
        std.log.info("[NFT] Project '{s}': applying {d} port mapping(s) (open_port={}, forward={})", .{
            project.remark,
            project.port_mappings.len,
            project.open_firewall_port,
            should_add_forward,
        });
    } else {
        std.log.info("[NFT] Project '{s}': port {d} -> {s}:{d} (open_port={}, forward={})", .{
            project.remark,
            project.listen_port,
            project.target_address,
            project.target_port,
            project.open_firewall_port,
            should_add_forward,
        });
    }

    if (project.port_mappings.len > 0) {
        for (project.port_mappings) |mapping| {
            if (project.open_firewall_port) {
                try addExpandedAcceptRules(
                    ctx,
                    allocator,
                    mapping.protocol,
                    mapping.listen_port,
                    project.remark,
                    project.family,
                    project.enable_firewall_stats,
                );
            }

            if (should_add_forward) {
                const default_src_zones = [_][]const u8{"wan"};
                const default_dest_zones = [_][]const u8{"lan"};

                const src_zones = if (project.src_zones.len != 0) project.src_zones else default_src_zones[0..];
                const dest_zones = if (project.dest_zones.len != 0) project.dest_zones else default_dest_zones[0..];

                for (src_zones) |src_zone| {
                    for (dest_zones) |dest_zone| {
                        try addExpandedRedirectRules(
                            ctx,
                            allocator,
                            src_zone,
                            mapping.protocol,
                            mapping.listen_port,
                            dest_zone,
                            project.target_address,
                            mapping.target_port,
                            project.remark,
                            project.family,
                            project.preserve_source_ip,
                            project.enable_firewall_stats,
                        );
                    }
                }
            }
        }
    } else {
        const listen_port_str = try std.fmt.allocPrint(allocator, "{d}", .{project.listen_port});
        defer allocator.free(listen_port_str);

        const target_port_str = try std.fmt.allocPrint(allocator, "{d}", .{project.target_port});
        defer allocator.free(target_port_str);

        if (project.open_firewall_port) {
            try addExpandedAcceptRules(
                ctx,
                allocator,
                project.protocol,
                listen_port_str,
                project.remark,
                project.family,
                project.enable_firewall_stats,
            );
        }

        if (should_add_forward) {
            const default_src_zones = [_][]const u8{"wan"};
            const default_dest_zones = [_][]const u8{"lan"};

            const src_zones = if (project.src_zones.len != 0) project.src_zones else default_src_zones[0..];
            const dest_zones = if (project.dest_zones.len != 0) project.dest_zones else default_dest_zones[0..];

            for (src_zones) |src_zone| {
                for (dest_zones) |dest_zone| {
                    try addExpandedRedirectRules(
                        ctx,
                        allocator,
                        src_zone,
                        project.protocol,
                        listen_port_str,
                        dest_zone,
                        project.target_address,
                        target_port_str,
                        project.remark,
                        project.family,
                        project.preserve_source_ip,
                        project.enable_firewall_stats,
                    );
                }
            }
        }
    }
}

/// Flushes the entire portweaver nftables table.
pub fn clearRules(ctx: anytype) !void {
    std.log.info("[NFT] Flushing portweaver table rules", .{});
    const cmd: [*:0]const u8 = "flush table inet portweaver";
    try runCommandLogged(ctx, cmd);
}

/// Creates the nftables table and chains used by portweaver.
pub fn setupTable(ctx: anytype, allocator: std.mem.Allocator) !void {
    std.log.info("[NFT] Setting up table and chains (inet portweaver)", .{});
    const cmd = try std.fmt.allocPrintSentinel(
        allocator,
        \\add table inet portweaver
        \\add chain inet portweaver dstnat {{ type nat hook prerouting priority -101; }}
        \\add chain inet portweaver srcnat {{ type nat hook postrouting priority 101; }}
        \\add chain inet portweaver input {{ type filter hook input priority 0; }}
        \\add chain inet portweaver forward {{ type filter hook forward priority 0; }}
    ,
        .{},
        0,
    );
    defer allocator.free(cmd);

    try runCommandLogged(ctx, cmd);
}

/// nftables rules are applied immediately, so reload is a no-op.
pub fn reloadFirewall(allocator: std.mem.Allocator) !void {
    _ = allocator;
}

/// Traffic statistics from a named nftables counter.
pub const CounterStats = struct {
    packets: u64 = 0,
    bytes: u64 = 0,
};

/// Reads a named counter via `nft reset counter` (atomic read+reset) in JSON mode,
/// parses the output and returns packet/byte counts.
/// Returns zero values if the counter does not exist.
pub fn getCounterStats(ctx: anytype, allocator: std.mem.Allocator, counter_name: []const u8) !CounterStats {
    const cmd = try std.fmt.allocPrintSentinel(
        allocator,
        "reset counter {s} \"{s}\"",
        .{ NFT_TABLE, counter_name },
        0,
    );
    defer allocator.free(cmd);

    ctx.runCommand(cmd) catch {
        // Counter might not exist yet — return zeros
        return CounterStats{};
    };

    const output = ctx.getOutputMsg() orelse return CounterStats{};
    return parseCounterJson(output) orelse CounterStats{};
}

/// Parses nftables JSON counter output to extract packets and bytes.
/// Expected JSON structure (simplified):
///   { "nftables": [ { "metainfo": ... }, { "counter": { "packets": N, "bytes": N } } ] }
/// Returns null if parsing fails.
fn parseCounterJson(json_str: []const u8) ?CounterStats {
    var result = CounterStats{};

    // Find "packets" and "bytes" values by scanning for their keys.
    // This avoids a full JSON parser dependency.
    if (extractJsonValue(json_str, "packets")) |v| {
        result.packets = std.fmt.parseInt(u64, v, 10) catch 0;
    }
    if (extractJsonValue(json_str, "bytes")) |v| {
        result.bytes = std.fmt.parseInt(u64, v, 10) catch 0;
    }

    return result;
}

/// Extracts the value of a JSON key as a string slice. Handles `"key": <numeric_value>`.
/// Scans for `"key":` pattern and returns the subsequent numeric string.
/// Zero allocations — scans the input directly.
fn extractJsonValue(json_str: []const u8, key: []const u8) ?[]const u8 {
    var pos: usize = 0;
    while (pos + key.len + 3 <= json_str.len) {
        if (json_str[pos] == '"') {
            const key_start = pos + 1;
            const key_end = key_start + key.len;
            if (key_end + 2 <= json_str.len and
                std.mem.eql(u8, json_str[key_start..key_end], key) and
                json_str[key_end] == '"')
            {
                // Found "key", skip to colon
                pos = key_end + 1;
                while (pos < json_str.len and json_str[pos] == ' ') : (pos += 1) {}
                if (pos < json_str.len and json_str[pos] == ':') {
                    pos += 1;
                    while (pos < json_str.len and json_str[pos] == ' ') : (pos += 1) {}
                    const val_start = pos;
                    while (pos < json_str.len and json_str[pos] >= '0' and json_str[pos] <= '9') : (pos += 1) {}
                    if (pos > val_start) return json_str[val_start..pos];
                }
            }
        }
        pos += 1;
    }
    return null;
}

/// Like extractJsonValue but starts scanning from `start_pos`.
/// Used to scope key lookup to a specific counter entry in batch JSON output.
fn extractJsonValueAfter(json_str: []const u8, start_pos: usize, key: []const u8) ?[]const u8 {
    var pos = start_pos;
    while (pos + key.len + 3 <= json_str.len) {
        if (json_str[pos] == '"') {
            const key_start = pos + 1;
            const key_end = key_start + key.len;
            if (key_end + 2 <= json_str.len and
                std.mem.eql(u8, json_str[key_start..key_end], key) and
                json_str[key_end] == '"')
            {
                pos = key_end + 1;
                while (pos < json_str.len and json_str[pos] == ' ') : (pos += 1) {}
                if (pos < json_str.len and json_str[pos] == ':') {
                    pos += 1;
                    while (pos < json_str.len and json_str[pos] == ' ') : (pos += 1) {}
                    const val_start = pos;
                    while (pos < json_str.len and json_str[pos] >= '0' and json_str[pos] <= '9') : (pos += 1) {}
                    if (pos > val_start) return json_str[val_start..pos];
                }
            }
        }
        pos += 1;
    }
    return null;
}

/// Finds a specific named counter in batch JSON output from `nft reset counters`.
/// Scans for `"name":"<counter_name>"` then extracts `"packets"` and `"bytes"`
/// scoped to that entry. Returns null if the counter is not found.
pub fn parseNamedCounter(json_str: []const u8, counter_name: []const u8) ?CounterStats {
    const needle = "\"name\":\"";
    var pos: usize = 0;
    while (pos + needle.len + counter_name.len + 1 <= json_str.len) {
        if (std.mem.startsWith(u8, json_str[pos..], needle)) {
            const val_start = pos + needle.len;
            const val_end = val_start + counter_name.len;
            if (val_end + 1 <= json_str.len and
                json_str[val_end] == '"' and
                std.mem.eql(u8, json_str[val_start..val_end], counter_name))
            {
                var result = CounterStats{};
                if (extractJsonValueAfter(json_str, val_end, "packets")) |v| {
                    result.packets = std.fmt.parseInt(u64, v, 10) catch 0;
                }
                if (extractJsonValueAfter(json_str, val_end, "bytes")) |v| {
                    result.bytes = std.fmt.parseInt(u64, v, 10) catch 0;
                }
                return result;
            }
        }
        pos += 1;
    }
    return null;
}

// Mock context for testing nftables rule generation
const MockContext = struct {
    commands: std.ArrayList([]const u8),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) @This() {
        return .{
            .commands = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *@This()) void {
        for (self.commands.items) |cmd| {
            self.allocator.free(cmd);
        }
        self.commands.deinit(self.allocator);
    }

    pub fn runCommand(self: *@This(), cmd: [*:0]const u8) !void {
        const span = std.mem.span(cmd);
        const duped = try self.allocator.dupe(u8, span);
        try self.commands.append(self.allocator, duped);
    }

    pub fn getErrorMsg(self: *@This()) ?[:0]const u8 {
        _ = self;
        return null;
    }
};

test "addAcceptRule generates correct command" {
    const allocator = std.testing.allocator;
    var mock = MockContext.init(allocator);
    defer mock.deinit();

    try addAcceptRule(&mock, allocator, "tcp", "80", "web", .ipv4, false);

    try std.testing.expectEqual(@as(usize, 1), mock.commands.items.len);
    const cmd = mock.commands.items[0];
    try std.testing.expect(std.mem.indexOf(u8, cmd, "input") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "tcp dport 80 accept") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "PORTWEAVER_80_tcp_web") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "ip saddr 0.0.0.0/0") != null);
}

test "addRedirectRule generates correct DNAT command" {
    const allocator = std.testing.allocator;
    var mock = MockContext.init(allocator);
    defer mock.deinit();

    try addRedirectRule(&mock, allocator, "wan", "tcp", "80", "lan", "192.168.1.100", "8080", "web", .ipv4, false, false);

    try std.testing.expectEqual(@as(usize, 1), mock.commands.items.len);
    const cmd = mock.commands.items[0];
    try std.testing.expect(std.mem.indexOf(u8, cmd, "dnat ip to 192.168.1.100:8080") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "iifname \"wan\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "PORTWEAVER_80_tcp_web") != null);
}

test "addRedirectRule with preserve_source_ip adds NAT rule" {
    const allocator = std.testing.allocator;
    var mock = MockContext.init(allocator);
    defer mock.deinit();

    try addRedirectRule(&mock, allocator, "wan", "tcp", "80", "lan", "192.168.1.100", "8080", "web", .ipv4, true, false);

    // Should generate NAT rule + DNAT rule
    try std.testing.expectEqual(@as(usize, 2), mock.commands.items.len);
    // First command is the srcnat rule
    try std.testing.expect(std.mem.indexOf(u8, mock.commands.items[0], "srcnat") != null);
    try std.testing.expect(std.mem.indexOf(u8, mock.commands.items[0], "oifname \"wan\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mock.commands.items[0], "accept") != null);
    // Second command is the DNAT rule
    try std.testing.expect(std.mem.indexOf(u8, mock.commands.items[1], "dstnat") != null);
}

test "applyRulesForProject handles protocol expansion" {
    const allocator = std.testing.allocator;
    var mock = MockContext.init(allocator);
    defer mock.deinit();

    const project = types.Project{
        .listen_port = 80,
        .target_port = 8080,
        .target_address = "192.168.1.100",
        .protocol = .both,
        .family = .ipv4,
        .remark = "test",
    };

    try applyRulesForProject(&mock, allocator, project);

    // .both -> 2 accept (tcp+udp) + 2 redirect (tcp+udp) = 4 commands
    try std.testing.expectEqual(@as(usize, 4), mock.commands.items.len);

    var has_tcp = false;
    var has_udp = false;
    for (mock.commands.items) |cmd| {
        if (std.mem.indexOf(u8, cmd, "tcp") != null) has_tcp = true;
        if (std.mem.indexOf(u8, cmd, "udp") != null) has_udp = true;
    }
    try std.testing.expect(has_tcp);
    try std.testing.expect(has_udp);
}

test "applyRulesForProject handles family expansion" {
    const allocator = std.testing.allocator;
    var mock = MockContext.init(allocator);
    defer mock.deinit();

    const project = types.Project{
        .listen_port = 80,
        .target_port = 8080,
        .target_address = "::1",
        .protocol = .tcp,
        .family = .any,
        .remark = "test",
    };

    try applyRulesForProject(&mock, allocator, project);

    // .any -> ipv4+ipv6 for both accept and redirect = 4 commands
    try std.testing.expectEqual(@as(usize, 4), mock.commands.items.len);

    // Verify IPv6 DNAT uses ip6 syntax
    var found_ipv6_dnat = false;
    for (mock.commands.items) |cmd| {
        if (std.mem.indexOf(u8, cmd, "dnat ip6 to [::1]:80") != null) found_ipv6_dnat = true;
    }
    try std.testing.expect(found_ipv6_dnat);
}

test "applyRulesForProject handles multi-port mode" {
    const allocator = std.testing.allocator;
    var mock = MockContext.init(allocator);
    defer mock.deinit();

    const mappings = [_]types.PortMapping{
        .{ .listen_port = "8080-8090", .target_port = "80-90", .protocol = .tcp },
    };
    const project = types.Project{
        .target_address = "192.168.1.100",
        .port_mappings = &mappings,
        .remark = "test",
    };

    try applyRulesForProject(&mock, allocator, project);

    // 1 accept + 1 redirect = 2 commands
    try std.testing.expectEqual(@as(usize, 2), mock.commands.items.len);

    var found_port_range = false;
    for (mock.commands.items) |cmd| {
        if (std.mem.indexOf(u8, cmd, "dport 8080-8090") != null) found_port_range = true;
    }
    try std.testing.expect(found_port_range);
}

test "clearRules flushes table" {
    const allocator = std.testing.allocator;
    var mock = MockContext.init(allocator);
    defer mock.deinit();

    try clearRules(&mock);

    try std.testing.expectEqual(@as(usize, 1), mock.commands.items.len);
    try std.testing.expectEqualStrings("flush table inet portweaver", mock.commands.items[0]);
}

test "setupTable creates table and chains" {
    const allocator = std.testing.allocator;
    var mock = MockContext.init(allocator);
    defer mock.deinit();

    try setupTable(&mock, allocator);

    try std.testing.expectEqual(@as(usize, 1), mock.commands.items.len);
    const cmd = mock.commands.items[0];
    try std.testing.expect(std.mem.indexOf(u8, cmd, "add table inet portweaver") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "add chain inet portweaver dstnat") != null);
}

test "addAcceptRule with firewall stats injects counter" {
    const allocator = std.testing.allocator;
    var mock = MockContext.init(allocator);
    defer mock.deinit();

    try addAcceptRule(&mock, allocator, "tcp", "80", "web", .ipv4, true);

    try std.testing.expectEqual(@as(usize, 1), mock.commands.items.len);
    const cmd = mock.commands.items[0];
    try std.testing.expect(std.mem.indexOf(u8, cmd, "counter name \"pw_80_tcp_accept\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "accept") != null);
}

test "addRedirectRule with firewall stats injects dstnat counter" {
    const allocator = std.testing.allocator;
    var mock = MockContext.init(allocator);
    defer mock.deinit();

    try addRedirectRule(&mock, allocator, "wan", "tcp", "80", "lan", "192.168.1.100", "8080", "web", .ipv4, false, true);

    try std.testing.expectEqual(@as(usize, 1), mock.commands.items.len);
    const cmd = mock.commands.items[0];
    try std.testing.expect(std.mem.indexOf(u8, cmd, "counter name \"pw_80_tcp_dstnat\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, cmd, "dnat ip to 192.168.1.100:8080") != null);
}

test "addRedirectRule with firewall stats and preserve_source_ip adds both counters" {
    const allocator = std.testing.allocator;
    var mock = MockContext.init(allocator);
    defer mock.deinit();

    try addRedirectRule(&mock, allocator, "wan", "tcp", "80", "lan", "192.168.1.100", "8080", "web", .ipv4, true, true);

    // srcnat + dstnat = 2 commands, both with counters
    try std.testing.expectEqual(@as(usize, 2), mock.commands.items.len);
    try std.testing.expect(std.mem.indexOf(u8, mock.commands.items[0], "counter name \"pw_80_tcp_srcnat\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, mock.commands.items[1], "counter name \"pw_80_tcp_dstnat\"") != null);
}

test "applyRulesForProject with enable_firewall_stats adds counters to all rules" {
    const allocator = std.testing.allocator;
    var mock = MockContext.init(allocator);
    defer mock.deinit();

    const project = types.Project{
        .listen_port = 80,
        .target_port = 8080,
        .target_address = "192.168.1.100",
        .protocol = .tcp,
        .family = .ipv4,
        .remark = "test",
        .enable_firewall_stats = true,
    };

    try applyRulesForProject(&mock, allocator, project);

    // accept + redirect = 2 commands, both with counters
    try std.testing.expectEqual(@as(usize, 2), mock.commands.items.len);
    for (mock.commands.items) |cmd| {
        try std.testing.expect(std.mem.indexOf(u8, cmd, "counter name") != null);
    }
}

test "enable_app_stats no longer blocks firewall forward" {
    const allocator = std.testing.allocator;
    var mock = MockContext.init(allocator);
    defer mock.deinit();

    const project = types.Project{
        .listen_port = 80,
        .target_port = 8080,
        .target_address = "192.168.1.100",
        .protocol = .tcp,
        .family = .ipv4,
        .remark = "test",
        .enable_app_stats = true,
        .add_firewall_forward = true,
    };

    try applyRulesForProject(&mock, allocator, project);

    // accept + redirect = 2 commands (forward rules ARE generated despite enable_app_stats)
    try std.testing.expectEqual(@as(usize, 2), mock.commands.items.len);
    try std.testing.expect(std.mem.indexOf(u8, mock.commands.items[1], "dstnat") != null);
}

test "counter name contains port and protocol" {
    const allocator = std.testing.allocator;
    var mock = MockContext.init(allocator);
    defer mock.deinit();

    // Port range
    try addAcceptRule(&mock, allocator, "udp", "8080-8090", "test", .any, true);

    // .any → 2 commands (ipv4 + ipv6), both sharing the same counter name
    try std.testing.expectEqual(@as(usize, 2), mock.commands.items.len);
    for (mock.commands.items) |cmd| {
        try std.testing.expect(std.mem.indexOf(u8, cmd, "counter name \"pw_8080-8090_udp_accept\"") != null);
    }
}

test "parseCounterJson extracts packets and bytes" {
    const json =
        \\{"nftables":[{"metainfo":{"json_schema_version":1}},{"counter":{"family":"inet","table":"portweaver","name":"pw_80_tcp_accept","packets":42,"bytes":12345}}]}
    ;
    const result = parseCounterJson(json);
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u64, 42), result.?.packets);
    try std.testing.expectEqual(@as(u64, 12345), result.?.bytes);
}

test "parseCounterJson handles missing counter" {
    const json = "no counter data here";
    const result = parseCounterJson(json);
    // parseCounterJson returns CounterStats{} with zeros when keys not found
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u64, 0), result.?.packets);
    try std.testing.expectEqual(@as(u64, 0), result.?.bytes);
}

test "parseNamedCounter finds specific counter in batch output" {
    const batch_json =
        \\{"nftables":[{"metainfo":{"json_schema_version":1}},{"counter":{"family":"inet","table":"portweaver","name":"pw_80_tcp_dstnat","packets":10,"bytes":1000}},{"counter":{"family":"inet","table":"portweaver","name":"pw_80_tcp_srcnat","packets":5,"bytes":500}}]}
    ;
    const dstnat = parseNamedCounter(batch_json, "pw_80_tcp_dstnat");
    try std.testing.expect(dstnat != null);
    try std.testing.expectEqual(@as(u64, 10), dstnat.?.packets);
    try std.testing.expectEqual(@as(u64, 1000), dstnat.?.bytes);

    const srcnat = parseNamedCounter(batch_json, "pw_80_tcp_srcnat");
    try std.testing.expect(srcnat != null);
    try std.testing.expectEqual(@as(u64, 5), srcnat.?.packets);
    try std.testing.expectEqual(@as(u64, 500), srcnat.?.bytes);
}

test "parseNamedCounter returns null for missing counter" {
    const batch_json =
        \\{"nftables":[{"metainfo":{"json_schema_version":1}},{"counter":{"family":"inet","table":"portweaver","name":"pw_80_tcp_dstnat","packets":10,"bytes":1000}}]}
    ;
    const result = parseNamedCounter(batch_json, "pw_999_udp_accept");
    try std.testing.expect(result == null);
}

test "parseNamedCounter does not leak across counter boundaries" {
    const batch_json =
        \\{"nftables":[{"metainfo":{}},{"counter":{"name":"pw_80_tcp_dstnat","packets":100,"bytes":20000}},{"counter":{"name":"pw_80_tcp_srcnat","packets":50,"bytes":10000}}]}
    ;
    // Verify each counter returns its OWN values, not the other's
    const dstnat = parseNamedCounter(batch_json, "pw_80_tcp_dstnat").?;
    try std.testing.expectEqual(@as(u64, 100), dstnat.packets);
    try std.testing.expectEqual(@as(u64, 20000), dstnat.bytes);

    const srcnat = parseNamedCounter(batch_json, "pw_80_tcp_srcnat").?;
    try std.testing.expectEqual(@as(u64, 50), srcnat.packets);
    try std.testing.expectEqual(@as(u64, 10000), srcnat.bytes);
}
