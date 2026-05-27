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
) !void {
    switch (family) {
        .any => {
            try addAcceptRule(ctx, allocator, proto, port_str, remark, .ipv4);
            try addAcceptRule(ctx, allocator, proto, port_str, remark, .ipv6);
        },
        .ipv4, .ipv6 => try addAcceptRule(ctx, allocator, proto, port_str, remark, family),
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
) !void {
    switch (family) {
        .any => {
            try addRedirectRule(
                ctx,
                allocator,
                src_zone,
                proto,
                listen_port,
                dest_zone,
                dest_ip,
                dest_port,
                remark,
                .ipv4,
                preserve_source_ip,
            );
            try addRedirectRule(
                ctx,
                allocator,
                src_zone,
                proto,
                listen_port,
                dest_zone,
                dest_ip,
                dest_port,
                remark,
                .ipv6,
                preserve_source_ip,
            );
        },
        .ipv4, .ipv6 => try addRedirectRule(
            ctx,
            allocator,
            src_zone,
            proto,
            listen_port,
            dest_zone,
            dest_ip,
            dest_port,
            remark,
            family,
            preserve_source_ip,
        ),
    }
}

fn addExpandedAcceptRules(
    ctx: anytype,
    allocator: std.mem.Allocator,
    protocol: types.Protocol,
    port_str: []const u8,
    remark: []const u8,
    family: types.AddressFamily,
) !void {
    switch (protocol) {
        .tcp => try addAcceptRulesForProtocolFamily(ctx, allocator, "tcp", port_str, remark, family),
        .udp => try addAcceptRulesForProtocolFamily(ctx, allocator, "udp", port_str, remark, family),
        .both => {
            try addAcceptRulesForProtocolFamily(ctx, allocator, "tcp", port_str, remark, family);
            try addAcceptRulesForProtocolFamily(ctx, allocator, "udp", port_str, remark, family);
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
) !void {
    switch (protocol) {
        .tcp => try addRedirectRulesForProtocolFamily(
            ctx,
            allocator,
            src_zone,
            "tcp",
            listen_port,
            dest_zone,
            dest_ip,
            dest_port,
            remark,
            family,
            preserve_source_ip,
        ),
        .udp => try addRedirectRulesForProtocolFamily(
            ctx,
            allocator,
            src_zone,
            "udp",
            listen_port,
            dest_zone,
            dest_ip,
            dest_port,
            remark,
            family,
            preserve_source_ip,
        ),
        .both => {
            try addRedirectRulesForProtocolFamily(
                ctx,
                allocator,
                src_zone,
                "tcp",
                listen_port,
                dest_zone,
                dest_ip,
                dest_port,
                remark,
                family,
                preserve_source_ip,
            );
            try addRedirectRulesForProtocolFamily(
                ctx,
                allocator,
                src_zone,
                "udp",
                listen_port,
                dest_zone,
                dest_ip,
                dest_port,
                remark,
                family,
                preserve_source_ip,
            );
        },
    }
}

/// Adds an ACCEPT rule to the input chain.
pub fn addAcceptRule(
    ctx: anytype,
    allocator: std.mem.Allocator,
    proto: []const u8,
    port_str: []const u8,
    remark: []const u8,
    family: ?types.AddressFamily,
) !void {
    const cmd = try std.fmt.allocPrintSentinel(
        allocator,
        "add rule {s} input{s} {s} dport {s} accept comment \"PORTWEAVER_{s}_{s}_{s}\"",
        .{ NFT_TABLE, familyInputMatch(family), proto, port_str, port_str, proto, remark },
        0,
    );
    defer allocator.free(cmd);

    try runCommandLogged(ctx, cmd);
}

/// Adds a NAT rule used when preserve_source_ip is enabled.
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
) !void {
    const addr_keyword = familyAddrKeyword(family);
    const cmd = try std.fmt.allocPrintSentinel(
        allocator,
        "add rule {s} srcnat oifname \"{s}\" {s} dport {s} {s} daddr {s} {s} dport {s} accept comment \"PORTWEAVER_{s}_{s}_{s}\"",
        .{ NFT_TABLE, src_zone, proto, listen_port, addr_keyword, dest_ip, proto, dest_port, listen_port, proto, remark },
        0,
    );
    defer allocator.free(cmd);

    try runCommandLogged(ctx, cmd);
}

/// Adds a DNAT rule and optional NAT rule.
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
) !void {
    _ = dest_zone;

    if (preserve_source_ip) {
        try addNatRule(ctx, allocator, src_zone, proto, listen_port, dest_ip, dest_port, remark, family);
    }

    const dnat_spec = try dnatTargetSpec(allocator, family, dest_ip, dest_port);
    defer allocator.free(dnat_spec);

    const cmd = try std.fmt.allocPrintSentinel(
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
    const should_add_forward = project.add_firewall_forward and !project.enable_stats;

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
                    );
                }
            }
        }
    }
}

/// Flushes the entire portweaver nftables table.
pub fn clearRules(ctx: anytype) !void {
    const cmd: [*:0]const u8 = "flush table inet portweaver";
    try runCommandLogged(ctx, cmd);
}

/// Creates the nftables table and chains used by portweaver.
pub fn setupTable(ctx: anytype, allocator: std.mem.Allocator) !void {
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

    try addAcceptRule(&mock, allocator, "tcp", "80", "web", .ipv4);

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

    try addRedirectRule(&mock, allocator, "wan", "tcp", "80", "lan", "192.168.1.100", "8080", "web", .ipv4, false);

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

    try addRedirectRule(&mock, allocator, "wan", "tcp", "80", "lan", "192.168.1.100", "8080", "web", .ipv4, true);

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
