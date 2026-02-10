const std = @import("std");
const uci = @import("../uci/mod.zig");
const types = @import("../config/types.zig");

pub const FirewallError = error{
    UciOperationFailed,
    InvalidConfiguration,
};

/// 设置 UCI 选项的辅助函数
fn setUciOption(
    ctx: uci.UciContext,
    allocator: std.mem.Allocator,
    package: []const u8,
    section: []const u8,
    option: []const u8,
    value: []const u8,
) !void {
    var ptr = uci.UciPtr.init();
    const ptr_str = try std.fmt.allocPrintSentinel(
        allocator,
        "{s}.{s}.{s}={s}",
        .{ package, section, option, value },
        0,
    );
    defer allocator.free(ptr_str);

    try ctx.parsePtr(&ptr, @constCast(@as([*c]u8, @ptrCast(ptr_str.ptr))));
    try ctx.set(&ptr);
}

/// 添加 UCI 列表选项的辅助函数
fn addUciListOption(
    ctx: uci.UciContext,
    allocator: std.mem.Allocator,
    package: []const u8,
    section: []const u8,
    option: []const u8,
    value: []const u8,
) !void {
    var ptr = uci.UciPtr.init();
    const ptr_str = try std.fmt.allocPrintSentinel(
        allocator,
        "{s}.{s}.{s}={s}",
        .{ package, section, option, value },
        0,
    );
    defer allocator.free(ptr_str);

    try ctx.parsePtr(&ptr, @constCast(@as([*c]u8, @ptrCast(ptr_str.ptr))));
    try ctx.addList(&ptr);
}

/// 添加防火墙接受规则 (firewall rule)
/// 支持端口范围如 "8080-8090" 或单个端口如 "8080"
pub fn addFirewallAcceptRule(
    ctx: uci.UciContext,
    allocator: std.mem.Allocator,
    proto: []const u8,
    port_str: []const u8,
    remark: []const u8,
    family: ?types.AddressFamily,
) !void {
    var fw_pkg = try ctx.load("firewall");
    defer fw_pkg.unload() catch {};

    // 添加一个新的 rule section
    var section = try fw_pkg.addSection("rule");
    const sec_name = uci.cStr(section.name() orelse return FirewallError.UciOperationFailed);

    // 构建规则名称: PORTWEAVER_{port}_{proto}_{remark}
    const rule_name = try std.fmt.allocPrint(
        allocator,
        "PORTWEAVER_{s}_{s}_{s}",
        .{ port_str, proto, remark },
    );
    defer allocator.free(rule_name);

    // 设置各个选项 - 使用 UciPtr
    try setUciOption(ctx, allocator, "firewall", sec_name, "name", rule_name);
    try setUciOption(ctx, allocator, "firewall", sec_name, "src", "*");

    try setUciOption(ctx, allocator, "firewall", sec_name, "dest_port", port_str);

    // 处理协议 (tcp,udp 需要拆分为列表)
    var proto_iter = std.mem.splitSequence(u8, proto, ",");
    while (proto_iter.next()) |p| {
        try addUciListOption(ctx, allocator, "firewall", sec_name, "proto", p);
    }

    try setUciOption(ctx, allocator, "firewall", sec_name, "target", "ACCEPT");

    // 设置地址族
    if (family) |f| {
        const family_str = switch (f) {
            .ipv4 => "ipv4",
            .ipv6 => "ipv6",
            .any => null,
        };
        if (family_str) |fs| {
            try setUciOption(ctx, allocator, "firewall", sec_name, "family", fs);
        }
    }

    const overwrite = false;
    try fw_pkg.commit(overwrite);
}

/// 添加防火墙 NAT 规则
/// 添加防火墙 NAT 规则（ACCEPT - 禁用地址重写，保留源 IP）
/// 支持端口范围
pub fn addFirewallNat(
    ctx: uci.UciContext,
    allocator: std.mem.Allocator,
    src_zone: []const u8,
    proto: []const u8,
    listen_port_str: []const u8,
    dest_ip: []const u8,
    dest_port_str: []const u8,
    remark: []const u8,
    family: ?types.AddressFamily,
) !void {
    var fw_pkg = try ctx.load("firewall");
    defer fw_pkg.unload() catch {};

    var section = try fw_pkg.addSection("nat");
    const sec_name = uci.cStr(section.name() orelse return FirewallError.UciOperationFailed);

    const rule_name = try std.fmt.allocPrint(
        allocator,
        "PORTWEAVER_{s}_{s}_{s}",
        .{ listen_port_str, proto, remark },
    );
    defer allocator.free(rule_name);

    try setUciOption(ctx, allocator, "firewall", sec_name, "name", rule_name);
    try setUciOption(ctx, allocator, "firewall", sec_name, "src", src_zone);

    var proto_iter = std.mem.splitSequence(u8, proto, ",");
    while (proto_iter.next()) |p| {
        try addUciListOption(ctx, allocator, "firewall", sec_name, "proto", p);
    }

    try setUciOption(ctx, allocator, "firewall", sec_name, "dest_ip", dest_ip);
    try setUciOption(ctx, allocator, "firewall", sec_name, "dest_port", dest_port_str);
    try setUciOption(ctx, allocator, "firewall", sec_name, "snat_port", listen_port_str);
    try setUciOption(ctx, allocator, "firewall", sec_name, "target", "ACCEPT");

    if (family) |f| {
        const family_str = switch (f) {
            .ipv4 => "ipv4",
            .ipv6 => "ipv6",
            .any => null,
        };
        if (family_str) |fs| {
            try setUciOption(ctx, allocator, "firewall", sec_name, "family", fs);
        }
    }

    const overwrite = false;
    try fw_pkg.commit(overwrite);
}

/// 添加防火墙重定向规则 (DNAT)
/// 支持端口范围
pub fn addFirewallRedirectRule(
    ctx: uci.UciContext,
    allocator: std.mem.Allocator,
    src_zone: []const u8,
    proto: []const u8,
    listen_port_str: []const u8,
    dest_zone: []const u8,
    dest_ip: []const u8,
    dest_port_str: []const u8,
    remark: []const u8,
    family: ?types.AddressFamily,
    preserve_source_ip: bool,
) !void {
    // 当需要保留源 IP 时添加 NAT 规则
    if (preserve_source_ip) {
        try addFirewallNat(
            ctx,
            allocator,
            src_zone,
            proto,
            listen_port_str,
            dest_ip,
            dest_port_str,
            remark,
            family,
        );
    }

    var fw_pkg = try ctx.load("firewall");
    defer fw_pkg.unload() catch {};

    // 添加 redirect section
    var section = try fw_pkg.addSection("redirect");
    const sec_name = uci.cStr(section.name() orelse return FirewallError.UciOperationFailed);

    const rule_name = try std.fmt.allocPrint(
        allocator,
        "PORTWEAVER_{s}_{s}_{s}",
        .{ listen_port_str, proto, remark },
    );
    defer allocator.free(rule_name);

    try setUciOption(ctx, allocator, "firewall", sec_name, "name", rule_name);
    try setUciOption(ctx, allocator, "firewall", sec_name, "src", src_zone);

    try setUciOption(ctx, allocator, "firewall", sec_name, "src_dport", listen_port_str);

    var proto_iter = std.mem.splitSequence(u8, proto, ",");
    while (proto_iter.next()) |p| {
        try addUciListOption(ctx, allocator, "firewall", sec_name, "proto", p);
    }

    try setUciOption(ctx, allocator, "firewall", sec_name, "dest", dest_zone);
    try setUciOption(ctx, allocator, "firewall", sec_name, "dest_ip", dest_ip);

    try setUciOption(ctx, allocator, "firewall", sec_name, "dest_port", dest_port_str);

    try setUciOption(ctx, allocator, "firewall", sec_name, "target", "DNAT");

    if (family) |f| {
        const family_str = switch (f) {
            .ipv4 => "ipv4",
            .ipv6 => "ipv6",
            .any => null,
        };
        if (family_str) |fs| {
            try setUciOption(ctx, allocator, "firewall", sec_name, "family", fs);
        }
    }

    const overwrite = false;
    try fw_pkg.commit(overwrite);
}

/// 清理所有 PORTWEAVER 相关的防火墙规则
pub fn clearFirewallRules(ctx: uci.UciContext, allocator: std.mem.Allocator) !void {
    var fw_pkg = try ctx.load("firewall");
    defer fw_pkg.unload() catch {};

    var sections_to_delete = std.array_list.Managed([]const u8).init(allocator);
    defer {
        for (sections_to_delete.items) |name| {
            allocator.free(name);
        }
        sections_to_delete.deinit();
    }

    // 遍历所有 section，找到名称包含 PORTWEAVER_ 的
    var sec_it = uci.sections(fw_pkg);
    while (sec_it.next()) |sec| {
        var opt_it = sec.options();
        while (opt_it.next()) |opt| {
            const opt_name = uci.cStr(opt.name());
            if (std.mem.eql(u8, opt_name, "name")) {
                if (opt.isString()) {
                    const name_val = uci.cStr(opt.getString());
                    if (std.mem.startsWith(u8, name_val, "PORTWEAVER_")) {
                        const sec_name = uci.cStr(sec.name());
                        try sections_to_delete.append(try allocator.dupe(u8, sec_name));
                        break;
                    }
                }
            }
        }
    }

    // 删除找到的 sections
    for (sections_to_delete.items) |sec_name| {
        var ptr = uci.UciPtr.init();
        const ptr_str = try std.fmt.allocPrintSentinel(
            allocator,
            "firewall.{s}",
            .{sec_name},
            0,
        );
        defer allocator.free(ptr_str);

        try ctx.parsePtr(&ptr, @constCast(@as([*c]u8, @ptrCast(ptr_str.ptr))));
        try ctx.delete(&ptr);
    }

    const overwrite = false;
    try fw_pkg.commit(overwrite);
}

/// 根据配置项应用防火墙规则
///
/// 逻辑说明：
/// 1. open_firewall_port=true: 添加 ACCEPT 规则（放通端口）
/// 2. add_firewall_forward=true: 添加 DNAT/redirect 规则（防火墙层转发）
/// 3. enable_app_forward=true + add_firewall_forward=false: 只需要 ACCEPT 规则
/// 4. enable_app_forward=false + add_firewall_forward=true: 需要 ACCEPT + DNAT 规则
/// 5. enable_stats=true: 跳过 DNAT/redirect 规则（与防火墙转发互斥），但仍需 ACCEPT 规则
pub fn applyFirewallRulesForProject(
    ctx: uci.UciContext,
    allocator: std.mem.Allocator,
    project: types.Project,
) !void {
    // 统计模式与防火墙转发互斥，但仍需要 ACCEPT 规则来放通端口
    const should_add_forward = project.add_firewall_forward and !project.enable_stats;
    const family: ?types.AddressFamily = if (project.family == .any) null else project.family;

    // 检查是单端口模式还是多端口模式
    if (project.port_mappings.len > 0) {
        // 多端口模式：为每个映射添加规则
        for (project.port_mappings) |mapping| {
            const proto = switch (mapping.protocol) {
                .tcp => "tcp",
                .udp => "udp",
                .both => "tcp,udp",
            };

            // 如果需要打开防火墙端口
            if (project.open_firewall_port) {
                if (mapping.protocol == .both) {
                    if (project.family == .any or project.family == .ipv4) {
                        try addFirewallAcceptRule(ctx, allocator, "tcp", mapping.listen_port, project.remark, .ipv4);
                        try addFirewallAcceptRule(ctx, allocator, "udp", mapping.listen_port, project.remark, .ipv4);
                    }
                    if (project.family == .any or project.family == .ipv6) {
                        try addFirewallAcceptRule(ctx, allocator, "tcp", mapping.listen_port, project.remark, .ipv6);
                        try addFirewallAcceptRule(ctx, allocator, "udp", mapping.listen_port, project.remark, .ipv6);
                    }
                } else {
                    if (project.family == .any) {
                        try addFirewallAcceptRule(ctx, allocator, proto, mapping.listen_port, project.remark, null);
                    } else {
                        try addFirewallAcceptRule(ctx, allocator, proto, mapping.listen_port, project.remark, family);
                    }
                }
            }

            // 只有在明确启用防火墙转发时才添加 DNAT/redirect 规则
            // 应用层转发不需要这些规则
            // 统计模式下也跳过（与防火墙转发互斥）
            if (should_add_forward) {
                const default_src_zones = [_][]const u8{"wan"};
                const default_dest_zones = [_][]const u8{"lan"};

                const src_zones = if (project.src_zones.len != 0) project.src_zones else default_src_zones[0..];
                const dest_zones = if (project.dest_zones.len != 0) project.dest_zones else default_dest_zones[0..];

                for (src_zones) |src_zone| {
                    for (dest_zones) |dest_zone| {
                        try addFirewallRedirectRule(
                            ctx,
                            allocator,
                            src_zone,
                            proto,
                            mapping.listen_port,
                            dest_zone,
                            project.target_address,
                            mapping.target_port,
                            project.remark,
                            family,
                            project.preserve_source_ip,
                        );
                    }
                }
            }
        }
    } else {
        // 单端口模式：使用原有逻辑
        const proto = switch (project.protocol) {
            .tcp => "tcp",
            .udp => "udp",
            .both => "tcp,udp",
        };

        const listen_port_str = try std.fmt.allocPrint(allocator, "{d}", .{project.listen_port});
        defer allocator.free(listen_port_str);

        const target_port_str = try std.fmt.allocPrint(allocator, "{d}", .{project.target_port});
        defer allocator.free(target_port_str);

        // 如果需要打开防火墙端口
        if (project.open_firewall_port) {
            // 处理 tcp,udp 需要分别添加规则
            if (project.protocol == .both) {
                // IPv4 和 IPv6 分别处理
                if (project.family == .any or project.family == .ipv4) {
                    try addFirewallAcceptRule(ctx, allocator, "tcp", listen_port_str, project.remark, .ipv4);
                    try addFirewallAcceptRule(ctx, allocator, "udp", listen_port_str, project.remark, .ipv4);
                }
                if (project.family == .any or project.family == .ipv6) {
                    try addFirewallAcceptRule(ctx, allocator, "tcp", listen_port_str, project.remark, .ipv6);
                    try addFirewallAcceptRule(ctx, allocator, "udp", listen_port_str, project.remark, .ipv6);
                }
            } else {
                // 单协议情况
                if (project.family == .any) {
                    // 不指定 family 时添加规则
                    try addFirewallAcceptRule(ctx, allocator, proto, listen_port_str, project.remark, null);
                } else {
                    // 指定了 family
                    try addFirewallAcceptRule(ctx, allocator, proto, listen_port_str, project.remark, family);
                }
            }
        }

        // 只有在明确启用防火墙转发时才添加 DNAT/redirect 规则
        // 应用层转发不需要这些规则
        // 统计模式下也跳过（与防火墙转发互斥）
        if (should_add_forward) {
            const default_src_zones = [_][]const u8{"wan"};
            const default_dest_zones = [_][]const u8{"lan"};

            const src_zones = if (project.src_zones.len != 0) project.src_zones else default_src_zones[0..];
            const dest_zones = if (project.dest_zones.len != 0) project.dest_zones else default_dest_zones[0..];

            for (src_zones) |src_zone| {
                for (dest_zones) |dest_zone| {
                    try addFirewallRedirectRule(
                        ctx,
                        allocator,
                        src_zone,
                        proto,
                        listen_port_str,
                        dest_zone,
                        project.target_address,
                        target_port_str,
                        project.remark,
                        family,
                        project.preserve_source_ip,
                    );
                }
            }
        }
    }
}

extern "c" fn fork() i32;
extern "c" fn execve([*:0]const u8, [*:null]?[*:0]const u8, [*:null]?[*:0]const u8) i32;
extern "c" fn waitpid(i32, *i32, i32) i32;

/// 重新加载防火墙配置
pub fn reloadFirewall(allocator: std.mem.Allocator) !void {
    // 使用 fork/execve 避免复杂的 stdio 管理
    const pid = fork();
    if (pid < 0) {
        return FirewallError.UciOperationFailed;
    }

    if (pid == 0) {
        // 子进程
        const argv = [_:null]?[*:0]const u8{
            @ptrCast(@constCast(@as([*:0]const u8, "/etc/init.d/firewall"))),
            @ptrCast(@constCast(@as([*:0]const u8, "reload"))),
            null,
        };
        const envp = [_:null]?[*:0]const u8{null};

        _ = execve("/etc/init.d/firewall", @ptrCast(@constCast(&argv)), @ptrCast(@constCast(&envp)));
        // 如果 execve 返回则出错
        std.process.exit(1);
    } else {
        // 父进程
        var status: i32 = 0;
        _ = allocator;
        _ = waitpid(pid, &status, 0);
    }
}
