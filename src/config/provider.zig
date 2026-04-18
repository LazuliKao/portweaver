const std = @import("std");
const uci = @import("../uci/mod.zig");
const build_options = @import("build_options");
const types = @import("types.zig");
const uci_loader = @import("uci_loader.zig");
const file_log = @import("../file_log.zig");

/// Compile-time generic config loader.
///
/// Best-practice Zig polymorphism: any `source` that provides
/// `pub fn load(self, allocator) !types.Config` works.
pub fn loadFrom(allocator: std.mem.Allocator, source: anytype) !types.Config {
    const T = @TypeOf(source);
    comptime {
        if (!@hasDecl(T, "load")) {
            @compileError("Config source must provide: pub fn load(self, allocator) !Config");
        }
    }
    return source.load(allocator);
}

pub const UciProvider = struct {
    ctx: uci.UciContext,
    package_name: [*c]const u8,

    pub fn load(self: UciProvider, allocator: std.mem.Allocator) !types.Config {
        return uci_loader.loadFromUci(allocator, self.ctx, self.package_name);
    }
};

pub const JsonProvider = if (build_options.uci_mode) struct {
    path: []const u8,
    pub fn load(self: JsonProvider, allocator: std.mem.Allocator) !types.Config {
        _ = self;
        _ = allocator;
        return types.ConfigError.UnsupportedFeature;
    }
} else struct {
    path: []const u8,
    pub fn load(self: JsonProvider, allocator: std.mem.Allocator) !types.Config {
        return @import("json_loader.zig").loadFromJsonFile(allocator, self.path);
    }
};

test "config provider: loadFrom delegates to source load" {
    const TestSource = struct {
        fn load(_: @This(), allocator: std.mem.Allocator) !types.Config {
            const projects = try allocator.alloc(types.Project, 0);
            errdefer allocator.free(projects);

            const ddns_configs = try allocator.alloc(types.DdnsConfig, 0);
            errdefer allocator.free(ddns_configs);

            const log_config = try file_log.defaultLogConfig(allocator);

            return .{
                .log_config = log_config,
                .projects = projects,
                .frpc_nodes = std.StringHashMap(types.FrpcNode).init(allocator),
                .frps_nodes = std.StringHashMap(types.FrpsNode).init(allocator),
                .ddns_configs = ddns_configs,
            };
        }
    };

    var cfg = try loadFrom(std.testing.allocator, TestSource{});
    defer cfg.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), cfg.projects.len);
    try std.testing.expectEqual(@as(usize, 0), cfg.ddns_configs.len);
    try std.testing.expectEqual(@as(usize, 0), cfg.frpc_nodes.count());
    try std.testing.expectEqual(@as(usize, 0), cfg.frps_nodes.count());
}

test "config provider: json provider matches feature gate" {
    const provider = JsonProvider{ .path = "/tmp/nonexistent-portweaver-config.json" };

    if (build_options.uci_mode) {
        try std.testing.expectError(types.ConfigError.UnsupportedFeature, provider.load(std.testing.allocator));
    } else {
        try std.testing.expectError(error.FileNotFound, provider.load(std.testing.allocator));
    }
}
