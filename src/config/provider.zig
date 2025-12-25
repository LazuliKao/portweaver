const std = @import("std");
const uci = @import("../uci/mod.zig");
const build_options = @import("build_options");
const types = @import("types.zig");
const uci_loader = @import("uci_loader.zig");

const json_loader = if (build_options.enable_json) @import("json_loader.zig") else struct {
    pub fn loadFromJsonFile(_: std.mem.Allocator, _: []const u8) !types.Config {
        return types.ConfigError.UnsupportedFeature;
    }
};

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

pub const JsonProvider = if (build_options.enable_json) struct {
    path: []const u8,

    pub fn load(self: JsonProvider, allocator: std.mem.Allocator) !types.Config {
        return json_loader.loadFromJsonFile(allocator, self.path);
    }
} else struct {
    path: []const u8,

    pub fn load(self: JsonProvider, allocator: std.mem.Allocator) !types.Config {
        _ = self;
        _ = allocator;
        return types.ConfigError.UnsupportedFeature;
    }
};

test "config: generic provider compiles" {
    const fake_ctx = uci.UciContext{ .ctx = null };
    const p = UciProvider{ .ctx = fake_ctx, .package_name = "portweaver" };
    // Only typechecks; should error at runtime with ctx=null.
    _ = loadFrom(std.testing.allocator, p) catch {};
}
