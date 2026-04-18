const build_options = @import("build_options");

const std = @import("std");

const types = @import("types.zig");

pub const ConfigError = types.ConfigError;
pub const AddressFamily = types.AddressFamily;
pub const Protocol = types.Protocol;
pub const FrpcNode = types.FrpcNode;
pub const FrpcForward = types.FrpcForward;
pub const PortMapping = types.PortMapping;
pub const Project = types.Project;
pub const Config = types.Config;
pub const ErrorType = types.ErrorType;
pub const ValidationError = types.ValidationError;
pub const ErrorCollector = types.ErrorCollector;

pub const parseBool = types.parseBool;
pub const parsePort = types.parsePort;
pub const parseFamily = types.parseFamily;
pub const parseProtocol = types.parseProtocol;
pub const dupeIfNonEmpty = types.dupeIfNonEmpty;

const provider = @import("provider.zig");
pub const UciProvider = provider.UciProvider;
pub const JsonProvider = provider.JsonProvider;
pub const loadFrom = provider.loadFrom;
const uci_loader = if (build_options.uci_mode)
    @import("uci_loader.zig")
else
    struct {
        pub fn loadFromUci(_: std.mem.Allocator, _: *@import("../uci/mod.zig").UciContext, _: []const u8) !Config {
            return error.UnsupportedFeature;
        }
    };
pub const loadFromUci = uci_loader.loadFromUci;

const json_loader = if (build_options.uci_mode)
    struct {
        pub fn loadFromJsonFile(_: std.mem.Allocator, _: []const u8) !Config {
            return ConfigError.UnsupportedFeature;
        }
    }
else
    @import("json_loader.zig");

pub const loadFromJsonFile = json_loader.loadFromJsonFile;

test "config mod: type and function re-exports match source modules" {
    try std.testing.expect(ConfigError == types.ConfigError);
    try std.testing.expect(AddressFamily == types.AddressFamily);
    try std.testing.expect(Protocol == types.Protocol);
    try std.testing.expect(FrpcNode == types.FrpcNode);
    try std.testing.expect(FrpcForward == types.FrpcForward);
    try std.testing.expect(PortMapping == types.PortMapping);
    try std.testing.expect(Project == types.Project);
    try std.testing.expect(Config == types.Config);
    try std.testing.expect(ErrorType == types.ErrorType);
    try std.testing.expect(ValidationError == types.ValidationError);
    try std.testing.expect(ErrorCollector == types.ErrorCollector);

    try std.testing.expect(parseBool == types.parseBool);
    try std.testing.expect(parsePort == types.parsePort);
    try std.testing.expect(parseFamily == types.parseFamily);
    try std.testing.expect(parseProtocol == types.parseProtocol);
    try std.testing.expect(dupeIfNonEmpty == types.dupeIfNonEmpty);

    try std.testing.expect(UciProvider == provider.UciProvider);
    try std.testing.expect(JsonProvider == provider.JsonProvider);
    try std.testing.expect(loadFrom == provider.loadFrom);
}

test "config mod: top-level json loader follows feature gate" {
    if (build_options.uci_mode) {
        try std.testing.expectError(ConfigError.UnsupportedFeature, loadFromJsonFile(std.testing.allocator, "/tmp/nonexistent-portweaver-config.json"));
    } else {
        try std.testing.expectError(error.FileNotFound, loadFromJsonFile(std.testing.allocator, "/tmp/nonexistent-portweaver-config.json"));
    }
}
