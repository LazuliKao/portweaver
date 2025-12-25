const build_options = @import("build_options");

const std = @import("std");

const types = @import("types.zig");

pub const ConfigError = types.ConfigError;
pub const AddressFamily = types.AddressFamily;
pub const Protocol = types.Protocol;
pub const Project = types.Project;
pub const Config = types.Config;

pub const parseBool = types.parseBool;
pub const parsePort = types.parsePort;
pub const parseFamily = types.parseFamily;
pub const parseProtocol = types.parseProtocol;
pub const dupeIfNonEmpty = types.dupeIfNonEmpty;

const provider = @import("provider.zig");
pub const UciProvider = provider.UciProvider;
pub const JsonProvider = provider.JsonProvider;
pub const loadFrom = provider.loadFrom;

pub const loadFromUci = @import("uci_loader.zig").loadFromUci;

const json_loader = if (build_options.enable_json)
    @import("json_loader.zig")
else
    struct {
        pub fn loadFromJsonFile(_: std.mem.Allocator, _: []const u8) !Config {
            return ConfigError.UnsupportedFeature;
        }
    };

pub const loadFromJsonFile = json_loader.loadFromJsonFile;
