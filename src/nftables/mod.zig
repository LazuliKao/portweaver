const std = @import("std");
const libnftables = @import("libnftables.zig");

pub const c = libnftables.c;
pub const isLoaded = libnftables.isLoaded;

pub const NftablesContext = struct {
    const Self = @This();

    ctx: ?*libnftables.c.nft_ctx,

    pub fn init(allocator: std.mem.Allocator) !Self {
        _ = allocator;

        const ctx = try libnftables.nft_ctx_new(0) orelse return error.NftablesInitFailed;
        errdefer libnftables.nft_ctx_free(ctx) catch |err| {
            std.log.err("failed to free nftables context during init cleanup: {}", .{err});
        };

        if (try libnftables.nft_ctx_buffer_output(ctx) != 0) {
            return error.NftablesInitFailed;
        }

        if (try libnftables.nft_ctx_buffer_error(ctx) != 0) {
            return error.NftablesInitFailed;
        }

        return .{ .ctx = ctx };
    }

    pub fn deinit(self: *Self) void {
        if (self.ctx) |ctx| {
            libnftables.nft_ctx_free(ctx) catch |err| {
                std.log.err("failed to free nftables context: {}", .{err});
            };
            self.ctx = null;
        }
    }

    pub fn runCommand(self: *Self, cmd: [*:0]const u8) !void {
        const result = try libnftables.nft_run_cmd_from_buffer(self.ctx, cmd);
        if (result == 0) return;

        if (self.getErrorMsg()) |msg| {
            std.log.err("nftables command failed: {s}", .{msg});
        } else {
            std.log.err("nftables command failed", .{});
        }

        return error.NftablesCommandFailed;
    }

    pub fn getOutputMsg(self: *Self) ?[:0]const u8 {
        const msg = libnftables.nft_ctx_get_output_buffer(self.ctx) catch return null;
        const text = msg orelse return null;
        if (text[0] == 0) return null;
        return std.mem.span(text);
    }

    pub fn getErrorMsg(self: *Self) ?[:0]const u8 {
        const msg = libnftables.nft_ctx_get_error_buffer(self.ctx) catch return null;
        const text = msg orelse return null;
        if (text[0] == 0) return null;
        return std.mem.span(text);
    }

    pub fn setDryRun(self: *Self, dry: bool) !void {
        try libnftables.nft_ctx_set_dry_run(self.ctx, dry);
    }

    pub fn setDebug(self: *Self, level: u32) !void {
        try libnftables.nft_ctx_set_debug(self.ctx, level);
    }

    /// Sets output flags on the nftables context.
    pub fn setOutputFlags(self: *Self, flags: u32) !void {
        try libnftables.nft_ctx_output_set_flags(self.ctx, flags);
    }

    /// Enables JSON output mode for the nftables context.
    /// When enabled, commands like `list counters` return JSON instead of text.
    pub fn setJsonOutput(self: *Self) !void {
        // NFT_CTX_OUTPUT_JSON = 1 << 4 = 16
        const NFT_CTX_OUTPUT_JSON: u32 = 1 << 4;
        try self.setOutputFlags(NFT_CTX_OUTPUT_JSON);
    }

    pub fn listRules(self: *Self) ?[:0]const u8 {
        self.runCommand("list table inet portweaver") catch {
            // Table might not exist yet
            return null;
        };
        return self.getOutputMsg();
    }
};
