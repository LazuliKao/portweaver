const std = @import("std");
const uci_loader = @import("libuci.zig");

const c = uci_loader.c;
pub const UciError = error{
    UciOk,
    UciErrMem,
    UciErrInval,
    UciErrNotfound,
    UciErrIo,
    UciErrParse,
    UciErrDuplicate,
    UciErrUnknown,
    UciErrLast,
    LibNotLoaded,
    LibLoadFailed,
};

/// Convert UCI error code to Zig error type
pub fn toUciError(code: c_int) !void {
    return switch (code) {
        c.UCI_OK => {}, // UCI_OK
        c.UCI_ERR_MEM => UciError.UciErrMem,
        c.UCI_ERR_INVAL => UciError.UciErrInval,
        c.UCI_ERR_NOTFOUND => UciError.UciErrNotfound,
        c.UCI_ERR_IO => UciError.UciErrIo,
        c.UCI_ERR_PARSE => UciError.UciErrParse,
        c.UCI_ERR_DUPLICATE => UciError.UciErrDuplicate,
        c.UCI_ERR_UNKNOWN => UciError.UciErrUnknown,
        c.UCI_ERR_LAST => UciError.UciErrLast,
        else => UciError.UciErrUnknown,
    };
}

pub const UciPackage = struct {
    ctx: [*c]c.uci_context,
    pkg: [*c]c.uci_package,

    pub fn isNull(self: UciPackage) bool {
        return self.pkg == null;
    }

    pub fn unload(self: *UciPackage) !void {
        if (self.ctx == null) {
            return UciError.UciErrInval;
        }
        if (self.pkg == null) {
            return;
        }

        const result = try uci_loader.uci_unload(self.ctx, self.pkg);
        try toUciError(result);
        self.pkg = null;
    }
};

pub const UciContext = struct {
    ctx: [*c]c.uci_context,

    /// Allocate a new UCI context
    pub fn alloc() !UciContext {
        std.debug.print("Calling uci_alloc_context...\n", .{});
        const ctx = try uci_loader.uci_alloc_context();
        std.debug.print("uci_alloc_context returned: {*}\n", .{ctx});
        if (ctx == null) {
            std.debug.print("Failed to allocate UCI context\n", .{});
            return UciError.UciErrMem;
        }

        std.debug.print("Successfully allocated UCI context\n", .{});
        return UciContext{
            .ctx = ctx,
        };
    }

    /// Free the UCI context
    pub fn free(self: UciContext) void {
        if (self.ctx != null) {
            uci_loader.uci_free_context(self.ctx) catch |err| {
                std.debug.print("Error freeing context: {}\n", .{err});
            };
        }
    }

    /// Load a UCI config file
    pub fn load(self: UciContext, name: [*c]const u8) !UciPackage {
        if (self.ctx == null) {
            return UciError.UciErrInval;
        }

        var package: [*c]c.uci_package = null;
        std.debug.print(
            "Calling uci_load with ctx={*}, name={s}, package_ptr={*}\n",
            .{ self.ctx, std.mem.span(name), &package },
        );
        const result = try uci_loader.uci_load(self.ctx, name, &package);
        std.debug.print("uci_load returned: {}, package={*}\n", .{ result, package });

        try toUciError(result);
        return UciPackage{ .ctx = self.ctx, .pkg = package };
    }

    /// Unload a UCI config package
    pub fn unload(self: UciContext, package: [*c]c.uci_package) !void {
        if (self.ctx == null) {
            return UciError.UciErrInval;
        }

        const result = try uci_loader.uci_unload(self.ctx, package);
        try toUciError(result);
    }

    /// Get error string for the last error
    pub fn getErrorStr(self: UciContext, allocator: std.mem.Allocator, prefix: [*c]const u8) ![]u8 {
        if (self.ctx == null) {
            return UciError.UciErrInval;
        }

        var dest: [*c]u8 = undefined;
        try uci_loader.uci_get_errorstr(self.ctx, &dest, prefix);
        const len = std.mem.len(dest);
        const result = try allocator.dupe(u8, dest[0..len]);
        return result;
    }

    /// Print error message
    pub fn perror(self: UciContext, prefix: [*c]const u8) void {
        if (self.ctx != null) {
            uci_loader.uci_perror(self.ctx, prefix) catch |err| {
                std.debug.print("Error in perror: {}\n", .{err});
            };
        }
    }
};

/// Get all sections and options from a UCI package
pub fn listConfigSections(_: std.mem.Allocator, package: [*c]c.uci_package) !void {
    // 简化实现：由于我们现在使用 opaque 类型，
    // 实际的遍历需要通过 C 函数接口
    std.debug.print("Package loaded successfully!\n", .{});
    // print [*c]*c.uci_context

    _ = package;
}
