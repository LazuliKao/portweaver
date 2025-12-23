const std = @import("std");

// 从 C 头文件导入类型定义
const c = @cImport({
    @cInclude("uci.h");
});
// 定义函数指针类型 - 使用与 @cImport 生成的完全匹配的类型
const UciAllocContextFn = *const fn () callconv(.c) [*c]c.uci_context;
const UciFreeContextFn = *const fn ([*c]c.uci_context) callconv(.c) void;
const UciLoadFn = *const fn (
    [*c]c.uci_context,
    [*:0]const u8,
    *?*c.uci_package,
) callconv(.c) c_int;
const UciUnloadFn = *const fn ([*c]c.uci_context, [*c]c.uci_package) callconv(.c) c_int;
const UciPerrorFn = *const fn ([*c]c.uci_context, [*c]const u8) callconv(.c) void;
const UciGetErrorstrFn = *const fn ([*c]c.uci_context, [*c]const u8, [*c]const u8) callconv(.c) void;

// 动态加载的库实例（线程安全使用静态变量）
var lib_loaded: bool = false;
var uci_lib: std.DynLib = undefined;
var uci_alloc_context: UciAllocContextFn = undefined;
var uci_free_context: UciFreeContextFn = undefined;
var uci_load: UciLoadFn = undefined;
var uci_unload: UciUnloadFn = undefined;
var uci_perror: UciPerrorFn = undefined;
var uci_get_errorstr: UciGetErrorstrFn = undefined;

// 初始化动态库
pub fn initLibUci() !void {
    if (lib_loaded) {
        std.debug.print("UCI library already loaded\n", .{});
        return;
    }

    // 尝试多个可能的库路径
    const lib_paths = [_][]const u8{
        "/lib/libuci.so.20250120",
        "/lib/libuci.so",
        "libuci.so",
    };

    var last_error: ?std.DynLib.Error = null;

    for (lib_paths) |path| {
        std.debug.print("Attempting to load libuci from: {s}\n", .{path});
        uci_lib = std.DynLib.open(path) catch |err| {
            std.debug.print("Failed to open {s}: {}\n", .{ path, err });
            last_error = err;
            continue;
        };

        std.debug.print("Successfully opened {s}, loading symbols...\n", .{path});

        // 加载所有函数
        uci_alloc_context = uci_lib.lookup(UciAllocContextFn, "uci_alloc_context") orelse {
            std.debug.print("Failed to lookup uci_alloc_context\n", .{});
            last_error = error.FileNotFound;
            continue;
        };
        uci_free_context = uci_lib.lookup(UciFreeContextFn, "uci_free_context") orelse {
            std.debug.print("Failed to lookup uci_free_context\n", .{});
            last_error = error.FileNotFound;
            continue;
        };
        uci_load = uci_lib.lookup(UciLoadFn, "uci_load") orelse {
            std.debug.print("Failed to lookup uci_load\n", .{});
            last_error = error.FileNotFound;
            continue;
        };
        uci_unload = uci_lib.lookup(UciUnloadFn, "uci_unload") orelse {
            std.debug.print("Failed to lookup uci_unload\n", .{});
            last_error = error.FileNotFound;
            continue;
        };
        uci_perror = uci_lib.lookup(UciPerrorFn, "uci_perror") orelse {
            std.debug.print("Failed to lookup uci_perror\n", .{});
            last_error = error.FileNotFound;
            continue;
        };
        uci_get_errorstr = uci_lib.lookup(UciGetErrorstrFn, "uci_get_errorstr") orelse {
            std.debug.print("Failed to lookup uci_get_errorstr\n", .{});
            last_error = error.FileNotFound;
            continue;
        };
        std.debug.print("Successfully loaded all UCI symbols from {s}\n", .{path});
        lib_loaded = true;
        return;
    }

    std.debug.print("Failed to load libuci from any path\n", .{});
    if (last_error) |err| {
        return err;
    }
    return error.LibLoadFailed;
}

// 使用从 C 导入的真实类型
pub const uci_context = c.uci_context;
pub const uci_package = c.uci_package;
pub const uci_element = c.uci_element;
pub const uci_section = c.uci_section;
pub const uci_option = c.uci_option;
pub const uci_list = c.uci_list;

pub const UCI_TYPE_STRING = 0;
pub const UCI_TYPE_LIST = 1;

pub const UciError = error{
    UciOk,
    UciErrMem,
    UciErrInval,
    UciErrNotfound,
    UciErrIo,
    UciErrParse,
    UciErrDuplicate,
    UciErrUnknown,
    LibNotLoaded,
    LibLoadFailed,
};

/// Convert UCI error code to Zig error type
pub fn toUciError(code: c_int) !void {
    return switch (code) {
        0 => {}, // UCI_OK
        1 => UciError.UciErrMem,
        2 => UciError.UciErrInval,
        3 => UciError.UciErrNotfound,
        4 => UciError.UciErrIo,
        5 => UciError.UciErrParse,
        6 => UciError.UciErrDuplicate,
        7 => UciError.UciErrUnknown,
        else => UciError.UciErrUnknown,
    };
}

pub const UciContext = struct {
    ctx: [*c]c.uci_context,

    /// Allocate a new UCI context
    pub fn alloc() !UciContext {
        // 确保库已加载
        try initLibUci();

        std.debug.print("Calling uci_alloc_context...\n", .{});
        const ctx = uci_alloc_context();
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
            uci_free_context(self.ctx);
        }
    }

    /// Load a UCI config file
    pub fn load(self: UciContext, name: [*c]const u8) ![*c]c.uci_package {
        if (self.ctx == null) {
            return UciError.UciErrInval;
        }

        var package: ?*c.uci_package = null;
        std.debug.print("Calling uci_load with ctx={*}, name={s}, package_ptr={*}, func={*}\n", .{ self.ctx, name, &package, uci_load });
        const result = uci_load(self.ctx, "network", &package);
        std.debug.print("uci_load returned: {}, package={*}\n", .{ result, package });

        try toUciError(result);
        return package;
    }

    /// Unload a UCI config package
    pub fn unload(self: UciContext, package: [*c]c.uci_package) !void {
        if (self.ctx == null) {
            return UciError.UciErrInval;
        }

        const result = uci_unload(self.ctx, package);
        try toUciError(result);
    }

    /// Get error string for the last error
    pub fn getErrorStr(self: UciContext, allocator: std.mem.Allocator, prefix: [*c]const u8) ![]u8 {
        if (self.ctx == null) {
            return UciError.UciErrInval;
        }

        var dest: [*c]u8 = undefined;
        uci_get_errorstr(self.ctx, &dest, prefix);
        const len = std.mem.len(dest);
        const result = try allocator.dupe(u8, dest[0..len]);
        return result;
    }

    /// Print error message
    pub fn perror(self: UciContext, prefix: [*c]const u8) void {
        if (self.ctx != null) {
            uci_perror(self.ctx, prefix);
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

/// Print all firewall configuration settings
pub fn printFirewallConfig(allocator: std.mem.Allocator) !void {
    std.debug.print("Loading firewall configuration...\n", .{});

    // Allocate UCI context
    var uci_ctx = try UciContext.alloc();
    defer uci_ctx.free();
    std.debug.print("UCI context allocated\n", .{});

    // // Try to load the firewall config
    const config_name: [*c]const u8 = "firewall";
    const package = uci_ctx.load(config_name) catch |err| {
        std.debug.print("Error loading firewall config: {}\n", .{err});
        uci_ctx.perror(config_name);
        return;
    };

    if (package != null) {
        defer {
            uci_ctx.unload(package) catch |err| {
                std.debug.print("Error unloading package: {}\n", .{err});
            };
        }

        std.debug.print("Firewall configuration:\n", .{});
        try listConfigSections(allocator, package);
    } else {
        std.debug.print("Firewall package is null\n", .{});
    }
}
