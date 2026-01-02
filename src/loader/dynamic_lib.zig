const std = @import("std");

/// 动态库加载器，支持自动查找版本化的库文件
pub const DynamicLibLoader = struct {
    lib_handle: ?std.DynLib = null,

    /// 初始化加载器
    pub fn init() DynamicLibLoader {
        return .{ .lib_handle = null };
    }

    /// 释放动态库资源
    pub fn deinit(self: *DynamicLibLoader) void {
        if (self.lib_handle) |*lib| {
            lib.close();
            self.lib_handle = null;
        }
    }

    /// 加载动态库，支持多种查找策略
    /// lib_name: 库名称（不含路径和扩展名），例如 "libuci"
    /// Returns: 加载成功返回 void，失败返回错误
    pub fn load(self: *DynamicLibLoader, lib_name: []const u8) !void {
        if (self.lib_handle != null) return;

        var last_error: ?std.DynLib.Error = null;

        // 策略1: 尝试标准路径
        const standard_paths = [_][]const u8{
            "/lib",
            "/usr/lib",
            "/usr/local/lib",
            ".", // 当前目录
        };

        // 首先尝试无版本号的标准路径
        for (standard_paths) |dir| {
            const paths = [_][]const u8{
                try std.fmt.allocPrint(std.heap.page_allocator, "{s}/{s}.so", .{ dir, lib_name }),
                try std.fmt.allocPrint(std.heap.page_allocator, "{s}.so", .{lib_name}),
            };
            defer {
                std.heap.page_allocator.free(paths[0]);
            }

            for (paths) |path| {
                if (std.DynLib.open(path)) |lib| {
                    self.lib_handle = lib;
                    return;
                } else |err| {
                    last_error = err;
                }
            }
        }

        // 策略2: 动态搜索版本化的库文件
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const allocator = arena.allocator();

        for (standard_paths) |dir| {
            if (std.mem.eql(u8, dir, ".")) continue; // 跳过当前目录的遍历

            var dir_handle = std.fs.openDirAbsolute(dir, .{ .iterate = true }) catch continue;
            defer dir_handle.close();

            var it = dir_handle.iterate();
            while (it.next() catch null) |entry| {
                if (entry.kind != .file) continue;

                // 检查文件名是否以 lib_name.so 开头
                const expected_prefix = try std.fmt.allocPrint(allocator, "{s}.so", .{lib_name});
                if (!std.mem.startsWith(u8, entry.name, expected_prefix)) continue;

                // 构建完整路径
                const full_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir, entry.name });

                if (std.DynLib.open(full_path)) |lib| {
                    self.lib_handle = lib;
                    return;
                } else |err| {
                    last_error = err;
                }
            }
        }

        // 所有策略都失败
        if (last_error) |err| {
            return err;
        }
        return error.LibraryNotFound;
    }

    /// 查找函数符号
    pub fn lookup(self: *DynamicLibLoader, comptime T: type, comptime name: [:0]const u8) !T {
        if (self.lib_handle == null) {
            return error.LibraryNotLoaded;
        }

        return self.lib_handle.?.lookup(T, name) orelse {
            std.log.debug("Failed to lookup function: {s}\n", .{name});
            return error.FunctionNotFound;
        };
    }

    /// 检查库是否已加载
    pub fn isLoaded(self: *const DynamicLibLoader) bool {
        return self.lib_handle != null;
    }
};

/// 缓存函数指针的加载器，用于提高性能
pub fn CachedFunctionLoader(comptime T: type) type {
    return struct {
        const Self = @This();

        loader: *DynamicLibLoader,
        cache: ?T = null,
        name: [:0]const u8,

        pub fn init(loader: *DynamicLibLoader, comptime name: [:0]const u8) Self {
            return .{
                .loader = loader,
                .cache = null,
                .name = name,
            };
        }

        pub fn get(self: *Self) !T {
            if (self.cache) |func| {
                return func;
            }

            const func = try self.loader.lookup(T, self.name);
            self.cache = func;
            return func;
        }
    };
}
