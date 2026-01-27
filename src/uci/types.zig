const std = @import("std");
const libuci = @import("libuci.zig");
const c = libuci.c;

fn toUciError(code: c_int) !void {
    return switch (code) {
        c.UCI_OK => {},
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

fn listToElement(node: *c.uci_list) *c.uci_element {
    return @fieldParentPtr("list", node);
}
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

        const result = try libuci.uci_unload(self.ctx, self.pkg);
        try toUciError(result);
        self.pkg = null;
    }

    pub fn save(self: UciPackage) !void {
        if (self.ctx == null or self.pkg == null) {
            return UciError.UciErrInval;
        }

        const result = try libuci.uci_save(self.ctx, self.pkg);
        try toUciError(result);
    }

    /// Commit changes to this package. Note: commit may update the package pointer.
    pub fn commit(self: *UciPackage, overwrite: bool) !void {
        if (self.ctx == null or self.pkg == null) {
            return UciError.UciErrInval;
        }

        const result = try libuci.uci_commit(self.ctx, &self.pkg, overwrite);
        try toUciError(result);
    }

    pub fn addSection(self: UciPackage, section_type: [*c]const u8) !UciSection {
        if (self.ctx == null or self.pkg == null) {
            return UciError.UciErrInval;
        }

        var section: [*c]c.uci_section = null;
        const result = try libuci.uci_add_section(self.ctx, self.pkg, section_type, &section);
        try toUciError(result);
        return UciSection{ .section = section };
    }
};

pub const UciSection = struct {
    section: [*c]c.uci_section,

    pub fn isNull(self: UciSection) bool {
        return self.section == null;
    }

    pub fn name(self: UciSection) ?[*c]const u8 {
        if (self.section == null) return null;
        return self.section.*.e.name;
    }

    pub fn sectionType(self: UciSection) ?[*c]const u8 {
        if (self.section == null) return null;
        return self.section.*.type;
    }

    pub fn options(self: UciSection) UciOptionIterator {
        if (self.section == null) {
            return UciOptionIterator.init(null);
        }
        return UciOptionIterator.init(&self.section.*.options);
    }
};

pub const UciOption = struct {
    option: [*c]c.uci_option,

    pub fn isNull(self: UciOption) bool {
        return self.option == null;
    }

    pub fn name(self: UciOption) ?[*c]const u8 {
        if (self.option == null) return null;
        return self.option.*.e.name;
    }

    pub fn isString(self: UciOption) bool {
        if (self.option == null) return false;
        return self.option.*.type == c.UCI_TYPE_STRING;
    }

    pub fn isList(self: UciOption) bool {
        if (self.option == null) return false;
        return self.option.*.type == c.UCI_TYPE_LIST;
    }

    pub fn getString(self: UciOption) ?[*c]const u8 {
        if (self.option == null) return null;
        if (self.option.*.type != c.UCI_TYPE_STRING) return null;
        return self.option.*.v.string;
    }

    /// Iterate list values when option type is list.
    pub fn values(self: UciOption) UciValueIterator {
        if (self.option == null) {
            return UciValueIterator.init(null);
        }
        if (self.option.*.type != c.UCI_TYPE_LIST) {
            return UciValueIterator.init(null);
        }

        return UciValueIterator.init(&self.option.*.v.list);
    }
};
pub const UciSectionIterator = struct {
    head: ?*c.uci_list,
    cur: ?*c.uci_list,

    pub fn init(head: ?*c.uci_list) UciSectionIterator {
        if (head == null) return .{ .head = null, .cur = null };
        return .{ .head = head, .cur = @ptrCast(head.?.*.next) };
    }

    pub fn next(self: *UciSectionIterator) ?UciSection {
        const head = self.head orelse return null;
        const cur = self.cur orelse return null;
        if (cur == head) return null;

        const element = listToElement(cur);
        self.cur = @ptrCast(cur.*.next);
        const section_ptr: *c.uci_section = @fieldParentPtr("e", element);
        return UciSection{ .section = @ptrCast(section_ptr) };
    }
};

pub const UciOptionIterator = struct {
    head: ?*c.uci_list,
    cur: ?*c.uci_list,

    pub fn init(head: ?*c.uci_list) UciOptionIterator {
        if (head == null) return .{ .head = null, .cur = null };
        return .{ .head = head, .cur = @ptrCast(head.?.*.next) };
    }

    pub fn next(self: *UciOptionIterator) ?UciOption {
        const head = self.head orelse return null;
        const cur = self.cur orelse return null;
        if (cur == head) return null;

        const element = listToElement(cur);
        self.cur = @ptrCast(cur.*.next);
        const option_ptr: *c.uci_option = @fieldParentPtr("e", element);
        return UciOption{ .option = @ptrCast(option_ptr) };
    }
};

pub const UciValueIterator = struct {
    head: ?*c.uci_list,
    cur: ?*c.uci_list,

    pub fn init(head: ?*c.uci_list) UciValueIterator {
        if (head == null) return .{ .head = null, .cur = null };
        return .{ .head = head, .cur = @ptrCast(head.?.*.next) };
    }

    /// Returns the list item's string value (stored as uci_element.name).
    pub fn next(self: *UciValueIterator) ?[*c]const u8 {
        const head = self.head orelse return null;
        const cur = self.cur orelse return null;
        if (cur == head) return null;

        const element = listToElement(cur);
        self.cur = @ptrCast(cur.*.next);
        return element.*.name;
    }
};

pub const UciPtr = struct {
    ptr: c.uci_ptr,

    pub fn init() UciPtr {
        return .{ .ptr = std.mem.zeroes(c.uci_ptr) };
    }

    pub fn isLookupComplete(self: UciPtr) bool {
        return (self.ptr.flags & c.UCI_LOOKUP_COMPLETE) != 0;
    }
};

pub const UciStringList = struct {
    list: [*c][*c]u8,

    pub fn isNull(self: UciStringList) bool {
        return self.list == null;
    }

    /// Frees memory allocated by `uci_list_configs`.
    pub fn deinit(self: *UciStringList) void {
        if (self.list == null) return;

        var i: usize = 0;
        while (self.list[i] != null) : (i += 1) {
            std.c.free(self.list[i]);
        }
        std.c.free(self.list);
        self.list = null;
    }

    pub fn get(self: UciStringList, index: usize) ?[*c]const u8 {
        if (self.list == null) return null;
        const item = self.list[index];
        if (item == null) return null;
        return item;
    }
};

pub const UciContext = struct {
    ctx: [*c]c.uci_context,

    /// Allocate a new UCI context
    pub fn alloc() !UciContext {
        std.log.debug("Calling uci_alloc_context...", .{});
        const ctx = try libuci.uci_alloc_context();
        std.log.debug("uci_alloc_context returned: {*}", .{ctx});
        if (ctx == null) {
            std.log.debug("Failed to allocate UCI context", .{});
            return UciError.UciErrMem;
        }

        std.log.debug("Successfully allocated UCI context", .{});
        return UciContext{
            .ctx = ctx,
        };
    }

    /// Free the UCI context
    pub fn free(self: UciContext) void {
        if (self.ctx != null) {
            libuci.uci_free_context(self.ctx) catch |err| {
                std.log.debug("Error freeing context: {}", .{err});
            };
        }
    }

    /// Load a UCI config file
    pub fn load(self: UciContext, name: [*c]const u8) !UciPackage {
        if (self.ctx == null) {
            return UciError.UciErrInval;
        }

        var package: [*c]c.uci_package = null;
        std.log.debug(
            "Calling uci_load with ctx={*}, name={s}, package_ptr={*}",
            .{ self.ctx, std.mem.span(name), &package },
        );
        const result = try libuci.uci_load(self.ctx, name, &package);
        std.log.debug("uci_load returned: {}, package={*}", .{ result, package });

        try toUciError(result);
        return UciPackage{ .ctx = self.ctx, .pkg = package };
    }

    /// Unload a UCI config package
    pub fn unload(self: UciContext, package: [*c]c.uci_package) !void {
        if (self.ctx == null) {
            return UciError.UciErrInval;
        }

        const result = try libuci.uci_unload(self.ctx, package);
        try toUciError(result);
    }

    /// Get error string for the last error
    pub fn getErrorStr(self: UciContext, allocator: std.mem.Allocator, prefix: [*c]const u8) ![]u8 {
        if (self.ctx == null) {
            return UciError.UciErrInval;
        }

        var dest: [*c]u8 = null;
        try libuci.uci_get_errorstr(self.ctx, &dest, prefix);
        if (dest == null) {
            return allocator.dupe(u8, "");
        }
        defer std.c.free(dest);
        const len = std.mem.len(dest);
        const result = try allocator.dupe(u8, dest[0..len]);
        return result;
    }

    /// Print error message
    pub fn perror(self: UciContext, prefix: [*c]const u8) void {
        if (self.ctx != null) {
            libuci.uci_perror(self.ctx, prefix) catch |err| {
                std.log.debug("Error in perror: {}", .{err});
            };
        }
    }

    pub fn lookupPtr(self: UciContext, ptr: *UciPtr, str: [*c]u8, extended: bool) !void {
        if (self.ctx == null) return UciError.UciErrInval;
        const result = try libuci.uci_lookup_ptr(self.ctx, @ptrCast(&ptr.ptr), str, extended);
        try toUciError(result);
    }

    pub fn parsePtr(self: UciContext, ptr: *UciPtr, str: [*c]u8) !void {
        if (self.ctx == null) return UciError.UciErrInval;
        const result = try libuci.uci_parse_ptr(self.ctx, @ptrCast(&ptr.ptr), str);
        try toUciError(result);
    }

    pub fn set(self: UciContext, ptr: *UciPtr) !void {
        if (self.ctx == null) return UciError.UciErrInval;
        const result = try libuci.uci_set(self.ctx, @ptrCast(&ptr.ptr));
        try toUciError(result);
    }

    pub fn addList(self: UciContext, ptr: *UciPtr) !void {
        if (self.ctx == null) return UciError.UciErrInval;
        const result = try libuci.uci_add_list(self.ctx, @ptrCast(&ptr.ptr));
        try toUciError(result);
    }

    pub fn delList(self: UciContext, ptr: *UciPtr) !void {
        if (self.ctx == null) return UciError.UciErrInval;
        const result = try libuci.uci_del_list(self.ctx, @ptrCast(&ptr.ptr));
        try toUciError(result);
    }

    pub fn rename(self: UciContext, ptr: *UciPtr) !void {
        if (self.ctx == null) return UciError.UciErrInval;
        const result = try libuci.uci_rename(self.ctx, @ptrCast(&ptr.ptr));
        try toUciError(result);
    }

    pub fn delete(self: UciContext, ptr: *UciPtr) !void {
        if (self.ctx == null) return UciError.UciErrInval;
        const result = try libuci.uci_delete(self.ctx, @ptrCast(&ptr.ptr));
        try toUciError(result);
    }

    pub fn revert(self: UciContext, ptr: *UciPtr) !void {
        if (self.ctx == null) return UciError.UciErrInval;
        const result = try libuci.uci_revert(self.ctx, @ptrCast(&ptr.ptr));
        try toUciError(result);
    }

    pub fn reorderSection(self: UciContext, section: UciSection, pos: c_int) !void {
        if (self.ctx == null) return UciError.UciErrInval;
        if (section.section == null) return UciError.UciErrInval;
        const result = try libuci.uci_reorder_section(self.ctx, section.section, pos);
        try toUciError(result);
    }

    pub fn setSavedir(self: UciContext, dir: [*c]const u8) !void {
        if (self.ctx == null) return UciError.UciErrInval;
        const result = try libuci.uci_set_savedir(self.ctx, dir);
        try toUciError(result);
    }

    pub fn setConfdir(self: UciContext, dir: [*c]const u8) !void {
        if (self.ctx == null) return UciError.UciErrInval;
        const result = try libuci.uci_set_confdir(self.ctx, dir);
        try toUciError(result);
    }

    pub fn setConf2dir(self: UciContext, dir: [*c]const u8) !void {
        if (self.ctx == null) return UciError.UciErrInval;
        const result = try libuci.uci_set_conf2dir(self.ctx, dir);
        try toUciError(result);
    }

    pub fn addDeltaPath(self: UciContext, dir: [*c]const u8) !void {
        if (self.ctx == null) return UciError.UciErrInval;
        const result = try libuci.uci_add_delta_path(self.ctx, dir);
        try toUciError(result);
    }

    pub fn setBackend(self: UciContext, name: [*c]const u8) !void {
        if (self.ctx == null) return UciError.UciErrInval;
        const result = try libuci.uci_set_backend(self.ctx, name);
        try toUciError(result);
    }

    pub fn listConfigs(self: UciContext) !UciStringList {
        if (self.ctx == null) return UciError.UciErrInval;

        var list: [*c][*c]u8 = null;
        const result = try libuci.uci_list_configs(self.ctx, &list);
        try toUciError(result);
        return .{ .list = list };
    }
};
