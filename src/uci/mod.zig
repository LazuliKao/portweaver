const std = @import("std");
const libuci = @import("libuci.zig");
const t = @import("types.zig");
const c = libuci.c;

pub const UciError = t.UciError;
pub const UciContext = t.UciContext;
pub const UciPackage = t.UciPackage;
pub const UciSection = t.UciSection;
pub const UciOption = t.UciOption;
pub const UciPtr = t.UciPtr;
pub const UciStringList = t.UciStringList;
pub const UciSectionIterator = t.UciSectionIterator;
pub const UciOptionIterator = t.UciOptionIterator;
pub const UciValueIterator = t.UciValueIterator;

/// Convert UCI error code to Zig error type
pub fn toUciError(code: c_int) !void {
    return switch (code) {
        c.UCI_OK => {}, // UCI_OK
        c.UCI_ERR_MEM => t.UciError.UciErrMem,
        c.UCI_ERR_INVAL => t.UciError.UciErrInval,
        c.UCI_ERR_NOTFOUND => t.UciError.UciErrNotfound,
        c.UCI_ERR_IO => t.UciError.UciErrIo,
        c.UCI_ERR_PARSE => t.UciError.UciErrParse,
        c.UCI_ERR_DUPLICATE => t.UciError.UciErrDuplicate,
        c.UCI_ERR_UNKNOWN => t.UciError.UciErrUnknown,
        c.UCI_ERR_LAST => t.UciError.UciErrLast,
        else => t.UciError.UciErrUnknown,
    };
}

fn listToElement(node: *c.uci_list) *c.uci_element {
    return @fieldParentPtr("list", node);
}

pub fn cStr(ptr: ?[*c]const u8) []const u8 {
    if (ptr == null) return "";
    return std.mem.span(@as([*:0]const u8, @ptrCast(ptr.?)));
}

pub fn sections(package: t.UciPackage) t.UciSectionIterator {
    if (package.pkg == null) {
        return t.UciSectionIterator.init(null);
    }
    return t.UciSectionIterator.init(&package.pkg.*.sections);
}

pub fn validateText(str: [*c]const u8) !bool {
    return try libuci.uci_validate_text(str);
}
