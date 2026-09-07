const std = @import("std");
const compat = @import("../compat.zig");

pub const MAX_CONTENT_BYTES: usize = 1024 * 1024;

pub const Kind = enum {
    frpc,
    frps,

    pub fn fromString(value: []const u8) !Kind {
        if (std.mem.eql(u8, value, "frpc")) return .frpc;
        if (std.mem.eql(u8, value, "frps")) return .frps;
        return error.InvalidArgument;
    }
};

const OpenedTarget = struct {
    parent: std.Io.Dir,
    basename: []const u8,

    fn deinit(self: OpenedTarget) void {
        self.parent.close(compat.io());
    }
};

/// Validates text before it crosses the FRP C API or reaches persistent storage.
pub fn validateContent(content: []const u8) !void {
    if (content.len > MAX_CONTENT_BYTES) return error.FileTooBig;
    if (std.mem.indexOfScalar(u8, content, 0) != null) return error.InvalidArgument;
}

/// Reads an external FRP configuration after resolving every component relative
/// to a trusted, opened directory handle without following symlinks.
pub fn read(allocator: std.mem.Allocator, root: []const u8, path: []const u8) ![]u8 {
    const target = try openTarget(root, path);
    defer target.deinit();

    var file = try target.parent.openFile(compat.io(), target.basename, .{
        .allow_directory = false,
        .follow_symlinks = false,
        .resolve_beneath = true,
    });
    defer file.close(compat.io());

    const stat = try file.stat(compat.io());
    if (stat.kind != .file) return error.InvalidArgument;
    if (stat.size > MAX_CONTENT_BYTES) return error.FileTooBig;

    const content = try allocator.alloc(u8, @intCast(stat.size));
    errdefer allocator.free(content);
    const bytes_read = try file.readPositionalAll(compat.io(), content, 0);
    if (bytes_read != content.len) return error.UnexpectedEndOfFile;
    try validateContent(content);
    return content;
}

/// Atomically replaces an external FRP configuration within its existing parent
/// directory. The caller must validate the FRP semantics before invoking this.
pub fn write(root: []const u8, path: []const u8, content: []const u8) !void {
    try validateContent(content);
    const target = try openTarget(root, path);
    defer target.deinit();

    // Reject an existing symlink or non-regular destination before replacement.
    var existing = target.parent.openFile(compat.io(), target.basename, .{
        .allow_directory = false,
        .follow_symlinks = false,
        .resolve_beneath = true,
    }) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    if (existing) |*file| {
        defer file.close(compat.io());
        if ((try file.stat(compat.io())).kind != .file) return error.InvalidArgument;
    }

    var atomic_file = try target.parent.createFileAtomic(compat.io(), target.basename, .{
        .permissions = .fromMode(0o600),
        .replace = true,
    });
    defer atomic_file.deinit(compat.io());

    try atomic_file.file.writeStreamingAll(compat.io(), content);
    try atomic_file.file.sync(compat.io());
    try atomic_file.replace(compat.io());
}

fn openTarget(root: []const u8, path: []const u8) !OpenedTarget {
    try validateRoot(root);
    if (!std.fs.path.isAbsolute(path) or std.mem.indexOfScalar(u8, path, 0) != null) {
        return error.InvalidArgument;
    }

    const root_len = trimmedRootLen(root);
    if (path.len <= root_len or !std.mem.eql(u8, path[0..root_len], root[0..root_len]) or path[root_len] != '/') {
        return error.AccessDenied;
    }

    const relative = path[root_len + 1 ..];
    const basename = std.fs.path.basename(relative);
    if (!isValidComponent(basename) or !hasAllowedExtension(basename)) return error.InvalidArgument;

    var dir = try openDirectoryPath(root);
    errdefer dir.close(compat.io());

    const parent_relative = std.fs.path.dirname(relative) orelse "";
    var components = std.mem.splitScalar(u8, parent_relative, '/');
    while (components.next()) |component| {
        if (component.len == 0) continue;
        if (!isValidComponent(component)) return error.InvalidArgument;
        const child = try dir.openDir(compat.io(), component, .{
            .follow_symlinks = false,
            .access_sub_paths = true,
        });
        dir.close(compat.io());
        dir = child;
    }

    return .{ .parent = dir, .basename = basename };
}

fn openDirectoryPath(path: []const u8) !std.Io.Dir {
    var dir = std.Io.Dir.cwd();
    var has_owned_dir = false;
    errdefer if (has_owned_dir) dir.close(compat.io());

    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (component.len == 0) continue;
        if (!isValidComponent(component)) return error.InvalidArgument;
        const child = try dir.openDir(compat.io(), component, .{
            .follow_symlinks = false,
            .access_sub_paths = true,
        });
        if (has_owned_dir) dir.close(compat.io());
        dir = child;
        has_owned_dir = true;
    }
    if (!has_owned_dir) return error.InvalidArgument;
    return dir;
}

fn validateRoot(root: []const u8) !void {
    if (!std.fs.path.isAbsolute(root) or std.mem.eql(u8, root, "/") or std.mem.indexOfScalar(u8, root, 0) != null) {
        return error.InvalidArgument;
    }

    var components = std.mem.splitScalar(u8, root, '/');
    while (components.next()) |component| {
        if (component.len == 0) continue;
        if (!isValidComponent(component)) return error.InvalidArgument;
    }
}

fn trimmedRootLen(root: []const u8) usize {
    var len = root.len;
    while (len > 1 and root[len - 1] == '/') : (len -= 1) {}
    return len;
}

fn isValidComponent(component: []const u8) bool {
    return component.len > 0 and
        !std.mem.eql(u8, component, ".") and
        !std.mem.eql(u8, component, "..") and
        std.mem.indexOfScalar(u8, component, 0) == null;
}

fn hasAllowedExtension(basename: []const u8) bool {
    return std.mem.endsWith(u8, basename, ".toml") or
        std.mem.endsWith(u8, basename, ".yaml") or
        std.mem.endsWith(u8, basename, ".yml") or
        std.mem.endsWith(u8, basename, ".json");
}

test "external FRP target paths reject escapes and unsupported extensions" {
    try validateRoot("/etc/portweaver");
    try std.testing.expectError(error.InvalidArgument, validateRoot("/"));
    try std.testing.expectError(error.InvalidArgument, validateRoot("/etc/../portweaver"));
    try std.testing.expectError(error.InvalidArgument, validateRoot("etc/portweaver"));
    try std.testing.expect(hasAllowedExtension("frps.toml"));
    try std.testing.expect(!hasAllowedExtension("frps.ini"));
}

test "external FRP content is bounded and cannot contain NUL" {
    try validateContent("bindPort = 7000");
    try std.testing.expectError(error.InvalidArgument, validateContent("bad\x00content"));
    var oversized: [MAX_CONTENT_BYTES + 1]u8 = undefined;
    try std.testing.expectError(error.FileTooBig, validateContent(&oversized));
}
