const std = @import("std");
const builtin = @import("builtin");
pub const c = @cImport({
    @cInclude("forwarder.h");
});

/// Capability passed only while executing on a forwarder runtime thread.
/// It intentionally wraps the C runtime pointer so forwarder lifecycle APIs do
/// not accept raw runtime pointers from arbitrary caller threads.
pub const RuntimeThreadToken = *opaque {};

pub inline fn runtimeToken(ctx: *c.forwarder_runtime_t) RuntimeThreadToken {
    return @ptrCast(ctx);
}

pub inline fn runtimeFromToken(token: RuntimeThreadToken) *c.forwarder_runtime_t {
    return @ptrCast(@alignCast(token));
}

const AllocationHeader = extern struct {
    len: usize,
};

/// Backend-specific diagnostic helper kept isolated in the runtime adapter.
/// The current forwarder runtime backend is libuv, so this calls the libuv C API.
pub fn backendVersion() [:0]const u8 {
    return std.mem.span(c.uv_get_version_string());
}

/// Backend-specific version logging for the currently linked runtime backend.
pub inline fn logBackendVersion() void {
    std.log.debug("forwarder runtime backend version: {s}", .{backendVersion()});
}

export fn forwarder_c_malloc(ctx: ?*anyopaque, size: usize) callconv(.c) ?*anyopaque {
    const allocator_ptr: *std.mem.Allocator = @ptrCast(@alignCast(ctx orelse return null));
    const header_size = @sizeOf(AllocationHeader);
    const total_size = std.math.add(usize, header_size, size) catch {
        return null;
    };
    const buf = allocator_ptr.alignedAlloc(u8, std.mem.Alignment.@"8", total_size) catch {
        return null;
    };

    const header: *AllocationHeader = @ptrCast(buf.ptr);
    header.* = .{ .len = total_size };

    return buf.ptr + header_size;
}

export fn forwarder_c_free(ctx: ?*anyopaque, ptr: ?*anyopaque) callconv(.c) void {
    if (ptr) |p| {
        const allocator_ptr: *std.mem.Allocator = @ptrCast(@alignCast(ctx orelse return));
        const header_size = @sizeOf(AllocationHeader);
        const data_ptr: [*]u8 = @ptrCast(@alignCast(p));
        const base_ptr = data_ptr - header_size;
        const header: *const AllocationHeader = @ptrCast(@alignCast(base_ptr));
        const buf: []align(@alignOf(AllocationHeader)) u8 = @alignCast(base_ptr[0..header.len]);
        allocator_ptr.free(buf);
    }
}

pub fn buildAllocator(allocator: *std.mem.Allocator) c.forwarder_allocator_t {
    return .{
        .ctx = allocator,
        .malloc_cb = forwarder_c_malloc,
        .free_cb = forwarder_c_free,
    };
}
