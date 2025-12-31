const std = @import("std");
const types = @import("../../config/types.zig");
const c = @cImport({
    @cInclude("sys/socket.h");
    @cInclude("arpa/inet.h");
    @cInclude("netinet/in.h");
    @cInclude("unistd.h");
});

const BUFFER_SIZE = 1 * 1024;

pub const UdpForwarder = struct {
    allocator: std.mem.Allocator,
    listen_port: u16,
    target_address: []const u8,
    target_port: u16,
    family: types.AddressFamily,
    socket: ?i32,
    running: std.atomic.Value(bool),

    pub fn init(
        allocator: std.mem.Allocator,
        listen_port: u16,
        target_address: []const u8,
        target_port: u16,
        family: types.AddressFamily,
    ) UdpForwarder {
        return .{
            .allocator = allocator,
            .listen_port = listen_port,
            .target_address = target_address,
            .target_port = target_port,
            .family = family,
            .socket = null,
            .running = std.atomic.Value(bool).init(false),
        };
    }

    pub fn start(self: *UdpForwarder) !void {
        self.running.store(true, .seq_cst);

        var bind_addr = try makeBindAddress(self.family, self.listen_port);
        const sock = c.socket(c.AF_INET, c.SOCK_DGRAM, 0);
        if (sock < 0) return error.ListenFailed;
        errdefer _ = c.close(sock);

        var opt: i32 = 1;
        _ = c.setsockopt(sock, c.SOL_SOCKET, c.SO_REUSEADDR, &opt, @sizeOf(i32));

        const bind_ptr: *c.sockaddr = @ptrCast(&bind_addr);
        if (c.bind(sock, bind_ptr, @sizeOf(c.sockaddr_in)) != 0) {
            return error.ListenFailed;
        }

        self.socket = sock;

        var target_addr = try makeTargetAddress(self.family, self.target_address, self.target_port);
        const target_ptr: *c.sockaddr = @ptrCast(&target_addr);
        if (c.connect(sock, target_ptr, @sizeOf(c.sockaddr_in)) != 0) {
            return error.ConnectFailed;
        }

        std.debug.print("[UDP] Listening on port {d}, forwarding to {s}:{d}\n", .{
            self.listen_port,
            self.target_address,
            self.target_port,
        });

        var buffer: [BUFFER_SIZE]u8 = undefined;

        while (self.running.load(.seq_cst)) {
            const n = c.recv(sock, &buffer, buffer.len, 0);
            if (n <= 0) {
                if (self.running.load(.seq_cst)) {
                    std.debug.print("[UDP] Receive error or closed: {d}\n", .{n});
                }
                continue;
            }

            const sent = c.send(sock, &buffer, @intCast(n), 0);
            if (sent < 0) {
                std.debug.print("[UDP] Send to target error: {d}\n", .{sent});
                continue;
            }

            std.debug.print("[UDP] Forwarded {d} bytes to {s}:{d}\n", .{ n, self.target_address, self.target_port });
        }
    }

    pub fn stop(self: *UdpForwarder) void {
        self.running.store(false, .seq_cst);
        if (self.socket) |sock| {
            _ = c.shutdown(sock, c.SHUT_RDWR);
            _ = c.close(sock);
            self.socket = null;
        }
    }
};

fn makeBindAddress(family: types.AddressFamily, port: u16) !c.sockaddr_in {
    _ = family; // currently IPv4-only bind
    var addr = std.mem.zeroes(c.sockaddr_in);
    addr.sin_family = c.AF_INET;
    addr.sin_port = c.htons(@intCast(port));
    addr.sin_addr = c.in_addr{ .s_addr = 0 }; // INADDR_ANY
    return addr;
}

fn makeTargetAddress(family: types.AddressFamily, address: []const u8, port: u16) !c.sockaddr_in {
    _ = family; // currently IPv4-only forward
    var addr = std.mem.zeroes(c.sockaddr_in);
    addr.sin_family = c.AF_INET;
    addr.sin_port = c.htons(@intCast(port));
    var addr_buf: [64]u8 = undefined;
    if (address.len >= addr_buf.len) return error.InvalidAddress;
    const c_addr = try std.fmt.bufPrintZ(&addr_buf, "{s}", .{address});
    const parsed = c.inet_pton(c.AF_INET, c_addr.ptr, &addr.sin_addr);
    if (parsed != 1) return error.InvalidAddress;
    return addr;
}
