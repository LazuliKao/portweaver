const std = @import("std");
const Io = std.Io;
const net = Io.net;
const posix = std.posix;
const builtin = @import("builtin");
const types = @import("../../config/types.zig");

pub const io_mode = .evented;

const BUFFER_SIZE = 1 * 1024;

pub const TcpForwarder = struct {
    allocator: std.mem.Allocator,
    listen_port: u16,
    target_address: []const u8,
    target_port: u16,
    family: types.AddressFamily,
    server: ?net.Server,
    running: std.atomic.Value(bool),

    pub fn init(
        allocator: std.mem.Allocator,
        listen_port: u16,
        target_address: []const u8,
        target_port: u16,
        family: types.AddressFamily,
    ) TcpForwarder {
        return .{
            .allocator = allocator,
            .listen_port = listen_port,
            .target_address = target_address,
            .target_port = target_port,
            .family = family,
            .server = null,
            .running = std.atomic.Value(bool).init(false),
        };
    }

    pub fn start(self: *TcpForwarder, io: Io) !void {
        self.running.store(true, .seq_cst);

        const address = switch (self.family) {
            .ipv4 => net.IpAddress.parseIp4("0.0.0.0", self.listen_port) catch return error.ListenFailed,
            .ipv6 => net.IpAddress.parseIp6("::", self.listen_port) catch return error.ListenFailed,
            .any => net.IpAddress.parseIp6("::", self.listen_port) catch
                net.IpAddress.parseIp4("0.0.0.0", self.listen_port) catch return error.ListenFailed,
        };

        var server = try address.listen(io, .{ .reuse_address = true });
        self.server = server;

        std.debug.print("[TCP] Listening on port {d}, forwarding to {s}:{d}\n", .{
            self.listen_port,
            self.target_address,
            self.target_port,
        });

        while (self.running.load(.seq_cst)) {
            const stream = server.accept(io) catch |err| {
                if (self.running.load(.seq_cst)) {
                    std.debug.print("[TCP] Accept error: {any}\n", .{err});
                }
                continue;
            };

            const thread = std.Thread.spawn(.{ .stack_size = 64 * 1024 }, handleTcpConnection, .{
                io,
                stream,
                self.target_address,
                self.target_port,
            }) catch |err| {
                std.debug.print("[TCP] Failed to spawn thread: {any}\n", .{err});
                stream.close(io);
                continue;
            };
            thread.detach();
        }
    }

    pub fn stop(self: *TcpForwarder) void {
        self.running.store(false, .seq_cst);
        if (self.server) |*server| {
            server.deinit();
            self.server = null;
        }
    }
};

fn handleTcpConnection(
    io: Io,
    stream: net.Stream,
    target_address: []const u8,
    target_port: u16,
) void {
    defer stream.close(io);

    const client_addr = stream.socket.address;
    std.debug.print("[TCP] New connection from {any}\n", .{client_addr});

    const address = Io.net.IpAddress.parse(target_address, target_port) catch |err| {
        std.debug.print("[TCP] Invalid target address {s}:{d}: {any}\n", .{ target_address, target_port, err });
        return;
    };

    const target = address.connect(io, .{ .mode = .stream }) catch |err| {
        std.debug.print("[TCP] Failed to connect to target {s}:{d}: {any}\n", .{ target_address, target_port, err });
        return;
    };
    defer target.close(io);

    std.debug.print("[TCP] Connected to target {s}:{d}\n", .{ target_address, target_port });

    var client_stream = stream;
    var target_stream = target;

    const forward_thread = std.Thread.spawn(.{ .stack_size = 64 * 1024 }, forwardData, .{ &client_stream, &target_stream, "client->target" }) catch |err| {
        std.debug.print("[TCP] Failed to spawn forward thread: {any}\n", .{err});
        return;
    };

    forwardData(&target_stream, &client_stream, "target->client");
    forward_thread.join();
}

fn forwardData(src: *net.Stream, dst: *net.Stream, direction: []const u8) void {
    var buffer: [BUFFER_SIZE]u8 = undefined;

    while (true) {
        const n = streamRead(src, &buffer) catch |err| {
            if (err != error.EndOfStream and err != error.ConnectionReset and err != error.BrokenPipe) {
                std.debug.print("[TCP] Read error ({s}): {any}\n", .{ direction, err });
            }
            break;
        };

        dstWriteAll(dst, buffer[0..n]) catch |err| {
            if (err != error.BrokenPipe and err != error.ConnectionReset) {
                std.debug.print("[TCP] Write error ({s}): {any}\n", .{ direction, err });
            }
            break;
        };
    }
}

fn streamRead(stream: *net.Stream, buffer: []u8) !usize {
    const n = posix.recv(stream.socket.handle, buffer, 0) catch |err| return err;
    if (n == 0) return error.EndOfStream;
    return n;
}

fn dstWriteAll(stream: *net.Stream, data: []const u8) !void {
    var sent: usize = 0;
    while (sent < data.len) {
        const n = posix.send(stream.socket.handle, data[sent..], 0) catch |err| return err;
        if (n == 0) return error.Unexpected;
        sent += n;
    }
}
