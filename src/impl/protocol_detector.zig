const std = @import("std");

pub const Protocol = enum {
    ssh,
    rdp,
    http,
    tls,
    vnc,
    socks5,
    postgresql,
    telnet,
    minecraft,
    mqtt,
    smb,
};

fn parseVarInt(data: []const u8, offset: usize) ?struct { value: i32, bytes: usize } {
    var value: i32 = 0;
    var position: usize = 0;
    var current_offset = offset;

    while (current_offset < data.len) {
        const current_byte = data[current_offset];
        value |= @as(i32, current_byte & 0x7F) << @as(u5, @intCast(position));

        if ((current_byte & 0x80) == 0) break;

        position += 7;
        current_offset += 1;

        if (position >= 32) return null;
    }

    if (current_offset >= data.len) return null;

    return .{ .value = value, .bytes = current_offset - offset + 1 };
}

fn checkMinecraftHandshake(data: []const u8) bool {
    const pkt_len = parseVarInt(data, 0) orelse return false;
    if (pkt_len.value <= 0) return false;

    var offset = pkt_len.bytes;
    const pkt_id = parseVarInt(data, offset) orelse return false;
    if (pkt_id.value != 0) return false;

    offset += pkt_id.bytes;
    const proto_ver = parseVarInt(data, offset) orelse return false;
    // check passed

    offset += proto_ver.bytes;
    const str_len = parseVarInt(data, offset) orelse return false;
    if (str_len.value < 0 or str_len.value > 255) return false;

    offset += str_len.bytes + @as(usize, @intCast(str_len.value));
    if (offset + 2 > data.len) return false;

    offset += 2; // port
    const next_state = parseVarInt(data, offset) orelse return false;
    if (next_state.value == 1 or next_state.value == 2) {
        return true;
    }
    return false;
}

fn parseMqttRemainingLength(data: []const u8) ?struct { value: usize, bytes: usize } {
    var multiplier: usize = 1;
    var value: usize = 0;
    var i: usize = 1;

    while (i < data.len and i <= 4) : (i += 1) {
        const encoded = data[i];
        value += @as(usize, encoded & 0x7F) * multiplier;

        if ((encoded & 0x80) == 0) {
            return .{ .value = value, .bytes = i };
        }

        multiplier *= 128;
    }

    return null;
}

pub fn detectProtocol(data: []const u8) ?Protocol {
    if (data.len >= 4 and std.mem.startsWith(u8, data, "SSH-")) {
        return .ssh;
    }

    if (data.len >= 11 and data[0] == 0x03 and data[1] == 0x00) {
        const tpkt_len = (@as(usize, data[2]) << 8) | data[3];
        if (tpkt_len >= 11 and data[5] == 0xE0) {
            return .rdp;
        }
    }

    if (data.len >= 4 and
        (std.mem.startsWith(u8, data, "GET ") or
            std.mem.startsWith(u8, data, "POST ") or
            std.mem.startsWith(u8, data, "PUT ") or
            std.mem.startsWith(u8, data, "HEAD ") or
            std.mem.startsWith(u8, data, "DELETE ") or
            std.mem.startsWith(u8, data, "OPTIONS ") or
            std.mem.startsWith(u8, data, "PATCH ") or
            std.mem.startsWith(u8, data, "CONNECT ") or
            std.mem.startsWith(u8, data, "TRACE ")))
    {
        return .http;
    }

    if (data.len >= 5 and data[0] == 0x16 and data[1] == 0x03) {
        const minor = data[2];
        const rec_len = (@as(usize, data[3]) << 8) | data[4];

        if (minor >= 0x00 and minor <= 0x04 and rec_len > 0) {
            if (data.len < 6 or data[5] == 0x01) {
                return .tls;
            }
        }
    }

    if (data.len >= 12 and std.mem.startsWith(u8, data, "RFB ")) {
        return .vnc;
    }

    if (data.len >= 2 and data[0] == 0x05) {
        const nmethods = data[1];
        if (nmethods != 0 and data.len >= 2 + @as(usize, nmethods)) {
            return .socks5;
        }
    }

    if (data.len >= 8) {
        const len = (@as(usize, data[0]) << 24) |
            (@as(usize, data[1]) << 16) |
            (@as(usize, data[2]) << 8) |
            data[3];

        const code = (@as(u32, data[4]) << 24) |
            (@as(u32, data[5]) << 16) |
            (@as(u32, data[6]) << 8) |
            data[7];

        if (len >= 8 and code == 0x00030000) return .postgresql;
        if (len == 8 and code == 0x04D2162F) return .postgresql;
    }

    if (data.len >= 3 and data[0] == 0xFF and data[1] >= 0xFB and data[1] <= 0xFE) {
        return .telnet;
    }

    if (checkMinecraftHandshake(data)) {
        return .minecraft;
    }

    if (data.len >= 2 and data[0] == 0x10) {
        if (parseMqttRemainingLength(data)) |rl| {
            const off = 1 + rl.bytes;
            if (data.len >= off + 6 and
                data[off] == 0x00 and data[off + 1] == 0x04 and
                std.mem.eql(u8, data[off + 2 .. off + 6], "MQTT"))
            {
                return .mqtt;
            }
        }
    }

    if (data.len >= 8 and data[0] == 0x00 and (data[4] == 0xFF or data[4] == 0xFE) and data[5] == 0x53 and data[6] == 0x4D and data[7] == 0x42) {
        return .smb;
    }

    return null;
}

pub fn protocolToString(p: Protocol) [:0]const u8 {
    return switch (p) {
        .ssh => "ssh",
        .rdp => "rdp",
        .http => "http",
        .tls => "tls",
        .vnc => "vnc",
        .socks5 => "socks5",
        .postgresql => "postgresql",
        .telnet => "telnet",
        .minecraft => "minecraft",
        .mqtt => "mqtt",
        .smb => "smb",
    };
}

pub fn protocolFromString(s: []const u8) ?Protocol {
    if (std.ascii.eqlIgnoreCase(s, "ssh")) return .ssh;
    if (std.ascii.eqlIgnoreCase(s, "rdp")) return .rdp;
    if (std.ascii.eqlIgnoreCase(s, "http")) return .http;
    if (std.ascii.eqlIgnoreCase(s, "tls")) return .tls;
    if (std.ascii.eqlIgnoreCase(s, "vnc")) return .vnc;
    if (std.ascii.eqlIgnoreCase(s, "socks5")) return .socks5;
    if (std.ascii.eqlIgnoreCase(s, "postgresql")) return .postgresql;
    if (std.ascii.eqlIgnoreCase(s, "telnet")) return .telnet;
    if (std.ascii.eqlIgnoreCase(s, "minecraft")) return .minecraft;
    if (std.ascii.eqlIgnoreCase(s, "mqtt")) return .mqtt;
    if (std.ascii.eqlIgnoreCase(s, "smb")) return .smb;
    return null;
}

test "detectProtocol identifies SSH and rejects short or wrong prefixes" {
    try std.testing.expectEqual(Protocol.ssh, detectProtocol("SSH-2.0-OpenSSH_9.6"));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol("SSH"));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol("SSX-2.0"));
}

test "detectProtocol identifies RDP and rejects invalid handshakes" {
    const valid = [_]u8{ 0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const invalid_type = [_]u8{ 0x03, 0x00, 0x00, 0x0B, 0x06, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00 };
    const too_short = [_]u8{ 0x03, 0x00, 0x00, 0x0B, 0x06, 0xE0 };

    try std.testing.expectEqual(Protocol.rdp, detectProtocol(&valid));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&invalid_type));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&too_short));
}

test "detectProtocol identifies HTTP methods and rejects unknown method prefixes" {
    try std.testing.expectEqual(Protocol.http, detectProtocol("GET / HTTP/1.1"));
    try std.testing.expectEqual(Protocol.http, detectProtocol("POST /submit HTTP/1.1"));
    try std.testing.expectEqual(Protocol.http, detectProtocol("PUT /item HTTP/1.1"));
    try std.testing.expectEqual(Protocol.http, detectProtocol("HEAD / HTTP/1.1"));
    try std.testing.expectEqual(Protocol.http, detectProtocol("DELETE /item HTTP/1.1"));
    try std.testing.expectEqual(Protocol.http, detectProtocol("OPTIONS * HTTP/1.1"));
    try std.testing.expectEqual(Protocol.http, detectProtocol("PATCH /item HTTP/1.1"));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol("POSTXYZ /bad HTTP/1.1"));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol("POS /bad HTTP/1.1"));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol("CONN"));
}

test "detectProtocol identifies TLS and rejects non-handshake records" {
    const valid = [_]u8{ 0x16, 0x03, 0x01, 0x00, 0x2A };
    const invalid_content_type = [_]u8{ 0x15, 0x03, 0x03, 0x00, 0x02 };
    const too_short = [_]u8{0x16};

    try std.testing.expectEqual(Protocol.tls, detectProtocol(&valid));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&invalid_content_type));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&too_short));
}

test "detectProtocol identifies VNC and rejects invalid banners" {
    try std.testing.expectEqual(Protocol.vnc, detectProtocol("RFB 003.008\n"));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol("RFA 003.008\n"));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol("RFB"));
}

test "detectProtocol identifies SOCKS5 and rejects invalid method counts" {
    const valid = [_]u8{ 0x05, 0x02, 0x00, 0x02 };
    const invalid_version = [_]u8{ 0x04, 0x02, 0x00, 0x02 };
    const invalid_nmethods = [_]u8{ 0x05, 0x09, 0x00, 0x02 };
    const too_short = [_]u8{0x05};

    try std.testing.expectEqual(Protocol.socks5, detectProtocol(&valid));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&invalid_version));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&invalid_nmethods));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&too_short));
}

test "detectProtocol identifies PostgreSQL StartupMessage and SSLRequest and rejects wrong payloads" {
    const valid_ssl = [_]u8{ 0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F };
    const valid_startup = [_]u8{ 0x00, 0x00, 0x00, 0x54, 0x00, 0x03, 0x00, 0x00 };
    const invalid_code = [_]u8{ 0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x30 };
    const too_short = [_]u8{ 0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16 };

    try std.testing.expectEqual(Protocol.postgresql, detectProtocol(&valid_ssl));
    try std.testing.expectEqual(Protocol.postgresql, detectProtocol(&valid_startup));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&invalid_code));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&too_short));
}

test "detectProtocol identifies Telnet and rejects non-command bytes" {
    const valid = [_]u8{ 0xFF, 0xFD, 0x18 };
    const invalid_command = [_]u8{ 0xFF, 0xFA, 0x18 };
    const invalid_prefix = [_]u8{ 0xFE, 0xFD, 0x18 };
    const too_short = [_]u8{0xFF};

    try std.testing.expectEqual(Protocol.telnet, detectProtocol(&valid));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&invalid_command));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&invalid_prefix));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&too_short));
}

test "detectProtocol returns null for empty and unknown payloads" {
    const unknown = [_]u8{ 0x01, 0x02, 0x03, 0x04 };

    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(""));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&unknown));
}

test "detectProtocol identifies Minecraft Handshake and rejects invalid" {
    const valid = [_]u8{ 0x10, 0x00, 0xF2, 0x05, 0x09, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F, 0x73, 0x74, 0x63, 0xDD, 0x01 };
    const invalid_id = [_]u8{ 0x10, 0x01, 0xF2, 0x05 };
    const too_long_length = [_]u8{ 0x80, 0x00, 0xF2, 0x05 };

    try std.testing.expectEqual(Protocol.minecraft, detectProtocol(&valid));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&invalid_id));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&too_long_length));
}

test "detectProtocol identifies MQTT CONNECT and rejects invalid" {
    const valid = [_]u8{ 0x10, 0x12, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C, 0x00, 0x06, 'c', 'l', 'i', 'e', 'n', 't' };
    const invalid_header = [_]u8{ 0x20, 0x12, 0x00, 0x04, 'M', 'Q', 'T', 'T' };
    const invalid_magic = [_]u8{ 0x10, 0x12, 0x00, 0x04, 'M', 'Q', 'I', 'S' };

    try std.testing.expectEqual(Protocol.mqtt, detectProtocol(&valid));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&invalid_header));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&invalid_magic));
}

test "detectProtocol identifies SMB and rejects invalid" {
    const valid_smb2 = [_]u8{ 0x00, 0x00, 0x00, 0x54, 0xFE, 0x53, 0x4D, 0x42, 0x40, 0x00, 0x00, 0x00 };
    const valid_smb1 = [_]u8{ 0x00, 0x00, 0x00, 0x2D, 0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00 };
    const invalid_magic = [_]u8{ 0x00, 0x00, 0x00, 0x54, 0xFD, 0x53, 0x4D, 0x42 };

    try std.testing.expectEqual(Protocol.smb, detectProtocol(&valid_smb2));
    try std.testing.expectEqual(Protocol.smb, detectProtocol(&valid_smb1));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&invalid_magic));
}

test "protocolToString and protocolFromString round-trip all protocols" {
    const protocols = [_]Protocol{ .ssh, .rdp, .http, .tls, .vnc, .socks5, .postgresql, .telnet, .minecraft, .mqtt, .smb };

    for (protocols) |protocol| {
        const name = protocolToString(protocol);
        try std.testing.expectEqual(protocol, protocolFromString(name).?);
    }
}

test "protocolFromString matches case-insensitively and rejects unknown names" {
    try std.testing.expectEqual(Protocol.ssh, protocolFromString("SSH"));
    try std.testing.expectEqual(Protocol.rdp, protocolFromString("RdP"));
    try std.testing.expectEqual(Protocol.http, protocolFromString("HTTP"));
    try std.testing.expectEqual(Protocol.tls, protocolFromString("Tls"));
    try std.testing.expectEqual(Protocol.vnc, protocolFromString("VNC"));
    try std.testing.expectEqual(Protocol.socks5, protocolFromString("SoCkS5"));
    try std.testing.expectEqual(Protocol.postgresql, protocolFromString("POSTGRESQL"));
    try std.testing.expectEqual(Protocol.telnet, protocolFromString("TelNet"));
    try std.testing.expectEqual(@as(?Protocol, null), protocolFromString("smtp"));
    try std.testing.expectEqual(@as(?Protocol, null), protocolFromString(""));
}
