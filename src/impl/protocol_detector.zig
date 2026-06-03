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
    var value: u32 = 0;
    var position: usize = 0;
    var current_offset = offset;

    while (current_offset < data.len) {
        if (position >= 32) return null;

        const current_byte = data[current_offset];
        const bits: u32 = current_byte & 0x7F;

        // At position 28 (5th byte), only 4 bits fit in u32; reject overflow.
        if (position == 28 and bits > 0x0F) return null;

        value |= bits << @as(u5, @intCast(position));

        if ((current_byte & 0x80) == 0) break;

        position += 7;
        current_offset += 1;
    }

    if (current_offset >= data.len) return null;

    return .{ .value = @as(i32, @bitCast(value)), .bytes = current_offset - offset + 1 };
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

/// Extract the Server Name Indication (SNI) from a TLS ClientHello.
///
/// Returns a slice pointing into `data` containing the host name,
/// or null if the data is not a valid TLS ClientHello or contains no SNI extension.
/// The returned slice is NOT owned; it is a view into the input buffer.
pub fn extractTlsSni(data: []const u8) ?[]const u8 {
    // Minimum: 5 (record header) + 4 (handshake header) + 2 (client version) +
    //          32 (random) + 1 (session id len) = 44 bytes
    if (data.len < 44) return null;

    // TLS record header: ContentType(1) + ProtocolVersion(2) + Length(2)
    if (data[0] != 0x16) return null; // Not a Handshake record
    if (data[1] != 0x03) return null; // Not TLS
    // data[2] is the minor version (0x00..0x04)

    var offset: usize = 5; // skip record header

    // Handshake header: HandshakeType(1) + Length(3)
    if (offset >= data.len) return null;
    if (data[offset] != 0x01) return null; // Not ClientHello
    offset += 1;

    // Handshake length (3 bytes, big-endian) — we just skip it
    if (offset + 3 > data.len) return null;
    offset += 3;

    // ClientVersion (2 bytes)
    if (offset + 2 > data.len) return null;
    offset += 2;

    // Random (32 bytes)
    if (offset + 32 > data.len) return null;
    offset += 32;

    // Session ID: length(1) + data
    if (offset >= data.len) return null;
    const session_id_len: usize = data[offset];
    offset += 1;
    if (offset + session_id_len > data.len) return null;
    offset += session_id_len;

    // Cipher Suites: length(2) + data
    if (offset + 2 > data.len) return null;
    const cipher_suites_len: usize = (@as(usize, data[offset]) << 8) | data[offset + 1];
    offset += 2;
    if (offset + cipher_suites_len > data.len) return null;
    offset += cipher_suites_len;

    // Compression Methods: length(1) + data
    if (offset >= data.len) return null;
    const compression_len: usize = data[offset];
    offset += 1;
    if (offset + compression_len > data.len) return null;
    offset += compression_len;

    // Extensions: total length(2) + extension data
    if (offset + 2 > data.len) return null;
    const extensions_len: usize = (@as(usize, data[offset]) << 8) | data[offset + 1];
    offset += 2;

    const extensions_end = offset + extensions_len;
    if (extensions_end > data.len) return null;

    // Walk through extensions looking for Server Name (type 0x0000)
    while (offset + 4 <= extensions_end) {
        const ext_type: u16 = (@as(u16, data[offset]) << 8) | data[offset + 1];
        const ext_len: usize = (@as(usize, data[offset + 2]) << 8) | data[offset + 3];
        offset += 4;

        if (offset + ext_len > extensions_end) return null;

        if (ext_type == 0x0000) {
            // Server Name extension found
            // ServerNameList: total length(2)
            if (ext_len < 2) return null;
            var sni_offset = offset;
            const sni_list_len: usize = (@as(usize, data[sni_offset]) << 8) | data[sni_offset + 1];
            sni_offset += 2;
            _ = sni_list_len;

            // Walk through ServerName entries
            // Each entry: type(1) + length(2) + name
            while (sni_offset + 3 <= offset + ext_len) {
                const name_type = data[sni_offset];
                const name_len: usize = (@as(usize, data[sni_offset + 1]) << 8) | data[sni_offset + 2];
                sni_offset += 3;

                if (sni_offset + name_len > offset + ext_len) return null;

                if (name_type == 0x00) {
                    // host_name type
                    return data[sni_offset .. sni_offset + name_len];
                }

                sni_offset += name_len;
            }
            return null; // SNI extension present but no host_name entry
        }

        offset += ext_len;
    }

    return null;
}

pub fn detectProtocol(data: []const u8) ?Protocol {
    if (data.len >= 4 and std.mem.startsWith(u8, data, "SSH-")) {
        return .ssh;
    }

    if (data.len >= 11 and data[0] == 0x03 and data[1] == 0x00) {
        const tpkt_len = (@as(usize, data[2]) << 8) | data[3];
        if (tpkt_len >= 11 and tpkt_len <= data.len and data[5] == 0xE0) {
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

        if (minor <= 0x04 and rec_len > 0) {
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
        if (nmethods != 0 and nmethods <= 16 and data.len >= 2 + @as(usize, nmethods)) {
            // Require at least one well-known auth method (NoAuth/GSSAPI/UserPass)
            // to reduce false positives from arbitrary data starting with 0x05.
            const methods = data[2 .. 2 + @as(usize, nmethods)];
            var has_known_method = false;
            for (methods) |m| {
                if (m <= 0x02) {
                    has_known_method = true;
                    break;
                }
            }
            if (has_known_method) return .socks5;
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
    const non_client_hello = [_]u8{ 0x16, 0x03, 0x01, 0x00, 0x2A, 0x02 };
    const too_short = [_]u8{0x16};

    try std.testing.expectEqual(Protocol.tls, detectProtocol(&valid));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&invalid_content_type));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&non_client_hello));
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
    const unknown_methods = [_]u8{ 0x05, 0x02, 0xFE, 0xFD };
    const too_short = [_]u8{0x05};

    try std.testing.expectEqual(Protocol.socks5, detectProtocol(&valid));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&invalid_version));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&invalid_nmethods));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol(&unknown_methods));
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

test "extractTlsSni extracts SNI from valid ClientHello" {
    // A minimal valid TLS 1.2 ClientHello with SNI extension for "example.com"
    //
    // Layout (byte counts after record header):
    //   Handshake header:   1 + 3 = 4
    //   ClientVersion:      2
    //   Random:             32
    //   Session ID len:     1 (value 0)
    //   Cipher suites:      2 + 2 = 4
    //   Compression:        1 + 1 = 2
    //   Extensions len:     2
    //   SNI ext:            4 (hdr) + 16 (body) = 20
    //   Total handshake body = 2+32+1+4+2+2+20 = 63
    //   Record payload = 4 + 63 = 67
    const client_hello = [_]u8{
        // TLS Record Header
        0x16, // ContentType: Handshake
        0x03, 0x01, // ProtocolVersion: TLS 1.0
        0x00, 0x43, // Record Length: 67 bytes

        // Handshake Header
        0x01, // HandshakeType: ClientHello
        0x00, 0x00, 0x3F, // Handshake Length: 63 bytes

        // ClientVersion
        0x03, 0x03, // TLS 1.2

        // Random (32 bytes)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,

        // Session ID
        0x00, // Length: 0

        // Cipher Suites
        0x00, 0x02, // Length: 2
        0xC0, 0x2F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

        // Compression Methods
        0x01, // Length: 1
        0x00, // null compression

        // Extensions
        0x00, 0x14, // Extensions Length: 20 bytes

        // SNI Extension (20 bytes total: 4 header + 16 body)
        0x00, 0x00, // Extension Type: server_name (0)
        0x00, 0x10, // Extension Length: 16
        0x00, 0x0E, // Server Name List Length: 14
        0x00, // Name Type: host_name (0)
        0x00, 0x0B, // Host Name Length: 11
        'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', // "example.com"
    };

    const sni = extractTlsSni(&client_hello);
    try std.testing.expect(sni != null);
    try std.testing.expectEqualStrings("example.com", sni.?);
}

test "extractTlsSni returns null for ClientHello without SNI extension" {
    // A minimal TLS ClientHello without any extensions
    const client_hello_no_ext = [_]u8{
        // TLS Record Header
        0x16, 0x03, 0x01, 0x00, 0x2D, // 45 byte record

        // Handshake Header
        0x01, 0x00, 0x00, 0x29, // ClientHello, 41 bytes

        // ClientVersion
        0x03, 0x03,

        // Random (32 bytes)
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,

        // Session ID
        0x00,

        // Cipher Suites
        0x00, 0x02,
        0xC0, 0x2F,

        // Compression Methods
        0x01, 0x00,

        // Extensions length = 0
        0x00, 0x00,
    };

    try std.testing.expectEqual(@as(?[]const u8, null), extractTlsSni(&client_hello_no_ext));
}

test "extractTlsSni returns null for truncated and non-TLS data" {
    // Too short
    try std.testing.expectEqual(@as(?[]const u8, null), extractTlsSni(""));
    try std.testing.expectEqual(@as(?[]const u8, null), extractTlsSni(&[_]u8{0x16, 0x03, 0x01}));

    // Not a Handshake record (ContentType 0x15 = Alert)
    const alert = [_]u8{ 0x15, 0x03, 0x03, 0x00, 0x02 } ++ [_]u8{0} ** 40;
    try std.testing.expectEqual(@as(?[]const u8, null), extractTlsSni(&alert));

    // Handshake but not ClientHello (HandshakeType 0x02 = ServerHello)
    const server_hello = [_]u8{ 0x16, 0x03, 0x01, 0x00, 0x30, 0x02 } ++ [_]u8{0} ** 44;
    try std.testing.expectEqual(@as(?[]const u8, null), extractTlsSni(&server_hello));
}
