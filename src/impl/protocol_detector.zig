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
};

pub fn detectProtocol(data: []const u8) ?Protocol {
    if (data.len >= 4 and std.mem.startsWith(u8, data, "SSH-")) {
        return .ssh;
    }

    if (data.len >= 7 and data[0] == 0x03 and data[1] == 0x00 and data[5] == 0xE0) {
        return .rdp;
    }

    if (data.len >= 4 and
        (std.mem.startsWith(u8, data, "GET ") or
            std.mem.startsWith(u8, data, "POST") or
            std.mem.startsWith(u8, data, "PUT ") or
            std.mem.startsWith(u8, data, "HEAD") or
            std.mem.startsWith(u8, data, "DELE") or
            std.mem.startsWith(u8, data, "OPTI") or
            std.mem.startsWith(u8, data, "PATC")))
    {
        return .http;
    }

    if (data.len >= 2 and data[0] == 0x16 and data[1] == 0x03) {
        return .tls;
    }

    if (data.len >= 4 and std.mem.startsWith(u8, data, "RFB ")) {
        return .vnc;
    }

    if (data.len >= 2 and data[0] == 0x05 and data[1] >= 0x01 and data[1] <= 0x08) {
        return .socks5;
    }

    if (data.len >= 8 and
        data[0] == 0x00 and
        data[1] == 0x00 and
        data[2] == 0x00 and
        data[3] == 0x08 and
        data[4] == 0x04 and
        data[5] == 0xD2 and
        data[6] == 0x16 and
        data[7] == 0x2F)
    {
        return .postgresql;
    }

    if (data.len >= 2 and data[0] == 0xFF and data[1] >= 0xFB and data[1] <= 0xFE) {
        return .telnet;
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
    return null;
}

test "detectProtocol identifies SSH and rejects short or wrong prefixes" {
    try std.testing.expectEqual(Protocol.ssh, detectProtocol("SSH-2.0-OpenSSH_9.6"));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol("SSH"));
    try std.testing.expectEqual(@as(?Protocol, null), detectProtocol("SSX-2.0"));
}

test "detectProtocol identifies RDP and rejects invalid handshakes" {
    const valid = [_]u8{ 0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0, 0x00 };
    const invalid_type = [_]u8{ 0x03, 0x00, 0x00, 0x13, 0x0E, 0xD0, 0x00 };
    const too_short = [_]u8{ 0x03, 0x00, 0x00, 0x13, 0x0E, 0xE0 };

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

test "detectProtocol identifies PostgreSQL SSLRequest and rejects wrong payloads" {
    const valid = [_]u8{ 0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F };
    const invalid_code = [_]u8{ 0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x30 };
    const too_short = [_]u8{ 0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16 };

    try std.testing.expectEqual(Protocol.postgresql, detectProtocol(&valid));
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

test "protocolToString and protocolFromString round-trip all protocols" {
    const protocols = [_]Protocol{ .ssh, .rdp, .http, .tls, .vnc, .socks5, .postgresql, .telnet };

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
