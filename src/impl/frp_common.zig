const std = @import("std");

/// Parse the status JSON returned by FRPC/FRPS status APIs.
/// Caller owns returned strings and must free them with the supplied allocator.
pub fn parseStatusJson(allocator: std.mem.Allocator, json: []const u8) !struct {
    status: []const u8,
    last_error: []const u8,
} {
    const status = findJsonStringField(json, "status") orelse "unknown";
    const last_error = findJsonStringField(json, "last_error") orelse "";

    return .{
        .status = try allocator.dupe(u8, status),
        .last_error = try allocator.dupe(u8, last_error),
    };
}

/// Return a log-safe copy of an FRP error string.
/// Caller owns the returned string.
pub fn sanitizeErrorForLog(allocator: std.mem.Allocator, message: []const u8) ![]const u8 {
    if (containsSensitiveWord(message)) {
        return allocator.dupe(u8, "[redacted sensitive frp error]");
    }
    return allocator.dupe(u8, message);
}

fn findJsonStringField(json: []const u8, field: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < json.len) {
        if (json[i] != '"') {
            i += 1;
            continue;
        }

        const key_start = i + 1;
        const key_end = findStringEnd(json, key_start) orelse return null;
        i = key_end + 1;

        var colon = i;
        while (colon < json.len and std.ascii.isWhitespace(json[colon])) : (colon += 1) {}
        if (colon >= json.len or json[colon] != ':') continue;

        var value_quote = colon + 1;
        while (value_quote < json.len and std.ascii.isWhitespace(json[value_quote])) : (value_quote += 1) {}
        if (value_quote >= json.len or json[value_quote] != '"') continue;

        const value_start = value_quote + 1;
        const value_end = findStringEnd(json, value_start) orelse return null;
        i = value_end + 1;

        if (std.mem.eql(u8, json[key_start..key_end], field)) {
            return json[value_start..value_end];
        }
    }

    return null;
}

fn findStringEnd(json: []const u8, start: usize) ?usize {
    var i = start;
    var escaped = false;
    while (i < json.len) : (i += 1) {
        if (escaped) {
            escaped = false;
            continue;
        }
        if (json[i] == '\\') {
            escaped = true;
            continue;
        }
        if (json[i] == '"') return i;
    }
    return null;
}

fn containsSensitiveWord(message: []const u8) bool {
    const words = [_][]const u8{ "token", "password", "passwd", "secret", "credential", "auth" };
    for (words) |word| {
        if (indexOfIgnoreCase(message, word) != null) return true;
    }
    return false;
}

fn indexOfIgnoreCase(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0 or needle.len > haystack.len) return null;

    var i: usize = 0;
    while (i <= haystack.len - needle.len) : (i += 1) {
        var matched = true;
        for (needle, 0..) |expected, offset| {
            if (std.ascii.toLower(haystack[i + offset]) != expected) {
                matched = false;
                break;
            }
        }
        if (matched) return i;
    }
    return null;
}

test "frp common: parseStatusJson extracts status and last error" {
    const allocator = std.testing.allocator;

    const parsed = try parseStatusJson(allocator, "{\"status\":\"error\",\"last_error\":\"boom\"}");
    defer allocator.free(parsed.status);
    defer allocator.free(parsed.last_error);

    try std.testing.expectEqualStrings("error", parsed.status);
    try std.testing.expectEqualStrings("boom", parsed.last_error);
}

test "frp common: parseStatusJson falls back for missing fields" {
    const allocator = std.testing.allocator;

    const parsed = try parseStatusJson(allocator, "{}");
    defer allocator.free(parsed.status);
    defer allocator.free(parsed.last_error);

    try std.testing.expectEqualStrings("unknown", parsed.status);
    try std.testing.expectEqualStrings("", parsed.last_error);
}

test "frp common: parseStatusJson handles status without last error" {
    const allocator = std.testing.allocator;

    const parsed = try parseStatusJson(allocator, "{\"status\":\"connected\"}");
    defer allocator.free(parsed.status);
    defer allocator.free(parsed.last_error);

    try std.testing.expectEqualStrings("connected", parsed.status);
    try std.testing.expectEqualStrings("", parsed.last_error);
}

test "frp common: parseStatusJson skips escaped quotes" {
    const allocator = std.testing.allocator;

    const parsed = try parseStatusJson(allocator, "{\"status\":\"error\",\"last_error\":\"bad \\\"token\\\" value\"}");
    defer allocator.free(parsed.status);
    defer allocator.free(parsed.last_error);

    try std.testing.expectEqualStrings("error", parsed.status);
    try std.testing.expectEqualStrings("bad \\\"token\\\" value", parsed.last_error);
}

test "frp common: parseStatusJson ignores key-like text inside strings" {
    const allocator = std.testing.allocator;

    const parsed = try parseStatusJson(allocator, "{\"message\":\"\\\"last_error\\\":\\\"fake\\\"\",\"last_error\":\"real\"}");
    defer allocator.free(parsed.status);
    defer allocator.free(parsed.last_error);

    try std.testing.expectEqualStrings("unknown", parsed.status);
    try std.testing.expectEqualStrings("real", parsed.last_error);
}

test "frp common: sanitizeErrorForLog redacts sensitive words" {
    const allocator = std.testing.allocator;

    const sanitized = try sanitizeErrorForLog(allocator, "invalid token: abc123");
    defer allocator.free(sanitized);

    try std.testing.expectEqualStrings("[redacted sensitive frp error]", sanitized);
}
