const std = @import("std");

/// Parse the status JSON returned by FRPC/FRPS status APIs.
/// Caller owns returned strings and must free them with the supplied allocator.
pub fn parseStatusJson(allocator: std.mem.Allocator, json: []const u8) !struct {
    status: []const u8,
    last_error: []const u8,
} {
    // Simple JSON parsing for {"status":"...","last_error":"..."}
    // We use a basic approach since std.json might not be available in all builds.
    var status: []const u8 = "unknown";
    var last_error: []const u8 = "";

    // Find "status":"..."
    if (std.mem.indexOf(u8, json, "\"status\":\"")) |start| {
        const value_start = start + 10; // length of "status":"
        if (std.mem.indexOfPos(u8, json, value_start, "\"")) |end| {
            status = json[value_start..end];
        }
    }

    // Find "last_error":"..."
    if (std.mem.indexOf(u8, json, "\"last_error\":\"")) |start| {
        const value_start = start + 14; // length of "last_error":"
        if (std.mem.indexOfPos(u8, json, value_start, "\"")) |end| {
            last_error = json[value_start..end];
        }
    }

    return .{
        .status = try allocator.dupe(u8, status),
        .last_error = try allocator.dupe(u8, last_error),
    };
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
