// src/all_tests.zig
test {
    _ = @import("./config/json_loader.zig");
    _ = @import("./app_forward_test.zig");
}
