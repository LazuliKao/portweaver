// src/all_tests.zig
const build_options = @import("build_options");

test {
    _ = @import("./impl/frp_status.zig");
    _ = @import("./config/mod.zig");
    _ = @import("./config/helper.zig");
    _ = @import("./config/json_loader.zig");
    _ = @import("./config/provider.zig");
    _ = @import("./config/types.zig");
    _ = @import("./app_forward_test.zig");
    _ = @import("./event_log.zig");
    _ = @import("./file_log.zig");
    _ = @import("./loader/dynamic_lib.zig");
    _ = @import("./process_lock_test.zig");
    _ = @import("./uci/mod.zig");
    _ = @import("./impl/project_status.zig");
    _ = @import("./impl/frp_common.zig");
    _ = @import("./impl/frps_forward.zig");
    _ = @import("./impl/app_forward/common.zig");
    _ = @import("./reload.zig");

    if (build_options.ddns_mode) {
        _ = @import("./impl/ddns_manager.zig");
        _ = @import("./impl/ddns/libddns.zig");
    }

    if (build_options.frpc_mode) {
        _ = @import("./impl/frpc_forward.zig");
    }

    if (build_options.frps_mode) {
        _ = @import("./impl/frps/libfrps.zig");
    }
}
