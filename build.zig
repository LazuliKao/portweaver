const std = @import("std");

fn addLibuv(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    const uv = b.addLibrary(.{
        .name = "uv",
        .linkage = .static,
        .root_module = b.createModule(.{
            .link_libc = true,
            .target = target,
            .optimize = optimize,
        }),
    });
    if (optimize == .ReleaseSmall) {
        uv.root_module.unwind_tables = .none;
    }

    uv.addIncludePath(b.path("deps/libuv/include"));
    // libuv has internal headers included from its own C sources.
    uv.addIncludePath(b.path("deps/libuv/src"));

    // Base sources from deps/libuv/CMakeLists.txt (uv_sources)
    uv.addCSourceFiles(.{
        .files = &.{
            "deps/libuv/src/fs-poll.c",
            "deps/libuv/src/idna.c",
            "deps/libuv/src/inet.c",
            "deps/libuv/src/random.c",
            "deps/libuv/src/strscpy.c",
            "deps/libuv/src/strtok.c",
            "deps/libuv/src/thread-common.c",
            "deps/libuv/src/threadpool.c",
            "deps/libuv/src/timer.c",
            "deps/libuv/src/uv-common.c",
            "deps/libuv/src/uv-data-getter-setters.c",
            "deps/libuv/src/version.c",
        },
        .flags = &.{},
    });
    const os_tag = target.result.os.tag;
    if (os_tag == .windows) {
        uv.root_module.linkSystemLibrary("ws2_32", .{});
        uv.root_module.linkSystemLibrary("dbghelp", .{});
        uv.root_module.linkSystemLibrary("ole32", .{});
        uv.root_module.linkSystemLibrary("userenv", .{});
        uv.root_module.linkSystemLibrary("iphlpapi", .{});
        // uv.root_module.linkSystemLibrary("advapi32");
        // exe.linkSystemLibrary("user32");
        // exe.linkSystemLibrary("shell32");
        // exe.linkSystemLibrary("psapi");
        uv.root_module.addCMacro("WIN32_LEAN_AND_MEAN", "1");
        uv.root_module.addCMacro("_WIN32_WINNT", "0x0A00");
        uv.root_module.addCMacro("_CRT_DECLARE_NONSTDC_NAMES", "0");

        uv.addCSourceFiles(.{
            .files = &.{
                "deps/libuv/src/win/async.c",
                "deps/libuv/src/win/core.c",
                "deps/libuv/src/win/detect-wakeup.c",
                "deps/libuv/src/win/dl.c",
                "deps/libuv/src/win/error.c",
                "deps/libuv/src/win/fs.c",
                "deps/libuv/src/win/fs-event.c",
                "deps/libuv/src/win/getaddrinfo.c",
                "deps/libuv/src/win/getnameinfo.c",
                "deps/libuv/src/win/handle.c",
                "deps/libuv/src/win/loop-watcher.c",
                "deps/libuv/src/win/pipe.c",
                "deps/libuv/src/win/thread.c",
                "deps/libuv/src/win/poll.c",
                "deps/libuv/src/win/process.c",
                "deps/libuv/src/win/process-stdio.c",
                "deps/libuv/src/win/signal.c",
                "deps/libuv/src/win/snprintf.c",
                "deps/libuv/src/win/stream.c",
                "deps/libuv/src/win/tcp.c",
                "deps/libuv/src/win/tty.c",
                "deps/libuv/src/win/udp.c",
                "deps/libuv/src/win/util.c",
                "deps/libuv/src/win/winapi.c",
                "deps/libuv/src/win/winsock.c",
            },
            .flags = &.{},
        });
    } else {
        // Unix-like base (non-Windows) from deps/libuv/CMakeLists.txt
        // uv.root_module.addCMacro("_FILE_OFFSET_BITS", "64");
        // uv.root_module.addCMacro("_LARGEFILE_SOURCE", "1");

        uv.addCSourceFiles(.{
            .files = &.{
                "deps/libuv/src/unix/async.c",
                "deps/libuv/src/unix/core.c",
                "deps/libuv/src/unix/dl.c",
                "deps/libuv/src/unix/fs.c",
                "deps/libuv/src/unix/getaddrinfo.c",
                "deps/libuv/src/unix/getnameinfo.c",
                "deps/libuv/src/unix/loop-watcher.c",
                "deps/libuv/src/unix/loop.c",
                "deps/libuv/src/unix/pipe.c",
                "deps/libuv/src/unix/poll.c",
                "deps/libuv/src/unix/process.c",
                "deps/libuv/src/unix/random-devurandom.c",
                "deps/libuv/src/unix/signal.c",
                "deps/libuv/src/unix/stream.c",
                "deps/libuv/src/unix/tcp.c",
                "deps/libuv/src/unix/thread.c",
                "deps/libuv/src/unix/tty.c",
                "deps/libuv/src/unix/udp.c",
            },
            .flags = &.{},
        });

        if (os_tag == .linux) {
            uv.root_module.linkSystemLibrary("pthread", .{});
            uv.root_module.linkSystemLibrary("dl", .{});
            uv.root_module.linkSystemLibrary("rt", .{});
            uv.root_module.linkSystemLibrary("m", .{});
            // Linux specifics from deps/libuv/CMakeLists.txt
            uv.root_module.addCMacro("_GNU_SOURCE", "1");
            uv.root_module.addCMacro("_POSIX_C_SOURCE", "200112");
            uv.addCSourceFiles(.{
                .files = &.{
                    "deps/libuv/src/unix/proctitle.c",
                    "deps/libuv/src/unix/linux.c",
                    "deps/libuv/src/unix/procfs-exepath.c",
                    "deps/libuv/src/unix/random-getrandom.c",
                    "deps/libuv/src/unix/random-sysctl-linux.c",
                },
                .flags = &.{},
            });
        }
    }

    return uv;
}

fn addGoLibrary(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    lib_dir: []const u8,
    output_name: []const u8,
    source_file: []const u8,
) *std.Build.Step {
    const os_tag = target.result.os.tag;
    const arch_tag = target.result.cpu.arch;

    const goos = switch (os_tag) {
        .windows => "windows",
        .linux => "linux",
        .macos => "darwin",
        else => "linux",
    };

    const goarch = switch (arch_tag) {
        .x86 => "386",
        .x86_64 => "amd64",
        .aarch64 => "arm64",
        .aarch64_be => "arm64be",
        .arm => "arm",
        .armeb => "armbe",
        .loongarch64 => "loong64",
        .mips => "mips",
        .mipsel => "mipsle",
        .mips64 => "mips64",
        .mips64el => "mips64le",
        .powerpc => "ppc",
        .powerpc64 => "ppc64",
        .powerpc64le => "ppc64le",
        .riscv32 => "riscv",
        .riscv64 => "riscv64",
        .s390x => "s390x",
        .sparc => "sparc",
        .sparc64 => "sparc64",
        else => @panic("Unsupported architecture"),
    };

    const go_cmd =
        if (optimize == .ReleaseSmall)
            b.addSystemCommand(&.{
                "go",
                "build",
                "-buildmode=c-archive",
                "-trimpath",
                "-ldflags=-s -extldflags=-static -w -buildid=",
                "-o",
                output_name,
                source_file,
            })
        else
            b.addSystemCommand(&.{
                "go",
                "build",
                "-buildmode=c-archive",
                "-o",
                output_name,
                source_file,
            });

    go_cmd.setCwd(b.path(lib_dir));

    go_cmd.addPathDir(b.path("wrapper").getPath(b));
    go_cmd.setEnvironmentVariable("GOOS", goos);
    go_cmd.setEnvironmentVariable("GOARCH", goarch);

    const zig_exe = b.graph.zig_exe;
    const target_triple = target.result.zigTriple(b.allocator) catch @panic("Failed to get target triple");

    const cc_cmd = std.fmt.allocPrint(b.allocator, "\"{s}\" cc -target {s}", .{ zig_exe, target_triple }) catch @panic("OOM");
    const cxx_cmd = std.fmt.allocPrint(b.allocator, "\"{s}\" c++ -target {s}", .{ zig_exe, target_triple }) catch @panic("OOM");
    const ar_cmd = std.fmt.allocPrint(b.allocator, "\"{s}\" ar", .{zig_exe}) catch @panic("OOM");
    go_cmd.setEnvironmentVariable("CGO_ENABLED", "1");
    go_cmd.setEnvironmentVariable("CC", cc_cmd);
    go_cmd.setEnvironmentVariable("CXX", cxx_cmd);
    go_cmd.setEnvironmentVariable("AR", ar_cmd);
    if (optimize == .ReleaseSmall) {
        go_cmd.setEnvironmentVariable("CGO_CFLAGS", "-Os -fno-exceptions -fno-rtti -ffunction-sections -fdata-sections");
        go_cmd.setEnvironmentVariable("CGO_LDFLAGS", "-Os -fno-exceptions -fno-rtti -ffunction-sections -fdata-sections");
    }
    return &go_cmd.step;
}

fn addLibFrp(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step {
    return addGoLibrary(b, target, optimize, "src/impl/frpc/libfrpc-go", "libfrp.a", "libfrp.go");
}

fn addLibDdns(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step {
    return addGoLibrary(b, target, optimize, "src/impl/ddns/libddns-go", "libddns.a", "libddns.go");
}

// Although this function looks imperative, it does not perform the build
// directly and instead it mutates the build graph (`b`) that will be then
// executed by an external runner. The functions in `std.Build` implement a DSL
// for defining build steps and express dependencies between them, allowing the
// build runner to parallelize the build automatically (and the cache system to
// know when a step doesn't need to be re-run).
pub fn build(b: *std.Build) void {
    const options = b.addOptions();

    const uci = b.option(bool, "uci", "UCI Mode") orelse false;
    options.addOption(bool, "uci_mode", uci);

    const ubus = b.option(bool, "ubus", "Ubus Support") orelse false;
    options.addOption(bool, "ubus_mode", ubus);

    const frpc = b.option(bool, "frpc", "FRP Client Support") orelse false;
    options.addOption(bool, "frpc_mode", frpc);

    const ddns = b.option(bool, "ddns", "DDNS Support") orelse false;
    options.addOption(bool, "ddns_mode", ddns);

    const options_mod = options.createModule();

    // Standard target options allow the person running `zig build` to choose
    // what target to build for. Here we set the default to x86_64-linux-musl
    // for OpenWrt compatibility, but can be overridden.
    const target = b.standardTargetOptions(.{
        // .default_target = .{
        //     .cpu_arch = .x86_64,
        //     .os_tag = .linux,
        //     .abi = .musl,
        // },
    });
    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});
    // It's also possible to define more custom flags to toggle optional features
    // of this build script using `b.option()`. All defined flags (including
    // target and optimize options) will be listed when running `zig build --help`
    // in this directory.

    // This creates a module, which represents a collection of source files alongside
    // some compilation options, such as optimization mode and linked system libraries.
    // Zig modules are the preferred way of making Zig code available to consumers.
    // addModule defines a module that we intend to make available for importing
    // to our consumers. We must give it a name because a Zig package can expose
    // multiple modules and consumers will need to be able to specify which
    // module they want to access.
    const mod = b.addModule("PortWeaver", .{
        // The root source file is the "entry point" of this module. Users of
        // this module will only be able to access public declarations contained
        // in this file, which means that if you have declarations that you
        // intend to expose to consumers that were defined in other files part
        // of this module, you will have to make sure to re-export them from
        // the root file.
        .root_source_file = b.path("src/main.zig"),
        // Later on we'll use this module as the root module of a test executable
        // which requires us to specify a target.
        .target = target,
    });

    if (optimize == .ReleaseSmall) {
        mod.unwind_tables = .none;
    }
    mod.addImport("build_options", options_mod);

    // Here we define an executable. An executable needs to have a root module
    // which needs to expose a `main` function. While we could add a main function
    // to the module defined above, it's sometimes preferable to split business
    // logic and the CLI into two separate modules.
    //
    // If your goal is to create a Zig library for others to use, consider if
    // it might benefit from also exposing a CLI tool. A parser library for a
    // data serialization format could also bundle a CLI syntax checker, for example.
    //
    // If instead your goal is to create an executable, consider if users might
    // be interested in also being able to embed the core functionality of your
    // program in their own executable in order to avoid the overhead involved in
    // subprocessing your CLI tool.
    //
    // If neither case applies to you, feel free to delete the declaration you
    // don't need and to put everything under a single module.
    const exe = b.addExecutable(.{
        .name = "portweaver",
        .root_module = b.createModule(.{
            .link_libc = true,
            // .strip = true,
            // .single_threaded = true,
            // .no_builtin = true,
            // b.createModule defines a new module just like b.addModule but,
            // unlike b.addModule, it does not expose the module to consumers of
            // this package, which is why in this case we don't have to give it a name.
            .root_source_file = b.path("src/main.zig"),
            // Target and optimization levels must be explicitly wired in when
            // defining an executable or library (in the root module), and you
            // can also hardcode a specific target for an executable or library
            // definition if desireable (e.g. firmware for embedded devices).
            .target = target,
            .optimize = optimize,
            // .strip = true,
            // List of modules available for import in source files part of the
            // root module.
            .imports = &.{
                // Here "PortWeaver" is the name you will use in your source code to
                // import this module (e.g. `@import("PortWeaver")`). The name is
                // repeated because you are allowed to rename your imports, which
                // can be extremely useful in case of collisions (which can happen
                // importing modules from different packages).
                .{ .name = "portweaver", .module = mod },
                .{ .name = "build_options", .module = options_mod },
            },
        }),
    });

    if (optimize == .ReleaseSmall) {
        exe.root_module.unwind_tables = .none;
    }
    // Build and link libuv from deps/libuv.
    const uv = addLibuv(b, target, optimize);
    exe.linkLibrary(uv);
    exe.addIncludePath(b.path("deps/libuv/include"));
    exe.addIncludePath(b.path("deps/libuv/src"));

    // Build and link libfrp (Go shared library) only when frpc support is enabled
    if (frpc) {
        const libfrp_build_step = addLibFrp(b, target, optimize);

        // 添加 libfrp 头文件路径
        exe.addIncludePath(b.path("src/impl/frpc/libfrpc-go"));

        // 静态链接 libfrp.a
        const libfrp_path = b.path("src/impl/frpc/libfrpc-go/libfrp.a");
        exe.addObjectFile(libfrp_path);

        // 确保 libfrp 在可执行文件之前构建
        exe.step.dependOn(libfrp_build_step);
    }

    // Build and link libddns (Go shared library) only when ddns support is enabled
    if (ddns) {
        const libddns_build_step = addLibDdns(b, target, optimize);

        exe.addIncludePath(b.path("src/impl/ddns/libddns-go"));

        const libddns_path = b.path("src/impl/ddns/libddns-go/libddns.a");
        exe.addObjectFile(libddns_path);

        exe.step.dependOn(libddns_build_step);
    }

    // Add C forwarder implementation

    exe.addIncludePath(b.path("src/impl/app_forward/forwarder"));
    exe.addCSourceFile(.{
        .file = b.path("src/impl/app_forward/forwarder/forwarder.c"),
        .flags = if (optimize == .Debug) &.{"-DDEBUG"} else &.{},
    });

    // Add C include paths for UCI library headers
    exe.addIncludePath(b.path("deps/uci"));
    // Add C include paths for Ubus library headers
    exe.addIncludePath(b.path("deps/fix"));
    exe.addIncludePath(b.path("deps/openwrt-tools"));
    exe.addIncludePath(b.path("deps/ubus"));
    if (frpc) {
        // Add frpc include paths
        exe.addIncludePath(b.path("src/impl/frpc/libfrpc-go"));
    }

    // For dynamic linking at runtime
    exe.linkage = .dynamic;

    // This declares intent for the executable to be installed into the
    // install prefix when running `zig build` (i.e. when executing the default
    // step). By default the install prefix is `zig-out/` but can be overridden
    // by passing `--prefix` or `-p`.
    b.installArtifact(exe);

    // This creates a top level step. Top level steps have a name and can be
    // invoked by name when running `zig build` (e.g. `zig build run`).
    // This will evaluate the `run` step rather than the default step.
    // For a top level step to actually do something, it must depend on other
    // steps (e.g. a Run step, as we will see in a moment).
    const run_step = b.step("run", "Run the app");

    // This creates a RunArtifact step in the build graph. A RunArtifact step
    // invokes an executable compiled by Zig. Steps will only be executed by the
    // runner if invoked directly by the user (in the case of top level steps)
    // or if another step depends on it, so it's up to you to define when and
    // how this Run step will be executed. In our case we want to run it when
    // the user runs `zig build run`, so we create a dependency link.
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    // By making the run step depend on the default step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // Creates an executable that will run `test` blocks from the provided module.
    // Here `mod` needs to define a target, which is why earlier we made sure to
    // set the releative field.
    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    // A run step that will run the test executable.
    const run_mod_tests = b.addRunArtifact(mod_tests);

    // Creates an executable that will run `test` blocks from the executable's
    // root module. Note that test executables only test one module at a time,
    // hence why we have to create two separate ones.
    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
    });

    // A run step that will run the second test executable.
    const run_exe_tests = b.addRunArtifact(exe_tests);

    // A top level step for running all tests. dependOn can be called multiple
    // times and since the two run steps do not depend on one another, this will
    // make the two of them run in parallel.
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    // Development remote mode: auto-build and upload to remote device
    const dev_remote_step = b.step("dev-remote", "Watch, build, and auto-upload to remote OpenWrt device");
    const dev_remote_cmd = b.addSystemCommand(&.{
        "dotnet",
        "fsi",
        "scripts/dev-remote.fsx",
    });
    dev_remote_step.dependOn(&dev_remote_cmd.step);

    // Just like flags, top level steps are also listed in the `--help` menu.
    //
    // The Zig build system is entirely implemented in userland, which means
    // that it cannot hook into private compiler APIs. All compilation work
    // orchestrated by the build system will result in other Zig compiler
    // subcommands being invoked with the right flags defined. You can observe
    // these invocations when one fails (or you pass a flag to increase
    // Lastly, the Zig build system is relatively simple and self-contained,
    // and reading its source code will allow you to master it.
}
