const std = @import("std");
fn applyLinkOptimization(_: *std.Build, target: std.Build.ResolvedTarget, exe: *std.Build.Step.Compile, optimize: std.builtin.OptimizeMode) void {
    // fix x_cgo_setenv crash
    if (target.result.abi.isMusl()) {
        exe.link_function_sections = true;
        exe.link_data_sections = true;
        exe.link_gc_sections = true;
    }
    if (target.result.os.tag == .linux) {
        if (target.result.cpu.arch == .aarch64 or target.result.cpu.arch == .x86_64) {
            if (optimize == .ReleaseSmall) {
                exe.lto = .full;
            }
        }
    }

    if (optimize == .ReleaseSmall) {
        exe.root_module.unwind_tables = .none;
        exe.root_module.strip = true;
    }
}
fn applyCOptimizationCmd(_: *std.Build, optimize: std.builtin.OptimizeMode) []const u8 {
    if (optimize == .ReleaseSmall) {
        return "-Os -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -fno-unwind-tables -fomit-frame-pointer";
    } else {
        return "-O1 -ffunction-sections -fdata-sections";
    }
}
fn applyLinkOptimizationCmd(_: *std.Build, optimize: std.builtin.OptimizeMode) []const u8 {
    if (optimize == .ReleaseSmall) {
        return "-Wl,--gc-sections,--strip-all,--strip-debug,--discard-all,--no-eh-frame-hdr";
    } else {
        return "-Wl,--gc-sections";
    }
}
fn addLibuv(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) *std.Build.Step.Compile {
    // MIPS targets use -mabicalls by default (required by the N32/N64 ABI),
    // which is incompatible with -fno-PIC that Zig passes to static libs.
    // Force PIC on MIPS so clang doesn't error out.
    const is_mips = switch (target.result.cpu.arch) {
        .mips, .mipsel, .mips64, .mips64el => true,
        else => false,
    };
    const uv = b.addLibrary(.{
        .name = "uv",
        .linkage = .static,
        .root_module = b.createModule(.{
            .link_libc = true,
            .target = target,
            .optimize = optimize,
            .pic = if (is_mips) true else null,
        }),
    });
    applyLinkOptimization(b, target, uv, optimize);

    // Zig (as of 0.14) does not inject musl libc header search paths for MIPS
    // targets when compiling C files via the build system (unlike `zig cc`).
    // Manually add them so that <stdio.h> and friends are found.
    if (is_mips) {
        const zig_lib = b.graph.zig_lib_directory.path orelse @panic("zig_lib_directory path is null");
        const libc_include = b.pathJoin(&.{ zig_lib, "libc", "include" });
        const arch_tag = switch (target.result.cpu.arch) {
            .mips64, .mips64el => "mips64-linux-musl",
            .mips, .mipsel => "mips-linux-musl",
            else => unreachable,
        };
        uv.root_module.addSystemIncludePath(.{ .cwd_relative = b.pathJoin(&.{ libc_include, arch_tag }) });
        uv.root_module.addSystemIncludePath(.{ .cwd_relative = b.pathJoin(&.{ libc_include, "generic-musl" }) });
        uv.root_module.addSystemIncludePath(.{ .cwd_relative = b.pathJoin(&.{ libc_include, "mips-linux-any" }) });
        uv.root_module.addSystemIncludePath(.{ .cwd_relative = b.pathJoin(&.{ libc_include, "any-linux-any" }) });
    }

    uv.root_module.addIncludePath(b.path("deps/libuv/include"));
    // libuv has internal headers included from its own C sources.
    uv.root_module.addIncludePath(b.path("deps/libuv/src"));

    // Base sources from deps/libuv/CMakeLists.txt (uv_sources)
    uv.root_module.addCSourceFiles(.{
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
        uv.root_module.linkSystemLibrary("advapi32", .{});
        uv.root_module.linkSystemLibrary("user32", .{});
        uv.root_module.linkSystemLibrary("shell32", .{});
        uv.root_module.addCMacro("WIN32_LEAN_AND_MEAN", "1");
        uv.root_module.addCMacro("_WIN32_WINNT", "0x0A00");
        uv.root_module.addCMacro("_CRT_DECLARE_NONSTDC_NAMES", "0");

        uv.root_module.addCSourceFiles(.{
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

        uv.root_module.addCSourceFiles(.{
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
            uv.root_module.addCSourceFiles(.{
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
        if (os_tag == .macos) {
            uv.root_module.addCMacro("_DARWIN_USE_64_BIT_INODE", "1");
            uv.root_module.addCMacro("_DARWIN_UNLIMITED_SELECT", "1");

            uv.root_module.addCSourceFiles(.{
                .files = &.{
                    "deps/libuv/src/unix/proctitle.c",
                    "deps/libuv/src/unix/bsd-ifaddrs.c",
                    "deps/libuv/src/unix/darwin.c",
                    "deps/libuv/src/unix/darwin-proctitle.c",
                    "deps/libuv/src/unix/fsevents.c",
                    "deps/libuv/src/unix/kqueue.c",
                    "deps/libuv/src/unix/random-getentropy.c",
                },
                .flags = &.{},
            });
        }
    }

    return uv;
}

/// Returns the CC value for a wrapper script. On Windows hosts, Go cannot find .sh files
/// in PATH, so we use "bash <abs-path>" with forward-slash conversion. On Linux, the wrapper
/// basename is sufficient (Go finds it via PATH and it's executable).
fn wrapperBashCmd(b: *std.Build, wrapper: std.Build.LazyPath) []const u8 {
    if (@import("builtin").os.tag == .windows) {
        const raw = wrapper.getPath(b);
        const buf = b.allocator.alloc(u8, raw.len + 5) catch @panic("OOM");
        @memcpy(buf[0..5], "bash ");
        for (raw, 0..) |c, i| {
            buf[i + 5] = if (c == '\\') '/' else c;
        }
        return buf;
    } else {
        return std.fs.path.basename(wrapper.getPath(b));
    }
}
fn createWrapperScript(
    b: *std.Build,
    wrapper_dir: std.Build.LazyPath,
    script_name: []const u8,
    zig_exe: []const u8,
    target_triple: ?[]const u8,
    is_cxx: bool,
    is_msvc: bool,
) !std.Build.LazyPath {
    const zig_dropin = b.fmt("zig-{s}", .{script_name});
    const wrapper_path = try wrapper_dir.join(b.allocator, zig_dropin);
    const cc_or_cxx = if (is_cxx) "c++" else "cc";
    const is_win = @import("builtin").os.tag == .windows;
    // Convert Windows backslash paths to forward slashes at build time.
    // "C:\Program Files\zig\zig.exe" → "C:/Program Files/zig/zig.exe"
    // Forward slashes work in bash and in Windows' CreateProcess.
    const zig_fwd = if (is_win) blk: {
        const buf = b.allocator.alloc(u8, zig_exe.len) catch @panic("OOM");
        for (zig_exe, 0..) |c, i| {
            buf[i] = if (c == '\\') '/' else c;
        }
        break :blk @as([]const u8, buf);
    } else zig_exe;
    const script_content = if (target_triple) |triple| blk: {
        if (is_msvc) {
            // Filter GCC-only flags from GOGCCFLAGS that Zig rejects for MSVC targets.
            break :blk b.fmt(
                "#!/bin/sh\n" ++
                    "zig='{s}'\n" ++
                    "\"$zig\" {s} -target {s} $(skip=0; for a in \"$@\"; do\n" ++
                    "  if [ \"$skip\" = 1 ]; then skip=0; continue; fi\n" ++
                    "  case \"$a\" in -mthreads|-m64|-gno-record-gcc-switches) continue;;\n" ++
                    "  -Wl) skip=1; continue;;\n" ++
                    "  -fmessage-length*|-ffile-prefix-map=*|-fmacro-prefix-map=*|-fdebug-prefix-map=*) continue;;\n" ++
                    "  esac\n" ++
                    "  printf '%s\\n' \"$a\"\n" ++
                    "done)\n",
                .{ zig_fwd, cc_or_cxx, triple },
            );
        } else {
            break :blk b.fmt(
                "#!/bin/sh\n'{s}' {s} -target {s} \"$@\"\n",
                .{ zig_fwd, cc_or_cxx, triple },
            );
        }
    } else b.fmt(
        "#!/bin/sh\n'{s}' ar \"$@\"\n",
        .{zig_fwd},
    );
    const io = b.graph.io;
    const file = if (@import("builtin").os.tag == .windows)
        try std.Io.Dir.cwd().createFile(io, wrapper_path.getPath(b), .{
            .truncate = true,
        })
    else
        try std.Io.Dir.cwd().createFile(io, wrapper_path.getPath(b), .{
            .truncate = true,
            .permissions = .fromMode(0o755),
        });
    defer file.close(io);
    try file.writeStreamingAll(io, script_content);
    return wrapper_path;
}
fn detectCustomGoBin(b: *std.Build, host_os: std.Target.Os.Tag, go_root_path: []const u8) ?[]const u8 {
    const default_go_bin = if (host_os == .windows)
        b.pathJoin(&.{ go_root_path, "bin", "go.exe" })
    else
        b.pathJoin(&.{ go_root_path, "bin", "go" });

    if (customGoRootComplete(b, go_root_path) and pathExists(b, default_go_bin)) {
        return default_go_bin;
    }

    // Windows zip often extracts under a top-level "go" folder.
    if (host_os == .windows) {
        const nested_go_root = b.pathJoin(&.{ go_root_path, "go" });
        const nested_go_bin = b.pathJoin(&.{ go_root_path, "go", "bin", "go.exe" });
        if (customGoRootComplete(b, nested_go_root) and pathExists(b, nested_go_bin)) {
            return nested_go_bin;
        }
    }

    return null;
}

fn pathExists(b: *std.Build, path: []const u8) bool {
    std.Io.Dir.cwd().access(b.graph.io, path, .{}) catch return false;
    return true;
}

fn customGoRootComplete(b: *std.Build, go_root_path: []const u8) bool {
    const required_paths = [_][]const u8{
        "src/unsafe/unsafe.go",
        "src/runtime/runtime.go",
        "src/sync/mutex.go",
        "src/net/net.go",
        "src/math/bits/bits.go",
    };

    for (required_paths) |required_path| {
        const path = b.pathJoin(&.{ go_root_path, required_path });
        if (!pathExists(b, path)) return false;
    }

    return true;
}

fn downloadFileWithFallback(b: *std.Build, host_os: std.Target.Os.Tag, url: []const u8, output_path: []const u8) void {
    const io = b.graph.io;
    var downloaded = false;

    const wget_argv = [_][]const u8{
        "wget",
        "-q",
        "-O",
        output_path,
        url,
    };
    const wget_result = std.process.run(b.allocator, io, .{ .argv = &wget_argv }) catch null;
    if (wget_result) |result| {
        defer b.allocator.free(result.stdout);
        defer b.allocator.free(result.stderr);
        if (result.term == .exited and result.term.exited == 0) {
            downloaded = true;
        }
    }

    if (!downloaded) {
        const curl_argv = [_][]const u8{
            "curl",
            "-L",
            "-f",
            "-sS",
            "-o",
            output_path,
            url,
        };
        const curl_result = std.process.run(b.allocator, io, .{ .argv = &curl_argv }) catch null;
        if (curl_result) |result| {
            defer b.allocator.free(result.stdout);
            defer b.allocator.free(result.stderr);
            if (result.term == .exited and result.term.exited == 0) {
                downloaded = true;
            }
        }
    }

    if (!downloaded and host_os == .windows) {
        const ps_cmd = b.fmt("Invoke-WebRequest -Uri \"{s}\" -OutFile \"{s}\"", .{ url, output_path });
        const ps_argv = [_][]const u8{
            "powershell",
            "-NoProfile",
            "-Command",
            ps_cmd,
        };
        const ps_result = std.process.run(b.allocator, io, .{ .argv = &ps_argv }) catch null;
        if (ps_result) |result| {
            defer b.allocator.free(result.stdout);
            defer b.allocator.free(result.stderr);
            if (result.term == .exited and result.term.exited == 0) {
                downloaded = true;
            }
        }
    }

    if (!downloaded) {
        @panic("Failed to download Go toolchain (tried wget, curl, and PowerShell on Windows)");
    }
}

fn ensureMuslGoToolchain(b: *std.Build) ?[]const u8 {
    const host_os = b.graph.host.result.os.tag;
    const host_arch = b.graph.host.result.cpu.arch;

    // Only support x86_64 hosts for now
    if (host_arch != .x86_64) {
        return null;
    }

    // Support both Linux and Windows hosts
    if (host_os != .linux and host_os != .windows) {
        return null;
    }
    const go_root = b.cache_root.join(b.allocator, &.{"portweaver-go"}) catch @panic("OOM");
    const go_root_path = b.path(go_root).getPath(b);

    if (detectCustomGoBin(b, host_os, go_root_path)) |cached_go_bin| {
        std.debug.print("Using cached patched Go: {s}\n", .{cached_go_bin});
        return cached_go_bin;
    }

    {
        // Need to download Go toolchain synchronously at config time
        std.debug.print("Downloading patched Go 1.25.7 for musl builds...\n", .{});
        std.Io.Dir.cwd().deleteTree(b.graph.io, go_root_path) catch |err| {
            std.debug.print("Warning: failed to clean incomplete Go toolchain cache: {}\n", .{err});
        };
        const tarball_ext = if (host_os == .windows) ".zip" else ".tar.gz";
        const temp_tarball = b.cache_root.join(b.allocator, &.{b.fmt("portweaver-go{s}", .{tarball_ext})}) catch @panic("OOM");
        const temp_tarball_path = b.path(temp_tarball).getPath(b);

        // Determine download URL based on host OS
        const go_url = switch (host_os) {
            .linux => "https://github.com/LazuliKao/build-golang/releases/download/go1.25.7/go1.25.7.linux-amd64.tar.gz",
            .windows => "https://github.com/LazuliKao/build-golang/releases/download/go1.25.7/go1.25.7.windows-amd64.zip",
            else => return null,
        };

        // Download tarball with fallbacks
        downloadFileWithFallback(b, host_os, go_url, temp_tarball_path);

        // Create go_root directory
        std.Io.Dir.cwd().createDirPath(b.graph.io, go_root_path) catch @panic("Failed to create go_root directory");
        // Extract based on file type
        if (host_os == .windows) {
            // Windows: use PowerShell to extract zip
            const unzip_argv = [_][]const u8{
                "powershell",
                "-Command",
                b.fmt("Expand-Archive -Path '{s}' -DestinationPath '{s}' -Force", .{ temp_tarball_path, go_root_path }),
            };
            const unzip_result = std.process.run(b.allocator, b.graph.io, .{ .argv = &unzip_argv }) catch @panic("Failed to run PowerShell");
            defer b.allocator.free(unzip_result.stdout);
            defer b.allocator.free(unzip_result.stderr);
            if (unzip_result.term != .exited or unzip_result.term.exited != 0) {
                @panic("zip extraction failed");
            }
        } else {
            // Linux: use tar
            const tar_argv = [_][]const u8{
                "tar",
                "xzf",
                temp_tarball_path,
                "-C",
                go_root_path,
                "--strip-components=1",
            };
            const tar_result = std.process.run(b.allocator, b.graph.io, .{ .argv = &tar_argv }) catch @panic("Failed to run tar");
            defer b.allocator.free(tar_result.stdout);
            defer b.allocator.free(tar_result.stderr);
            if (tar_result.term != .exited or tar_result.term.exited != 0) {
                @panic("tar extraction failed");
            }
        }
        // Remove tarball
        std.Io.Dir.cwd().deleteFile(b.graph.io, temp_tarball_path) catch {};

        const extracted_go_bin = detectCustomGoBin(b, host_os, go_root_path) orelse
            @panic("Downloaded Go toolchain but go binary was not found");
        return extracted_go_bin;
    }
}

const upx_version = "5.1.1";

fn ensureUpx(b: *std.Build) ?[]const u8 {
    const host_os = b.graph.host.result.os.tag;
    const host_arch = b.graph.host.result.cpu.arch;

    // Only x86_64 and aarch64 hosts are supported
    if (host_arch != .x86_64 and host_arch != .aarch64) {
        return null;
    }
    // Only Linux and Windows hosts
    if (host_os != .linux and host_os != .windows) {
        return null;
    }

    const upx_root = b.cache_root.join(b.allocator, &.{"portweaver-upx"}) catch @panic("OOM");
    const upx_root_path = b.path(upx_root).getPath(b);

    // Check for cached binary
    const upx_bin = if (host_os == .windows)
        b.pathJoin(&.{ upx_root_path, "upx.exe" })
    else
        b.pathJoin(&.{ upx_root_path, "upx" });

    if (pathExists(b, upx_bin)) {
        std.debug.print("Using cached UPX: {s}\n", .{upx_bin});
        return upx_bin;
    }

    {
        std.debug.print("Downloading UPX {s}...\n", .{upx_version});
        std.Io.Dir.cwd().deleteTree(b.graph.io, upx_root_path) catch |err| {
            std.debug.print("Warning: failed to clean incomplete UPX cache: {}\n", .{err});
        };

        // Determine download URL based on host OS and arch
        const arch_suffix = switch (host_arch) {
            .x86_64 => "amd64",
            .aarch64 => "arm64",
            else => return null,
        };
        const url = switch (host_os) {
            .linux => b.fmt(
                "https://github.com/upx/upx/releases/download/v{s}/upx-{s}-{s}_linux.tar.xz",
                .{ upx_version, upx_version, arch_suffix },
            ),
            .windows => b.fmt(
                "https://github.com/upx/upx/releases/download/v{s}/upx-{s}-win64.zip",
                .{ upx_version, upx_version },
            ),
            else => return null,
        };

        const is_zip = (host_os == .windows);
        const archive_ext = if (is_zip) ".zip" else ".tar.xz";
        const temp_archive = b.cache_root.join(b.allocator, &.{b.fmt("portweaver-upx{s}", .{archive_ext})}) catch @panic("OOM");
        const temp_archive_path = b.path(temp_archive).getPath(b);

        downloadFileWithFallback(b, host_os, url, temp_archive_path);

        // Create upx_root directory
        std.Io.Dir.cwd().createDirPath(b.graph.io, upx_root_path) catch @panic("Failed to create UPX cache directory");

        // Extract based on file type
        if (is_zip) {
            const unzip_argv = [_][]const u8{
                "powershell",
                "-NoProfile",
                "-Command",
                b.fmt("Expand-Archive -Path '{s}' -DestinationPath '{s}' -Force", .{ temp_archive_path, upx_root_path }),
            };
            const result = std.process.run(b.allocator, b.graph.io, .{ .argv = &unzip_argv }) catch @panic("Failed to run PowerShell");
            defer b.allocator.free(result.stdout);
            defer b.allocator.free(result.stderr);
            if (result.term != .exited or result.term.exited != 0) {
                @panic("UPX zip extraction failed");
            }
            // UPX win64 zip extracts with a version-prefixed directory — move files up
            const nested = b.pathJoin(&.{ upx_root_path, b.fmt("upx-{s}-win64", .{upx_version}) });
            if (pathExists(b, nested)) {
                const io = b.graph.io;
                var src_dir = std.Io.Dir.cwd().openDir(io, nested, .{ .iterate = true }) catch @panic("Failed to open nested UPX dir");
                defer src_dir.close(io);
                const upx_name = "upx.exe";
                // Use cross-directory rename: from nested/upx.exe → upx_root/upx.exe
                var dst_dir = std.Io.Dir.cwd().openDir(io, upx_root_path, .{}) catch @panic("Failed to open UPX cache dir");
                defer dst_dir.close(io);
                src_dir.rename(upx_name, dst_dir, upx_name, io) catch {};
            }
        } else {
            // Linux/macOS: tar.xz
            const tar_argv = [_][]const u8{
                "tar",
                "xJf",
                temp_archive_path,
                "-C",
                upx_root_path,
                "--strip-components=1",
            };
            const result = std.process.run(b.allocator, b.graph.io, .{ .argv = &tar_argv }) catch @panic("Failed to run tar");
            defer b.allocator.free(result.stdout);
            defer b.allocator.free(result.stderr);
            if (result.term != .exited or result.term.exited != 0) {
                @panic("UPX tar extraction failed");
            }
        }

        // Remove archive
        std.Io.Dir.cwd().deleteFile(b.graph.io, temp_archive_path) catch {};

        if (!pathExists(b, upx_bin)) {
            @panic("Downloaded UPX but binary was not found");
        }
        return upx_bin;
    }
}

fn addGoLibrary(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    output_path: []const u8, // Full output path including directory and filename
    tags: ?[]const u8,
) *std.Build.Step {
    const os_tag = target.result.os.tag;
    const arch_tag = target.result.cpu.arch;

    if (!goCArchiveSupported(os_tag, arch_tag)) {
        return &b.addFail("Go -buildmode=c-archive is not supported for this target; disable -Dfrpc/-Dfrps/-Dddns or choose a supported architecture").step;
    }

    // Check if we should use custom Go toolchain for musl targets
    const use_custom_go = target.result.abi.isMusl() and
        (b.graph.host.result.os.tag == .linux or b.graph.host.result.os.tag == .windows) and
        b.graph.host.result.cpu.arch == .x86_64;

    // Get custom Go path if needed
    const custom_go_path = if (use_custom_go) ensureMuslGoToolchain(b) else null;

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
    const goarm = if (arch_tag == .arm) switch (target.result.abi) {
        .gnueabi, .musleabi => "5",
        .gnueabihf, .musleabihf => "7",
        else => null,
    } else null;

    var go_args = std.ArrayListUnmanaged([]const u8).empty;
    const go_exe = if (custom_go_path) |path| path else "go";
    go_args.appendSlice(b.allocator, &.{
        go_exe,
        "build",
        "-buildmode=c-archive",
    }) catch @panic("OOM");

    const effective_tags = if (os_tag == .linux)
        if (tags) |t|
            b.fmt("{s},netgo,osusergo", .{t})
        else
            "netgo,osusergo"
    else
        tags;

    if (effective_tags) |t| {
        go_args.append(b.allocator, b.fmt("-tags={s}", .{t})) catch @panic("OOM");
    }

    if (optimize == .ReleaseSmall) {
        go_args.appendSlice(b.allocator, &.{
            "-trimpath",
            "-ldflags=-linkmode external -s -w -buildid= -extldflags=-static",
            "-gcflags=all=-l -B -C",
            "-o",
            output_path,
            ".",
        }) catch @panic("OOM");
    } else {
        go_args.appendSlice(b.allocator, &.{
            "-ldflags=-linkmode external -extldflags=-static",
            "-o",
            output_path,
            ".",
        }) catch @panic("OOM");
    }

    const go_cmd = b.addSystemCommand(go_args.items);

    // Go source files are always in src/impl/golibs
    go_cmd.setCwd(b.path("src/impl/golibs"));

    go_cmd.setEnvironmentVariable("GOOS", goos);
    go_cmd.setEnvironmentVariable("GOARCH", goarch);
    if (goarm) |goarm_value| {
        go_cmd.setEnvironmentVariable("GOARM", goarm_value);
    }

    // Use architecture-specific GOCACHE to avoid conflicts during parallel builds
    // GOCACHE must be an absolute path, use zig's cache root
    const target_triple_for_cache = target.result.linuxTriple(b.allocator) catch @panic("Failed to get target triple");
    const go_cache = b.cache_root.join(b.allocator, &.{ "go", goos, target_triple_for_cache }) catch @panic("OOM");
    const go_cache_rel = b.path(go_cache).getPath(b);

    // std.debug.print("Go cache path: {s}\n", .{go_cache_rel});

    go_cmd.setEnvironmentVariable("GOCACHE", go_cache_rel);
    // Force module mode explicitly so cross-builds behave consistently.
    go_cmd.setEnvironmentVariable("GO111MODULE", "on");

    // For musl targets, use sanitized environment with custom Go toolchain
    // This prevents conflicts with system Go installation
    if (use_custom_go) {
        go_cmd.setEnvironmentVariable("GOENV", "off");
        go_cmd.setEnvironmentVariable("GOTOOLDIR", "");
        go_cmd.setEnvironmentVariable("GOROOT_FINAL", "");

        // Set GOROOT to the actual root that contains src/pkg/bin.
        // On Windows zip builds this can be either <cache>/portweaver-go or
        // <cache>/portweaver-go/go depending on archive layout.
        const go_exe_path = custom_go_path orelse @panic("custom_go_path is null in use_custom_go branch");
        const go_bin_dir = std.fs.path.dirname(go_exe_path) orelse @panic("Invalid go executable path");
        const go_root_path = std.fs.path.dirname(go_bin_dir) orelse @panic("Invalid go bin directory path");
        go_cmd.setEnvironmentVariable("GOROOT", go_root_path);

        // Set GOMODCACHE to cache path for isolation
        const go_modcache = b.cache_root.join(b.allocator, &.{ "go", "modcache" }) catch @panic("OOM");
        const go_modcache_path = b.path(go_modcache).getPath(b);
        go_cmd.setEnvironmentVariable("GOMODCACHE", go_modcache_path);
        go_cmd.setEnvironmentVariable("GOFLAGS", "-modcacherw");

        // Set GOPATH as well to avoid GOPATH-derived defaults becoming invalid.
        const go_path = b.cache_root.join(b.allocator, &.{"go"}) catch @panic("OOM");
        go_cmd.setEnvironmentVariable("GOPATH", b.path(go_path).getPath(b));

        // Prevent empty/invalid GOPROXY inherited from host from breaking module downloads.
        if (b.graph.environ_map.get("GOPROXY")) |goproxy| {
            if (goproxy.len > 0) {
                go_cmd.setEnvironmentVariable("GOPROXY", goproxy);
            } else {
                go_cmd.setEnvironmentVariable("GOPROXY", "https://proxy.golang.org,direct");
            }
        } else {
            go_cmd.setEnvironmentVariable("GOPROXY", "https://proxy.golang.org,direct");
        }

        if (b.graph.environ_map.get("GOSUMDB")) |gosumdb| {
            if (gosumdb.len > 0) {
                go_cmd.setEnvironmentVariable("GOSUMDB", gosumdb);
            } else {
                go_cmd.setEnvironmentVariable("GOSUMDB", "sum.golang.org");
            }
        } else {
            go_cmd.setEnvironmentVariable("GOSUMDB", "sum.golang.org");
        }

        std.debug.print("Using sanitized Go environment for musl target\n", .{});
    } else {
        // Pass through GOROOT from environment if set - critical for using custom Go installation
        // Without this, Go may use system's default GOROOT which can cause conflicts
        if (b.graph.environ_map.get("GOROOT")) |goroot| {
            std.debug.print("Using GOROOT from environment: {s}\n", .{goroot});
            go_cmd.setEnvironmentVariable("GOROOT", goroot);
        } else {
            // std.debug.print("GOROOT not set in environment, Go will use its default\n", .{});
        }

        // Also pass through GOPATH and GOMODCACHE if set
        if (b.graph.environ_map.get("GOPATH")) |gopath| {
            go_cmd.setEnvironmentVariable("GOPATH", gopath);
        } else {}
        if (b.graph.environ_map.get("GOMODCACHE")) |gomodcache| {
            go_cmd.setEnvironmentVariable("GOMODCACHE", gomodcache);
        } else {}
    }
    const zig_exe = b.graph.zig_exe;
    // 构建目标三元组
    const target_triple = target.result.linuxTriple(b.allocator) catch @panic("Failed to get target triple");
    go_cmd.setEnvironmentVariable("CGO_ENABLED", "1");
    const is_msvc = target.result.os.tag == .windows and target.result.abi == .msvc;
    const wrapper_dir = b.path("wrapper");
    go_cmd.addPathDir(wrapper_dir.getPath(b));
    const is_win_host = b.graph.host.result.os.tag == .windows;
    if (is_msvc) {
        // MSVC targets: Go CGO adds -mthreads and GOGCCFLAGS which Zig rejects.
        // Use bash wrapper scripts that filter out GCC-only flags.
        const cc_wrapper = createWrapperScript(b, wrapper_dir, "cc", zig_exe, target_triple, false, true) catch @panic("Failed to create CC wrapper");
        const cxx_wrapper = createWrapperScript(b, wrapper_dir, "c++", zig_exe, target_triple, true, true) catch @panic("Failed to create CXX wrapper");
        const ar_wrapper = createWrapperScript(b, wrapper_dir, "ar", zig_exe, null, false, false) catch @panic("Failed to create AR wrapper");
        go_cmd.setEnvironmentVariable("CC", wrapperBashCmd(b, cc_wrapper));
        go_cmd.setEnvironmentVariable("CXX", wrapperBashCmd(b, cxx_wrapper));
        go_cmd.setEnvironmentVariable("AR", std.fs.path.basename(ar_wrapper.getPath(b)));
        // MSVC doesn't support GCC-style -static / -Wl flags
        go_cmd.setEnvironmentVariable("CGO_CFLAGS", applyCOptimizationCmd(b, optimize));
        go_cmd.setEnvironmentVariable("CGO_CXXFLAGS", applyCOptimizationCmd(b, optimize));
        go_cmd.setEnvironmentVariable("CGO_LDFLAGS", "");
    } else if (is_win_host) {
        // Windows host compiling for non-MSVC target (e.g. linux-musl):
        // No GCC flag filtering is needed, and we can invoke zig directly without wrapper scripts.
        const cc_cmd = b.fmt("\"{s}\" cc -target {s}", .{ zig_exe, target_triple });
        const cxx_cmd = b.fmt("\"{s}\" c++ -target {s}", .{ zig_exe, target_triple });
        const ar_cmd = b.fmt("\"{s}\" ar", .{zig_exe});
        go_cmd.setEnvironmentVariable("CC", cc_cmd);
        go_cmd.setEnvironmentVariable("CXX", cxx_cmd);
        go_cmd.setEnvironmentVariable("AR", ar_cmd);
        go_cmd.setEnvironmentVariable("CGO_CFLAGS", b.fmt("-static {s}", .{applyCOptimizationCmd(b, optimize)}));
        go_cmd.setEnvironmentVariable("CGO_CXXFLAGS", b.fmt("-static {s}", .{applyCOptimizationCmd(b, optimize)}));
        go_cmd.setEnvironmentVariable("CGO_LDFLAGS", b.fmt("-static {s}", .{applyLinkOptimizationCmd(b, optimize)}));
    } else {
        // Non-MSVC targets on non-Windows host (e.g. compiling on Linux):
        // Use wrapper scripts.
        const cc_wrapper = createWrapperScript(b, wrapper_dir, "cc", zig_exe, target_triple, false, false) catch @panic("Failed to create CC wrapper");
        const cxx_wrapper = createWrapperScript(b, wrapper_dir, "c++", zig_exe, target_triple, true, false) catch @panic("Failed to create CXX wrapper");
        const ar_wrapper = createWrapperScript(b, wrapper_dir, "ar", zig_exe, null, false, false) catch @panic("Failed to create AR wrapper");
        go_cmd.setEnvironmentVariable("CC", wrapperBashCmd(b, cc_wrapper));
        go_cmd.setEnvironmentVariable("CXX", wrapperBashCmd(b, cxx_wrapper));
        go_cmd.setEnvironmentVariable("AR", std.fs.path.basename(ar_wrapper.getPath(b)));
        go_cmd.setEnvironmentVariable("CGO_CFLAGS", b.fmt("-static {s}", .{applyCOptimizationCmd(b, optimize)}));
        go_cmd.setEnvironmentVariable("CGO_CXXFLAGS", b.fmt("-static {s}", .{applyCOptimizationCmd(b, optimize)}));
        go_cmd.setEnvironmentVariable("CGO_LDFLAGS", b.fmt("-static {s}", .{applyLinkOptimizationCmd(b, optimize)}));
    }
    return &go_cmd.step;
}

fn goCArchiveSupported(os_tag: std.Target.Os.Tag, arch_tag: std.Target.Cpu.Arch) bool {
    return switch (os_tag) {
        .linux => switch (arch_tag) {
            .x86,
            .x86_64,
            .arm,
            .aarch64,
            .loongarch64,
            .powerpc64,
            .powerpc64le,
            .riscv64,
            .s390x,
            => true,
            else => false,
        },
        else => true,
    };
}

const LibResult = struct { step: *std.Build.Step, dir: std.Build.LazyPath, libname: []const u8, libfilename: []const u8 };
fn addCombinedGoLib(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    frpc: bool,
    ddns: bool,
    frps: bool,
) LibResult {
    // Determine build tags based on feature flags
    // Handle all possible combinations of frpc, ddns, and frps

    if (!frpc and !ddns and !frps) {
        @panic("At least one of frpc, ddns, or frps must be true when calling addCombinedGoLib");
    }

    // Build tag lists dynamically based on feature flags
    var tag_parts: std.ArrayList([]const u8) = .empty;
    defer tag_parts.deinit(b.allocator);
    tag_parts.append(b.allocator, "noweb") catch @panic("OOM");
    if (frpc) {
        tag_parts.append(b.allocator, "libfrpc") catch @panic("OOM");
    }
    if (ddns) {
        tag_parts.append(b.allocator, "libddns") catch @panic("OOM");
    }
    if (frps) {
        tag_parts.append(b.allocator, "libfrps") catch @panic("OOM");
    }

    const tags = std.mem.join(b.allocator, ",", tag_parts.items) catch @panic("OOM");
    defer b.allocator.free(tags);
    const tags_dir = std.mem.join(b.allocator, "-", tag_parts.items) catch @panic("OOM");
    defer b.allocator.free(tags_dir);

    // Use architecture- and feature-specific output directory for parallel build support
    const target_triple = target.result.linuxTriple(b.allocator) catch @panic("Failed to get target triple");
    const arch_dir = b.fmt("src/impl/golibs/dist/{s}/{s}", .{ target_triple, tags_dir });
    const filename = if (target.result.os.tag == .windows) "golibs.lib" else "libgolibs.a";
    // Output path is relative to the Go working directory (src/impl/golibs)
    const output_path = b.fmt("dist/{s}/{s}/{s}", .{ target_triple, tags_dir, filename });

    // Ensure output directory exists (at build script parse time)
    std.Io.Dir.cwd().createDirPath(b.graph.io, arch_dir) catch {};

    return .{
        .step = addGoLibrary(b, target, optimize, output_path, tags),
        .dir = b.path(arch_dir),
        .libname = "golibs",
        .libfilename = filename,
    };
}

const ForwardBackend = enum { libuv, asio, io_uring };

const LibUringResult = struct {
    lib: *std.Build.Step.Compile,
    compat_h: *std.Build.Step.ConfigHeader,
    version_h: *std.Build.Step.ConfigHeader,
};

fn addLiburing(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) LibUringResult {
    const is_mips = switch (target.result.cpu.arch) {
        .mips, .mipsel, .mips64, .mips64el => true,
        else => false,
    };
    const lib = b.addLibrary(.{
        .name = "uring",
        .linkage = .static,
        .root_module = b.createModule(.{
            .link_libc = true,
            .target = target,
            .optimize = optimize,
            .pic = if (is_mips) true else null,
        }),
    });

    const compat_h = b.addConfigHeader(.{
        .style = .{ .cmake = b.path("src/impl/app_forward/forwarder/impl_io_uring/compat.h.in") },
        .include_path = "liburing/compat.h",
    }, .{});
    lib.root_module.addConfigHeader(compat_h);

    const version_h = b.addConfigHeader(.{
        .style = .{ .cmake = b.path("src/impl/app_forward/forwarder/impl_io_uring/io_uring_version.h.in") },
        .include_path = "liburing/io_uring_version.h",
    }, .{
        .IO_URING_VERSION_MAJOR = 2,
        .IO_URING_VERSION_MINOR = 15,
    });
    lib.root_module.addConfigHeader(version_h);

    lib.root_module.addCSourceFiles(.{
        .files = &.{
            "deps/liburing/src/setup.c",
            "deps/liburing/src/queue.c",
            "deps/liburing/src/register.c",
            "deps/liburing/src/syscall.c",
        },
        .flags = &.{ "-D_GNU_SOURCE", "-D_LARGEFILE_SOURCE", "-D_FILE_OFFSET_BITS=64" },
    });
    lib.root_module.addIncludePath(b.path("deps/liburing/src/include"));
    lib.root_module.addIncludePath(b.path("deps/liburing/src"));
    return .{
        .lib = lib,
        .compat_h = compat_h,
        .version_h = version_h,
    };
}

fn addForwarderBackend(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    backend: ForwardBackend,
    root_module: *std.Build.Module,
) void {
    root_module.addIncludePath(b.path("src/impl/app_forward/forwarder"));

    switch (backend) {
        .libuv => {
            const uv = addLibuv(b, target, optimize);
            root_module.linkLibrary(uv);
            root_module.addIncludePath(b.path("deps/libuv/include"));
            root_module.addIncludePath(b.path("deps/libuv/src"));
            root_module.addCSourceFile(.{
                .file = b.path("src/impl/app_forward/forwarder/impl_libuv/runtime.c"),
                .flags = if (optimize == .Debug) &.{"-DDEBUG"} else &.{},
            });
            root_module.addCSourceFile(.{
                .file = b.path("src/impl/app_forward/forwarder/impl_libuv/tcp_forwarder.c"),
                .flags = if (optimize == .Debug) &.{"-DDEBUG"} else &.{},
            });
            root_module.addCSourceFile(.{
                .file = b.path("src/impl/app_forward/forwarder/impl_libuv/udp_forwarder.c"),
                .flags = if (optimize == .Debug) &.{"-DDEBUG"} else &.{},
            });
            root_module.addCSourceFile(.{
                .file = b.path("src/impl/file_watcher.c"),
                .flags = if (optimize == .Debug) &.{"-DDEBUG"} else &.{},
            });
        },
        .asio => {
            root_module.addIncludePath(b.path("deps/asio/asio/include"));
            root_module.addCSourceFile(.{
                .file = b.path("src/impl/app_forward/forwarder/impl_asio/runtime.cpp"),
                .flags = if (optimize == .Debug) &.{ "-std=c++17", "-DDEBUG" } else &.{"-std=c++17"},
            });
            root_module.addCSourceFile(.{
                .file = b.path("src/impl/app_forward/forwarder/impl_asio/tcp_forwarder.cpp"),
                .flags = if (optimize == .Debug) &.{ "-std=c++17", "-DDEBUG" } else &.{"-std=c++17"},
            });
            root_module.addCSourceFile(.{
                .file = b.path("src/impl/app_forward/forwarder/impl_asio/udp_forwarder.cpp"),
                .flags = if (optimize == .Debug) &.{ "-std=c++17", "-DDEBUG" } else &.{"-std=c++17"},
            });
            root_module.linkSystemLibrary("c++", .{});
            if (target.result.os.tag == .windows) {
                root_module.linkSystemLibrary("ws2_32", .{});
                root_module.linkSystemLibrary("mswsock", .{});
            }
        },
        .io_uring => {
            if (target.result.os.tag != .linux) {
                @panic("io_uring backend requires Linux target. Use -Dforward_backend=libuv or asio for non-Linux targets.");
            }
            // The configuration file watcher remains libuv-based; only the
            // application-layer forwarding executor is replaced by io_uring.
            const uv = addLibuv(b, target, optimize);
            root_module.linkLibrary(uv);
            root_module.addIncludePath(b.path("deps/libuv/include"));
            root_module.addIncludePath(b.path("deps/libuv/src"));
            root_module.addCSourceFile(.{
                .file = b.path("src/impl/file_watcher.c"),
                .flags = if (optimize == .Debug) &.{"-DDEBUG"} else &.{},
            });
            const uring_res = addLiburing(b, target, optimize);
            root_module.linkLibrary(uring_res.lib);
            root_module.addConfigHeader(uring_res.compat_h);
            root_module.addConfigHeader(uring_res.version_h);
            root_module.addIncludePath(b.path("deps/liburing/src/include"));
            root_module.addCSourceFile(.{
                .file = b.path("src/impl/app_forward/forwarder/impl_io_uring/runtime.c"),
                .flags = if (optimize == .Debug) &.{ "-DDEBUG", "-D_GNU_SOURCE" } else &.{"-D_GNU_SOURCE"},
            });
            root_module.addCSourceFile(.{
                .file = b.path("src/impl/app_forward/forwarder/impl_io_uring/tcp_forwarder.c"),
                .flags = if (optimize == .Debug) &.{ "-DDEBUG", "-D_GNU_SOURCE" } else &.{"-D_GNU_SOURCE"},
            });
            root_module.addCSourceFile(.{
                .file = b.path("src/impl/app_forward/forwarder/impl_io_uring/udp_forwarder.c"),
                .flags = if (optimize == .Debug) &.{ "-DDEBUG", "-D_GNU_SOURCE" } else &.{"-D_GNU_SOURCE"},
            });
        },
    }
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

    const frps = b.option(bool, "frps", "FRP Server Support") orelse false;
    options.addOption(bool, "frps_mode", frps);

    const nftables = b.option(bool, "nftables", "nftables Support") orelse false;
    options.addOption(bool, "nftables_mode", nftables);

    const wol = b.option(bool, "wol", "Wake-on-LAN Support") orelse false;
    options.addOption(bool, "wol_mode", wol);

    const upx = b.option(bool, "upx", "Compress executable with UPX (auto-downloads if not cached)") orelse false;

    const forward_backend = b.option(ForwardBackend, "forward_backend", "Forwarding backend (libuv, asio or io_uring)") orelse .libuv;
    options.addOption(ForwardBackend, "forward_backend", forward_backend);

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

    // Build and link combined Go library (FRP, DDNS, and FRPS) when any feature is enabled
    if (frpc or ddns or frps) {
        const libgolibs_build_step = addCombinedGoLib(b, target, optimize, frpc, ddns, frps);

        // Add combined library header file path
        exe.root_module.addIncludePath(libgolibs_build_step.dir);

        // Static link libgolibs.a
        if (target.result.os.tag == .windows and target.result.cpu.arch == .aarch64) {
            const real_path = libgolibs_build_step.dir.join(b.allocator, libgolibs_build_step.libfilename) catch @panic("Failed to get path for combined Go library");
            std.debug.print("Extracting object files from {s}\n", .{real_path.getPath(b)});
            const extract_objects = b.addSystemCommand(&.{
                b.graph.zig_exe,
                "ar",
                "x",
                real_path.getPath(b),
            });
            const extract_objects_dir = libgolibs_build_step.dir.join(b.allocator, "obj") catch @panic("Failed to get path for extracted object files");
            const extract_objects_dir_real = extract_objects_dir.getPath(b);
            std.Io.Dir.cwd().access(b.graph.io, extract_objects_dir_real, .{}) catch {
                std.Io.Dir.cwd().createDirPath(b.graph.io, extract_objects_dir_real) catch @panic("Failed to create dist directory");
            };
            extract_objects.setCwd(extract_objects_dir);
            extract_objects.step.dependOn(libgolibs_build_step.step);
            exe.step.dependOn(&extract_objects.step);
            var dir = std.Io.Dir.cwd().openDir(b.graph.io, extract_objects_dir_real, .{ .iterate = true }) catch @panic("Failed to open dist directory");
            defer dir.close(b.graph.io);
            var it = dir.iterate();
            while (it.next(b.graph.io) catch @panic("Failed to iterate over dist directory")) |entry| {
                exe.root_module.addObjectFile(extract_objects_dir.join(b.allocator, entry.name) catch @panic("Failed to join path for extracted object file"));
            }
        } else {
            const libgolibs_path = libgolibs_build_step.dir.join(b.allocator, libgolibs_build_step.libfilename) catch @panic("Failed to get path for combined Go library");
            exe.root_module.addObjectFile(libgolibs_path);
            // exe.addLibraryPath(libgolibs_build_step.dir);
            // exe.root_module.linkSystemLibrary(libgolibs_build_step.libname, .{ .preferred_link_mode = .static });
        }

        // Ensure libgolibs is built before the executable
        exe.step.dependOn(libgolibs_build_step.step);
    }

    // Add C/C++ forwarder implementation (selected via -Dforward_backend)
    addForwarderBackend(b, target, optimize, forward_backend, exe.root_module);

    // Add C include paths for UCI library headers
    exe.root_module.addIncludePath(b.path("deps/uci"));
    // Add C include paths for Ubus library headers
    exe.root_module.addIncludePath(b.path("deps/fix"));
    exe.root_module.addIncludePath(b.path("deps/openwrt-tools"));
    exe.root_module.addIncludePath(b.path("deps/ubus"));
    exe.root_module.addIncludePath(b.path("deps/nftables"));

    if (target.result.os.tag == .windows) {
        exe.root_module.linkSystemLibrary("ws2_32", .{});
        exe.root_module.linkSystemLibrary("advapi32", .{});
        exe.root_module.linkSystemLibrary("user32", .{});
        exe.root_module.linkSystemLibrary("shell32", .{});
        exe.root_module.linkSystemLibrary("iphlpapi", .{});
        exe.root_module.linkSystemLibrary("dbghelp", .{});
        exe.root_module.linkSystemLibrary("ole32", .{});
        exe.root_module.linkSystemLibrary("userenv", .{});
        exe.root_module.linkSystemLibrary("psapi", .{});
    }

    if (target.result.os.tag == .macos) {
        if (b.sysroot) |sysroot| {
            // Add framework search path if sysroot is specified.
            // See: https://github.com/ziglang/zig/issues/22704
            // Framework paths need manual sysroot prefix, unlike library paths.
            const framework_path = b.pathJoin(&.{ sysroot, "System/Library/Frameworks" });
            exe.root_module.addFrameworkPath(.{ .cwd_relative = framework_path });
            // Only add /usr/lib, build system appends it to sysroot automatically
            exe.root_module.addLibraryPath(.{ .cwd_relative = "/usr/lib" });
            exe.root_module.linkFramework("CoreFoundation", .{});
            exe.root_module.linkFramework("Security", .{});
            exe.root_module.linkFramework("IOKit", .{});
        }
    }
    if (target.result.os.tag == .macos or target.result.os.tag == .linux) {
        exe.root_module.linkSystemLibrary("resolv", .{ .search_strategy = .mode_first });
    }

    exe.linkage = .dynamic;
    applyLinkOptimization(b, target, exe, optimize);

    // This declares intent for the executable to be installed into the
    // install prefix when running `zig build` (i.e. when executing the default
    // step). By default the install prefix is `zig-out/` but can be overridden
    // by passing `--prefix` or `-p`.
    if (upx) {
        // Chain: compile → install artifact → UPX compress → install step
        if (ensureUpx(b)) |upx_bin| {
            const install_artifact = b.addInstallArtifact(exe, .{});
            const upx_cmd = b.addSystemCommand(&.{ upx_bin, "--best" });
            upx_cmd.addArg(b.pathJoin(&.{ b.exe_dir, exe.out_filename }));
            upx_cmd.step.dependOn(&install_artifact.step);
            b.getInstallStep().dependOn(&upx_cmd.step);
        } else {
            @panic("UPX requested (-Dupx=true) but not available for this host platform");
        }
    } else {
        b.installArtifact(exe);
    }

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
        .root_module = b.createModule(.{
            .link_libc = true,
            // The root source file is the "entry point" of this module. Users of
            // this module will only be able to access public declarations contained
            // in this file, which means that if you have declarations that you
            // intend to expose to consumers that were defined in other files part
            // of this module, you will have to make sure to re-export them from
            // the root file.
            .root_source_file = b.path("src/all_tests.zig"),
            // Later on we'll use this module as the root module of a test executable
            // which requires us to specify a target.
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "build_options", .module = options_mod },
            },
        }),
    });

    if (frpc or ddns or frps) {
        const libgolibs_build_step = addCombinedGoLib(b, target, optimize, frpc, ddns, frps);
        mod_tests.root_module.addIncludePath(libgolibs_build_step.dir);
        const libgolibs_path = libgolibs_build_step.dir.join(b.allocator, libgolibs_build_step.libfilename) catch @panic("Failed to get path for combined Go library");
        mod_tests.root_module.addObjectFile(libgolibs_path);
        mod_tests.step.dependOn(libgolibs_build_step.step);
    }

    addForwarderBackend(b, target, optimize, forward_backend, mod_tests.root_module);
    mod_tests.root_module.addIncludePath(b.path("deps/uci"));
    mod_tests.root_module.addIncludePath(b.path("deps/fix"));
    mod_tests.root_module.addIncludePath(b.path("deps/openwrt-tools"));
    mod_tests.root_module.addIncludePath(b.path("deps/ubus"));
    mod_tests.root_module.addIncludePath(b.path("deps/nftables"));

    if (target.result.os.tag == .windows) {
        mod_tests.root_module.linkSystemLibrary("ws2_32", .{});
        mod_tests.root_module.linkSystemLibrary("advapi32", .{});
        mod_tests.root_module.linkSystemLibrary("user32", .{});
        mod_tests.root_module.linkSystemLibrary("shell32", .{});
        mod_tests.root_module.linkSystemLibrary("iphlpapi", .{});
        mod_tests.root_module.linkSystemLibrary("dbghelp", .{});
        mod_tests.root_module.linkSystemLibrary("ole32", .{});
        mod_tests.root_module.linkSystemLibrary("userenv", .{});
        mod_tests.root_module.linkSystemLibrary("psapi", .{});
    }

    if (target.result.os.tag == .macos) {
        if (b.sysroot) |sysroot| {
            const framework_path = b.pathJoin(&.{ sysroot, "System/Library/Frameworks" });
            mod_tests.root_module.addFrameworkPath(.{ .cwd_relative = framework_path });
            mod_tests.root_module.addLibraryPath(.{ .cwd_relative = "/usr/lib" });

            mod_tests.root_module.linkFramework("CoreFoundation", .{});
            mod_tests.root_module.linkFramework("Security", .{});
            mod_tests.root_module.linkFramework("IOKit", .{});
        }
    }

    if (target.result.os.tag == .macos or target.result.os.tag == .linux) {
        mod_tests.root_module.linkSystemLibrary("resolv", .{ .search_strategy = .mode_first });
    }

    // A run step that will run the test executable.
    const run_mod_tests = b.addRunArtifact(mod_tests);

    // Creates an executable that will run `test` blocks from the executable's
    // root module. Note that test executables only test one module at a time,
    // hence why we have to create two separate ones.
    const exe_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .link_libc = true,
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "portweaver", .module = mod },
                .{ .name = "build_options", .module = options_mod },
            },
        }),
    });

    if (frpc or ddns or frps) {
        const libgolibs_build_step = addCombinedGoLib(b, target, optimize, frpc, ddns, frps);
        exe_tests.root_module.addIncludePath(libgolibs_build_step.dir);
        const libgolibs_path = libgolibs_build_step.dir.join(b.allocator, libgolibs_build_step.libfilename) catch @panic("Failed to get path for combined Go library");
        exe_tests.root_module.addObjectFile(libgolibs_path);
        exe_tests.step.dependOn(libgolibs_build_step.step);
    }
    addForwarderBackend(b, target, optimize, forward_backend, exe_tests.root_module);
    exe_tests.root_module.addIncludePath(b.path("deps/uci"));
    exe_tests.root_module.addIncludePath(b.path("deps/fix"));
    exe_tests.root_module.addIncludePath(b.path("deps/openwrt-tools"));
    exe_tests.root_module.addIncludePath(b.path("deps/ubus"));
    exe_tests.root_module.addIncludePath(b.path("deps/nftables"));

    if (target.result.os.tag == .windows) {
        exe_tests.root_module.linkSystemLibrary("ws2_32", .{});
        exe_tests.root_module.linkSystemLibrary("advapi32", .{});
        exe_tests.root_module.linkSystemLibrary("user32", .{});
        exe_tests.root_module.linkSystemLibrary("shell32", .{});
        exe_tests.root_module.linkSystemLibrary("iphlpapi", .{});
        exe_tests.root_module.linkSystemLibrary("dbghelp", .{});
        exe_tests.root_module.linkSystemLibrary("ole32", .{});
        exe_tests.root_module.linkSystemLibrary("userenv", .{});
        exe_tests.root_module.linkSystemLibrary("psapi", .{});
    }

    if (target.result.os.tag == .macos) {
        if (b.sysroot) |sysroot| {
            const framework_path = b.pathJoin(&.{ sysroot, "System/Library/Frameworks" });
            exe_tests.root_module.addFrameworkPath(.{ .cwd_relative = framework_path });
            exe_tests.root_module.addLibraryPath(.{ .cwd_relative = "/usr/lib" });

            exe_tests.root_module.linkFramework("CoreFoundation", .{});
            exe_tests.root_module.linkFramework("Security", .{});
            exe_tests.root_module.linkFramework("IOKit", .{});
        }
    }

    if (target.result.os.tag == .macos or target.result.os.tag == .linux) {
        exe_tests.root_module.linkSystemLibrary("resolv", .{ .search_strategy = .mode_first });
    }

    // A run step that will run the second test executable.
    const run_exe_tests = b.addRunArtifact(exe_tests);
    b.installArtifact(exe_tests);

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
