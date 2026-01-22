#!/usr/bin/env -S dotnet fsi

// ========================================
// PortWeaver Development Remote Script
// ========================================
// Uses Zig's built-in --watch feature to automatically rebuild on source changes
// Monitors build artifacts and uploads to remote device when they change

#r "nuget: DotNetEnv, 3.1.1"
#r "nuget: SSH.NET, 2025.1.0"
#load "dev-upload.fsx"

open System
open System.IO
open System.Diagnostics
open System.Threading
open DotNetEnv
open DevUpload

// ========================================
// Configuration
// ========================================

type Config =
    { ProjectRoot: string
      WatchDebounceMs: int
      BuildTarget: string
      LocalBuildPath: string
      UploadConfig: UploadConfig }

let loadConfig () =
    let projectRoot =
        let scriptDir = __SOURCE_DIRECTORY__
        Path.GetFullPath(Path.Combine(scriptDir, ".."))

    let envPath = Path.Combine(projectRoot, ".env")

    if File.Exists envPath then
        Env.Load(envPath) |> ignore

    let getEnv key defaultValue =
        match Environment.GetEnvironmentVariable(key) with
        | null
        | "" -> defaultValue
        | value -> value

    { ProjectRoot = projectRoot
      WatchDebounceMs = getEnv "WATCH_DEBOUNCE_MS" "10000" |> int
      BuildTarget = getEnv "BUILD_TARGET" "x86_64-linux-musl"
      LocalBuildPath = Path.Combine(projectRoot, getEnv "LOCAL_BUILD_PATH" "zig-out/bin/portweaver")
      UploadConfig = Config.loadFromEnv projectRoot }

// ========================================
// Process Management
// ========================================

let mutable buildProcess: Process option = None
let mutable artifactWatcher: FileSystemWatcher option = None

let killProcess (proc: Process option) =
    match proc with
    | Some p when not p.HasExited ->
        try
            p.Kill(true) // Kill process tree
            p.WaitForExit(5000) |> ignore
        with _ ->
            ()
    | _ -> ()

// ========================================
// Build Artifact Watching & Upload
// ========================================

let mutable lastUploadTime = DateTime.MinValue
let uploadLock = obj ()

let processUpload (config: Config) (filePath: string) =
    lock uploadLock (fun () ->
        let now = DateTime.Now
        let timeSinceLastUpload = now - lastUploadTime

        // Debounce: don't upload if we just uploaded recently (within 2 seconds)
        if timeSinceLastUpload.TotalSeconds < 2.0 then
            printfn "⏭️  Skipping upload (debounce: %.1fs since last upload)" timeSinceLastUpload.TotalSeconds
        else
            printfn ""
            printfn "📝 Build artifact changed: %s" (Path.GetFileName filePath)

            // Wait a moment for file to stabilize
            Thread.Sleep 2000

            if SshClient.uploadFile config.UploadConfig filePath then
                lastUploadTime <- now
                printfn "")

let startArtifactWatcher (config: Config) =
    let watchPath = Path.GetDirectoryName config.LocalBuildPath
    let fileName = Path.GetFileName config.LocalBuildPath

    if not (Directory.Exists watchPath) then
        printfn "⚠️  Build output directory does not exist: %s" watchPath
        printfn "   Creating directory and waiting for first build..."
        Directory.CreateDirectory(watchPath) |> ignore

    printfn "📂 Watching build artifact: %s" watchPath
    printfn "📤 Upload to: %s@%s:%s" config.UploadConfig.SshUsername config.UploadConfig.SshHost config.UploadConfig.RemotePath
    printfn ""

    let watcher = new FileSystemWatcher()
    watcher.Path <- watchPath
    watcher.Filter <- fileName
    watcher.NotifyFilter <- NotifyFilters.LastWrite ||| NotifyFilters.Size ||| NotifyFilters.FileName ||| NotifyFilters.CreationTime
    watcher.IncludeSubdirectories <- false

    let handleFileEvent (args: FileSystemEventArgs) =
        if args.Name = fileName then
            printfn "🔔 File event detected: %s (%A)" args.Name args.ChangeType
            processUpload config args.FullPath

    // Handle file changes
    watcher.Changed.Add(handleFileEvent)

    // Handle new file creation
    watcher.Created.Add(handleFileEvent)

    // Handle file renames (Zig may use atomic writes: temp file -> rename)
    watcher.Renamed.Add(fun (args: RenamedEventArgs) ->
        if args.Name = fileName then
            printfn "🔔 File renamed to: %s" args.Name
            processUpload config args.FullPath)

    watcher.Error.Add(fun args -> printfn "❌ Artifact watcher error: %s" (args.GetException().Message))

    watcher.EnableRaisingEvents <- true

    // Upload immediately if file already exists
    if File.Exists config.LocalBuildPath then
        printfn "🚀 Initial upload of existing build artifact..."
        processUpload config config.LocalBuildPath

    watcher

// ========================================
// Build Process with Zig Watch
// ========================================

let startZigBuildWatch (config: Config) =
    printfn "🔨 Starting Zig build in watch mode..."
    printfn "   Target: %s" config.BuildTarget
    printfn "   Debounce: %dms (%.1fs)" config.WatchDebounceMs (float config.WatchDebounceMs / 1000.0)
    printfn ""

    let psi = ProcessStartInfo()
    psi.FileName <- "zig"
    psi.Arguments <- $"build --watch --debounce %d{config.WatchDebounceMs} -Duci=true -Dubus=true -Dfrpc=true -Dtarget=%s{config.BuildTarget}"
    psi.WorkingDirectory <- config.ProjectRoot
    psi.UseShellExecute <- false
    psi.CreateNoWindow <- false

    let proc = Process.Start psi
    buildProcess <- Some proc
    
    printfn "✅ Zig build watcher started (PID: %d)" proc.Id
    printfn ""
    proc

// ========================================
// Main
// ========================================

try
    printfn "🚀 Starting PortWeaver development mode with auto-upload..."
    printfn ""

    let config = loadConfig ()

    // Start artifact watcher first
    artifactWatcher <- Some(startArtifactWatcher config)

    Thread.Sleep(1000)

    // Start zig build --watch (this runs continuously)
    let zigProcess = startZigBuildWatch config

    printfn "👀 Watching for changes... (Press Ctrl+C to stop)"
    printfn ""

    // Keep the script running
    let mutable running = true

    Console.CancelKeyPress.Add(fun args ->
        printfn ""
        printfn ""
        printfn "👋 Shutting down..."
        args.Cancel <- true
        running <- false)

    while running do
        Thread.Sleep(1000)
        
        // Check if zig build process exited unexpectedly
        if zigProcess.HasExited then
            printfn "⚠️  Zig build process exited unexpectedly (exit code: %d)" zigProcess.ExitCode
            running <- false

    killProcess buildProcess
    artifactWatcher |> Option.iter (fun w -> w.Dispose())

    printfn "✅ Shutdown complete"
    0
with ex ->
    printfn "❌ Fatal error: %s" ex.Message
    printfn "%s" ex.StackTrace

    killProcess buildProcess
    artifactWatcher |> Option.iter (fun w -> w.Dispose())

    1
