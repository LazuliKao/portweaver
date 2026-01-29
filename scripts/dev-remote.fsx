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
open System.Security.Cryptography
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
        Env.Load envPath |> ignore

    let getEnv key defaultValue =
        match Environment.GetEnvironmentVariable key with
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
            p.Kill true // Kill process tree
            p.WaitForExit 5000 |> ignore
        with _ ->
            ()
    | _ -> ()

// ========================================
// Build Artifact Watching & Upload
// ========================================

let mutable isUploading = false
let mutable debounceTimer: System.Threading.Timer option = None
let mutable lastUploadedHash: string option = None
let uploadLock = obj ()

let calculateFileHash (filePath: string) : string =
    try
        use md5 = MD5.Create()
        use fileStream = File.OpenRead(filePath)
        let hash = md5.ComputeHash(fileStream)
        BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant()
    with ex ->
        printfn "⚠️  Failed to calculate file hash: %s" ex.Message
        ""

let rec processUploadDelayed (config: Config) (filePath: string) (retryCount: int) =
    if retryCount > 3 then
        printfn "⚠️  File still being written after 6 seconds, proceeding with upload"

    if isUploading then
        printfn "⏭️  Skipping upload (upload already in progress)"
    else
        lock uploadLock (fun () ->
            if isUploading then
                printfn "⏭️  Skipping upload (upload in progress)"
            else
                // Calculate hash of current file
                let currentHash = calculateFileHash filePath
                
                // Skip upload if hash matches last uploaded version
                if lastUploadedHash = Some currentHash then
                    printfn "⏭️  Skipping upload (file unchanged - hash: %s)" (currentHash.Substring(0, 8) + "...")
                else
                    isUploading <- true
                    printfn ""
                    printfn "📝 Build artifact changed: %s" (Path.GetFileName filePath)
                    
                    if not (String.IsNullOrEmpty currentHash) then
                        printfn "   Hash: %s" (currentHash.Substring(0, 8) + "...")

                    try
                        if SshClient.uploadFile config.UploadConfig filePath then
                            lastUploadedHash <- Some currentHash
                            printfn ""
                    finally
                        isUploading <- false)

let startDebounceTimer (config: Config) (filePath: string) =
    // Cancel existing timer if any
    debounceTimer |> Option.iter (fun t -> t.Dispose())

    // Create new timer that fires after 2 seconds of inactivity
    let timerCallback = TimerCallback(fun _ -> processUploadDelayed config filePath 0)
    let timer = new System.Threading.Timer(timerCallback, null, 2000, System.Threading.Timeout.Infinite)
    debounceTimer <- Some timer

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
        if args.Name = fileName && not isUploading then
            printfn "🔔 File event detected: %s (%A)" args.Name args.ChangeType
            startDebounceTimer config args.FullPath

    // Handle file changes
    watcher.Changed.Add handleFileEvent

    // Handle new file creation
    watcher.Created.Add handleFileEvent

    // Handle file renames (Zig may use atomic writes: temp file -> rename)
    watcher.Renamed.Add(fun (args: RenamedEventArgs) ->
        if args.Name = fileName && not isUploading then
            printfn "🔔 File renamed to: %s" args.Name
            startDebounceTimer config args.FullPath)

    watcher.Error.Add(fun args -> printfn "❌ Artifact watcher error: %s" (args.GetException().Message))

    watcher.EnableRaisingEvents <- true

    // Upload immediately if file already exists
    if File.Exists config.LocalBuildPath then
        printfn "🚀 Initial upload of existing build artifact..."
        processUploadDelayed config config.LocalBuildPath 0

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
    psi.Arguments <- $"build --watch --debounce %d{config.WatchDebounceMs} -Duci=true -Dubus=true -Dfrpc=true -Dddns=true -Dtarget=%s{config.BuildTarget}"
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
    debounceTimer |> Option.iter (fun t -> t.Dispose())

    printfn "✅ Shutdown complete"
    0
with ex ->
    printfn "❌ Fatal error: %s" ex.Message
    printfn "%s" ex.StackTrace

    killProcess buildProcess
    artifactWatcher |> Option.iter (fun w -> w.Dispose())
    debounceTimer |> Option.iter (fun t -> t.Dispose())

    1
