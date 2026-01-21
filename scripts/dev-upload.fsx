#!/usr/bin/env -S dotnet fsi

// ========================================
// PortWeaver Development Upload Module
// ========================================
// Reusable SSH/SFTP upload module for development workflows
// Can be used as both a standalone script and a library module

#r "nuget: SSH.NET, 2025.1.0"
#r "nuget: DotNetEnv, 3.1.1"

namespace DevUpload

open System
open System.IO
open Renci.SshNet
open DotNetEnv

// ========================================
// Configuration
// ========================================

type UploadConfig =
    { SshHost: string
      SshPort: int
      SshUsername: string
      SshPassword: string option
      SshKeyPath: string option
      SshKeyPassphrase: string option
      RemotePath: string
      RemoteService: string
      AutoRestartService: bool }

module Config =
    let loadFromEnv (projectRoot: string) : UploadConfig =
        let envPath = Path.Combine(projectRoot, ".env")

        if not (File.Exists envPath) then
            failwithf "❌ .env file not found at: %s" envPath

        Env.Load(envPath) |> ignore

        let getEnv key = Environment.GetEnvironmentVariable(key)

        let getEnvOpt key =
            match getEnv key with
            | null
            | "" -> None
            | value -> Some value

        let sshPassword = getEnvOpt "SSH_PASSWORD"
        let sshKeyPath = getEnvOpt "SSH_KEY_PATH"

        if sshPassword.IsNone && sshKeyPath.IsNone then
            failwith "❌ No authentication method configured. Please set SSH_PASSWORD or SSH_KEY_PATH in .env"

        { SshHost = getEnv "SSH_HOST"
          SshPort = getEnv "SSH_PORT" |> int
          SshUsername = getEnv "SSH_USERNAME"
          SshPassword = sshPassword
          SshKeyPath = sshKeyPath
          SshKeyPassphrase = getEnvOpt "SSH_KEY_PASSPHRASE"
          RemotePath = getEnv "SSH_REMOTE_PATH"
          RemoteService = getEnv "SSH_REMOTE_SERVICE"
          AutoRestartService =
            match getEnv "AUTO_RESTART_SERVICE" with
            | "true"
            | "True"
            | "TRUE"
            | "1" -> true
            | _ -> false }

// ========================================
// SSH/SFTP Operations
// ========================================

module SshClient =
    let private createConnectionInfo (config: UploadConfig) =
        let authMethods = ResizeArray<AuthenticationMethod>()

        // Try SSH key first
        match config.SshKeyPath with
        | Some keyPath ->
            let expandedPath =
                if keyPath.StartsWith("~") then
                    Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                        keyPath.Substring(1).TrimStart('/', '\\')
                    )
                else
                    keyPath

            if File.Exists expandedPath then
                let keyFile =
                    match config.SshKeyPassphrase with
                    | Some passphrase -> new PrivateKeyFile(expandedPath, passphrase)
                    | None -> new PrivateKeyFile(expandedPath)

                authMethods.Add(new PrivateKeyAuthenticationMethod(config.SshUsername, keyFile))
            else
                printfn "⚠️  Private key not found at %s, falling back to password" expandedPath
        | None -> ()

        // Add password authentication if available
        match config.SshPassword with
        | Some password -> authMethods.Add(new PasswordAuthenticationMethod(config.SshUsername, password))
        | None -> ()

        new ConnectionInfo(config.SshHost, config.SshPort, config.SshUsername, authMethods.ToArray())

    let uploadFile (config: UploadConfig) (localPath: string) : bool =
        try
            let fileName = Path.GetFileName(localPath)
            let remotePath = Path.Combine(config.RemotePath, fileName).Replace("\\", "/")
            let tempPath = remotePath + ".tmp"

            printfn "📡 Connecting to %s@%s:%d..." config.SshUsername config.SshHost config.SshPort

            // Step 1: Stop service first (if auto-restart is enabled)
            if config.AutoRestartService then
                printfn "⏸️  Stopping service: %s" config.RemoteService

                use ssh = new SshClient(createConnectionInfo config)
                ssh.Connect()

                let stopCmd = sprintf "service %s stop" config.RemoteService
                let stopResult = ssh.RunCommand(stopCmd)

                if stopResult.ExitStatus.HasValue && stopResult.ExitStatus.Value = 0 then
                    printfn "✅ Service stopped"
                else
                    printfn
                        "⚠️  Service stop returned: %d"
                        (if stopResult.ExitStatus.HasValue then
                             stopResult.ExitStatus.Value
                         else
                             -1)

                ssh.Disconnect()

            // Step 2: Upload via SFTP
            use sftp = new SftpClient(createConnectionInfo config)
            sftp.OperationTimeout <- TimeSpan.FromMinutes(5.0)
            sftp.Connect()

            printfn "✅ Connected via SFTP"

            // Check if remote directory exists
            let remoteDir = Path.GetDirectoryName(remotePath).Replace("\\", "/")

            if not (sftp.Exists(remoteDir)) then
                printfn "❌ Remote directory does not exist: %s" remoteDir
                printfn "   Please create it first or change SSH_REMOTE_PATH in .env"
                sftp.Disconnect()
                false
            else
                printfn "📤 Uploading to temporary path: %s" tempPath

                try
                    // Upload to temporary file first
                    use fileStream = File.OpenRead(localPath)
                    let fileSize = fileStream.Length
                    let mutable lastProgress = 0L

                    sftp.BufferSize <- 32768u // 32KB buffer

                    let ctop = Console.CursorTop

                    sftp.UploadFile(
                        fileStream,
                        tempPath,
                        true,
                        fun uploaded ->
                            let progress = int64 uploaded * 100L / fileSize

                            if progress > lastProgress + 10L then
                                Console.CursorTop <- ctop
                                Console.CursorLeft <- 0

                                printf
                                    "   Progress: %d%% (%.1f MB / %.1f MB)"
                                    progress
                                    (float uploaded / 1024.0 / 1024.0)
                                    (float fileSize / 1024.0 / 1024.0)

                                lastProgress <- progress
                    )

                    printfn ""
                    printfn "✅ Upload complete"

                    sftp.Disconnect()

                    // Step 3: Move temp file to final location and set permissions via SSH
                    printfn "🔄 Moving file to final location..."

                    use ssh = new SshClient(createConnectionInfo config)
                    ssh.Connect()

                    // Delete old file and move new one atomically
                    let deployCmd =
                        sprintf "rm -f '%s' && mv '%s' '%s' && chmod 755 '%s'" remotePath tempPath remotePath remotePath

                    let deployResult = ssh.RunCommand(deployCmd)

                    if not (deployResult.ExitStatus.HasValue && deployResult.ExitStatus.Value = 0) then
                        printfn "❌ Deploy failed: %s" deployResult.Error
                        ssh.Disconnect()
                        false
                    else
                        printfn "✅ File deployed successfully"

                        // Step 4: Restart service
                        if config.AutoRestartService then
                            printfn "🔄 Restarting service: %s" config.RemoteService

                            let command = sprintf "service %s start" config.RemoteService
                            let result = ssh.RunCommand(command)

                            if result.ExitStatus.HasValue then
                                if result.ExitStatus.Value = 0 then
                                    printfn "✅ Service restarted successfully"

                                    if not (String.IsNullOrWhiteSpace result.Result) then
                                        printfn "   Output: %s" (result.Result.Trim())
                                else
                                    printfn "⚠️  Service restart failed (exit code: %d)" result.ExitStatus.Value

                                    if not (String.IsNullOrWhiteSpace result.Error) then
                                        printfn "   Error: %s" (result.Error.Trim())
                            else
                                printfn "⚠️  Service restart returned no exit status"

                        ssh.Disconnect()
                        printfn ""
                        true

                with uploadEx ->
                    printfn "❌ Upload failed: %s" uploadEx.Message

                    if uploadEx.InnerException <> null then
                        printfn "   Details: %s" uploadEx.InnerException.Message

                    sftp.Disconnect()

                    // Try to restart service anyway (in case it was stopped)
                    if config.AutoRestartService then
                        printfn "🔄 Attempting to restart service..."

                        use ssh = new SshClient(createConnectionInfo config)
                        ssh.Connect()
                        ssh.RunCommand(sprintf "service %s start" config.RemoteService) |> ignore
                        ssh.Disconnect()

                    false

        with ex ->
            printfn "❌ Connection failed: %s" ex.Message

            if ex.InnerException <> null then
                printfn "   Details: %s" ex.InnerException.Message

            false
