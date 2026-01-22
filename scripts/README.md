# PortWeaver Development Scripts

Auto-build and upload system for remote OpenWrt device development.

## Overview

This directory contains F# scripts that enable automatic building and uploading of PortWeaver to a remote OpenWrt device during development, similar to the frontend's development workflow.

### Features

- ✅ **Cross-platform**: Works on Windows, Linux, and macOS
- ✅ **File watching**: Monitors `.zig`, `.c`, `.h`, `.go` files for changes
- ✅ **Smart debouncing**: Builds only once per 10 seconds to avoid frequent rebuilds
- ✅ **Auto-upload**: Uploads build artifacts via SFTP when build completes
- ✅ **Service restart**: Automatically restarts the service on remote device
- ✅ **SSH authentication**: Supports both password and SSH key authentication

## Prerequisites

1. **.NET SDK 6.0+** installed ([Download](https://dotnet.microsoft.com/download))
2. **Zig** compiler installed
3. **SSH access** to your OpenWrt device

## Setup

### 1. Configure SSH Connection

```bash
cp ../.env.example ../.env
```

Edit `.env` with your OpenWrt device details:

```env
SSH_HOST=192.168.1.1
SSH_PORT=22
SSH_USERNAME=root
SSH_PASSWORD=your_password

# Or use SSH key (recommended):
# SSH_KEY_PATH=~/.ssh/id_rsa
# SSH_KEY_PASSPHRASE=your_passphrase

SSH_REMOTE_PATH=/usr/bin
SSH_REMOTE_SERVICE=portweaver
LOCAL_BUILD_PATH=zig-out/bin/portweaver
AUTO_RESTART_SERVICE=true
WATCH_DEBOUNCE_MS=10000
```

### 2. Test SSH Connection

Verify you can connect to your OpenWrt device:

```bash
ssh root@192.168.1.1
```

## Usage

### Option 1: Using Wrapper Scripts (Recommended)

**Windows (PowerShell):**
```powershell
.\scripts\dev-remote.ps1
```

**Linux/macOS:**
```bash
chmod +x scripts/dev-remote.sh
./scripts/dev-remote.sh
```

### Option 2: Using zig build

From the project root:
```bash
zig build dev-remote
```

### Option 3: Direct F# Script Execution

```bash
cd portweaver
dotnet fsi scripts/dev-remote.fsx
```

## How It Works

### Architecture

```
dev-remote.fsx (All-in-one)
├── Monitors: zig-out/bin/portweaver (build artifact)
├── Triggers: zig build --watch (automatic rebuild)
├── Uploads via SFTP when artifact changes
├── Sets executable permissions (chmod +x)
└── Runs: service portweaver restart
```

### File Watching

The system uses Zig's built-in `--watch` feature to monitor source files and rebuild automatically:
- Zig watches: `.zig`, `.c`, `.h` files in `src/`
- F# watches: `zig-out/bin/portweaver` (build artifact)

**Debounce Behavior:**
- Multiple source changes within configured time trigger only ONE build
- Upload only happens when build artifact actually changes
- Configurable via `WATCH_DEBOUNCE_MS` in `.env`

### Upload Process

1. Zig build completes successfully
2. `dev-remote.fsx` detects new binary in `zig-out/bin/`
3. Uploads to remote device via SFTP
4. Sets executable permissions: `chmod 755`
5. Restarts service: `service portweaver restart`
6. Reports success/failure

## Scripts Reference

### `dev-remote.fsx`

Main development script that:
- Uses `zig build --watch` for automatic rebuilds
- Monitors build artifacts for changes
- Uploads binary via SFTP when build completes
- Sets permissions and restarts remote service
- Handles graceful shutdown

### `dev-upload.fsx`

Reusable SSH/SFTP library module providing:
- Configuration loading from `.env`
- SSH connection management
- SFTP file upload with fallback methods
- Permission setting and service restart

### `dev-remote.sh` / `dev-remote.ps1`

Platform-specific wrapper scripts that:
- Check for .NET SDK installation
- Validate `.env` file exists
- Execute `dev-remote.fsx`

## Troubleshooting

### "❌ .NET SDK is not installed"

Install .NET SDK from: https://dotnet.microsoft.com/download

Verify installation:
```bash
dotnet --version
```

### "❌ .env file not found"

Create `.env` from template:
```bash
cp .env.example .env
```

Then edit with your device details.

### "❌ SSH connection failed"

Check:
1. Device is reachable: `ping 192.168.1.1`
2. SSH service is running on device
3. Credentials are correct in `.env`
4. Firewall allows SSH connections

Test connection:
```bash
ssh root@192.168.1.1
```

### "❌ Upload failed: Permission denied"

Ensure:
1. Remote path exists: `SSH_REMOTE_PATH=/usr/bin`
2. User has write permissions to remote path
3. Try with `sudo` or root user

### "⚠️ Service restart failed"

Check:
1. Service name is correct: `SSH_REMOTE_SERVICE=portweaver`
2. Service exists on remote device: `service portweaver status`
3. User has permission to restart services

### Build triggers too frequently

Increase debounce threshold in `.env`:
```env
WATCH_DEBOUNCE_MS=15000  # 15 seconds
```

### Build doesn't trigger on file change

Check:
1. File extension is monitored (`.zig`, `.c`, `.h`, `.go`)
2. File is inside `src/` or `deps/` directory
3. Check console for watcher errors

## Advanced Usage

### Custom Build Commands

Edit `dev-remote.fsx` build arguments:
```fsharp
psi.Arguments <- "build --watch --debounce 15000 -Duci=true -Dubus=true -Dfrpc=true"
```

### Custom Build Target

In `.env`:
```env
BUILD_TARGET=aarch64-linux-musl  # For ARM64 devices
```

### Disable Service Restart

In `.env`:
```env
AUTO_RESTART_SERVICE=false
```

## Development Workflow

1. Start dev-remote: `./scripts/dev-remote.ps1` (or `.sh`)
2. Edit source files in your IDE
3. Save changes
4. Script automatically:
   - Builds the project
   - Uploads to device
   - Restarts service
5. Test on device immediately

Press `Ctrl+C` to stop.

## Tips

- **Use SSH keys** instead of passwords for security
- **Test manually first**: Build and upload manually before using automation
- **Monitor console output**: Watch for build errors and upload status
- **Check remote logs**: `logread -f` on OpenWrt device
- **Version control**: Add `.env` to `.gitignore` (don't commit credentials)

## Dependencies

F# scripts automatically download these NuGet packages:
- `SSH.NET 2025.1.0` - SSH/SFTP client library
- `DotNetEnv 3.1.1` - Environment variable loading

No manual installation needed - packages are downloaded on first run.
