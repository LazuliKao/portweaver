# ========================================
# PortWeaver Development Remote Script
# ========================================
# Wrapper script for dev-remote.fsx (Windows)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir

Write-Host "🚀 Starting PortWeaver development mode..." -ForegroundColor Cyan
Write-Host ""

if (-not (Get-Command dotnet -ErrorAction SilentlyContinue)) {
    Write-Host "❌ .NET SDK is not installed" -ForegroundColor Red
    Write-Host "   Please install .NET SDK from: https://dotnet.microsoft.com/download"
    exit 1
}

$EnvFile = Join-Path $ProjectRoot ".env"
if (-not (Test-Path $EnvFile)) {
    Write-Host "❌ .env file not found" -ForegroundColor Red
    Write-Host "   Please copy .env.example to .env and configure it:"
    Write-Host "   Copy-Item .env.example .env"
    exit 1
}

$ScriptPath = Join-Path $ScriptDir "dev-remote.fsx"
Set-Location $ProjectRoot
& dotnet fsi $ScriptPath
