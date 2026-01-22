#!/bin/bash

# ========================================
# PortWeaver Development Remote Script
# ========================================
# Wrapper script for dev-remote.fsx (Linux/macOS)

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

echo "🚀 Starting PortWeaver development mode..."
echo ""

# Check if .NET SDK is installed
if ! command -v dotnet &> /dev/null; then
    echo "❌ .NET SDK is not installed"
    echo "   Please install .NET SDK from: https://dotnet.microsoft.com/download"
    exit 1
fi

# Check if .env exists
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    echo "❌ .env file not found"
    echo "   Please copy .env.example to .env and configure it:"
    echo "   cp .env.example .env"
    exit 1
fi

# Run the F# script
cd "$PROJECT_ROOT"
exec dotnet fsi "$SCRIPT_DIR/dev-remote.fsx"
