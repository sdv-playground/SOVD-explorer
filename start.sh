#!/bin/bash
# =============================================================================
# Start SOVDd Explorer GUI
#
# Launches the Tauri dev GUI and cleans up on Ctrl+C.
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

TAURI_PID=""

cleanup() {
    echo ""
    if [[ -n "$TAURI_PID" ]] && kill -0 "$TAURI_PID" 2>/dev/null; then
        kill "$TAURI_PID" 2>/dev/null || true
        sleep 1
        kill -0 "$TAURI_PID" 2>/dev/null && kill -9 "$TAURI_PID" 2>/dev/null || true
    fi
    echo "Explorer stopped"
}

trap cleanup SIGINT SIGTERM EXIT

cd "$SCRIPT_DIR"
npm install
npm run tauri dev &
TAURI_PID=$!

wait "$TAURI_PID"
