#!/bin/bash
# Copyright 2024-2026 catitodev
# Licensed under the Apache License, Version 2.0
# SPDX-License-Identifier: Apache-2.0
#
# Desktop launcher — starts the app silently and opens the browser

PROJECT_DIR="/home/catitodev/1. Linux_security_homecommandcenter"
SOCKET_DIR="/tmp/security-command-center"
SOCKET_PATH="$SOCKET_DIR/api.sock"
FRONTEND_PORT=5173
PID_FILE="/tmp/lshcc.pid"
LOG_FILE="/tmp/lshcc.log"

# Kill any previous instance
if [ -f "$PID_FILE" ]; then
    while read pid; do
        kill "$pid" 2>/dev/null
    done < "$PID_FILE"
    rm -f "$PID_FILE"
fi

# Create socket directory
mkdir -p "$SOCKET_DIR"

# Build backend if needed (silently)
cd "$PROJECT_DIR"
if [ ! -f "target/release/backend-api" ]; then
    # First time: show a notification that we're compiling
    notify-send "LinuxSec Command Center" "Compilando pela primeira vez... aguarde ~2 min" --icon="$PROJECT_DIR/assets/LHSCC.png" 2>/dev/null
    cargo build --release --bin backend-api >> "$LOG_FILE" 2>&1
fi

# Start backend
export SCC_SOCKET_PATH="$SOCKET_PATH"
"$PROJECT_DIR/target/release/backend-api" >> "$LOG_FILE" 2>&1 &
echo $! > "$PID_FILE"

# Start scan server (real security tool execution)
node "$PROJECT_DIR/scripts/scan-server.js" >> "$LOG_FILE" 2>&1 &
echo $! >> "$PID_FILE"

# Install frontend deps if needed
cd "$PROJECT_DIR/frontend"
if [ ! -d "node_modules" ]; then
    npm install --silent >> "$LOG_FILE" 2>&1
fi

# Start frontend (headless, no terminal needed)
npx vite --port "$FRONTEND_PORT" >> "$LOG_FILE" 2>&1 &
echo $! >> "$PID_FILE"

# Wait for frontend to be ready
sleep 2

# Open browser
xdg-open "http://localhost:$FRONTEND_PORT" 2>/dev/null || \
    sensible-browser "http://localhost:$FRONTEND_PORT" 2>/dev/null || \
    firefox "http://localhost:$FRONTEND_PORT" 2>/dev/null || \
    chromium-browser "http://localhost:$FRONTEND_PORT" 2>/dev/null

# Send notification
notify-send "LinuxSec Command Center" "Dashboard aberto em http://localhost:$FRONTEND_PORT" --icon="$PROJECT_DIR/assets/LHSCC.png" 2>/dev/null
