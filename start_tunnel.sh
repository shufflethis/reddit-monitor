#!/bin/bash
# Localtunnel mit Auto-Restart für reddit-monitor
# Usage: nohup ./start_tunnel.sh &

PORT="${1:-5001}"
SUBDOMAIN="reddit-famesuite"
LOG="/tmp/localtunnel.log"

# Kill any existing tunnel first
pkill -f "lt --port $PORT" 2>/dev/null
sleep 1

echo "[$(date)] Starting tunnel on port $PORT with subdomain $SUBDOMAIN" >> "$LOG"

while true; do
    lt --port "$PORT" --subdomain "$SUBDOMAIN" >> "$LOG" 2>&1
    echo "[$(date)] Tunnel died (exit $?), restarting in 5s..." >> "$LOG"
    sleep 5
done
