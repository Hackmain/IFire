#!/bin/bash
# IFIRE management helper
# Usage: ./scripts/ifire.sh {start|stop|status|block|unblock|ai-train|ai-infer}

IFIRE_BIN="./ifire"
IFIRE_LOG="/var/log/ifire/ifire.jsonl"
IFIRE_PID="/var/run/ifire.pid"
AI_DIR="./ai"

case "$1" in
start)
    echo "[IFIRE] Starting IDS mode..."
    "$IFIRE_BIN" -q -j "$IFIRE_LOG" &
    echo $! > "$IFIRE_PID"
    echo "[IFIRE] PID $(cat $IFIRE_PID)"
    ;;
start-ips)
    echo "[IFIRE] Starting IPS mode (requires root)..."
    sudo "$IFIRE_BIN" -B -q \
        -b ./config/blacklist.txt \
        -W ./config/whitelist.txt \
        -j "$IFIRE_LOG" &
    echo $! > "$IFIRE_PID"
    echo "[IFIRE] PID $(cat $IFIRE_PID)"
    ;;
stop)
    if [ -f "$IFIRE_PID" ]; then
        kill "$(cat $IFIRE_PID)" 2>/dev/null && echo "[IFIRE] Stopped."
        rm -f "$IFIRE_PID"
    else
        echo "[IFIRE] Not running."
    fi
    ;;
status)
    if [ -f "$IFIRE_PID" ] && kill -0 "$(cat $IFIRE_PID)" 2>/dev/null; then
        echo "[IFIRE] Running (PID $(cat $IFIRE_PID))"
    else
        echo "[IFIRE] Not running."
    fi
    ;;
block)
    shift
    if [ -z "$1" ]; then echo "Usage: $0 block <ip>"; exit 1; fi
    echo "$1" | sudo tee -a ./config/blacklist.txt
    sudo iptables -I INPUT -s "$1" -j DROP
    sudo iptables -I FORWARD -s "$1" -j DROP
    echo "[IFIRE] Blocked $1"
    ;;
unblock)
    shift
    if [ -z "$1" ]; then echo "Usage: $0 unblock <ip>"; exit 1; fi
    sudo iptables -D INPUT -s "$1" -j DROP 2>/dev/null
    sudo iptables -D FORWARD -s "$1" -j DROP 2>/dev/null
    sed -i "/^$1$/d" ./config/blacklist.txt 2>/dev/null
    echo "[IFIRE] Unblocked $1"
    ;;
ai-train)
    shift
    LOG="${1:-$IFIRE_LOG}"
    echo "[IFIRE] Training AI on $LOG..."
    python3 "$AI_DIR/ifire_ai.py" train "$LOG" --model-dir "$AI_DIR/models"
    ;;
ai-infer)
    shift
    LOG="${1:-$IFIRE_LOG}"
    echo "[IFIRE] Running AI inference on $LOG..."
    python3 "$AI_DIR/ifire_ai.py" infer "$LOG" --model-dir "$AI_DIR/models"
    ;;
ai-watch)
    shift
    LOG="${1:-$IFIRE_LOG}"
    echo "[IFIRE] Starting AI watch on $LOG..."
    python3 "$AI_DIR/ifire_ai.py" watch "$LOG" --model-dir "$AI_DIR/models"
    ;;
*)
    echo "IFIRE Management Script"
    echo "Usage: $0 {start|start-ips|stop|status|block <ip>|unblock <ip>|ai-train [log]|ai-infer [log]|ai-watch [log]}"
    ;;
esac
