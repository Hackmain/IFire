#!/bin/bash
# IFIRE installation script
# Run as root: sudo ./scripts/install.sh

set -e

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/ifire"
LOG_DIR="/var/log/ifire"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

if [ "$EUID" -ne 0 ]; then
    echo "[IFIRE] Please run as root: sudo $0"
    exit 1
fi

echo "[IFIRE] Installing dependencies..."
apt-get install -q -y libpcap-dev python3 python3-pip iptables 2>/dev/null || \
    yum install -q -y libpcap-devel python3 python3-pip iptables 2>/dev/null || true

echo "[IFIRE] Building from source..."
cd "$PROJECT_DIR"
make clean 2>/dev/null || true
make

echo "[IFIRE] Installing binary..."
install -m 755 ifire "$INSTALL_DIR/ifire"

echo "[IFIRE] Setting up config directory..."
mkdir -p "$CONFIG_DIR" "$LOG_DIR"
[ -f "$CONFIG_DIR/ifire.conf" ] || cp config/ifire.conf "$CONFIG_DIR/"
[ -f "$CONFIG_DIR/blacklist.txt" ] || cp config/blacklist.txt "$CONFIG_DIR/"
[ -f "$CONFIG_DIR/whitelist.txt" ] || cp config/whitelist.txt "$CONFIG_DIR/"

echo "[IFIRE] Installing Python AI engine..."
pip3 install -q -r ai/requirements.txt
install -m 755 ai/ifire_ai.py "$INSTALL_DIR/ifire_ai"

echo "[IFIRE] Installation complete."
echo ""
echo "  Start IDS mode:  sudo ifire -q -j /var/log/ifire/ifire.jsonl"
echo "  Start IPS mode:  sudo ifire -B -q -j /var/log/ifire/ifire.jsonl"
echo "  AI training:     ifire_ai train /var/log/ifire/baseline.jsonl"
echo "  AI inference:    ifire_ai infer /var/log/ifire/ifire.jsonl"
echo ""
