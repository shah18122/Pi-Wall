#!/usr/bin/env bash
# Install Pi-Wall on a Raspberry Pi (Raspberry Pi OS / Debian).
set -euo pipefail

APP_DIR=/opt/pi-wall
echo ">> Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip nftables libpcap0.8

echo ">> Copying Pi-Wall to ${APP_DIR}..."
sudo mkdir -p "$APP_DIR"
sudo cp -r "$(dirname "$0")/.." "$APP_DIR"
cd "$APP_DIR"

echo ">> Creating virtualenv and installing Python deps..."
sudo python3 -m venv .venv
sudo .venv/bin/pip install --upgrade pip
sudo .venv/bin/pip install -r requirements.txt

echo ">> Setting up nftables table for enforcement..."
sudo nft add table inet piwall 2>/dev/null || true
sudo nft 'add chain inet piwall input { type filter hook input priority 0 ; }' 2>/dev/null || true

echo ">> Installing systemd service..."
sudo cp deploy/piwall.service /etc/systemd/system/piwall.service
sudo systemctl daemon-reload
sudo systemctl enable piwall.service

echo ">> Done. Start with:  sudo systemctl start piwall"
echo ">> Dashboard (edit host in config/piwall.yml to expose): http://<pi-ip>:8787"
echo ">> Try locally first:  sudo ${APP_DIR}/.venv/bin/pi-wall run --live --iface eth0"
