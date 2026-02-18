#!/bin/bash
# Reddit Monitor - Deploy Script
# Run with: sudo bash install.sh

set -e

echo "=== Reddit Monitor Deployment ==="

# 1. Copy systemd service
echo "[1/5] Installing systemd service..."
cp reddit-monitor.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable reddit-monitor
systemctl start reddit-monitor

# 2. Copy nginx config
echo "[2/5] Installing nginx config..."
cp reddit.famesuite.de.conf /etc/nginx/sites-available/
ln -sf /etc/nginx/sites-available/reddit.famesuite.de.conf /etc/nginx/sites-enabled/

# 3. Test nginx config
echo "[3/5] Testing nginx config..."
nginx -t

# 4. Reload nginx
echo "[4/5] Reloading nginx..."
systemctl reload nginx

# 5. Get SSL certificate
echo "[5/5] Getting SSL certificate..."
certbot --nginx -d reddit.famesuite.de --non-interactive --agree-tos --email admin@famesuite.de --redirect

echo ""
echo "=== DONE! ==="
echo "Reddit Monitor is now live at: https://reddit.famesuite.de"
echo ""
echo "Commands:"
echo "  systemctl status reddit-monitor  - Check app status"
echo "  journalctl -u reddit-monitor -f  - View logs"
