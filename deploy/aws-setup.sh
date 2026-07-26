#!/bin/bash
# Deploy script for QUIC TUN VPN server on AWS
# Run this on the AWS server after copying the binary

set -e

BINARY="http-tunnel"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/quic-tunnel"
SERVICE_NAME="quic-tunnel"

echo "=== Setting up QUIC TUN VPN server ==="

# 1. Install binary
echo "Installing binary..."
sudo cp "$BINARY" "$INSTALL_DIR/$BINARY"
sudo chmod +x "$INSTALL_DIR/$BINARY"

# 2. Create config directory
sudo mkdir -p "$CONFIG_DIR"

# 3. Generate self-signed certificate if not exists
if [ ! -f "$CONFIG_DIR/cert.pem" ]; then
    echo "Generating self-signed certificate..."
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$CONFIG_DIR/key.pem" -out "$CONFIG_DIR/cert.pem" \
        -days 365 -nodes -subj '/CN=tunnel'
    sudo chmod 600 "$CONFIG_DIR/key.pem"
    echo "Certificate generated."
else
    echo "Certificate already exists, skipping."
fi

# 4. Enable IP forwarding
echo "Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1
# Make permanent
grep -q 'net.ipv4.ip_forward=1' /etc/sysctl.conf || \
    echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf

# 5. Setup NAT/masquerade
echo "Setting up NAT..."
# Find the main interface
MAIN_IF=$(ip route get 1.1.1.1 | grep -oP 'dev \K\S+')
echo "Main interface: $MAIN_IF"

sudo iptables -t nat -C POSTROUTING -s 10.9.0.0/24 -o "$MAIN_IF" -j MASQUERADE 2>/dev/null || \
    sudo iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o "$MAIN_IF" -j MASQUERADE
echo "NAT configured."

# 6. Stop AWG on port 443 if running (we'll use it for QUIC)
echo "Checking for conflicting services on port 443..."
if ss -ulnp | grep -q ':443 '; then
    echo "WARNING: Something is already listening on UDP 443!"
    echo "You may need to stop it first (e.g., AWG server)."
fi

# 7. Create systemd service
echo "Creating systemd service..."
sudo tee /etc/systemd/system/${SERVICE_NAME}.service > /dev/null << 'EOF'
[Unit]
Description=QUIC TUN VPN Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/http-tunnel --bind 0.0.0.0:443 tun-server \
    --cert /etc/quic-tunnel/cert.pem \
    --key /etc/quic-tunnel/key.pem \
    --tun-addr 10.9.0.1
Restart=always
RestartSec=5
LimitNOFILE=65536

# Security
NoNewPrivileges=no
ProtectSystem=false

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
echo "Systemd service created."

echo ""
echo "=== Setup complete ==="
echo ""
echo "To start:  sudo systemctl start $SERVICE_NAME"
echo "To enable: sudo systemctl enable $SERVICE_NAME"
echo "To check:  sudo systemctl status $SERVICE_NAME"
echo "Logs:      sudo journalctl -u $SERVICE_NAME -f"
