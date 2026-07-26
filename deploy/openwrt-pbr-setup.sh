#!/bin/bash
# Setup PBR policy for quic1 interface on OpenWrt
# Run this AFTER the quic-tunnel client is running

set -e

ROUTER="root@192.168.1.1"
SSH_KEY="$HOME/.ssh/id_ed25519"
SSH="ssh -i $SSH_KEY $ROUTER"

# Domains to route through QUIC tunnel
DOMAINS=(
    "robinhood.com"
    "tradingview.com"
    "tradestation.com"
    "rithmic.com"
    "bookmap.com"
    "dxfeed.com"
    "massive.com"
    # dxfeed subdomains and CDN
    "tools.dxfeed.com"
    "demo.dxfeed.com"
    "webdev.dxfeed.com"
)

echo "=== Setting up quic1 interface and PBR on OpenWrt ==="

# 1. Create firewall zone for quic1
echo "Creating firewall zone..."
$SSH "
# Check if zone already exists
if ! uci show firewall | grep -q \"name='quic1'\"; then
    # Add firewall zone
    uci add firewall zone
    uci set firewall.@zone[-1].name='quic1'
    uci set firewall.@zone[-1].input='REJECT'
    uci set firewall.@zone[-1].output='ACCEPT'
    uci set firewall.@zone[-1].forward='REJECT'
    uci set firewall.@zone[-1].masq='1'
    uci set firewall.@zone[-1].mtu_fix='1'
    uci set firewall.@zone[-1].network='quic1'

    # Add forwarding from lan to quic1
    uci add firewall forwarding
    uci set firewall.@forwarding[-1].src='lan'
    uci set firewall.@forwarding[-1].dest='quic1'

    uci commit firewall
    /etc/init.d/firewall restart
    echo 'Firewall zone created'
else
    echo 'Firewall zone already exists'
fi
"

# 2. Create PBR policy
echo "Creating PBR policy..."
DOMAIN_LIST=$(printf '%s ' "${DOMAINS[@]}")

$SSH "
# Add PBR policy for quic1
if ! uci show pbr | grep -q \"name='To_QUIC'\"; then
    uci add pbr policy
    uci set pbr.@policy[-1].name='To_QUIC'
    uci set pbr.@policy[-1].interface='quic1'
    uci set pbr.@policy[-1].dest_addr='$DOMAIN_LIST'
    uci set pbr.@policy[-1].enabled='1'
    uci commit pbr
    echo 'PBR policy created'
else
    echo 'PBR policy already exists'
fi

# Restart PBR
/etc/init.d/pbr restart 2>&1 | tail -3
echo 'PBR restarted'
"

# 3. Restart dnsmasq (for nftset population)
echo "Restarting dnsmasq..."
$SSH "/etc/init.d/dnsmasq restart"

echo ""
echo "=== PBR Setup Complete ==="
echo "Domains routed through quic1:"
for d in "${DOMAINS[@]}"; do
    echo "  - $d"
done
echo ""
echo "Test with: traceroute robinhood.com"
