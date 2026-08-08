#!/usr/bin/env bash
echo "[+] Killing arpspoof..."
pkill arpspoof 2>/dev/null || true
sleep 2

echo "[+] Removing nftables redirect..."
nft delete table ip netwatch_nat 2>/dev/null || true

echo "[+] Removing DoH/DoT block rules..."
nft delete table inet netwatch_doh_block 2>/dev/null || true

# Also clear legacy iptables NAT rules if any
iptables -t nat -F PREROUTING 2>/dev/null || true
iptables -t nat -F POSTROUTING 2>/dev/null || true

echo "[✓] DNS interception stopped. Network restored."
