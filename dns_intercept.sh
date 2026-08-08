#!/usr/bin/env bash
# DNS interception using nftables + arpspoof (whole-subnet mode)
set -e

IFACE="eno1"
HUB_IP="192.168.1.8"
ROUTER_IP="192.168.1.1"

echo "[+] Enabling IP forwarding..."
sysctl -w net.ipv4.ip_forward=1 >/dev/null

echo "[+] Setting up nftables DNS redirect..."
# Remove old table if exists
nft delete table ip netwatch_nat 2>/dev/null || true

nft add table ip netwatch_nat
nft add chain ip netwatch_nat prerouting '{ type nat hook prerouting priority -100 ; }'
nft add chain ip netwatch_nat postrouting '{ type nat hook postrouting priority 100 ; }'
nft add rule  ip netwatch_nat prerouting iifname "$IFACE" udp dport 53 ip daddr != $HUB_IP dnat to $HUB_IP:53
nft add rule  ip netwatch_nat prerouting iifname "$IFACE" tcp dport 53 ip daddr != $HUB_IP dnat to $HUB_IP:53
nft add rule  ip netwatch_nat postrouting masquerade

echo "[+] Blocking DoH/DoT so clients fall back to plain DNS..."
# hook forward (not output): this traffic belongs to other LAN devices being
# routed through the hub, not traffic the hub itself originates.
nft delete table inet netwatch_doh_block 2>/dev/null || true
nft -f - <<'NFT'
table inet netwatch_doh_block {
    set doh_ips4 {
        type ipv4_addr
        elements = {
            1.1.1.1, 1.0.0.1, 1.1.1.2, 1.1.1.3,  # Cloudflare — also Mozilla's default DoH (mozilla.cloudflare-dns.com resolves here)
            8.8.8.8, 8.8.4.4,                     # Google — also dns.google resolves here
            9.9.9.9, 149.112.112.112,             # Quad9
            94.140.14.14, 94.140.15.15            # AdGuard
        }
    }
    set doh_ips6 {
        type ipv6_addr
        elements = { 2606:4700:4700::1111 }       # Cloudflare
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
        ip daddr @doh_ips4 tcp dport 443 drop
        ip daddr @doh_ips4 udp dport 443 drop
        ip6 daddr @doh_ips6 tcp dport 443 drop
        ip6 daddr @doh_ips6 udp dport 443 drop
        tcp dport 853 drop
        udp dport 853 drop
    }
}
NFT

echo "[+] Starting arpspoof (spoofing entire LAN as router)..."
pkill arpspoof 2>/dev/null || true
sleep 1
# No -t = spoof everyone on the network
nohup arpspoof -i $IFACE $ROUTER_IP > /var/log/arpspoof.log 2>&1 &
ARPID=$!
sleep 2

# Verify it actually started
if kill -0 $ARPID 2>/dev/null; then
    echo "[✓] DNS interception active. arpspoof PID: $ARPID"
    echo "[!] To stop: sudo /opt/netwatch/dns_unintercept.sh"
else
    echo "[✗] arpspoof failed to start. Check /var/log/arpspoof.log"
    exit 1
fi
