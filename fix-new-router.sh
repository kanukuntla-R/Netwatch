#!/usr/bin/env bash
# NetWatch — Fix for new router (run with: sudo bash ~/netwatch-files/fix-new-router.sh)
set -euo pipefail

INSTALL_DIR="/opt/netwatch"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; RST='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Run as root:${RST} sudo bash $0"
    exit 1
fi

echo -e "${CYN}NetWatch — Fixing for new router...${RST}\n"

# ── 1. Restore known_devices.json from OLD backup ─────────────────────────
echo -e "${YLW}[1/6]${RST} Restoring known device registry..."

# Merge OLD file with current: keep all OLD history, update with current seen data
python3 - <<'PYEOF'
import json
from datetime import datetime

old_path  = "/opt/netwatch/known_devices.OLD.json"
cur_path  = "/opt/netwatch/known_devices.json"
out_path  = "/opt/netwatch/known_devices.json"

with open(old_path)  as f: old  = json.load(f)
with open(cur_path)  as f: cur  = json.load(f)

# Start from OLD (has all history), then update with any newer entries from cur
merged = dict(old)
for mac, d in cur.items():
    if mac in merged:
        # Update last_seen and seen_count from the current (newer) data
        merged[mac]["last_seen"]  = d["last_seen"]
        merged[mac]["seen_count"] = max(merged[mac].get("seen_count",0), d.get("seen_count",0))
        # Restore hostname if cur has one and old doesn't
        if d.get("hostname") and not merged[mac].get("hostname"):
            merged[mac]["hostname"] = d["hostname"]
    else:
        merged[mac] = d

# Trust and label the new router
new_router_mac = "0C:36:23:AB:5E:B0"
if new_router_mac in merged:
    merged[new_router_mac]["trusted"] = True
    merged[new_router_mac]["label"]   = "Router (New)"
    merged[new_router_mac]["os_guess"] = "Linux (Router)"
    merged[new_router_mac]["os_confidence"] = "medium"
    merged[new_router_mac]["os_notes"] = ["Sagemcom DSL Router (dsldevice.lan)"]
    merged[new_router_mac]["vendor"]   = "Sagemcom"

# Trust and label this hub (keyed by IP since nmap can't ARP-scan itself)
hub_key = "192.168.1.8"
if hub_key in merged:
    merged[hub_key]["trusted"] = True
    merged[hub_key]["label"]   = "Hub (Speed10)"

# Label the iPhone if it's in the registry
iphone_mac = "BA:77:9D:B8:D5:38"
if iphone_mac in merged:
    merged[iphone_mac]["trusted"] = True
    if not merged[iphone_mac].get("label"):
        merged[iphone_mac]["label"] = "Ruthvik's iPhone"

# Trust known family MacBook
macbook_mac = "26:8D:B1:2F:EC:C2"
if macbook_mac in merged:
    merged[macbook_mac]["trusted"] = True
    if not merged[macbook_mac].get("label"):
        merged[macbook_mac]["label"] = "Ruthvik's MacBook"

# Label old Fire TV
firetv_mac = "CC:9E:A2:AA:17:1F"
if firetv_mac in merged:
    if not merged[firetv_mac].get("label"):
        merged[firetv_mac]["label"] = "Amazon Fire TV"

# Label LG TV
lgtv_mac = "C2:64:F2:C5:81:E4"
if lgtv_mac in merged:
    if not merged[lgtv_mac].get("label"):
        merged[lgtv_mac]["label"] = "LG Smart TV"

with open(out_path, "w") as f:
    json.dump(merged, f, indent=2, default=str)
print(f"  ✓ Restored {len(merged)} devices (was {len(cur)}, was {len(old)} in OLD backup)")
PYEOF

# ── 2. Update config.json — trust new router, restore OS detection ─────────
echo -e "${YLW}[2/6]${RST} Updating config.json..."

python3 - <<'PYEOF'
import json

cfg_path = "/opt/netwatch/config.json"
with open(cfg_path) as f:
    cfg = json.load(f)

# Add new router MAC to trusted list (avoid duplicates)
new_trusted = [
    "0C:36:23:AB:5E:B0",   # new router (Sagemcom DSL)
    "8C:13:E2:3A:71:85",   # old router (in case it ever comes back)
    "26:8D:B1:2F:EC:C2",   # MacBook (privacy MAC)
    "28:EA:2D:86:39:78",   # iPhone (hardware MAC)
    "4A:B5:D3:FE:AE:29",   # previously watched device
]
existing = [m.upper() for m in cfg.get("trusted_macs", [])]
for mac in new_trusted:
    if mac.upper() not in existing:
        cfg["trusted_macs"].append(mac)

# Restore OS detection flags for better vendor/device identification
cfg["nmap_flags"] = "-sn -T4 -O --osscan-guess"

with open(cfg_path, "w") as f:
    json.dump(cfg, f, indent=2)
print(f"  ✓ trusted_macs now has {len(cfg['trusted_macs'])} entries")
print(f"  ✓ nmap_flags: {cfg['nmap_flags']}")
PYEOF

# ── 3. Update network_monitor.py — add Sagemcom OUI ─────────────────────
echo -e "${YLW}[3/6]${RST} Adding new router OUI to device detection..."

# Copy updated network_monitor.py (we'll patch the OUI table in-place)
python3 - <<'PYEOF'
import re

path = "/opt/netwatch/network_monitor.py"
with open(path) as f:
    src = f.read()

# Only add if not already present
if '"0C:36:23"' not in src:
    old = '    # Routers\n    "8C:13:E2": ("Linux (Router)",       "Netlink ICT Router"),'
    new = ('    # Routers\n'
           '    "8C:13:E2": ("Linux (Router)",       "Netlink ICT Router"),\n'
           '    "0C:36:23": ("Linux (Router)",       "Sagemcom DSL Router"),')
    src = src.replace(old, new)
    with open(path, "w") as f:
        f.write(src)
    print("  ✓ Added Sagemcom OUI (0C:36:23) to OUI_OS_MAP")
else:
    print("  ✓ Sagemcom OUI already present")
PYEOF

# ── 4. Restore nftables DNS interception ──────────────────────────────────
echo -e "${YLW}[4/6]${RST} Restoring nftables DNS interception..."

IFACE="eno1"
HUB_IP="192.168.1.8"

# Remove stale table if it exists
nft delete table ip netwatch_nat 2>/dev/null || true

nft add table ip netwatch_nat
nft add chain ip netwatch_nat prerouting '{ type nat hook prerouting priority -100 ; }'
nft add chain ip netwatch_nat postrouting '{ type nat hook postrouting priority 100 ; }'
nft add rule  ip netwatch_nat prerouting iifname "$IFACE" udp dport 53 ip daddr != $HUB_IP dnat to ${HUB_IP}:53
nft add rule  ip netwatch_nat prerouting iifname "$IFACE" tcp dport 53 ip daddr != $HUB_IP dnat to ${HUB_IP}:53
nft add rule  ip netwatch_nat postrouting masquerade

echo "  ✓ nftables DNS redirect active (LAN DNS → ${HUB_IP}:53)"

# Ensure IP forwarding is on
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "  ✓ IP forwarding enabled"

# ── 5. Ensure arpspoof is running ─────────────────────────────────────────
echo -e "${YLW}[5/6]${RST} Checking arpspoof..."

if pgrep -x arpspoof >/dev/null 2>&1; then
    echo "  ✓ arpspoof already running (PID: $(pgrep -x arpspoof | head -1))"
else
    echo "  ↻ Starting arpspoof..."
    nohup arpspoof -i "$IFACE" 192.168.1.1 > /var/log/arpspoof.log 2>&1 &
    sleep 2
    if pgrep -x arpspoof >/dev/null 2>&1; then
        echo "  ✓ arpspoof started (PID: $(pgrep -x arpspoof | head -1))"
    else
        echo "  ✗ arpspoof failed — check /var/log/arpspoof.log"
    fi
fi

# ── 6. Deploy updated netwatch CLI and restart services ──────────────────
echo -e "${YLW}[6/6]${RST} Deploying updated netwatch CLI and restarting services..."

cp "$SRC_DIR/netwatch" /opt/netwatch/netwatch
chmod +x /opt/netwatch/netwatch
echo "  ✓ netwatch CLI updated (live dashboard bug fixes)"

cp "$SRC_DIR/network_monitor.py" /opt/netwatch/network_monitor.py
echo "  ✓ network_monitor.py updated (Sagemcom OUI)"

systemctl restart netwatch
sleep 3
STATUS=$(systemctl is-active netwatch)
echo "  ✓ netwatch service: $STATUS"

echo ""
echo -e "${GRN}Done! Summary of fixes:${RST}"
echo "  • Restored $(python3 -c "import json; d=json.load(open('/opt/netwatch/known_devices.json')); print(len(d))") devices in known_devices.json (was 3)"
echo "  • New router (0C:36:23:AB:5E:B0 Sagemcom) marked as trusted"
echo "  • nmap OS detection restored (-sn -T4 -O --osscan-guess)"
echo "  • Sagemcom DSL OUI added to device detection"
echo "  • nftables DNS interception restored"
echo ""
echo -e "${YLW}Next steps:${RST}"
echo "  • Run: sudo netwatch devices   (see all known devices)"
echo "  • Run: sudo netwatch traffic   (see today's activity)"
echo "  • Run: sudo netwatch traffic-live   (real-time dashboard)"
echo "  • Devices still on old IPs (.33-.48) will reappear as they reconnect"
echo "  • If your MacBook/phone appears with a new privacy MAC, run:"
echo "      sudo netwatch label <MAC> \"Device Name\""
