#!/usr/bin/env bash
# NetWatch — traffic-capture healthcheck (run every 5 min via netwatch-healthcheck.timer)
# Verifies the arpspoof + nftables MITM path is actually up, not just that
# dns-intercept.service reports "active". Self-heals and alerts on Telegram.
set -uo pipefail

STATE_FILE="/opt/netwatch/.healthcheck_state"
CONFIG="/opt/netwatch/config.json"

send_telegram() {
    python3 - "$1" <<'PYEOF'
import json, sys, urllib.request, urllib.parse

msg = sys.argv[1]
cfg = json.load(open("/opt/netwatch/config.json"))
tg = cfg.get("alert", {}).get("telegram", {})
if not tg.get("enabled") or not tg.get("bot_token") or not tg.get("chat_id"):
    sys.exit(0)

url = f"https://api.telegram.org/bot{tg['bot_token']}/sendMessage"
data = urllib.parse.urlencode({"chat_id": tg["chat_id"], "text": msg}).encode()
try:
    urllib.request.urlopen(url, data=data, timeout=10)
except Exception as e:
    print(f"telegram send failed: {e}", file=sys.stderr)
PYEOF
}

ok=true
reasons=()

pgrep -x arpspoof >/dev/null 2>&1 || { ok=false; reasons+=("arpspoof not running"); }
nft list tables 2>/dev/null | grep -q netwatch_nat || { ok=false; reasons+=("nftables netwatch_nat table missing"); }
[ "$(systemctl is-active dnsmasq)" = "active" ] || { ok=false; reasons+=("dnsmasq not active"); }

prev="unknown"
[ -f "$STATE_FILE" ] && prev=$(cat "$STATE_FILE")

if [ "$ok" = false ]; then
    reason_str=$(IFS=', '; echo "${reasons[*]}")
    if [ "$prev" != "broken" ]; then
        send_telegram "⚠️ NetWatch traffic capture DOWN: ${reason_str}. Attempting recovery..."
    fi
    systemctl reset-failed dnsmasq >/dev/null 2>&1 || true
    systemctl restart dns-intercept >/dev/null 2>&1 || true
    echo "broken" > "$STATE_FILE"
else
    if [ "$prev" = "broken" ]; then
        send_telegram "✅ NetWatch traffic capture RECOVERED."
    fi
    echo "ok" > "$STATE_FILE"
fi
