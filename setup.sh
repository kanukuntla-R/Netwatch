#!/usr/bin/env bash
# NetWatch Setup & Management Script
# Usage: ./setup.sh [install|start|stop|status|logs|label|test-scan]

set -euo pipefail

INSTALL_DIR="/opt/netwatch"
SERVICE_NAME="netwatch"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
CYN='\033[0;36m'
RST='\033[0m'

banner() {
  echo -e "${CYN}"
  echo "  ███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗"
  echo "  ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║"
  echo "  ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║"
  echo "  ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║"
  echo "  ██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║"
  echo "  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝"
  echo -e "${RST}"
  echo -e "  ${YLW}Home Network Monitor for Arch Linux${RST}"
  echo ""
}

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error:${RST} Run this as root: sudo ./setup.sh $1"
    exit 1
  fi
}

cmd_install() {
  require_root install
  echo -e "${BLU}[1/5]${RST} Checking dependencies..."
  if ! command -v nmap &>/dev/null; then
    echo "  Installing nmap..."
    pacman -S --noconfirm nmap
  else
    echo "  nmap: ✓"
  fi

  if ! command -v python3 &>/dev/null; then
    echo "  Installing python3..."
    pacman -S --noconfirm python
  else
    echo "  python3: ✓"
  fi

  echo -e "${BLU}[2/5]${RST} Creating install directory: $INSTALL_DIR"
  mkdir -p "$INSTALL_DIR"

  echo -e "${BLU}[3/5]${RST} Copying files..."
  cp "$SCRIPT_DIR/network_monitor.py" "$INSTALL_DIR/"
  chmod +x "$INSTALL_DIR/network_monitor.py"

  # Only copy config if it doesn't already exist (preserve user edits)
  if [[ ! -f "$INSTALL_DIR/config.json" ]]; then
    cp "$SCRIPT_DIR/config.json" "$INSTALL_DIR/"
    echo "  Config written. Edit $INSTALL_DIR/config.json before starting."
  else
    echo "  Config already exists — keeping existing config."
  fi

  echo -e "${BLU}[4/5]${RST} Installing systemd service..."
  cp "$SCRIPT_DIR/netwatch.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable $SERVICE_NAME

  echo -e "${BLU}[5/5]${RST} Done!"
  echo ""
  echo -e "${YLW}Next steps:${RST}"
  echo "  1. Edit your config:  nano $INSTALL_DIR/config.json"
  echo "  2. Add your subnet    (e.g. 192.168.0.0/24)"
  echo "  3. Add trusted MACs   (your family devices)"
  echo "  4. Enable Telegram or webhook alerts (optional)"
  echo "  5. Start the service: sudo ./setup.sh start"
  echo ""
}

cmd_start() {
  require_root start
  systemctl start $SERVICE_NAME
  echo -e "${GRN}NetWatch started.${RST}"
  systemctl status $SERVICE_NAME --no-pager -l
}

cmd_stop() {
  require_root stop
  systemctl stop $SERVICE_NAME
  echo -e "${YLW}NetWatch stopped.${RST}"
}

cmd_restart() {
  require_root restart
  systemctl restart $SERVICE_NAME
  echo -e "${GRN}NetWatch restarted.${RST}"
}

cmd_status() {
  echo -e "${CYN}── Service Status ──────────────────────────────────${RST}"
  systemctl status $SERVICE_NAME --no-pager -l 2>/dev/null || true

  if [[ -f "$INSTALL_DIR/known_devices.json" ]]; then
    echo ""
    echo -e "${CYN}── Known Devices ────────────────────────────────────${RST}"
    python3 - <<'PYEOF'
import json, sys
path = "/opt/netwatch/known_devices.json"
try:
    with open(path) as f:
        devs = json.load(f)
    print(f"  {'MAC':<20} {'IP':<16} {'Label/Host':<24} {'OS':<30} {'Last Seen'}")
    print("  " + "─"*110)
    for mac, d in devs.items():
        label = d.get('label') or d.get('hostname') or '—'
        os_g  = d.get('os_guess') or '—'
        print(f"  {mac:<20} {d.get('ip','?'):<16} {label:<24} {os_g:<30} {d.get('last_seen','?')}")
    print(f"\n  Total: {len(devs)} known device(s)")
except Exception as e:
    print(f"  (Could not read devices: {e})")
PYEOF
  fi
}

cmd_logs() {
  echo -e "${CYN}── NetWatch Live Logs (Ctrl+C to exit) ──────────────${RST}"
  journalctl -u $SERVICE_NAME -f --no-pager
}

cmd_log_file() {
  if [[ -f "$INSTALL_DIR/netwatch.log" ]]; then
    tail -n 50 "$INSTALL_DIR/netwatch.log"
  else
    echo "Log file not found: $INSTALL_DIR/netwatch.log"
  fi
}

cmd_test_scan() {
  echo -e "${YLW}Running a one-shot test scan (needs root for full results)...${RST}"
  if [[ -f "$INSTALL_DIR/config.json" ]]; then
    RANGE=$(python3 -c "import json; c=json.load(open('$INSTALL_DIR/config.json')); print(c['network_range'])" 2>/dev/null || echo "192.168.1.0/24")
  else
    RANGE="192.168.1.0/24"
  fi
  echo "Scanning: $RANGE"
  nmap -sn "$RANGE"
}

cmd_label() {
  # Usage: ./setup.sh label <MAC> <label>
  MAC="${2:-}"
  LABEL="${3:-}"
  if [[ -z "$MAC" || -z "$LABEL" ]]; then
    echo "Usage: ./setup.sh label <MAC_ADDRESS> <friendly_name>"
    echo "Example: ./setup.sh label AA:BB:CC:DD:EE:FF \"Wife's iPhone\""
    exit 1
  fi
  python3 - "$MAC" "$LABEL" <<'PYEOF'
import json, sys
mac, label = sys.argv[1].upper(), sys.argv[2]
path = "/opt/netwatch/known_devices.json"
try:
    with open(path) as f:
        devs = json.load(f)
    if mac in devs:
        devs[mac]["label"] = label
        devs[mac]["trusted"] = True
        with open(path, "w") as f:
            json.dump(devs, f, indent=2)
        print(f"✓ Labelled {mac} as '{label}' and marked trusted.")
    else:
        print(f"MAC {mac} not found in registry. Run a scan first.")
except Exception as e:
    print(f"Error: {e}")
PYEOF
}

cmd_uninstall() {
  require_root uninstall
  echo -e "${RED}Uninstalling NetWatch...${RST}"
  systemctl stop $SERVICE_NAME 2>/dev/null || true
  systemctl disable $SERVICE_NAME 2>/dev/null || true
  rm -f /etc/systemd/system/netwatch.service
  systemctl daemon-reload
  echo "Service removed. Data at $INSTALL_DIR is preserved."
  echo "To remove data: rm -rf $INSTALL_DIR"
}

banner

CMD="${1:-help}"
case "$CMD" in
  install)   cmd_install ;;
  start)     cmd_start ;;
  stop)      cmd_stop ;;
  restart)   cmd_restart ;;
  status)    cmd_status ;;
  logs)      cmd_logs ;;
  logfile)   cmd_log_file ;;
  test-scan) cmd_test_scan ;;
  label)     cmd_label "$@" ;;
  uninstall) cmd_uninstall ;;
  *)
    echo "Usage: sudo ./setup.sh <command>"
    echo ""
    echo "  install     Install NetWatch to /opt/netwatch + enable systemd service"
    echo "  start       Start the daemon"
    echo "  stop        Stop the daemon"
    echo "  restart     Restart the daemon"
    echo "  status      Show service status + known devices table"
    echo "  logs        Follow live journal logs"
    echo "  logfile     Tail the local log file"
    echo "  test-scan   Run a quick one-shot nmap scan"
    echo "  label       Label a device: label <MAC> <name>"
    echo "  uninstall   Remove service (keeps data)"
    echo ""
    ;;
esac
