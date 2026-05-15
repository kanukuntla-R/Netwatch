#!/usr/bin/env python3
"""
NetWatch - Home Network Monitor Daemon
Scans LAN using Nmap, detects new/unknown devices, and fires alerts.
Designed for Arch Linux hub running 24/7.
"""

import json
import os
import re
import subprocess
import sys
import time
import logging
import signal
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime
from pathlib import Path


# ─────────────────────────────────────────────
#  Paths & Defaults
# ─────────────────────────────────────────────
BASE_DIR       = Path(__file__).parent
CONFIG_FILE    = BASE_DIR / "config.json"
DEVICES_FILE   = BASE_DIR / "known_devices.json"
LOG_FILE       = BASE_DIR / "netwatch.log"
HISTORY_FILE   = BASE_DIR / "scan_history.json"

DEFAULT_CONFIG = {
    "network_range": "192.168.1.0/24",   # adjust to your subnet
    "scan_interval_seconds": 60,
    "nmap_flags": "-sn -O --osscan-guess",  # ping scan + OS detection
    "trusted_macs": [],                   # MACs that are always "known family"
    "alert": {
        "telegram": {
            "enabled": False,
            "bot_token": "",
            "chat_id": ""
        },
        "webhook": {
            "enabled": False,
            "url": "",                    # POST JSON payload here
            "secret_header": ""          # optional header value
        },
        "local_log": {
            "enabled": True              # always logs to netwatch.log
        },
        "desktop_notify": {
            "enabled": False             # uses notify-send (needs libnotify)
        }
    },
    "scan_on_start": True,
    "alert_on_reconnect": False,         # alert when a known device re-joins
    "log_level": "INFO"
}


# ─────────────────────────────────────────────
#  Logging
# ─────────────────────────────────────────────
def setup_logging(level_str: str):
    level = getattr(logging, level_str.upper(), logging.INFO)
    fmt   = "%(asctime)s [%(levelname)s] %(message)s"
    handlers = [
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, encoding="utf-8")
    ]
    logging.basicConfig(level=level, format=fmt, handlers=handlers)

log = logging.getLogger("netwatch")


# ─────────────────────────────────────────────
#  Config helpers
# ─────────────────────────────────────────────
def load_config() -> dict:
    if not CONFIG_FILE.exists():
        log.warning("config.json not found — writing defaults.")
        save_json(CONFIG_FILE, DEFAULT_CONFIG)
        return DEFAULT_CONFIG.copy()
    with open(CONFIG_FILE) as f:
        cfg = json.load(f)
    # merge missing keys from defaults
    merged = {**DEFAULT_CONFIG, **cfg}
    merged["alert"] = {**DEFAULT_CONFIG["alert"], **cfg.get("alert", {})}
    return merged


def save_json(path: Path, data: dict):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def load_json(path: Path, default=None):
    if not path.exists():
        return default if default is not None else {}
    with open(path) as f:
        return json.load(f)


# ─────────────────────────────────────────────
#  Nmap scanner
# ─────────────────────────────────────────────
def run_nmap(network_range: str, flags: str) -> str:
    """Run nmap and return raw stdout. Must be root for OS detection."""
    cmd = ["nmap"] + flags.split() + [network_range]
    log.debug("Running: %s", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            log.warning("nmap stderr: %s", result.stderr.strip())
        return result.stdout
    except subprocess.TimeoutExpired:
        log.error("nmap scan timed out.")
        return ""
    except FileNotFoundError:
        log.error("nmap not found. Install it: sudo pacman -S nmap")
        return ""


def parse_nmap_output(raw: str) -> list[dict]:
    """
    Parse nmap -sn -O output into a list of device dicts.
    Returns: [{ ip, mac, vendor, hostname, os_guess, last_seen }]
    """
    devices = []
    current = {}

    for line in raw.splitlines():
        line = line.strip()

        # New host block
        nmap_report = re.match(r"Nmap scan report for (.+)", line)
        if nmap_report:
            if current:
                devices.append(current)
            host_part = nmap_report.group(1)
            # Could be "hostname (ip)" or just "ip"
            ip_match = re.search(r"\(?([\d.]+)\)?$", host_part)
            hostname_match = re.match(r"(.+?)\s+\(", host_part)
            current = {
                "ip":        ip_match.group(1) if ip_match else host_part,
                "hostname":  hostname_match.group(1) if hostname_match else "",
                "mac":       "",
                "vendor":    "",
                "os_guess":  "",
                "last_seen": datetime.now().isoformat(timespec="seconds")
            }
            continue

        # MAC address line
        mac_match = re.match(r"MAC Address: ([0-9A-F:]{17})\s*\((.+)\)", line, re.I)
        if mac_match and current:
            current["mac"]    = mac_match.group(1).upper()
            current["vendor"] = mac_match.group(2)
            continue

        # OS guess
        os_match = re.match(r"OS details:\s*(.+)", line, re.I)
        if not os_match:
            os_match = re.match(r"Aggressive OS guesses:\s*(.+)", line, re.I)
        if os_match and current:
            # Take first guess before any comma
            current["os_guess"] = os_match.group(1).split(",")[0].strip()
            continue

        os_running = re.match(r"Running:\s*(.+)", line, re.I)
        if os_running and current and not current["os_guess"]:
            current["os_guess"] = os_running.group(1).strip()

    if current:
        devices.append(current)

    return devices


# ─────────────────────────────────────────────
#  Device registry
# ─────────────────────────────────────────────
def load_known_devices() -> dict:
    """Load known devices keyed by MAC address."""
    return load_json(DEVICES_FILE, {})


def save_known_devices(devices: dict):
    save_json(DEVICES_FILE, devices)


def register_device(known: dict, device: dict, trusted_macs: list) -> dict:
    """Add or update a device in the registry. Returns the stored record."""
    mac = device["mac"] or device["ip"]   # fallback to IP if no MAC
    now = datetime.now().isoformat(timespec="seconds")

    if mac not in known:
        known[mac] = {
            **device,
            "first_seen": now,
            "seen_count": 1,
            "trusted":    mac in [m.upper() for m in trusted_macs],
            "label":      ""     # user can set a friendly name via known_devices.json
        }
    else:
        known[mac].update({
            "ip":        device["ip"],
            "hostname":  device["hostname"] or known[mac].get("hostname", ""),
            "os_guess":  device["os_guess"] or known[mac].get("os_guess", ""),
            "vendor":    device["vendor"]   or known[mac].get("vendor", ""),
            "last_seen": now,
            "seen_count": known[mac].get("seen_count", 0) + 1
        })
    return known[mac]


# ─────────────────────────────────────────────
#  Alert system
# ─────────────────────────────────────────────
def format_device_info(device: dict) -> str:
    label     = device.get("label") or device.get("hostname") or "Unknown"
    mac       = device.get("mac", "N/A")
    ip        = device.get("ip", "N/A")
    vendor    = device.get("vendor", "Unknown vendor")
    os_guess  = device.get("os_guess", "Unknown OS")
    first     = device.get("first_seen", "?")
    return (
        f"  Label/Name : {label}\n"
        f"  IP Address : {ip}\n"
        f"  MAC Address: {mac}\n"
        f"  Vendor     : {vendor}\n"
        f"  OS Guess   : {os_guess}\n"
        f"  First Seen : {first}"
    )


def send_telegram(token: str, chat_id: str, message: str):
    url  = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id":    chat_id,
        "text":       message,
        "parse_mode": "HTML"
    }).encode()
    try:
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            log.debug("Telegram response: %s", resp.read().decode())
    except Exception as e:
        log.error("Telegram send failed: %s", e)


def send_webhook(url: str, payload: dict, secret: str = ""):
    data    = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-NetWatch-Secret"] = secret
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            log.debug("Webhook response: %d", resp.getcode())
    except Exception as e:
        log.error("Webhook send failed: %s", e)


def send_desktop_notify(title: str, body: str):
    try:
        subprocess.run(["notify-send", title, body, "-i", "network-wired"], 
                       timeout=5, check=False)
    except Exception as e:
        log.debug("Desktop notify failed: %s", e)


def fire_alert(cfg: dict, event: str, device: dict, total_online: int):
    """
    Fire all configured alerts for a network event.
    event: 'new_device' | 'reconnected' | 'scan_complete'
    """
    now   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    label = device.get("label") or device.get("hostname") or device.get("ip", "?")
    mac   = device.get("mac", "N/A")
    ip    = device.get("ip", "N/A")
    vendor = device.get("vendor", "?")
    os_g  = device.get("os_guess", "?")

    if event == "new_device":
        subject = f"⚠️ NEW DEVICE on network: {label}"
        body = (
            f"A device just joined your network!\n\n"
            f"{format_device_info(device)}\n\n"
            f"Total devices online: {total_online}\n"
            f"Time: {now}"
        )
        tg_msg = (
            f"🚨 <b>New Device Detected!</b>\n"
            f"<b>Name:</b> {label}\n"
            f"<b>IP:</b> {ip}\n"
            f"<b>MAC:</b> {mac}\n"
            f"<b>Vendor:</b> {vendor}\n"
            f"<b>OS:</b> {os_g}\n"
            f"<b>Devices online:</b> {total_online}\n"
            f"<b>Time:</b> {now}"
        )
    elif event == "reconnected":
        subject = f"📶 Device reconnected: {label}"
        body = f"Known device back online:\n{format_device_info(device)}\nTime: {now}"
        tg_msg = f"📶 <b>Device Reconnected:</b> {label} ({ip})\n<b>Time:</b> {now}"
    else:
        return  # no alerts for scan_complete by default

    # Log always
    log.warning("ALERT [%s]: %s", event, subject)

    alert_cfg = cfg.get("alert", {})

    # Telegram
    tg = alert_cfg.get("telegram", {})
    if tg.get("enabled") and tg.get("bot_token") and tg.get("chat_id"):
        send_telegram(tg["bot_token"], tg["chat_id"], tg_msg)

    # Webhook
    wh = alert_cfg.get("webhook", {})
    if wh.get("enabled") and wh.get("url"):
        payload = {
            "event":         event,
            "timestamp":     now,
            "device":        device,
            "total_online":  total_online
        }
        send_webhook(wh["url"], payload, wh.get("secret_header", ""))

    # Desktop notification
    dn = alert_cfg.get("desktop_notify", {})
    if dn.get("enabled"):
        send_desktop_notify(subject, body)


# ─────────────────────────────────────────────
#  Core scan loop
# ─────────────────────────────────────────────
def run_scan(cfg: dict, known: dict) -> tuple[dict, list]:
    """
    Run one nmap scan. Return (updated_known_devices, new_device_list).
    """
    raw     = run_nmap(cfg["network_range"], cfg["nmap_flags"])
    if not raw:
        return known, []

    scanned = parse_nmap_output(raw)
    log.info("Scan complete — %d device(s) found online.", len(scanned))

    new_devices        = []
    reconnected_devices = []
    trusted_macs       = [m.upper() for m in cfg.get("trusted_macs", [])]

    for device in scanned:
        mac = device["mac"] or device["ip"]
        is_new = mac not in known

        stored = register_device(known, device, trusted_macs)

        if is_new:
            log.info("NEW device: %s  IP: %s  Vendor: %s  OS: %s",
                     mac, device["ip"], device["vendor"], device["os_guess"])
            new_devices.append(stored)
        else:
            log.debug("Known device: %s (%s)", mac, device["ip"])
            if cfg.get("alert_on_reconnect"):
                reconnected_devices.append(stored)

    # Save updated registry
    save_known_devices(known)

    # Save scan to history
    history = load_json(HISTORY_FILE, [])
    history.append({
        "timestamp":   datetime.now().isoformat(timespec="seconds"),
        "total_found": len(scanned),
        "new_count":   len(new_devices),
        "devices":     scanned
    })
    # Keep last 100 scans in history
    save_json(HISTORY_FILE, history[-100:])

    total = len(scanned)

    for dev in new_devices:
        fire_alert(cfg, "new_device", dev, total)

    for dev in reconnected_devices:
        fire_alert(cfg, "reconnected", dev, total)

    return known, new_devices


def print_status(known: dict, online_ips: set):
    """Print a clean status table to stdout."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{'═'*60}")
    print(f"  NetWatch Status  —  {now}")
    print(f"{'═'*60}")
    print(f"  Total known devices : {len(known)}")
    print(f"  Currently online    : {len(online_ips)}")
    print(f"{'─'*60}")
    for mac, dev in known.items():
        online_marker = "●" if dev.get("ip") in online_ips else "○"
        label = dev.get("label") or dev.get("hostname") or "—"
        print(f"  {online_marker}  {dev.get('ip','?'):>15}  {mac}  {label}")
    print(f"{'═'*60}\n")


# ─────────────────────────────────────────────
#  Graceful shutdown
# ─────────────────────────────────────────────
_running = True

def handle_signal(sig, frame):
    global _running
    log.info("Signal %d received — shutting down gracefully.", sig)
    _running = False

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT,  handle_signal)


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────
def main():
    cfg = load_config()
    setup_logging(cfg.get("log_level", "INFO"))

    log.info("NetWatch starting — monitoring %s every %ds",
             cfg["network_range"], cfg["scan_interval_seconds"])

    # Check if running as root (needed for OS detection & MAC addresses)
    if os.geteuid() != 0:
        log.warning("Not running as root — MAC addresses and OS detection "
                    "may not work. Run with sudo or as root via systemd.")

    known = load_known_devices()
    log.info("Loaded %d known devices from registry.", len(known))

    interval = cfg["scan_interval_seconds"]
    last_scan = 0.0

    if cfg.get("scan_on_start"):
        last_scan = -interval  # force immediate scan

    while _running:
        now = time.time()
        if now - last_scan >= interval:
            try:
                known, new_devs = run_scan(cfg, known)
                online_ips = {d["ip"] for d in known.values() if d.get("ip")}
                if log.isEnabledFor(logging.DEBUG):
                    print_status(known, online_ips)
            except Exception as e:
                log.exception("Scan error: %s", e)
            last_scan = time.time()
            # Reload config in case it was edited
            cfg = load_config()

        time.sleep(5)   # poll every 5s for shutdown signal responsiveness

    log.info("NetWatch stopped.")


if __name__ == "__main__":
    main()
