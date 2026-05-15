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

# ─────────────────────────────────────────────
#  Smart OS Detection Engine
# ─────────────────────────────────────────────

# MAC OUI prefix → (likely OS, confidence note)
OUI_OS_MAP = {
    # Apple
    "00:03:93": ("iOS / macOS",         "Apple device"),
    "00:0A:27": ("macOS",               "Apple Mac"),
    "00:0A:95": ("macOS",               "Apple Mac"),
    "00:11:24": ("iOS / macOS",         "Apple device"),
    "00:17:F2": ("macOS",               "Apple Mac"),
    "00:1B:63": ("macOS",               "Apple Mac"),
    "00:1C:B3": ("iOS / macOS",         "Apple device"),
    "00:1E:52": ("iOS / macOS",         "Apple device"),
    "00:1F:5B": ("macOS",               "Apple Mac"),
    "00:21:E9": ("macOS",               "Apple Mac"),
    "00:22:41": ("macOS",               "Apple Mac"),
    "00:23:12": ("macOS",               "Apple Mac"),
    "00:23:32": ("iOS / macOS",         "Apple device"),
    "00:23:6C": ("iOS",                 "Apple iPhone/iPad"),
    "00:24:36": ("macOS",               "Apple Mac"),
    "00:25:00": ("iOS / macOS",         "Apple device"),
    "00:25:4B": ("macOS",               "Apple Mac"),
    "00:26:08": ("macOS",               "Apple Mac"),
    "00:26:B0": ("iOS / macOS",         "Apple device"),
    "00:26:BB": ("iOS / macOS",         "Apple device"),
    "04:15:52": ("iOS / macOS",         "Apple device"),
    "04:4B:ED": ("iOS",                 "Apple iPhone/iPad"),
    "04:54:53": ("iOS / macOS",         "Apple device"),
    "08:70:45": ("iOS / macOS",         "Apple device"),
    "10:40:F3": ("iOS / macOS",         "Apple device"),
    "28:37:37": ("iOS / macOS",         "Apple device"),
    "28:CF:E9": ("iOS / macOS",         "Apple device"),
    "28:EA:2D": ("iOS",                 "Apple iPhone"),
    "3C:07:54": ("iOS / macOS",         "Apple device"),
    "40:6C:8F": ("iOS / macOS",         "Apple device"),
    "48:43:7C": ("iOS / macOS",         "Apple device"),
    "60:03:08": ("iOS / macOS",         "Apple device"),
    "60:33:4B": ("iOS / macOS",         "Apple device"),
    "6C:40:08": ("iOS / macOS",         "Apple device"),
    "70:73:CB": ("iOS / macOS",         "Apple device"),
    "7C:6D:62": ("iOS / macOS",         "Apple device"),
    "80:E6:50": ("iOS / macOS",         "Apple device"),
    "98:FE:94": ("iOS / macOS",         "Apple device"),
    "A4:67:06": ("iOS / macOS",         "Apple device"),
    "AC:BC:32": ("iOS / macOS",         "Apple device"),
    "B8:09:8A": ("macOS",               "Apple Mac"),
    "C8:2A:14": ("iOS / macOS",         "Apple device"),
    "DC:2B:2A": ("iOS / macOS",         "Apple device"),
    "E0:AC:CB": ("macOS",               "Apple Mac"),
    "F4:F1:5A": ("iOS / macOS",         "Apple device"),
    # Samsung
    "00:15:99": ("Android",             "Samsung device"),
    "00:16:32": ("Android",             "Samsung device"),
    "00:17:C9": ("Android",             "Samsung Galaxy"),
    "00:21:19": ("Android",             "Samsung device"),
    "00:23:39": ("Android",             "Samsung device"),
    "00:26:37": ("Android",             "Samsung device"),
    "08:08:C2": ("Android",             "Samsung device"),
    "08:D4:2B": ("Android",             "Samsung Galaxy"),
    "18:67:B0": ("Android",             "Samsung Galaxy"),
    "30:CD:A7": ("Android",             "Samsung device"),
    "34:23:BA": ("Android",             "Samsung device"),
    "38:16:D1": ("Android",             "Samsung Galaxy"),
    "50:01:BB": ("Android",             "Samsung device"),
    "5C:49:79": ("Android",             "Samsung Galaxy"),
    "6C:2F:2C": ("Android",             "Samsung device"),
    "84:38:38": ("Android",             "Samsung device"),
    "8C:71:F8": ("Android",             "Samsung Galaxy"),
    "A0:07:98": ("Android",             "Samsung device"),
    "B4:07:F9": ("Android",             "Samsung Galaxy"),
    "CC:07:AB": ("Android",             "Samsung device"),
    "E4:92:FB": ("Android",             "Samsung device"),
    "F8:04:2E": ("Android",             "Samsung Galaxy"),
    # Google / Pixel
    "00:1A:11": ("Android",             "Google device"),
    "3C:5A:B4": ("Android",             "Google Pixel"),
    "54:60:09": ("Android",             "Google Pixel"),
    "94:EB:2C": ("Android",             "Google device"),
    "F4:F5:D8": ("Android",             "Google Pixel"),
    # OnePlus
    "04:4E:AF": ("Android",             "OnePlus device"),
    "8C:47:6E": ("Android",             "OnePlus device"),
    "94:65:2D": ("Android",             "OnePlus device"),
    # Xiaomi
    "00:9E:C8": ("Android",             "Xiaomi device"),
    "04:CF:8C": ("Android",             "Xiaomi device"),
    "10:2A:B3": ("Android",             "Xiaomi device"),
    "18:59:36": ("Android",             "Xiaomi device"),
    "20:82:C0": ("Android",             "Xiaomi device"),
    "28:6C:07": ("Android",             "Xiaomi device"),
    "34:80:B3": ("Android",             "Xiaomi device"),
    "38:A4:ED": ("Android",             "Xiaomi device"),
    "4A:B5:D3": ("Android / iOS",       "Xiaomi or randomized MAC"),
    "50:64:2B": ("Android",             "Xiaomi device"),
    "58:44:98": ("Android",             "Xiaomi device"),
    "64:09:80": ("Android",             "Xiaomi device"),
    "64:B4:73": ("Android",             "Xiaomi device"),
    "68:DF:DD": ("Android",             "Xiaomi device"),
    "74:23:44": ("Android",             "Xiaomi device"),
    "78:11:DC": ("Android",             "Xiaomi device"),
    "8C:BE:BE": ("Android",             "Xiaomi device"),
    "9C:99:A0": ("Android",             "Xiaomi device"),
    "AC:C1:EE": ("Android",             "Xiaomi device"),
    "B0:E2:35": ("Android",             "Xiaomi device"),
    "C4:0B:CB": ("Android",             "Xiaomi device"),
    "D4:97:0B": ("Android",             "Xiaomi device"),
    "F4:8B:32": ("Android",             "Xiaomi device"),
    "F8:A4:5F": ("Android",             "Xiaomi device"),
    # Huawei
    "00:18:82": ("Android / HarmonyOS", "Huawei device"),
    "00:E0:FC": ("Android / HarmonyOS", "Huawei device"),
    "04:BD:88": ("Android / HarmonyOS", "Huawei device"),
    "18:B4:30": ("Android / HarmonyOS", "Huawei device"),
    "20:F3:A3": ("Android / HarmonyOS", "Huawei device"),
    "2C:AB:00": ("Android / HarmonyOS", "Huawei device"),
    "34:6B:D3": ("Android / HarmonyOS", "Huawei device"),
    "40:4D:7F": ("Android / HarmonyOS", "Huawei device"),
    "48:00:31": ("Android / HarmonyOS", "Huawei device"),
    "54:51:1B": ("Android / HarmonyOS", "Huawei device"),
    "5C:C3:07": ("Android / HarmonyOS", "Huawei device"),
    "70:54:D2": ("Android / HarmonyOS", "Huawei device"),
    "78:1D:BA": ("Android / HarmonyOS", "Huawei device"),
    "80:D4:A5": ("Android / HarmonyOS", "Huawei device"),
    "90:67:1C": ("Android / HarmonyOS", "Huawei device"),
    "B4:CD:27": ("Android / HarmonyOS", "Huawei device"),
    "C8:14:79": ("Android / HarmonyOS", "Huawei device"),
    "D4:6A:A8": ("Android / HarmonyOS", "Huawei device"),
    "E8:CD:2D": ("Android / HarmonyOS", "Huawei device"),
    "F4:CB:52": ("Android / HarmonyOS", "Huawei device"),
    # Amazon
    "00:BB:3A": ("Amazon Fire OS",       "Amazon Echo/Fire"),
    "10:AE:60": ("Amazon Fire OS",       "Amazon device"),
    "34:D2:70": ("Amazon Fire OS",       "Amazon Echo"),
    "40:B4:CD": ("Amazon Fire OS",       "Amazon Echo/Fire"),
    "44:65:0D": ("Amazon Fire OS",       "Amazon device"),
    "50:F5:DA": ("Amazon Fire OS",       "Amazon Echo"),
    "68:37:E9": ("Amazon Fire OS",       "Amazon Echo"),
    "74:C2:46": ("Amazon Fire OS",       "Amazon device"),
    "84:D6:D0": ("Amazon Fire OS",       "Amazon Echo"),
    "A0:02:DC": ("Amazon Fire OS",       "Amazon Echo"),
    "B4:7C:9C": ("Amazon Fire OS",       "Amazon Echo"),
    "CC:9E:A2": ("Amazon Fire OS",       "Amazon Fire TV"),
    "F0:4F:7C": ("Amazon Fire OS",       "Amazon Echo"),
    "F0:81:73": ("Amazon Fire OS",       "Amazon Echo"),
    "FC:A6:67": ("Amazon Fire OS",       "Amazon Echo"),
    # Raspberry Pi
    "B8:27:EB": ("Linux (Raspberry Pi)", "Raspberry Pi"),
    "DC:A6:32": ("Linux (Raspberry Pi)", "Raspberry Pi 4"),
    "E4:5F:01": ("Linux (Raspberry Pi)", "Raspberry Pi"),
    # Windows / PC
    "00:50:56": ("Windows / Linux",      "VMware VM"),
    "08:00:27": ("Linux",                "VirtualBox VM"),
    "00:15:5D": ("Windows",              "Hyper-V VM"),
    # Smart TVs
    "00:17:88": ("Hue Bridge / IoT",     "Philips Hue"),
    "00:24:BE": ("Android TV",           "Sony TV"),
    "18:4B:0D": ("Tizen / Android TV",   "Samsung TV"),
    "20:6E:9C": ("webOS",                "LG TV"),
    "34:7E:5C": ("Android TV",           "Sony TV"),
    "40:2C:F4": ("Tizen",                "Samsung TV"),
    "48:44:F7": ("Android TV",           "Nvidia Shield"),
    "5C:AA:FD": ("Tizen",                "Samsung TV"),
    "78:BD:BC": ("webOS",                "LG TV"),
    "9C:84:BF": ("Android TV",           "Sony TV"),
    "A0:75:91": ("webOS",                "LG Smart TV"),
    "BC:30:7E": ("Tizen",                "Samsung Smart TV"),
    "CC:6D:A0": ("Tizen",                "Samsung TV"),
    # Routers
    "8C:13:E2": ("Linux (Router)",       "Netlink ICT Router"),
}

# Hostname pattern → OS guess
HOSTNAME_OS_PATTERNS = [
    (r"iphone",           "iOS",                "Apple iPhone"),
    (r"ipad",             "iPadOS",             "Apple iPad"),
    (r"macbook",          "macOS",              "Apple MacBook"),
    (r"imac",             "macOS",              "Apple iMac"),
    (r"apple",            "iOS / macOS",        "Apple device"),
    (r"android",          "Android",            "Android phone/tablet"),
    (r"galaxy",           "Android",            "Samsung Galaxy"),
    (r"pixel",            "Android",            "Google Pixel"),
    (r"oneplus",          "Android",            "OnePlus phone"),
    (r"xiaomi|miphone",   "Android",            "Xiaomi phone"),
    (r"huawei",           "Android/HarmonyOS",  "Huawei device"),
    (r"echo|alexa",       "Amazon Fire OS",     "Amazon Echo"),
    (r"kindle|fire",      "Amazon Fire OS",     "Amazon Fire tablet"),
    (r"firetv|fire-tv",   "Amazon Fire OS",     "Amazon Fire TV"),
    (r"raspberrypi|rpi",  "Linux (Raspberry Pi)","Raspberry Pi"),
    (r"ubuntu|debian|fedora|arch|centos", "Linux", "Linux PC"),
    (r"windows|win10|win11", "Windows",         "Windows PC"),
    (r"xbox",             "Xbox OS",            "Microsoft Xbox"),
    (r"playstation|ps[45]","PlayStation OS",    "Sony PlayStation"),
    (r"nintendo|switch",  "Nintendo OS",        "Nintendo Switch"),
    (r"roku",             "Roku OS",            "Roku device"),
    (r"chromecast",       "ChromeOS",           "Google Chromecast"),
    (r"nest|google-home", "Android/IoT",        "Google Home/Nest"),
    (r"ring",             "Linux (IoT)",        "Ring device"),
    (r"sonos",            "Linux (IoT)",        "Sonos speaker"),
    (r"synology",         "Linux (NAS)",        "Synology NAS"),
    (r"qnap",             "Linux (NAS)",        "QNAP NAS"),
]

# Vendor string → OS guess
VENDOR_OS_MAP = {
    "apple":     ("iOS / macOS",         "Apple device"),
    "samsung":   ("Android",             "Samsung device"),
    "xiaomi":    ("Android",             "Xiaomi/MIUI device"),
    "huawei":    ("Android/HarmonyOS",   "Huawei device"),
    "google":    ("Android",             "Google device"),
    "amazon":    ("Amazon Fire OS",      "Amazon device"),
    "microsoft": ("Windows",             "Microsoft device"),
    "sony":      ("Android TV / PS OS",  "Sony device"),
    "lg":        ("webOS / Android",     "LG device"),
    "raspberry": ("Linux",               "Raspberry Pi"),
    "netlink":   ("Linux (Router FW)",   "Home Router"),
    "tp-link":   ("Linux (Router FW)",   "TP-Link device"),
    "asus":      ("Linux (Router/PC)",   "ASUS device"),
    "netgear":   ("Linux (Router FW)",   "Netgear device"),
    "linksys":   ("Linux (Router FW)",   "Linksys device"),
    "ubiquiti":  ("Linux (Router FW)",   "Ubiquiti device"),
    "cisco":     ("IOS / Linux",         "Cisco device"),
    "intel":     ("Windows / Linux",     "Intel NIC — PC"),
    "realtek":   ("Windows / Linux",     "PC NIC"),
    "broadcom":  ("Linux / Windows",     "PC or router"),
}

# Randomized MAC prefixes (locally administered bit set)
RANDOMIZED_MAC_PREFIXES = {"2", "6", "a", "e"}  # second nibble of first byte


def is_randomized_mac(mac: str) -> bool:
    """Check if MAC is locally administered (randomized privacy MAC)."""
    if not mac or len(mac) < 2:
        return False
    # Second hex digit of first octet: bit 1 set = locally administered
    try:
        first_byte = int(mac.replace(":", "")[:2], 16)
        return bool(first_byte & 0x02)
    except Exception:
        return False


def guess_os(device: dict) -> dict:
    """
    Return enriched OS guess using multiple signals:
    MAC OUI → hostname patterns → vendor string → nmap result → randomized MAC
    Returns { os_guess, os_confidence, os_notes }
    """
    mac      = (device.get("mac") or "").upper()
    hostname = (device.get("hostname") or "").lower()
    vendor   = (device.get("vendor") or "").lower()
    nmap_os  = (device.get("os_guess") or "").strip()
    oui      = mac[:8]   # first 3 octets e.g. "28:EA:2D"

    os_guess      = ""
    os_confidence = "low"
    os_notes      = []

    # 1. OUI lookup (most reliable for real MACs)
    if oui in OUI_OS_MAP and not is_randomized_mac(mac):
        os_guess, note = OUI_OS_MAP[oui]
        os_confidence = "high"
        os_notes.append(f"OUI match: {note}")

    # 2. Hostname pattern match
    for pattern, os_name, note in HOSTNAME_OS_PATTERNS:
        if re.search(pattern, hostname, re.I):
            if not os_guess:
                os_guess = os_name
                os_confidence = "high"
            os_notes.append(f"Hostname hint: {note}")
            break

    # 3. Vendor string match
    if not os_guess:
        for keyword, (os_name, note) in VENDOR_OS_MAP.items():
            if keyword in vendor:
                os_guess = os_name
                os_confidence = "medium"
                os_notes.append(f"Vendor hint: {note}")
                break

    # 4. nmap OS result (use if we have nothing better, or to confirm)
    if nmap_os:
        if not os_guess:
            os_guess = nmap_os
            os_confidence = "medium"
            os_notes.append("nmap OS fingerprint")
        elif os_guess.lower().split()[0] in nmap_os.lower():
            os_confidence = "high"
            os_notes.append(f"Confirmed by nmap: {nmap_os}")
        else:
            os_notes.append(f"nmap also suggests: {nmap_os}")

    # 5. Randomized MAC → add as a note
    if is_randomized_mac(mac):
        os_notes.append("Randomized/private MAC — real vendor hidden")
        if not os_guess:
            os_guess = "Unknown (privacy MAC)"
            os_confidence = "low"
        elif os_confidence == "high":
            os_confidence = "medium"   # downgrade since MAC hides true vendor

    # 6. Fallback
    if not os_guess:
        os_guess = "Unknown"
        os_confidence = "low"
        os_notes.append("No signals matched")

    return {
        "os_guess":      os_guess,
        "os_confidence": os_confidence,
        "os_notes":      os_notes
    }


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

    smart = guess_os(device)
    if mac not in known:
        known[mac] = {
            **device,
            "first_seen":    now,
            "seen_count":    1,
            "trusted":       mac in [m.upper() for m in trusted_macs],
            "label":         "",
            "os_guess":      smart["os_guess"],
            "os_confidence": smart["os_confidence"],
            "os_notes":      smart["os_notes"],
        }
    else:
        known[mac].update({
            "ip":            device["ip"],
            "hostname":      device["hostname"] or known[mac].get("hostname", ""),
            "os_guess":      smart["os_guess"],
            "os_confidence": smart["os_confidence"],
            "os_notes":      smart["os_notes"],
            "vendor":        device["vendor"] or known[mac].get("vendor", ""),
            "last_seen":     now,
            "seen_count":    known[mac].get("seen_count", 0) + 1
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
        # Run smart OS detection
        smart = guess_os(device)
        os_display    = smart["os_guess"]
        os_confidence = smart["os_confidence"]
        os_notes_str  = " • ".join(smart["os_notes"])
        conf_emoji    = {"high": "🟢", "medium": "🟡", "low": "🔴"}.get(os_confidence, "⚪")
        rand_note     = " ⚠️ Privacy/randomized MAC" if is_randomized_mac(mac) else ""

        subject = f"⚠️ NEW DEVICE on network: {label}"
        body = (
            f"A device just joined your network!\n\n"
            f"{format_device_info(device)}\n"
            f"  OS (smart)  : {os_display} ({os_confidence} confidence)\n"
            f"  OS signals  : {os_notes_str}\n\n"
            f"Total devices online: {total_online}\n"
            f"Time: {now}"
        )
        tg_msg = (
            f"🚨 <b>New Device Detected!</b>{rand_note}\n\n"
            f"<b>Name:</b> {label}\n"
            f"<b>IP:</b> {ip}\n"
            f"<b>MAC:</b> {mac}\n"
            f"<b>Vendor:</b> {vendor}\n\n"
            f"<b>OS Guess:</b> {os_display}\n"
            f"<b>Confidence:</b> {conf_emoji} {os_confidence}\n"
            f"<b>Signals:</b> {os_notes_str}\n\n"
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
