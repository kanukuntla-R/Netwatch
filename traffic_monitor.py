#!/usr/bin/env python3
"""
TraffWatch — Per-device traffic activity monitor
Part of the NetWatch suite for Arch Linux Hub.

Uses tshark to passively sniff DNS queries and TLS SNI headers,
maps them to service categories (YouTube, Gaming, Social etc.),
tracks per-device usage, and fires Telegram alerts on time limits.

Requires: tshark (sudo pacman -S wireshark-cli)
Must run as root.
"""

import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.parse
from collections import defaultdict
from datetime import datetime, date, timedelta
from pathlib import Path


# ─────────────────────────────────────────────
#  Paths
# ─────────────────────────────────────────────
BASE_DIR        = Path("/opt/netwatch")
CONFIG_FILE     = BASE_DIR / "config.json"
TRAFF_CFG_FILE  = BASE_DIR / "traffic_config.json"
DEVICES_FILE    = BASE_DIR / "known_devices.json"
ACTIVITY_FILE   = BASE_DIR / "activity_log.json"
LOG_FILE        = BASE_DIR / "traffwatch.log"

import logging

def setup_logging():
    fmt = "%(asctime)s [%(levelname)s] %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(LOG_FILE, encoding="utf-8")
        ]
    )

log = logging.getLogger("traffwatch")


# ─────────────────────────────────────────────
#  Service / domain database
# ─────────────────────────────────────────────
# Each entry: domain_keyword → (category, service_name, age_flag)
# age_flag: "ok" | "watch" | "flag"
# "watch"  = monitor time (gaming, social)
# "flag"   = alert immediately regardless of time

SERVICE_DB = {
    # ── Video streaming ───────────────────────
    "youtube.com":          ("Video",    "YouTube",       "watch"),
    "youtu.be":             ("Video",    "YouTube",       "watch"),
    "googlevideo.com":      ("Video",    "YouTube",       "watch"),
    "ytimg.com":            ("Video",    "YouTube",       "watch"),
    "yt3.ggpht.com":        ("Video",    "YouTube",       "watch"),
    "netflix.com":          ("Video",    "Netflix",       "watch"),
    "nflxvideo.net":        ("Video",    "Netflix",       "watch"),
    "nflximg.net":          ("Video",    "Netflix",       "watch"),
    "disneyplus.com":       ("Video",    "Disney+",       "watch"),
    "dssott.com":           ("Video",    "Disney+",       "watch"),
    "hulu.com":             ("Video",    "Hulu",          "watch"),
    "hulustream.com":       ("Video",    "Hulu",          "watch"),
    "twitch.tv":            ("Video",    "Twitch",        "watch"),
    "twitchsvc.net":        ("Video",    "Twitch",        "watch"),
    "jtvnw.net":            ("Video",    "Twitch",        "watch"),
    "primevideo.com":       ("Video",    "Prime Video",   "watch"),
    "aiv-cdn.net":          ("Video",    "Prime Video",   "watch"),
    "hbomax.com":           ("Video",    "HBO Max",       "watch"),
    "max.com":              ("Video",    "Max",           "watch"),
    "peacocktv.com":        ("Video",    "Peacock",       "watch"),
    "paramountplus.com":    ("Video",    "Paramount+",    "watch"),
    "crunchyroll.com":      ("Video",    "Crunchyroll",   "watch"),
    "vimeo.com":            ("Video",    "Vimeo",         "watch"),
    "dailymotion.com":      ("Video",    "Dailymotion",   "watch"),

    # ── Social media ──────────────────────────
    "tiktok.com":           ("Social",   "TikTok",        "watch"),
    "tiktokcdn.com":        ("Social",   "TikTok",        "watch"),
    "musical.ly":           ("Social",   "TikTok",        "watch"),
    "instagram.com":        ("Social",   "Instagram",     "watch"),
    "cdninstagram.com":     ("Social",   "Instagram",     "watch"),
    "facebook.com":         ("Social",   "Facebook",      "watch"),
    "fbcdn.net":            ("Social",   "Facebook",      "watch"),
    "snapchat.com":         ("Social",   "Snapchat",      "watch"),
    "snapkit.com":          ("Social",   "Snapchat",      "watch"),
    "sc-cdn.net":           ("Social",   "Snapchat",      "watch"),
    "twitter.com":          ("Social",   "Twitter/X",     "watch"),
    "x.com":                ("Social",   "Twitter/X",     "watch"),
    "t.co":                 ("Social",   "Twitter/X",     "watch"),
    "reddit.com":           ("Social",   "Reddit",        "watch"),
    "redd.it":              ("Social",   "Reddit",        "watch"),
    "redditstatic.com":     ("Social",   "Reddit",        "watch"),
    "pinterest.com":        ("Social",   "Pinterest",     "watch"),
    "tumblr.com":           ("Social",   "Tumblr",        "watch"),
    "discord.com":          ("Social",   "Discord",       "watch"),
    "discord.gg":           ("Social",   "Discord",       "watch"),
    "discordapp.com":       ("Social",   "Discord",       "watch"),
    "discordapp.net":       ("Social",   "Discord",       "watch"),
    "whatsapp.com":         ("Social",   "WhatsApp",      "ok"),
    "whatsapp.net":         ("Social",   "WhatsApp",      "ok"),
    "telegram.org":         ("Social",   "Telegram",      "ok"),
    "messenger.com":        ("Social",   "Messenger",     "watch"),

    # ── Gaming ────────────────────────────────
    "roblox.com":           ("Gaming",   "Roblox",        "watch"),
    "rbxcdn.com":           ("Gaming",   "Roblox",        "watch"),
    "minecraft.net":        ("Gaming",   "Minecraft",     "watch"),
    "mojang.com":           ("Gaming",   "Minecraft",     "watch"),
    "epicgames.com":        ("Gaming",   "Fortnite/Epic", "watch"),
    "fortnite.com":         ("Gaming",   "Fortnite",      "watch"),
    "steamgames.com":       ("Gaming",   "Steam",         "watch"),
    "steampowered.com":     ("Gaming",   "Steam",         "watch"),
    "steamcontent.com":     ("Gaming",   "Steam",         "watch"),
    "valvesoftware.com":    ("Gaming",   "Steam",         "watch"),
    "gog.com":              ("Gaming",   "GOG",           "watch"),
    "ea.com":               ("Gaming",   "EA Games",      "watch"),
    "origin.com":           ("Gaming",   "EA Origin",     "watch"),
    "battlenet.com":        ("Gaming",   "Battle.net",    "watch"),
    "blizzard.com":         ("Gaming",   "Blizzard",      "watch"),
    "riotgames.com":        ("Gaming",   "Riot/Valorant", "watch"),
    "leagueoflegends.com":  ("Gaming",   "League",        "watch"),
    "valorant.com":         ("Gaming",   "Valorant",      "watch"),
    "ubisoft.com":          ("Gaming",   "Ubisoft",       "watch"),
    "ubi.com":              ("Gaming",   "Ubisoft",       "watch"),
    "activision.com":       ("Gaming",   "Activision",    "watch"),
    "callofduty.com":       ("Gaming",   "Call of Duty",  "watch"),
    "xbox.com":             ("Gaming",   "Xbox",          "watch"),
    "xboxlive.com":         ("Gaming",   "Xbox Live",     "watch"),
    "live.com":             ("Gaming",   "Xbox Live",     "watch"),
    "playstation.com":      ("Gaming",   "PlayStation",   "watch"),
    "playstation.net":      ("Gaming",   "PlayStation",   "watch"),
    "sonyentertainmentnetwork.com": ("Gaming", "PSN",     "watch"),
    "nintendo.com":         ("Gaming",   "Nintendo",      "watch"),
    "nintendo.net":         ("Gaming",   "Nintendo",      "watch"),
    "supercell.com":        ("Gaming",   "Clash of Clans","watch"),
    "clash.com":            ("Gaming",   "Clash",         "watch"),
    "pubg.com":             ("Gaming",   "PUBG",          "watch"),
    "gameloft.com":         ("Gaming",   "Gameloft",      "watch"),
    "pocketgems.com":       ("Gaming",   "Mobile Game",   "watch"),
    "agame.com":            ("Gaming",   "Online Games",  "watch"),
    "miniclip.com":         ("Gaming",   "Miniclip",      "watch"),
    "itch.io":              ("Gaming",   "Itch.io",       "watch"),
    "overwolf.com":         ("Gaming",   "Overwolf",      "watch"),
    "rockstargames.com":    ("Gaming",   "Rockstar",      "watch"),
    "2k.com":               ("Gaming",   "2K Games",      "watch"),
    "genshin.hoyoverse.com":("Gaming",   "Genshin Impact","watch"),
    "hoyoverse.com":        ("Gaming",   "HoYoverse",     "watch"),
    "freerealms.com":       ("Gaming",   "Free Realms",   "watch"),

    # ── Adult / explicit (flag immediately) ───
    "pornhub.com":          ("Adult",    "PornHub",       "flag"),
    "xvideos.com":          ("Adult",    "XVideos",       "flag"),
    "xnxx.com":             ("Adult",    "XNXX",          "flag"),
    "xhamster.com":         ("Adult",    "XHamster",      "flag"),
    "redtube.com":          ("Adult",    "RedTube",       "flag"),
    "youporn.com":          ("Adult",    "YouPorn",       "flag"),
    "onlyfans.com":         ("Adult",    "OnlyFans",      "flag"),
    "brazzers.com":         ("Adult",    "Adult",         "flag"),
    "livejasmin.com":       ("Adult",    "Adult",         "flag"),
    "chaturbate.com":       ("Adult",    "Adult",         "flag"),
    "stripchat.com":        ("Adult",    "Adult",         "flag"),
    "cam4.com":             ("Adult",    "Adult",         "flag"),
    "myfreecams.com":       ("Adult",    "Adult",         "flag"),

    # ── Gambling ──────────────────────────────
    "bet365.com":           ("Gambling", "Bet365",        "flag"),
    "draftkings.com":       ("Gambling", "DraftKings",    "flag"),
    "fanduel.com":          ("Gambling", "FanDuel",       "flag"),
    "pokerstars.com":       ("Gambling", "PokerStars",    "flag"),
    "caesars.com":          ("Gambling", "Caesars",       "flag"),
    "mgmresorts.com":       ("Gambling", "MGM",           "flag"),
    "betway.com":           ("Gambling", "Betway",        "flag"),
    "ladbrokes.com":        ("Gambling", "Ladbrokes",     "flag"),

    # ── Education ────────────────────────────
    "khanacademy.org":      ("Education","Khan Academy",  "ok"),
    "duolingo.com":         ("Education","Duolingo",      "ok"),
    "quizlet.com":          ("Education","Quizlet",       "ok"),
    "coursera.org":         ("Education","Coursera",      "ok"),
    "edx.org":              ("Education","edX",           "ok"),
    "udemy.com":            ("Education","Udemy",         "ok"),
    "chegg.com":            ("Education","Chegg",         "ok"),
    "wolframalpha.com":     ("Education","Wolfram Alpha", "ok"),
    "britannica.com":       ("Education","Britannica",    "ok"),
    "wikipedia.org":        ("Education","Wikipedia",     "ok"),
    "nationalgeographic.com":("Education","NatGeo",       "ok"),
    "ted.com":              ("Education","TED",           "ok"),
    "codecademy.com":       ("Education","Codecademy",    "ok"),
    "scratch.mit.edu":      ("Education","Scratch",       "ok"),
    "code.org":             ("Education","Code.org",      "ok"),

    # ── Streaming music ───────────────────────
    "spotify.com":          ("Music",    "Spotify",       "ok"),
    "scdn.co":              ("Music",    "Spotify",       "ok"),
    "pscdn.co":             ("Music",    "Spotify",       "ok"),
    "apple.com":            ("Music",    "Apple Music",   "ok"),
    "mzstatic.com":         ("Music",    "Apple Music",   "ok"),
    "pandora.com":          ("Music",    "Pandora",       "ok"),
    "soundcloud.com":       ("Music",    "SoundCloud",    "ok"),

    # ── Communication ────────────────────────
    "zoom.us":              ("Comms",    "Zoom",          "ok"),
    "zoom.com":             ("Comms",    "Zoom",          "ok"),
    "teams.microsoft.com":  ("Comms",    "Teams",         "ok"),
    "skype.com":            ("Comms",    "Skype",         "ok"),
    "facetime.apple.com":   ("Comms",    "FaceTime",      "ok"),
    "meet.google.com":      ("Comms",    "Google Meet",   "ok"),
    "googlemeet.com":       ("Comms",    "Google Meet",   "ok"),

    # ── Shopping ─────────────────────────────
    "amazon.com":           ("Shopping", "Amazon",        "ok"),
    "ebay.com":             ("Shopping", "eBay",          "ok"),
    "etsy.com":             ("Shopping", "Etsy",          "ok"),
    "shopify.com":          ("Shopping", "Shopify",       "ok"),
    "walmart.com":          ("Shopping", "Walmart",       "ok"),
}

# Category display colors for CLI output (ANSI)
CATEGORY_COLORS = {
    "Video":     "\033[0;36m",    # cyan
    "Social":    "\033[0;35m",    # purple
    "Gaming":    "\033[0;33m",    # amber
    "Adult":     "\033[0;31m",    # red
    "Gambling":  "\033[0;31m",    # red
    "Education": "\033[0;32m",    # green
    "Music":     "\033[0;34m",    # blue
    "Comms":     "\033[2m",       # dim
    "Shopping":  "\033[2m",       # dim
    "Other":     "\033[2m",       # dim
}
RST = "\033[0m"


# ─────────────────────────────────────────────
#  Domain matcher
# ─────────────────────────────────────────────
def match_domain(domain: str) -> tuple:
    """
    Match a domain to (category, service, flag).
    Returns ("Other", domain, "ok") if no match.
    """
    if not domain:
        return ("Other", domain, "ok")
    d = domain.lower().rstrip(".")
    # exact match
    if d in SERVICE_DB:
        return SERVICE_DB[d]
    # suffix match — check if domain ends with any key
    for key, val in SERVICE_DB.items():
        if d.endswith("." + key) or d == key:
            return val
    return ("Other", d, "ok")


# ─────────────────────────────────────────────
#  Config
# ─────────────────────────────────────────────
DEFAULT_TRAFF_CONFIG = {
    "enabled": True,
    "interface": "auto",          # auto-detect or set e.g. "eno1"
    "watched_devices": {},        # MAC → { "label": "Kid's iPad", "limits": { "Gaming": 60, "Video": 90 } }
    "alert_on_flag": True,        # immediately alert on Adult/Gambling
    "alert_on_limit": True,       # alert when a time limit is hit
    "daily_summary_hour": 21,     # send summary at 9pm
    "summary_enabled": True,
    "cooldown_minutes": 15,       # min gap between repeat alerts for same device+category
}

def load_traff_config() -> dict:
    if not TRAFF_CFG_FILE.exists():
        save_json(TRAFF_CFG_FILE, DEFAULT_TRAFF_CONFIG)
        return DEFAULT_TRAFF_CONFIG.copy()
    with open(TRAFF_CFG_FILE) as f:
        cfg = json.load(f)
    return {**DEFAULT_TRAFF_CONFIG, **cfg}

def load_main_config() -> dict:
    if not CONFIG_FILE.exists():
        return {}
    with open(CONFIG_FILE) as f:
        return json.load(f)

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)

def load_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


# ─────────────────────────────────────────────
#  Device label lookup
# ─────────────────────────────────────────────
# IP → label cache (refreshed from known_devices.json periodically)
_ip_label_cache = {}
_ip_cache_time = 0

def get_device_label(ip: str) -> str:
    global _ip_label_cache, _ip_cache_time
    now = time.time()
    if now - _ip_cache_time > 30:
        devices = load_json(DEVICES_FILE, {})
        _ip_label_cache = {}
        for mac, d in devices.items():
            ip_d = d.get("ip", "")
            label = d.get("label") or d.get("hostname") or mac
            if ip_d:
                _ip_label_cache[ip_d] = label
        _ip_cache_time = now
    return _ip_label_cache.get(ip, ip)


# ─────────────────────────────────────────────
#  Activity log
# ─────────────────────────────────────────────
# Structure: { date: { ip: { category: { service: count } } } }

def load_activity() -> dict:
    return load_json(ACTIVITY_FILE, {})

def save_activity(activity: dict):
    save_json(ACTIVITY_FILE, activity)

def record_activity(activity: dict, ip: str, category: str, service: str):
    today = date.today().isoformat()
    activity.setdefault(today, {})
    activity[today].setdefault(ip, {})
    activity[today][ip].setdefault(category, {})
    activity[today][ip][category][service] = (
        activity[today][ip][category].get(service, 0) + 1
    )

def get_today_minutes(activity: dict, ip: str, category: str) -> float:
    """
    Estimate minutes spent on a category today.
    Each DNS hit ≈ 1 query per ~30 seconds of activity → count / 2 = minutes.
    """
    today = date.today().isoformat()
    cats = activity.get(today, {}).get(ip, {}).get(category, {})
    total_hits = sum(cats.values())
    return total_hits / 2.0   # 1 DNS query ≈ 30s of activity → /2 = minutes


# ─────────────────────────────────────────────
#  Telegram alerts
# ─────────────────────────────────────────────
def send_telegram(token: str, chat_id: str, message: str):
    url  = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id":    chat_id,
        "text":       message,
        "parse_mode": "HTML"
    }).encode()
    try:
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception as e:
        log.error("Telegram send failed: %s", e)


# ─────────────────────────────────────────────
#  Network interface auto-detect
# ─────────────────────────────────────────────
def detect_interface() -> str:
    """Find the active non-loopback interface."""
    try:
        result = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"],
            capture_output=True, text=True, timeout=5
        )
        m = re.search(r"dev\s+(\S+)", result.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    try:
        result = subprocess.run(
            ["ip", "link", "show", "up"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            m = re.match(r"\d+:\s+(\w+):", line)
            if m and m.group(1) not in ("lo", "sit0"):
                return m.group(1)
    except Exception:
        pass
    return "eth0"


# ─────────────────────────────────────────────
#  Main monitor class
# ─────────────────────────────────────────────
class TraffWatch:
    def __init__(self):
        self.tcfg       = load_traff_config()
        self.mcfg       = load_main_config()
        self.activity   = load_activity()
        self.running    = False
        self._lock      = threading.Lock()
        self._last_alert: dict = {}   # (ip, category) → timestamp of last alert
        self._last_save = time.time()
        self._last_summary_date = None
        self._hit_count = 0           # domain observations since last heartbeat

        iface = self.tcfg.get("interface", "auto")
        self.interface = detect_interface() if iface == "auto" else iface
        log.info("Using interface: %s", self.interface)

    # ── tshark runners ────────────────────────
    def _run_dns_sniffer(self):
        """Sniff DNS queries (UDP port 53) and yield (src_ip, domain)."""
        cmd = [
            "tshark", "-i", self.interface,
            "-f", "udp port 53",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "dns.qry.name",
            "-e", "dns.flags.response",
            "-l", "-q"
        ]
        log.info("Starting DNS sniffer on %s ...", self.interface)
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1
            )
            for line in proc.stdout:
                if not self.running:
                    break
                parts = line.strip().split("\t")
                if len(parts) < 3:
                    continue
                src_ip, domain, is_response = parts[0], parts[1], parts[2]
                # Only process queries (not responses) to avoid double-counting
                if is_response == "0" and domain:
                    self._handle_domain(src_ip, domain)
            proc.wait()
        except FileNotFoundError:
            log.error("tshark not found. Install: sudo pacman -S wireshark-cli")
        except Exception as e:
            log.error("DNS sniffer error: %s", e)

    def _run_sni_sniffer(self):
        """Sniff TLS SNI from port 443 and yield (src_ip, hostname)."""
        cmd = [
            "tshark", "-i", self.interface,
            "-f", "tcp port 443",
            "-Y", "tls.handshake.type == 1",
            "-T", "fields",
            "-e", "ip.src",
            "-e", "tls.handshake.extensions_server_name",
            "-l", "-q"
        ]
        log.info("Starting SNI sniffer on %s ...", self.interface)
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1
            )
            for line in proc.stdout:
                if not self.running:
                    break
                parts = line.strip().split("\t")
                if len(parts) >= 2:
                    src_ip, hostname = parts[0], parts[1]
                    if hostname:
                        self._handle_domain(src_ip, hostname)
            proc.wait()
        except FileNotFoundError:
            log.error("tshark not found.")
        except Exception as e:
            log.error("SNI sniffer error: %s", e)

    # ── Domain handler ────────────────────────
    def _handle_domain(self, src_ip: str, domain: str):
        with self._lock:
            self._hit_count += 1

        category, service, flag = match_domain(domain)

        if category == "Other":
            return   # skip unrecognised domains for performance

        with self._lock:
            record_activity(self.activity, src_ip, category, service)

        label = get_device_label(src_ip)
        tg    = self.mcfg.get("alert", {}).get("telegram", {})

        # Emit structured log line for live dashboard
        if category != "Other":
            log.info("%s → %s (%s) %s", src_ip, service, category, domain)
        if flag == "flag" and self.tcfg.get("alert_on_flag"):
            alert_key = (src_ip, category, service)
            now = time.time()
            last = self._last_alert.get(alert_key, 0)
            cooldown = self.tcfg.get("cooldown_minutes", 15) * 60
            if now - last > cooldown:
                self._last_alert[alert_key] = now
                msg = (
                    f"🚨 <b>⚠️ Blocked content accessed!</b>\n\n"
                    f"<b>Device:</b> {label} ({src_ip})\n"
                    f"<b>Category:</b> {category}\n"
                    f"<b>Service:</b> {service}\n"
                    f"<b>Domain:</b> {domain}\n"
                    f"<b>Time:</b> {datetime.now().strftime('%H:%M:%S')}"
                )
                log.warning("FLAG: %s → %s (%s)", label, service, domain)
                if tg.get("enabled") and tg.get("bot_token"):
                    send_telegram(tg["bot_token"], tg["chat_id"], msg)

        # Time limit check
        elif flag == "watch" and self.tcfg.get("alert_on_limit"):
            self._check_limits(src_ip, label, category, service, tg)

        # Periodic save
        now = time.time()
        if now - self._last_save > 60:
            with self._lock:
                save_activity(self.activity)
            self._last_save = now

    def _check_limits(self, ip, label, category, service, tg):
        """Check if this device has exceeded its time limit for a category."""
        watched = self.tcfg.get("watched_devices", {})

        # Find this device's config by IP
        device_cfg = None
        devices = load_json(DEVICES_FILE, {})
        for mac, d in devices.items():
            if d.get("ip") == ip:
                mac_key = mac
                device_cfg = watched.get(mac)
                break

        if not device_cfg:
            return

        limits = device_cfg.get("limits", {})
        limit_mins = limits.get(category)
        if not limit_mins:
            return

        with self._lock:
            used_mins = get_today_minutes(self.activity, ip, category)

        if used_mins >= limit_mins:
            alert_key = (ip, category + "_limit")
            now = time.time()
            last = self._last_alert.get(alert_key, 0)
            cooldown = self.tcfg.get("cooldown_minutes", 15) * 60
            if now - last > cooldown:
                self._last_alert[alert_key] = now
                msg = (
                    f"⏰ <b>Time limit reached!</b>\n\n"
                    f"<b>Device:</b> {label} ({ip})\n"
                    f"<b>Category:</b> {category}\n"
                    f"<b>Currently on:</b> {service}\n"
                    f"<b>Time used today:</b> ~{int(used_mins)} min\n"
                    f"<b>Limit:</b> {limit_mins} min\n"
                    f"<b>Time:</b> {datetime.now().strftime('%H:%M:%S')}"
                )
                log.warning("LIMIT: %s hit %s limit (%d/%d min)",
                            label, category, int(used_mins), limit_mins)
                if tg.get("enabled") and tg.get("bot_token"):
                    send_telegram(tg["bot_token"], tg["chat_id"], msg)

    # ── Heartbeat ─────────────────────────────
    def _heartbeat_loop(self):
        """Log a periodic line so a quiet-but-alive sniffer looks different
        in the log from a sniffer that has stopped seeing any packets."""
        while self.running:
            time.sleep(300)
            with self._lock:
                n = self._hit_count
                self._hit_count = 0
            log.info("[HEARTBEAT] %d domain hits in last 5 min", n)

    # ── Daily summary ────────────────────────
    def _summary_loop(self):
        """Send a daily activity summary at the configured hour."""
        while self.running:
            now = datetime.now()
            target_hour = self.tcfg.get("daily_summary_hour", 21)
            if (now.hour == target_hour and
                    now.date().isoformat() != self._last_summary_date and
                    self.tcfg.get("summary_enabled")):
                self._send_daily_summary()
                self._last_summary_date = now.date().isoformat()
            time.sleep(60)

    def _send_daily_summary(self):
        tg    = self.mcfg.get("alert", {}).get("telegram", {})
        today = date.today().isoformat()

        with self._lock:
            day_data = self.activity.get(today, {})

        if not day_data:
            return

        devices = load_json(DEVICES_FILE, {})
        ip_to_label = {d.get("ip"): d.get("label") or d.get("hostname") or mac
                       for mac, d in devices.items()}

        lines = [f"📊 <b>Daily Activity Report — {today}</b>\n"]
        for ip, cats in day_data.items():
            label = ip_to_label.get(ip, ip)
            lines.append(f"\n<b>{label}</b>")
            for cat, services in sorted(cats.items()):
                total_hits = sum(services.values())
                est_mins   = int(total_hits / 2)
                top_svc    = max(services, key=services.get)
                lines.append(f"  {cat}: ~{est_mins} min  (mainly {top_svc})")

        msg = "\n".join(lines)
        log.info("Sending daily summary.")
        if tg.get("enabled") and tg.get("bot_token"):
            send_telegram(tg["bot_token"], tg["chat_id"], msg)

    # ── Start / stop ──────────────────────────
    def start(self):
        if os.geteuid() != 0:
            log.error("Must run as root for packet capture.")
            sys.exit(1)

        self.running = True
        self.mcfg    = load_main_config()
        self.tcfg    = load_traff_config()

        threads = [
            threading.Thread(target=self._run_dns_sniffer, daemon=True),
            threading.Thread(target=self._run_sni_sniffer, daemon=True),
            threading.Thread(target=self._summary_loop,    daemon=True),
            threading.Thread(target=self._heartbeat_loop,  daemon=True),
        ]
        for t in threads:
            t.start()

        log.info("TraffWatch running — monitoring %s", self.interface)

        while self.running:
            time.sleep(5)

        save_activity(self.activity)
        log.info("TraffWatch stopped.")

    def stop(self):
        self.running = False


# ─────────────────────────────────────────────
#  Graceful shutdown
# ─────────────────────────────────────────────
_monitor = None

def handle_signal(sig, frame):
    global _monitor
    log.info("Signal %d received — shutting down.", sig)
    if _monitor:
        _monitor.stop()

signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT,  handle_signal)


# ─────────────────────────────────────────────
#  Entry point
# ─────────────────────────────────────────────
def main():
    global _monitor
    setup_logging()
    log.info("TraffWatch starting ...")
    _monitor = TraffWatch()
    _monitor.start()


if __name__ == "__main__":
    main()
