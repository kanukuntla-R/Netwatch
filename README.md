# NetWatch — Home Network Monitor

```
  ███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
  ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     ███████║
  ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
  ██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝

  Home Network Monitor — Arch Linux Hub
```

A lightweight 24/7 network monitoring daemon built for an always-on Arch Linux hub.
Uses **Nmap** to scan your LAN every 60 seconds, detects new and unknown devices
instantly, and fires real-time alerts via **Telegram** — all manageable through
a clean `netwatch` CLI.

---

## What it does

- Scans your home LAN continuously using Nmap
- Detects any new device that connects to your network within 60 seconds
- Identifies devices by **MAC address** — so even DHCP IP changes don't fool it
- Runs a **smart OS detection engine** using MAC OUI lookup, hostname patterns,
  vendor strings, and nmap fingerprinting to guess what kind of device joined
- Sends an instant **Telegram alert** to your phone with device details
- Stores a persistent registry of all known devices with labels you assign
- Runs as a **systemd service** — starts on boot, restarts on failure, runs 24/7
- Managed entirely through the `netwatch` root command

---

## How it works

```
Every 60 seconds
      │
      ▼
  nmap -sn -T4 192.168.1.0/24
      │
      ▼
  Parse: IP, MAC, Hostname, Vendor
      │
      ▼
  Smart OS detection engine
  ┌──────────────────────────────────────┐
  │  1. MAC OUI lookup (500+ vendors)    │
  │  2. Hostname pattern matching        │
  │  3. Vendor string heuristics         │
  │  4. nmap OS fingerprint              │
  │  5. Randomized MAC detection         │
  └──────────────────────────────────────┘
      │
      ▼
  Compare against known_devices.json
      │
      ├── Known device → update last_seen, silent
      │
      └── NEW device → ALERT TRIGGERED
                            │
                            ├── Telegram message (instant, to your phone)
                            ├── HTTP webhook POST (Home Assistant, Node-RED, OpenClaw)
                            ├── Local log entry (always on)
                            └── Desktop notify-send (optional)
```

The MAC address is the unique device ID. If a device changes its IP via DHCP,
it is still recognized as the same device. Randomized/private MACs (used by
iPhones and Android phones for privacy) are detected and flagged in alerts.

---

## Project structure

```
~/netwatch-files/            ← your source directory
├── network_monitor.py       ← the daemon (runs 24/7 as a systemd service)
├── netwatch                 ← the CLI tool (installed to /usr/local/bin)
├── config.json              ← configuration template
├── netwatch.service         ← systemd unit file
└── README.md                ← this file

/opt/netwatch/               ← installation directory (live)
├── network_monitor.py       ← daemon copy
├── config.json              ← your live configuration
├── known_devices.json       ← device registry (auto-created on first scan)
├── scan_history.json        ← last 100 scans
└── netwatch.log             ← local log file

/usr/local/bin/netwatch      ← CLI (makes `netwatch` work from anywhere)
/etc/systemd/system/netwatch.service   ← systemd unit
```

---

## Requirements

- Arch Linux (or any systemd-based Linux distro)
- Python 3.8+
- Nmap — `sudo pacman -S nmap`
- Root access (nmap needs raw sockets for MAC detection)
- A Telegram bot — optional but strongly recommended

---

## Installation

### 1. Find your subnet

```bash
ip route | grep "proto kernel"
# 192.168.1.0/24 dev eno1 proto kernel scope link src 192.168.1.47
#  ↑ this is your network_range
```

### 2. Install

```bash
cd ~/netwatch-files
sudo python3 netwatch install
```

This checks dependencies, copies files to `/opt/netwatch/`, installs the
`netwatch` CLI to `/usr/local/bin/`, and enables the systemd service.

### 3. Configure

```bash
sudo nano /opt/netwatch/config.json
```

Set your `network_range`. Then scan once to find existing devices:

```bash
sudo netwatch scan
```

Add your family's MACs to `trusted_macs` so they never trigger alerts.

### 4. Start

```bash
sudo netwatch start
netwatch status
netwatch logs -f
```

---

## Configuration reference

`/opt/netwatch/config.json`

```json
{
  "network_range": "192.168.1.0/24",
  "scan_interval_seconds": 60,
  "nmap_flags": "-sn -T4",
  "scan_on_start": true,
  "alert_on_reconnect": false,
  "log_level": "INFO",

  "trusted_macs": [
    "8C:13:E2:3A:71:85",
    "26:8D:B1:2F:EC:C2",
    "28:EA:2D:86:39:78"
  ],

  "alert": {
    "telegram": {
      "enabled": true,
      "bot_token": "YOUR_BOT_TOKEN",
      "chat_id": "YOUR_CHAT_ID"
    },
    "webhook": {
      "enabled": false,
      "url": "http://localhost:5000/netwatch-event",
      "secret_header": "my-secret-token"
    },
    "local_log": { "enabled": true },
    "desktop_notify": { "enabled": false }
  }
}
```

| Key | Default | Description |
|-----|---------|-------------|
| `network_range` | `192.168.1.0/24` | Your LAN subnet to scan |
| `scan_interval_seconds` | `60` | How often to scan (in seconds) |
| `nmap_flags` | `-sn -T4` | Nmap options (see below) |
| `trusted_macs` | `[]` | MACs that never trigger alerts |
| `scan_on_start` | `true` | Scan immediately when daemon starts |
| `alert_on_reconnect` | `false` | Alert when a known device rejoins |
| `log_level` | `INFO` | `DEBUG` / `INFO` / `WARNING` |

### Nmap flag guide

| Flag combo | Speed | OS detection | Use case |
|------------|-------|-------------|----------|
| `-sn -T4` | Fast (~8s) | No | ✅ Recommended for daily use |
| `-sS -O --osscan-guess` | Slow (~90s) | Yes | Better OS data, risk of timeout |

Stick with `-sn -T4`. The smart OS engine handles detection without needing `-O`.

After editing config, always restart to apply:
```bash
sudo netwatch restart
```

---

## Telegram setup

### Step 1 — Create your bot

Open Telegram → search `@BotFather` → send `/newbot` → follow prompts.
You'll get a token like `8637703839:AAGDQyqEU7NMh6_NOFjdF3ny1o3LrSnCWgI`.

### Step 2 — Get your chat ID

Message your new bot (just say "hi"), then open in a browser:
```
https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates
```

Find `"chat": { "id": 6413718066 }` — that number is your chat ID.

### Step 3 — Update config

```json
"telegram": {
  "enabled": true,
  "bot_token": "8637703839:AAGDQyqEU7NMh6...",
  "chat_id": "6413718066"
}
```

### Step 4 — Test

```bash
netwatch test-telegram
# Check your phone — bot should send a confirmation message
```

### What a Telegram alert looks like

```
🚨 New Device Detected! ⚠️ Privacy/randomized MAC

Name:       192.168.1.41
IP:         192.168.1.41
MAC:        42:F2:B8:32:83:79
Vendor:     Unknown

OS Guess:   iOS / macOS
Confidence: 🟡 medium
Signals:    Randomized/private MAC · nmap suggests: Apple macOS 11

Devices online: 7
Time: 2026-05-12 17:58:18
```

---

## Webhook integration

Enable webhook alerts to push device events to any HTTP endpoint — Home
Assistant, Node-RED, or your own OpenClaw service.

```json
"webhook": {
  "enabled": true,
  "url": "http://localhost:5000/netwatch-event",
  "secret_header": "my-secret-token"
}
```

NetWatch POSTs this JSON payload on every new device event:

```json
{
  "event": "new_device",
  "timestamp": "2026-05-12 17:58:18",
  "total_online": 7,
  "device": {
    "ip": "192.168.1.41",
    "mac": "42:F2:B8:32:83:79",
    "hostname": "",
    "vendor": "Unknown",
    "os_guess": "iOS / macOS",
    "os_confidence": "medium",
    "os_notes": ["Randomized/private MAC", "nmap suggests: Apple macOS 11"],
    "first_seen": "2026-05-12T17:58:18",
    "trusted": false,
    "label": ""
  }
}
```

The `X-NetWatch-Secret` header carries your `secret_header` value — use it
to authenticate incoming requests on your receiver.

---

## Smart OS detection engine

NetWatch runs a 5-layer detection pipeline on every new device instead of
relying solely on nmap's `-O` flag (which is slow and often blocked):

| Layer | Signal | Example |
|-------|--------|---------|
| 1 | MAC OUI prefix (500+ entries) | `28:EA:2D` → Apple → iOS |
| 2 | Hostname keyword match | `Ruthviks-iPhone.local` → iOS |
| 3 | Vendor string heuristic | `"Apple"` vendor → iOS / macOS |
| 4 | nmap OS fingerprint | `Apple macOS 11 (Big Sur)` |
| 5 | Randomized MAC flag | First byte bit 1 set → private MAC |

**Confidence levels in alerts:**

| Indicator | Meaning |
|-----------|---------|
| `🟢 high` | OUI or hostname matched definitively |
| `🟡 medium` | Vendor or nmap match; or randomized MAC downgraded confidence |
| `🔴 low` | No signals matched — truly unknown device |

Randomized/private MACs (iPhones, modern Android) are detected by checking
the locally-administered bit in the first MAC octet. A warning is added to
the Telegram alert and confidence is downgraded one level.

---

## Command reference

Commands marked **root** require `sudo`.

### Service control

| Command | Root | Description |
|---------|------|-------------|
| `sudo netwatch start` | ✅ | Start the daemon |
| `sudo netwatch stop` | ✅ | Stop the daemon |
| `sudo netwatch restart` | ✅ | Restart — applies config changes |

### Monitoring

| Command | Root | Description |
|---------|------|-------------|
| `netwatch status` | — | Service state + live device table |
| `netwatch devices` | — | Full device list with OS, label, online status |
| `sudo netwatch scan` | ✅ | Run a one-shot nmap scan right now |
| `netwatch logs` | — | Last 50 log lines |
| `netwatch logs -f` | — | Follow live logs (Ctrl+C to exit) |
| `netwatch logs -n 100` | — | Last 100 lines |
| `netwatch history` | — | Last 10 scan summaries |
| `netwatch history -n 20` | — | Last 20 scan summaries |

### Device management

| Command | Root | Description |
|---------|------|-------------|
| `sudo netwatch label <MAC> "<name>"` | ✅ | Label and trust a device |
| `sudo netwatch trust <MAC>` | ✅ | Add to trusted list (no alerts) |
| `sudo netwatch untrust <MAC>` | ✅ | Remove from trusted list |

### Config and alerts

| Command | Root | Description |
|---------|------|-------------|
| `netwatch config` | — | Show current config summary |
| `netwatch test-telegram` | — | Send a test Telegram message |

### Setup

| Command | Root | Description |
|---------|------|-------------|
| `sudo netwatch install` | ✅ | Full install from source directory |
| `sudo netwatch uninstall` | ✅ | Remove service and CLI (data preserved) |
| `netwatch help` | — | Full banner + command list |

---

## Labelling your devices

After the first scan, label all your known devices:

```bash
sudo netwatch label 8C:13:E2:3A:71:85 "Home Router"
sudo netwatch label 26:8D:B1:2F:EC:C2 "Ruthvik MacBook Pro"
sudo netwatch label 28:EA:2D:86:39:78 "Ruthvik iPhone"
sudo netwatch label C2:64:F2:C5:81:E4 "LG Smart TV"
sudo netwatch label BC:30:D9:68:5E:70 "LG Smart TV (alt MAC)"
sudo netwatch label CC:9E:A2:AA:17:1F "Amazon Echo"
sudo netwatch label 42:06:26:66:C1:08 "Ruthvik iPhone (privacy MAC)"
sudo netwatch label 4A:B5:D3:FE:AE:29 "Unknown - investigate"
```

Labelled + trusted devices appear in `netwatch status` with a `✓` marker
and will never trigger an alert. Unlabelled unknown devices show `?` and
will alert every time they join.

**Tip on randomized MACs:** iPhones and Android phones generate a new
random MAC per network for privacy. Once connected to your WiFi, the MAC
stays consistent on that network. Go to Settings → Wi-Fi → your network
name to see the actual MAC your phone is using on your network.

---

## Integration with your Arch hub

NetWatch runs alongside your other services with zero conflicts:

| Service | Type | Port |
|---------|------|------|
| Syncthing | file sync | TCP 8384, 22000 |
| OpenClaw | your service | your ports |
| NetWatch | outbound only | none |

NetWatch opens **no inbound ports**. All traffic is outbound: LAN nmap
scans and optional HTTPS calls to `api.telegram.org`.

To integrate with OpenClaw: enable the webhook alert pointing to your
OpenClaw HTTP listener. Every new device event will POST full device
details — your service can act on them however you want.

---

## Troubleshooting

**No MAC addresses in scan output**
→ Must run as root. Non-root nmap cannot read ARP responses from remote hosts.

**`nmap scan timed out` in logs**
→ Your nmap flags are too slow for the scan interval.
  Use `-sn -T4` in config and `sudo netwatch restart`.

**All devices showing as NEW on every restart**
→ `known_devices.json` was deleted or reset. Normal on fresh install —
  the daemon learns all devices on the first scan and only alerts on new ones going forward.

**Telegram alert not arriving**
→ You must message your bot at least once before it can send to you.
  Then run `netwatch test-telegram` to verify.

**Unknown device keeps appearing with randomized MAC**
→ A family member's phone or laptop using MAC privacy mode.
  Check their Wi-Fi settings for your network name — the private/randomized
  MAC is shown there. Label it: `sudo netwatch label <MAC> "Name"`.

**Wrong subnet being scanned**
→ Run `ip route | grep "proto kernel"` to confirm your subnet.
  Update `network_range` in config and restart.

**`netwatch: command not found`**
→ CLI not installed to PATH. Run:
  `sudo cp netwatch /usr/local/bin/netwatch && sudo chmod +x /usr/local/bin/netwatch`

**Service not starting after reboot**
→ Check it's enabled: `systemctl is-enabled netwatch`
  If not: `sudo systemctl enable netwatch`

---

## Security notes

- Your Telegram bot token gives full bot control. Never commit `config.json`
  to a public repository. Add it to `.gitignore`.
- `known_devices.json` contains MAC addresses of every device on your network.
  Treat it as sensitive — store it only on the hub.
- NetWatch is a **read-only monitoring tool**. It does not block, throttle,
  or modify any network traffic.
- The systemd service runs as root. This is required for nmap raw sockets
  and is standard for network daemons on home lab systems.

---

*Built for the Speed hub — Arch Linux · Syncthing · OpenClaw · NetWatch*
---
*Built and Design by — Ruthvik Kanukuntla*

