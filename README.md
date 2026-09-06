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

A lightweight 24/7 network monitoring suite built for an always-on Arch Linux hub.
Three daemons, one `netwatch` CLI:

- **NetWatch** — scans your LAN with Nmap, detects new/unknown devices
- **TraffWatch** — sniffs DNS/TLS SNI to see what each device is doing, enforces time limits
- **ThreatWatch** — runs Suricata IDS + VirusTotal lookups on intercepted traffic

All three fire real-time alerts via **Telegram**.

---

## What it does

**NetWatch (device discovery)**
- Scans your home LAN continuously using Nmap
- Detects any new device that connects to your network within 60 seconds
- Identifies devices by **MAC address** — so even DHCP IP changes don't fool it
- Runs a **smart OS detection engine** using MAC OUI lookup, hostname patterns,
  vendor strings, and nmap fingerprinting to guess what kind of device joined
- Sends an instant **Telegram alert** to your phone with device details
- Stores a persistent registry of all known devices with labels you assign

**TraffWatch (traffic visibility)**
- Passively sniffs DNS queries and TLS SNI via `tshark` — no per-app agent needed
- Classifies traffic into categories (Video, Gaming, Social, Adult, Gambling, ...)
- Tracks per-device daily usage and lets you set time limits (`traffic-watch <MAC> Gaming 60`)
- Alerts on Telegram when a device hits its limit or visits a flagged category

**ThreatWatch (intrusion detection)**
- Runs **Suricata** (ETOpen ruleset) against LAN traffic for known-bad signatures
- Enriches suspicious destination IPs via the **VirusTotal** API (cached, rate-limited)
- Alerts on Telegram for high/critical severity hits, with a live threat dashboard

**DNS interception (what makes TraffWatch/ThreatWatch see anything)**
- ARP-spoofs the LAN so the hub sits in the traffic path, redirects DNS to itself
- Blocks DNS-over-HTTPS/TLS (Cloudflare, Google, Quad9, AdGuard) so devices can't
  bypass interception via encrypted DNS
- Reversible with one script; a healthcheck timer self-heals if the MITM path drops

All daemons run as **systemd services** — start on boot, restart on failure, run 24/7 —
and are managed entirely through the `netwatch` root command.

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
~/netwatch-files/                 ← your source directory
├── netwatch                      ← the CLI tool (installed to /usr/local/bin)
├── network_monitor.py            ← NetWatch daemon (device discovery)
├── traffic_monitor.py            ← TraffWatch daemon (traffic classification)
├── threat_monitor.py             ← ThreatWatch daemon (Suricata → VT → Telegram)
├── config.json                   ← configuration template
├── dns_intercept.sh              ← starts ARP spoof + DNS redirect + DoH/DoT block
├── dns_unintercept.sh            ← reverts dns_intercept.sh
├── netwatch_healthcheck.sh       ← verifies the MITM path is actually up, self-heals
├── fix-new-router.sh             ← re-detects subnet/gateway after a router swap
├── dnsmasq.conf                  ← DNS server config the hub runs once interception is on
├── netwatch.service              ← systemd unit — NetWatch
├── traffwatch.service            ← systemd unit — TraffWatch
├── threatwatch.service           ← systemd unit — ThreatWatch
├── netwatch-healthcheck.service / .timer   ← runs netwatch_healthcheck.sh every 5 min
├── suricata/                     ← Suricata config templates + systemd/logrotate units
├── test_threat_monitor.py        ← unit tests for threat_monitor.py
└── README.md                     ← this file

/opt/netwatch/                    ← installation directory (live)
├── network_monitor.py / traffic_monitor.py / threat_monitor.py   ← daemon copies
├── config.json                   ← your live configuration
├── known_devices.json            ← device registry (auto-created on first scan)
├── scan_history.json             ← last 100 scans
├── activity_log.json / traffic_config.json   ← TraffWatch state + time limits
├── vt_cache.json                 ← VirusTotal lookup cache
└── *.log                         ← local log files

/home/suricata-logs/eve.json      ← Suricata's alert feed (read by ThreatWatch)
/home/threatwatch/threats_log.jsonl   ← ThreatWatch's own alert log

/usr/local/bin/netwatch           ← CLI (makes `netwatch` work from anywhere)
/etc/systemd/system/{netwatch,traffwatch,threatwatch}.service   ← systemd units
```

---

## Requirements

**NetWatch (core)**
- Arch Linux (or any systemd-based Linux distro)
- Python 3.8+
- Nmap — `sudo pacman -S nmap`
- Root access (nmap needs raw sockets for MAC detection)
- A Telegram bot — optional but strongly recommended

**TraffWatch (optional)**
- `tshark` — `sudo pacman -S wireshark-cli` (installed automatically by `traffic-install`)

**ThreatWatch (optional)**
- `suricata`, `suricata-update`, `logrotate`
- A free [VirusTotal](https://www.virustotal.com/) API key (500 lookups/day)

**DNS interception (needed for TraffWatch/ThreatWatch to see anything)**
- `nftables`, `dsniff` (for `arpspoof`), `dnsmasq`
- Runs the hub as a MITM for the LAN — see [Security notes](#security-notes)
  before enabling it.

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

### 5. (Optional) Enable DNS interception

TraffWatch and ThreatWatch can only see traffic that passes through the hub.
Run this on the hub to ARP-spoof the LAN and redirect DNS to itself, and set
up `dnsmasq` (`dnsmasq.conf`) as the local resolver first:

```bash
sudo cp dnsmasq.conf /etc/dnsmasq.conf   # edit `interface=` to match your hub's iface
sudo systemctl enable --now dnsmasq
sudo cp dns_intercept.sh dns_unintercept.sh netwatch_healthcheck.sh /opt/netwatch/
sudo /opt/netwatch/dns_intercept.sh
```

To revert at any time: `sudo /opt/netwatch/dns_unintercept.sh`.
Optionally install the healthcheck timer so the MITM path self-heals if
`arpspoof` dies or the router changes:

```bash
sudo cp netwatch-healthcheck.service netwatch-healthcheck.timer /etc/systemd/system/
sudo systemctl enable --now netwatch-healthcheck.timer
```

If you swap routers later, re-run `sudo bash fix-new-router.sh` to
re-detect the subnet/gateway and merge your device history forward.

### 6. (Optional) Install TraffWatch

```bash
sudo netwatch traffic-install
sudo netwatch traffic-start
sudo netwatch traffic-watch <MAC> Gaming 60   # alert after 60 min/day
netwatch traffic-live                          # see what's happening now
```

### 7. (Optional) Install ThreatWatch

```bash
sudo nano /opt/netwatch/config.json   # set threatwatch.virustotal_api_key
sudo netwatch threat-install
netwatch threats-status
```

`threat-install` auto-detects your interface/subnet, installs Suricata with
the ETOpen ruleset, and enables the `suricata`, `suricata-update.timer`,
`logrotate.timer`, and `threatwatch` services.

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
  },

  "threatwatch": {
    "virustotal_api_key": "",
    "severity_threshold": 2,
    "alert_cooldown_minutes": 5,
    "vt_cache_ttl_hours": 24
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
| `threatwatch.virustotal_api_key` | `""` | Your VirusTotal API key (required for `threats-lookup` + enrichment) |
| `threatwatch.severity_threshold` | `2` | Alert on Suricata severity `<=` this (1=critical, 2=high) |
| `threatwatch.alert_cooldown_minutes` | `5` | Minimum gap between repeat Telegram alerts for the same signature/dest |
| `threatwatch.vt_cache_ttl_hours` | `24` | How long a VirusTotal result is cached before re-querying |

TraffWatch's own settings (time limits, watched categories) live separately
in `/opt/netwatch/traffic_config.json`, managed via `netwatch traffic-watch` /
`traffic-unwatch` rather than hand-edited.

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

### TraffWatch

| Command | Root | Description |
|---------|------|--------------|
| `sudo netwatch traffic-install` | ✅ | Install `tshark` + the TraffWatch service |
| `sudo netwatch traffic-start` / `-stop` / `-restart` | ✅ | Service control |
| `netwatch traffic` | — | Today's activity for all devices |
| `netwatch traffic-live` | — | Live dashboard — what each device is doing now |
| `netwatch traffic-activity <MAC> [-d days]` | — | Activity history for one device |
| `netwatch traffic-limits` | — | Show all configured time limits |
| `sudo netwatch traffic-watch <MAC> <Category> <mins>` | ✅ | Set a daily time limit (e.g. `Gaming 60`) |
| `sudo netwatch traffic-unwatch <MAC> [Category]` | ✅ | Remove a time limit |
| `netwatch traffic-logs [-f] [-n N]` | — | TraffWatch service logs |

### ThreatWatch

| Command | Root | Description |
|---------|------|--------------|
| `sudo netwatch threat-install` | ✅ | Install Suricata + the ThreatWatch service |
| `netwatch threats` | — | Today's threat summary (top targets/signatures/categories) |
| `netwatch threats-live` | — | Live threat dashboard |
| `netwatch threats-history [-n days]` | — | Threats grouped by day |
| `netwatch threats-lookup <IP>` | — | Manually query VirusTotal for an IP |
| `netwatch threats-status` | — | Suricata/ThreatWatch health, rule count, VT quota |

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

- Your Telegram bot token and VirusTotal API key give real access — never commit
  `config.json` to a public repository. Add it to `.gitignore`.
- `known_devices.json` contains MAC addresses of every device on your network.
  Treat it as sensitive — store it only on the hub.
- NetWatch's device scanner is **read-only**. It does not block, throttle, or
  modify traffic on its own.
- DNS interception (`dns_intercept.sh`) is **not** read-only: it ARP-spoofs the
  entire LAN so the hub becomes a man-in-the-middle for every device's traffic,
  redirects their DNS to the hub, and drops outbound DoH/DoT to keep them from
  bypassing it. This is the only way TraffWatch/ThreatWatch can see traffic —
  only enable it on a network you own and control, and only for family devices
  you have the right to monitor. `sudo /opt/netwatch/dns_unintercept.sh` reverts
  it instantly.
- The systemd services run as root. This is required for nmap raw sockets,
  ARP spoofing, and packet capture, and is standard for network daemons on
  home lab systems.

---

*Built for the Speed hub — Arch Linux · Syncthing · OpenClaw · NetWatch*
---
*Built and Design by — Ruthvik Kanukuntla*

