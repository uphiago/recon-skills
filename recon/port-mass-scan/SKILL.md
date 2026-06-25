---
name: port-mass-scan
description: Port scan /8-/24 with Masscan+RustScan and nmap banners.
version: 1.0.0
author: agentiko
license: MIT
platforms: [linux]
compatibility: Requires agentiko worker (curl, nmap, python3, masscan, subfinder, httpx, nuclei)
metadata:
  hermes:
    tags: [recon, port-scan, masscan, rustscan, nmap, infrastructure]
    category: recon
    related_skills:
      - port-service-discovery
      - iot-camera-recon
      - exchange-owa-attack
---

# Port Mass Scan Skill

High-speed port scanning methodology using RustScan for single hosts and Masscan for large IP ranges. RustScan provides 400x speedup over Nmap for 1000-port scans (3-10s vs 5-10min). Masscan handles /8 and /16 ranges that Nmap cannot. Battle-tested on 5000+ scans across Brazilian ISPs, PRODERJ government networks, and OVH cloud infrastructure.

## When to Use

- Scanning a /24 or larger IP range (Masscan territory — Nmap would take days).
- Fast single-host port discovery before Nmap service enumeration.
- Hunting for specific services across ISP blocks (RTSP cameras, MySQL, Redis, SSH).
- After `subdomain-enumeration` — scan resolved IPs for non-HTTP services.
- After `deep-invade` — expand attack surface beyond web ports.

## Prerequisites

- `terminal` tool with masscan, rustscan, and nmap installed.
- For Masscan: root access (uses raw sockets), libpcap.
- For RustScan: nmap must be installed (for service enumeration pass-through).

## How to Run

```bash
# Single host — RustScan (3-10 seconds for 1000 ports)
rustscan -a TARGET -r 1-65535 -- -sV

# /24 range — Masscan (2-5 minutes)
masscan -p1-65535 --rate=10000 -iL targets.txt -oJ scan.json

# /8 range — Masscan with banner grab (hours)
masscan -p80,443,8080,8443,22,3306,6379 --rate=50000 --banners -iL /8_range.txt -oJ scan.json
```

## Quick Reference

| Scenario | Tool | Command | Time |
|----------|------|---------|------|
| Single host, all ports | RustScan | `rustscan -a IP -r 1-65535` | 3-10s |
| /24 range, common ports | Masscan | `masscan -p1-1000 --rate=10000 -iL /24.txt` | 2-5 min |
| /16 range, web ports | Masscan | `masscan -p80,443,8080,8443 --rate=50000 -iL /16.txt` | 10-30 min |
| /8 camera hunt | Masscan | `masscan -p554,80,8010 --rate=100000 -iL /8.txt` | Hours |
| Banner grab (1 IP) | Masscan | `masscan -p1-65535 --banners --source-ip ETH0_IP IP` | 1-5 min |

### Performance Comparison (empirical, 5000+ scans)

| Tool | 1000 ports (1 host) | /24 (1000 ports each) | /8 (web ports) | Accuracy |
|------|--------------------|-----------------------|-----------------|--------|
| Nmap | 5-10 min | ~30 min | Impossible (days) | 99% |
| RustScan | 3-10s | 15-30s | ~2 min | 98% (then Nmap -sV) |
| Masscan | 15-20s | 2-5 min | 30-60 min | 99% (TCP) |

## Procedure

### RustScan — Single Host Fast Discovery

```bash
TARGET="$1"
OUTDIR="/root/output/ports"
mkdir -p "$OUTDIR"

echo "[*] RustScan: all 65535 ports on $TARGET"

# Fast scan + auto Nmap service detection
rustscan -a "$TARGET" -r 1-65535 -b 500 --accessible -- -sV -oN "$OUTDIR/${TARGET}_rustscan.nmap"

echo "[*] Open ports:"
grep 'open' "$OUTDIR/${TARGET}_rustscan.nmap" || echo "  None"

# For WAF/IDS evasion: slower batch size
rustscan -a "$TARGET" -r 1-65535 -b 100 -t 1500 -- -sV
```

### Masscan — Large Range Scanning

```bash
RANGE_FILE="$1"      # One IP or CIDR per line
OUTDIR="/root/output/ports"
mkdir -p "$OUTDIR"

# Step 1: Fast common ports scan
echo "[*] Masscan: common ports on $(wc -l < "$RANGE_FILE") targets"
masscan -p80,443,22,3306,6379,27017,8080,8443,554,21,25,5432,3389 \
  --rate=10000 -iL "$RANGE_FILE" -oJ "$OUTDIR/masscan_common.json" --wait=10

# Step 2: Full port scan on targets with hits
grep -oP '"ip":"[^"]+"' "$OUTDIR/masscan_common.json" | sort -u | \
  sed 's/"ip":"//;s/"//' > "$OUTDIR/hits.txt"

echo "[*] Full scan on $(wc -l < "$OUTDIR/hits.txt") targets with open ports"
masscan -p1-65535 --rate=5000 -iL "$OUTDIR/hits.txt" \
  -oJ "$OUTDIR/masscan_full.json" --wait=30
```

### Masscan — Banner Grabbing (service identification)

```bash
TARGET="$1"
OUTDIR="/root/output/ports"

# Banner grabbing requires a separate IP for the TCP handshake
SOURCE_IP=$(hostname -I | awk '{print $1}')
echo "[*] Masscan banner grab from source IP: $SOURCE_IP"

masscan -p1-10000 --rate=5000 --banners --source-ip "$SOURCE_IP" \
  "$TARGET" -oJ "$OUTDIR/${TARGET}_banners.json"

# Alternative: two-phase (Masscan ports → Nmap services)
masscan -p1-65535 --rate=10000 "$TARGET" -oG "$OUTDIR/${TARGET}_grepable.txt" --wait=10
OPEN_PORTS=$(grep -oP 'Host: \S+ \(\)\s+Ports:\s+\K[^#]+' "$OUTDIR/${TARGET}_grepable.txt" | \
  grep -oP '\d+/open' | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')

if [[ -n "$OPEN_PORTS" ]]; then
  echo "[*] Nmap service detection on ports: $OPEN_PORTS"
  nmap -sV -p "$OPEN_PORTS" "$TARGET" -oN "$OUTDIR/${TARGET}_services.nmap"
fi
```

### Masscan — IP Camera Hunting (RTSP port 554)

```bash
# Scan Brazilian ISP ranges for cameras (from Vivo, Claro, Oi)
echo "[*] Camera hunt on Claro 3G/4G ranges"
masscan -p554,80,8010,8011 --rate=50000 \
  --range 177.0.0.0-177.255.255.255 -oJ cameras_claro.json

echo "[*] Camera hunt on Vivo ranges"
masscan -p554,80,8010,8011 --rate=50000 \
  --range 187.0.0.0-187.255.255.255 -oJ cameras_vivo.json

# Post-process: probe discovered cameras for snapshots
grep -oP '"ip":"[^"]+"' cameras_*.json | sed 's/"ip":"//;s/"//' | sort -u | \
while read ip; do
  # Axis camera snapshot
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "http://$ip:8010/axis-cgi/jpg/image.cgi")
  [[ "$code" == "200" ]] && echo "[CAMERA] Axis: $ip:8010"
  # Generic RTSP
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "http://$ip:554/")
  [[ "$code" != "000" ]] && echo "[RTSP] $ip:554"
done
```

### Sharding — Distribute Across N Machines

```bash
# On machine 1 (shard 1/4):
masscan -p1-65535 --rate=50000 --shard 1/4 -iL /8_range.txt -oJ shard1.json

# On machine 2 (shard 2/4):
masscan -p1-65535 --rate=50000 --shard 2/4 -iL /8_range.txt -oJ shard2.json

# On machine 3 (shard 3/4):
masscan -p1-65535 --rate=50000 --shard 3/4 -iL /8_range.txt -oJ shard3.json

# On machine 4 (shard 4/4):
masscan -p1-65535 --rate=50000 --shard 4/4 -iL /8_range.txt -oJ shard4.json

# Merge results
cat shard*.json | jq -s '.[]' > merged.json
```

## Real Production Results

### PRODERJ Network (/24 subnet, 187.62.129.0/24)
- 40+ IPs with active services across 18 government agencies
- Systems mapped: SEEDUC (Matricula Facil on .4,.6,.7,.8), AGENERSA (Joomla on .46), GLPI (.40), ITERJ (.47), DETRO (.57,.58), VOX (.69), Tomcat (.73), IIS 6.0 (.53)
- PHP 5.2.11 on Windows 2008R2 exposed at .128.54
- Apache 2.2 Win32 "It works!" exposed at .129.115

### Engebras Radar Fleet (500+ IPs across Claro 3G/4G)
- 502 radar IPs identified via Masscan on port 5000 (Werkzeug banner)
- 2 Werkzeug versions: 3.1.3 (Python 3.10.12) and 2.0.3 (Python 3.6.9 EOL)
- 75 radars also exposed SSH on port 22 (OpenSSH 7.6p1) + nginx on 80

### Camera Hunting (Brazil, Shodan + Masscan)
- 99,428 RTSP (port 554) devices in Brazil (Shodan stats)
- Axis P1378-LE at 187.141.142.149:8010 — config dump of 988 parameters unauthenticated
- Intelbras RX 1500 at 45.187.140.96

## Pitfalls

- **Masscan requires root.** Uses raw sockets. Run as root or with `sudo`.
- **Rate > 100k may trigger IDS/IPS.** Use `--rate=50000` or lower for stealth. Use `-T4` equivalent by setting appropriate `--rate`.
- **Banner grabbing kills connections.** Without `--source-ip`, Masscan must complete a full TCP handshake which tears down the connection. Use the two-phase approach (Masscan ports → Nmap services) for reliable service detection.
- **UDP scanning is experimental.** Masscan UDP support is limited. Use Nmap `-sU` for UDP.
- **Ctrl+C auto-saves.** Masscan saves progress on interrupt. Resume with `--resume paused.conf`.
- **`--excludefile` is critical.** Always exclude your own IPs and RFC 1918 ranges to avoid scanning yourself.

## Verification

- RustScan: open ports must be confirmed with Nmap `-sV` for service version.
- Masscan: results must be deduplicated (Masscan may report same port multiple times from retransmissions).
- Banner grab: service versions must match between Masscan banners and Nmap probes.
- All open TCP ports must have a corresponding service identified (no "unknown" ports).
