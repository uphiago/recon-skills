---
name: hunt-source-leak
description: "Hunt source code and build artifact leakage — JavaScript source maps (.js.map) reconstructing TypeScript/ES6 source, Swagger/OpenAPI JSON endpoint discovery, .env/.git exposure, webpack chunks with hardcoded secrets, robots.txt/security.txt recon, build-info files, asset-manifest.json API route discovery, .DS_Store file listing. Use at the START of every recon session — these findings often unlock the entire attack surface."
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux, macos]
metadata:
  tags: [source, leak, hunt, redteam]
  category: redteam
---

# HUNT-SOURCE-LEAK — Source Code & Build Artifact Leakage

## When to Use

- Recon surfaces `.js.map`, Swagger/OpenAPI, `.env`, `.git`, webpack chunks, or build manifests.
- You need to reconstruct source or extract secrets from build artifacts before hunting.

## Prerequisites

- Explicit authorization, target boundaries, and rate limits for the target.
- Tooling: `censys`, `curl`, `git-dumper`, `python3`, `shodan`, `trufflehog`.
- A writable evidence directory: `export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`.
- For any state-changing step (writes, uploads, credential attempts), obtain explicit confirmation immediately before the command.

## How to Run

```bash
# Set once per engagement; every step below uses these.
TARGET="example.com"   # or the engagement target
export OUTPUT_DIR="${OUTPUT_DIR:-./output}"

# Fetch a candidate map, then classify the first 80 bytes before processing
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/static/js/main.js.map" -o /tmp/map_file
head -c 80 /tmp/map_file
# "<!DOCTYPE" or "<html" = faux map (SPA serving HTML)
# "{" or ")))}" = real source map

python3 - <<'PY'
with open('/tmp/map_file') as f:
    d = f.read()
if d.strip().startswith('{'):
    print('Real source map')
elif '<!DOCTYPE' in d or '<html' in d:
    print('FAUX — SPA serving HTML')
else:
    print(f'Unknown, first 80b: {repr(d[:80])}')
PY
```

## Procedure

The phases below are the procedure. Keep each probe bounded (`--max-time`), record evidence beneath `OUTPUT_DIR`, and stop at the stop-conditions listed in Pitfalls.

## Crown Jewel Targets

Source map exposing TypeScript source = see all API routes, auth logic, secrets. Swagger/OpenAPI JSON = complete API surface map.

**Highest-value findings:**
- **`.js.map` source maps** — reconstruct full TypeScript/ES6 source code → find hardcoded API keys, internal endpoints, auth logic bypasses
- **`swagger.json` / `openapi.json`** — complete REST API specification with all endpoints, parameters, auth schemes, and internal route names
- **`.env` / `.env.production`** — APP_KEY, DB_PASSWORD, API_KEY, SECRET_KEY in plaintext
- **`.git/` exposure** — `git clone` the entire source history → all past hardcoded secrets
- **`asset-manifest.json` / `_next/static/`** — all JS bundle paths → systematic source map discovery
- **`build-info` / `info.json`** — git commit hash, build timestamp, dependency versions → CVE targeting

---

## Pitfalls

### 1. Fake Source Maps — HTML Serving as .map

Some SPAs (Angular/React on nginx) serve their `index.html` for **any unhandled route**, including `.js.map` URLs. The URL ends in `.map` and returns HTTP 200, but the content is HTML — not JSON.

**Detect before processing:**
```bash
# First 80 bytes tell the story
head -c 80 /tmp/map_file
# "<!DOCTYPE" or "<html" = faux map (SPA serving HTML)
# "{" or ")))}" = real source map

python3 - <<'PY'
with open('/tmp/map_file') as f:
    d = f.read()
if d.strip().startswith('{'):
    print('Real source map')
elif '<!DOCTYPE' in d or '<html' in d:
    print('FAUX — SPA serving HTML')
else:
    print(f'Unknown, first 80b: {repr(d[:80])}')
PY
```

**Fallback:** Download raw JS bundles and grep directly (Phase 8).

### 2. BusyBox / Alpine grep -P

On minimal containers (Alpine Linux), `grep -P` (Perl-compatible regex) is NOT available. This affects Phase 2 Step 2, Phase 7, and swagger extraction. Use Python3 `re` instead:

```bash
# Instead of: grep -Eo 'pattern' file
python3 -c "import sys, re; print(*(re.findall(r'pattern', sys.stdin.read())), sep='\n')" < file
```

### 3. crt.sh Rate Limiting

The crt.sh API rate-limits aggressively — queries too close together return empty JSON/timeouts. Wait 10-15s between queries. Use `&limit=20` to reduce response size: `https://crt.sh/?q=%25.TARGET&output=json&limit=20`

---

## Phase 1 — Quick Wins (Run First)

```bash
# These 10 requests take <30 seconds and often yield Critical findings
for PATH in \
  "/.env" \
  "/.env.production" \
  "/.env.local" \
  "/.git/HEAD" \
  "/swagger.json" \
  "/api/swagger.json" \
  "/v1/swagger.json" \
  "/openapi.json" \
  "/api/openapi.json" \
  "/api-docs"; do
  STATUS=$(curl --max-time 30 --connect-timeout 10 -s -o /tmp/sl_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] HIT: https://$TARGET$PATH"
    head -5 /tmp/sl_test
    echo "---"
  fi
done
```

---

## Phase 2 — Source Map Discovery

See `references/react-api-extraction.md` for the full React SPA source-map API extraction pipeline.

```bash
# Step 1: Get asset manifest to find all JS bundle paths
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/asset-manifest.json" | python3 -m json.tool 2>/dev/null
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/static/js/main.*.js" 2>/dev/null | head -3

# Next.js
BUILD_ID=$(curl --max-time 30 --connect-timeout 10 -s https://$TARGET/ | grep -Po '"buildId":"\K[^"]+')
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_next/static/$BUILD_ID/_buildManifest.js" | head -5

# Step 2: For each JS bundle, check for source map reference at end of file
for JS_URL in $(curl --max-time 30 --connect-timeout 10 -s https://$TARGET/ | grep -Eo 'src="[^"]*\.js"' | sed 's/src="//;s/"//'); do
  LAST_LINE=$(curl --max-time 30 --connect-timeout 10 -s "https://$TARGET$JS_URL" | tail -1)
  echo "$LAST_LINE" | grep -q "sourceMappingURL" && echo "[+] Source map: $JS_URL"
done

# Step 3: Download and reconstruct source from .map files
JS_URL="https://$TARGET/static/js/main.abc123.js"
MAP_URL="${JS_URL}.map"
curl --max-time 30 --connect-timeout 10 -s "$MAP_URL" | python3 -c "
import sys, json, os
data = json.load(sys.stdin)
sources = data.get('sources', [])
contents = data.get('sourcesContent', [])
for i, (src, content) in enumerate(zip(sources, contents)):
    if content:
        path = '/tmp/sourcemap_extract/' + src.replace('../','').replace('./',''). replace('webpack://','')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            f.write(content)
        print(f'[+] Extracted: {src}')
"

# Step 4: Grep extracted source for secrets
grep -r "API_KEY\|SECRET\|PASSWORD\|TOKEN\|PRIVATE" /tmp/sourcemap_extract/ 2>/dev/null
grep -r "process\.env\." /tmp/sourcemap_extract/ 2>/dev/null | grep -v "NEXT_PUBLIC_" | head -20
grep -r "http://internal\|localhost\|127\.0\.0\.1\|10\.\|172\.\|192\.168" /tmp/sourcemap_extract/ 2>/dev/null | head -20
```

---

## Phase 3 — Swagger / OpenAPI Discovery

```bash
# Common paths
SWAGGER_PATHS=(
  "/swagger.json" "/swagger.yaml" "/swagger/"
  "/api/swagger.json" "/api/swagger.yaml"
  "/v1/swagger.json" "/v2/swagger.json" "/v3/swagger.json"
  "/openapi.json" "/openapi.yaml"
  "/api/openapi.json" "/api-docs" "/api-docs.json"
  "/api/v1/swagger.json" "/api/v2/swagger.json"
  "/rest/swagger.json" "/rest/api-docs"
  "/.well-known/openapi.json"
  "/graphql/schema.json"
)

for PATH in "${SWAGGER_PATHS[@]}"; do
  STATUS=$(curl --max-time 30 --connect-timeout 10 -s -o /tmp/swagger_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] Found: https://$TARGET$PATH"
    # Extract all API paths from swagger
    python3 -c "
import sys, json
try:
    d = json.load(open('/tmp/swagger_test'))
    paths = list(d.get('paths', {}).keys())
    print(f'Endpoints: {len(paths)}')
    print('\n'.join(sorted(paths)))
except: pass
" | head -50
  fi
done
```

---

## Phase 4 — .git Exposure

```bash
# Check if .git directory is accessible
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.git/HEAD" | grep -q "ref:" && echo "[+] .git exposed!"

# If exposed, reconstruct repo
# Tool: git-dumper
pip3 install git-dumper
git-dumper "https://$TARGET/.git/" /tmp/dumped-repo/

# Grep for secrets in all git history
cd /tmp/dumped-repo && \
  git log --all --oneline 2>/dev/null | head -20
  git grep -i "password\|secret\|api_key\|token" $(git rev-list --all) 2>/dev/null | head -30

# trufflehog on git history
trufflehog git file:///tmp/dumped-repo/ 2>/dev/null | head -50
```

---

## Phase 5 — Forgotten Files & Debug Endpoints

```bash
# Build artifacts and debug files
DEBUG_PATHS=(
  "/build-info.json" "/build/build-info.json"
  "/info" "/actuator/info" "/api/info"
  "/version" "/api/version" "/_version"
  "/health" "/status" "/ping"
  "/robots.txt" "/security.txt" "/.well-known/security.txt"
  "/sitemap.xml" "/manifest.json" "/browserconfig.xml"
  "/crossdomain.xml" "/clientaccesspolicy.xml"
  "/phpinfo.php" "/info.php" "/test.php"
  "/server-status" "/server-info" "/.htaccess"
  "/web.config" "/applicationHost.config"
  "/WEB-INF/web.xml" "/META-INF/MANIFEST.MF"
  "/package.json" "/composer.json" "/Gemfile"
  "/Dockerfile" "/docker-compose.yml" "/.dockerenv"
)

for PATH in "${DEBUG_PATHS[@]}"; do
  STATUS=$(curl --max-time 30 --connect-timeout 10 -s -o /tmp/debug_test -w "%{http_code}" "https://$TARGET$PATH")
  if [ "$STATUS" = "200" ]; then
    echo "[+] Found: https://$TARGET$PATH ($STATUS, $(wc -c < /tmp/debug_test) bytes)"
    head -3 /tmp/debug_test
    echo "---"
  fi
done
```

---

## Phase 6 — .DS_Store File Listing

```bash
# .DS_Store files on macOS-deployed web servers reveal directory structure
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.DS_Store" | xxd | head -10

# Parse .DS_Store to extract filenames
pip3 install ds_store
python3 -c "
from ds_store import DSStore
with DSStore.open('/tmp/ds_store_test', 'r') as d:
    for entry in d:
        print(entry.filename)
"

# Recursive .DS_Store enumeration
# Tool: https://github.com/lijiejie/ds_store_exp
python3 ds_store_exp.py "https://$TARGET/"
```

---

## Phase 7 — webpack Chunk Analysis

**⚠ BusyBox/Alpine**: Skip `grep -Eo` below — use Python3 `re` instead (see Pitfalls section).

```bash
# Download and analyze webpack chunks for hardcoded values
# Find chunk files
curl --max-time 30 --connect-timeout 10 -s https://$TARGET/ | grep -Eo '"[^"]*\.chunk\.js"' | tr -d '"' | while read chunk; do
  echo "Analyzing: $chunk"
  curl --max-time 30 --connect-timeout 10 -s "https://$TARGET$chunk" | \
    grep -oE '"(api_key|apiKey|secret|password|token|key)"\s*:\s*"[^"]+"' | head -5
done

# Also grep for internal hostnames
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/static/js/main.*.js" | \
  grep -oE '"(https?://[^"]*internal[^"]*|http://[^"]*localhost[^"]*)"' | sort -u

# Check for Base64-encoded secrets
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/static/js/main.*.js" | \
  grep -Eo '"[A-Za-z0-9+/]{30,}={0,2}"' | while read b64; do
  DECODED=$(echo "$b64" | tr -d '"' | base64 -d 2>/dev/null)
  echo "$DECODED" | grep -iE "key|secret|password|token" && echo "  B64: $b64"
done
```

---

## Phase 8 — Raw JS Bundle Fallback (When Source Maps Fail)

When source map URLs return HTML (faux maps) or 404, **do not abandon analysis** — download raw JS bundles and grep them directly. Slower than source map reconstruction, but can still reveal internal API URLs, hardcoded credentials, and platform internals.

### 8.1 Download All JS Bundles

```bash
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/" -o /tmp/homepage.html

# Extract ALL JS URLs (both absolute and relative)
python3 -c "
import sys, re
html = open('/tmp/homepage.html').read()
seen = set()
for m in re.finditer(r'src=\"([^\"]+\.js[^\"]*)\"', html):
    j = m.group(1)
    if j not in seen: seen.add(j); print(j)
for m in re.finditer(r'\"([^\"]+\.js[^\"]*)\"', html):
    j = m.group(1)
    if j not in seen and '.js' in j and 'node_module' not in j:
        seen.add(j); print(j)
" | while read js_url; do
  full=$(echo "$js_url" | grep -q "^http" && echo "$js_url" || echo "https://$TARGET$js_url")
  curl --max-time 30 --connect-timeout 10 -sk "$full" -o "/tmp/js_$(basename $js_url | cut -d? -f1)" 2>/dev/null
  sleep 1
done
```

### 8.2 Grep for Secrets and Internal Endpoints

```bash
python3 - <<'PY'
import os, re

for name in os.listdir('/tmp'):
    if not name.startswith('js_'):
        continue
    data = open(os.path.join('/tmp', name)).read()

    # Firebase API keys
    for m in re.findall(r'AIza[0-9A-Za-z_-]{35}', data):
        print(f'[{name}] FIREBASE_KEY: {m}')

    # AWS access keys
    for m in re.findall(r'AKIA[0-9A-Z]{16}', data):
        print(f'[{name}] AWS_KEY: {m}')

    # Stripe keys
    for m in re.findall(r's[kr]_(live|test)_[A-Za-z0-9]+', data):
        print(f'[{name}] STRIPE_KEY: {m}')

    # Internal URLs with custom ports — HIGH VALUE
    for m in re.findall(r"https?://[^\"'\\)\s,;:]+:\d{3,5}[^\"'\\)\s,;]*", data):
        print(f'[{name}] INTERNAL_URL: {m}')

    # Non-public env var references
    for m in re.findall(r'process\.env\.(?!NEXT_PUBLIC_)([A-Z_]+)', data):
        print(f'[{name}] ENV_REF: process.env.{m}')
PY
```

### 8.3 Framework-Specific Checks

**Angular** (real-world: [STAGING_ENV] from this session):
- Look for `environment` or `environments` variables
- Grep for `.com:PORT` patterns — reveals internal API gateways
- Check `manifest.json` for all JS bundle paths

**React/Next.js:**
- Search for `__NEXT_DATA__` in HTML (embedded state/props)
- Check `_next/static/chunks/pages/` for page-level JS

**Vue.js:**
- Search for `__NUXT__` state in HTML
- Check `/js/app.*.js` for bundled API calls

### 8.4 Real-World Example

From this session's MedxGo recon on [STAGING_ENV] — source maps returned HTML (faux maps), so raw JS was analyzed:
```bash
# 3.8MB Angular main.js — one grep line found the jackpot:
python3 - <<'PY'
import re
data = open('/tmp/js_main.js').read()
for m in re.findall(r"https?://[^\"'\\)\s,;:]+:\d+", data):
    print(m)
PY
# → https://mean.[STAGING_ENV]:446
```
This was an undocumented internal MEAN stack API server. One grep line discovered a whole new attack surface.

---

## Chain Table

| Source leak finding | Chain to | Impact |
|--------------------|----------|--------|
| Source map with API key | Use key directly → API access | High/Critical |
| Source map with auth logic | Find auth bypass route | Critical |
| Swagger → internal endpoints | Test undocumented admin routes | High |
| .git exposed | Full source history → all past secrets | Critical |
| build-info with git hash | CVE targeting exact version | High |
| .env with DB_PASSWORD | Direct database access | Critical |

---

## Tools

```bash
# git-dumper (reconstruct exposed .git)
pip3 install git-dumper
git-dumper "https://target.com/.git/" /tmp/repo/

# sourcemap-explorer (visualize what's in bundles)
npm install -g source-map-explorer
source-map-explorer main.js

# unwebpack-sourcemap (extract all source files)
npm install -g unwebpack-sourcemap

# trufflehog (secret scanning)
trufflehog filesystem /tmp/repo/
```

---

## Validation

✅ Source map: reconstructed TypeScript source contains API endpoints or hardcoded secrets
✅ Swagger: JSON contains internal endpoints not visible in UI
✅ .git exposed: git-dumper successfully clones repo, secrets in history
✅ .env exposed: DATABASE_URL, API_KEY, SECRET_KEY visible in plaintext

**Severity:**
- .env with credentials: Critical
- .git with secrets in history: Critical
- Source map with secrets: High
- Swagger with internal routes: Medium-High
- robots.txt only: Informational

## Verification

- A leak finding requires sensitive content (`DB_`, `APP_KEY`, `_SECRET`, API keys, source frames), not an accessible path or HTTP 200.
- Catch-all rejection: a bare HTML homepage must not pass the content filter.

  ```bash
  printf '<!doctype html><title>home</title>' > /tmp/sl_catchall.html
  grep -qiE 'DB_|APP_|_KEY|_SECRET|DB_PASSWORD' /tmp/sl_catchall.html \
    && echo "FAIL: catch-all flagged as leak" || echo "PASS: catch-all rejected"
  ```

- The path, status, byte count, and matching content excerpt are recorded beneath `${OUTPUT_DIR:-./output}`.

---

## Related Skills

- hunt-wordpress — wp-config.php, debug.log, wp-content/uploads exposure
- hunt-firebase — Firebase API key discovery in JS bundles
- hunt-supabase — Supabase URL/key discovery in JS and .env
- hunt-frameworks — Laravel .env, storage/logs/laravel.log, APP_KEY exposure
- hunt-nextjs — _next/static, buildId, source map analysis
- security-arsenal — regex patterns for API keys, JWT, cloud credentials
- offensive-osint — GitHub dorking, exposed repos, Shodan/Censys
- cors-chain-automation — CORS testing on exposed API endpoints from source maps
