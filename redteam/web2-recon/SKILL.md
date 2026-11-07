---
name: web2-recon
description: Web2 recon pipeline — subdomain enumeration (subfinder, Chaos API, assetfinder), live host discovery (dnsx, httpx), URL crawling (katana, waybackurls, gau), directory fuzzing (ffuf), JS analysis (LinkFinder, SecretFinder), continuous monitoring (new subdomain alerts, JS change detection, GitHub commit watch). Use when starting recon on any web2 target or when asked about asset discovery, subdomain enum, or attack surface mapping.
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [web2, recon, redteam]
  category: redteam
---

# WEB2 RECON PIPELINE

Full asset discovery from nothing to a prioritized URL list ready for hunting.

---

## When to Use

- Starting recon on any web2 target or when asked about asset discovery, subdomain enum.
- Attack surface mapping.

## Prerequisites

- Explicit authorization, target boundaries, and rate limits for the target.
- Tooling: `censys`, `chaos`, `curl`, `dalfox`, `dig`, `dnsx`, `ffuf`, `gau`, `gf`, `gh`.
- A writable evidence directory: `export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`.
- For any state-changing step (writes, uploads, credential attempts), obtain explicit confirmation immediately before the command.

## How to Run

```bash
# 1. Set your Chaos API key (get free key at chaos.projectdiscovery.io)
export CHAOS_API_KEY="your-key-here"
# Add to ~/.zshrc or ~/.bashrc for persistence:
echo 'export CHAOS_API_KEY="your-key-here"' >> ~/.zshrc

# 2. Update nuclei templates (run weekly)
nuclei -update-templates

# 3. Configure subfinder with API keys for more sources
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/config.yaml << 'EOF'
# Get free keys at: virustotal.com, securitytrails.com, censys.io, shodan.io
virustotal: [YOUR_VT_KEY]
securitytrails: [YOUR_ST_KEY]
# ... (continues in Procedure)
```

## Procedure

The phases below are the procedure. Keep each probe bounded (`--max-time`), record evidence beneath `OUTPUT_DIR`, and stop at the stop-conditions listed in Pitfalls.

## SETUP (one-time)

```bash
# 1. Set your Chaos API key (get free key at chaos.projectdiscovery.io)
export CHAOS_API_KEY="your-key-here"
# Add to ~/.zshrc or ~/.bashrc for persistence:
echo 'export CHAOS_API_KEY="your-key-here"' >> ~/.zshrc

# 2. Update nuclei templates (run weekly)
nuclei -update-templates

# 3. Configure subfinder with API keys for more sources
mkdir -p ~/.config/subfinder
cat > ~/.config/subfinder/config.yaml << 'EOF'
# Get free keys at: virustotal.com, securitytrails.com, censys.io, shodan.io
virustotal: [YOUR_VT_KEY]
securitytrails: [YOUR_ST_KEY]
censys_apiid: YOUR_CENSYS_ID
censys_secret: YOUR_CENSYS_SECRET
shodan: [YOUR_SHODAN_KEY]
EOF

# 4. Verify alltools installed
which subfinder httpx dnsx nuclei katana waybackurls gau dalfox ffuf anew gf interactsh-client
```

---

## THE 5-MINUTE RULE

> If a target shows nothing interesting after 5 minutes of recon, move on. Don't burn hours on dead surface.

**5-minute kill signals:**
- All subdomains return 403 or static marketing pages
- No API endpoints visible in URLs
- No JavaScript bundles with interesting endpoint paths
- nuclei returns 0 medium/high findings
- No forms, no authentication, no user data

---

## STANDARD RECON PIPELINE

### Pre-Hunt: Always Run First

```bash
TARGET="target.com"

# Step 0: Passive — crt.sh certificate transparency (no API key needed)
curl --max-time 30 --connect-timeout 10 -s "https://crt.sh/?q=%.${TARGET}&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u > /tmp/subs.txt
echo "[+] crt.sh: $(wc -l < /tmp/subs.txt) subdomains"

# Step 1: Chaos API (ProjectDiscovery — most comprehensive source)
curl --max-time 30 --connect-timeout 10 -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" \
  | jq -r '.[]' >> /tmp/subs.txt

echo "[+] Chaos returned $(wc -l < /tmp/subs.txt) subdomains"

# Step 2: subfinder (passive multi-source)
subfinder -d $TARGET -silent | anew /tmp/subs.txt
assetfinder --subs-only $TARGET | anew /tmp/subs.txt

echo "[+] Total subdomains after all sources: $(wc -l < /tmp/subs.txt)"

# Step 3: DNS resolution + live host check
cat /tmp/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect | tee /tmp/live.txt

echo "[+] Live hosts: $(wc -l < /tmp/live.txt)"

# Step 4: URL crawl
cat /tmp/live.txt | awk '{print $1}' | katana -d 3 -jc -kf all -silent | anew /tmp/urls.txt

# Step 5: Historical URLs
echo $TARGET | waybackurls | anew /tmp/urls.txt
gau $TARGET --subs | anew /tmp/urls.txt

echo "[+] Total URLs: $(wc -l < /tmp/urls.txt)"

# Step 6: Nuclei scan
nuclei -l /tmp/live.txt -t ~/nuclei-templates/ -severity critical,high,medium -o /tmp/nuclei.txt
```

### Output to Organized Directory

```bash
TARGET="target.com"
RECON_DIR="recon/$TARGET"
mkdir -p $RECON_DIR

# All outputs go here:
/tmp/subs.txt         → $RECON_DIR/subdomains.txt
/tmp/live.txt         → $RECON_DIR/live-hosts.txt
/tmp/urls.txt         → $RECON_DIR/urls.txt
/tmp/nuclei.txt       → $RECON_DIR/nuclei.txt
```

---

## ATTACK SURFACE TRIAGE

### Find Interesting Targets in URL List

```bash
# Parameters worth testing
cat /tmp/urls.txt | grep -E "[?&](id|user|file|path|url|redirect|next|src|token|key|api_key)=" | tee /tmp/interesting-params.txt

# API endpoints
cat /tmp/urls.txt | grep -E "/api/|/v1/|/v2/|/v3/|/graphql|/rest/|/gql" | tee /tmp/api-endpoints.txt

# File upload endpoints
cat /tmp/urls.txt | grep -E "upload|file|attachment|document|image|avatar|photo|media" | tee /tmp/uploads.txt

# Admin/internal paths
cat /tmp/urls.txt | grep -E "/admin|/internal|/debug|/test|/staging|/dev|/management|/console" | tee /tmp/admin-paths.txt

# Authentication endpoints
cat /tmp/urls.txt | grep -E "/oauth|/login|/auth|/sso|/saml|/oidc|/callback|/token" | tee /tmp/auth-paths.txt
```

### gf Patterns (Quick Classification)

```bash
# Install gf patterns: https://github.com/tomnomnom/gf
cat /tmp/urls.txt | gf xss | tee /tmp/xss-candidates.txt
cat /tmp/urls.txt | gf ssrf | tee /tmp/ssrf-candidates.txt
cat /tmp/urls.txt | gf idor | tee /tmp/idor-candidates.txt
cat /tmp/urls.txt | gf sqli | tee /tmp/sqli-candidates.txt
cat /tmp/urls.txt | gf redirect | tee /tmp/redirect-candidates.txt
cat /tmp/urls.txt | gf lfi | tee /tmp/lfi-candidates.txt
cat /tmp/urls.txt | gf rce | tee /tmp/rce-candidates.txt
```

---

## JS ANALYSIS

### SecretFinder (API keys, tokens in JS bundles)

```bash
# Activate venv
source ~/tools/SecretFinder/.venv/bin/activate

# Scan a single JS file
python3 ~/tools/SecretFinder/SecretFinder.py -i "https://target.com/static/js/main.js" -o cli

# Scan all JS URLs found in recon
cat /tmp/urls.txt | grep "\.js$" | head -50 | while read url; do
  echo "=== $url ==="
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done

deactivate
```

### LinkFinder (Endpoints hidden in JS)

```bash
source ~/tools/LinkFinder/.venv/bin/activate

# Single JS file
python3 ~/tools/LinkFinder/linkfinder.py -i "https://target.com/app.js" -o cli

# All pages (crawls JS from HTML)
python3 ~/tools/LinkFinder/linkfinder.py -i "https://target.com" -d -o cli

deactivate
```

---

## DIRECTORY FUZZING

### ffuf — Standard Fuzzing

```bash
# Directory discovery on a live host
ffuf -u "https://target.com/FUZZ" \
     -w ~/wordlists/common.txt \
     -mc 200,201,204,301,302,307,401,403 \
     -ac \
     -t 40 \
     -o /tmp/ffuf-dirs.json

# API endpoint discovery
ffuf -u "https://target.com/api/FUZZ" \
     -w ~/wordlists/api-endpoints.txt \
     -mc 200,201,204,301,302 \
     -ac \
     -t 20

# IDOR fuzzing with authenticated request
# Create req.txt with Authorization: Bearer TOKEN
ffuf -request /tmp/req.txt \
     -request-proto https \
     -w <(seq 1 10000) \
     -fc 404 \
     -ac \
     -t 10
```

---

## TARGET SCORING — GO / NO-GO

Score before spending time. Skip if score < 4.

| Criterion | Points |
|---|---|
| Max bounty >= $5K | +2 |
| Large user base (>100K) or handles money | +2 |
| Program launched < 60 days ago | +2 |
| Complex features: API, OAuth, file upload, GraphQL | +1 |
| Recent code/feature changes (GitHub, changelog) | +1 |
| Private program (less competition) | +1 |
| Tech stack you know | +1 |
| Source code available | +1 |
| Prior disclosed reports to study | +1 |

**< 4:** Skip
**4-5:** Only if nothing better available
**6-8:** Good — spend 1-3 days
**>= 9:** Excellent — spend up to 1 week

### Pre-Dive Hard Kill Signals

1. Max bounty < $500 → not worth your time
2. All recent reports are N/A or duplicate → hunters saturated it
3. Scope is only a static marketing page → no attack surface
4. Company < 5 employees with no revenue → won't pay
5. Explicitly excludes your planned bug class in rules

---

## TECH STACK DETECTION (2 min)

```bash
# Response headers reveal backend
curl --max-time 30 --connect-timeout 10 -sI https://target.com | grep -iE "server|x-powered-by|x-aspnet|x-runtime|x-generator"

# Common signals:
# Server: nginx + X-Powered-By: PHP/7.4 → PHP backend
# Server: gunicorn OR X-Powered-By: Express → Python/Node.js
# X-Powered-By: ASP.NET → .NET
# Server: Apache Tomcat → Java
# X-Runtime: Ruby → Ruby on Rails

# Framework from JS bundle paths:
# /_next/static/ → Next.js
# /static/js/main.chunk.js → CRA (React)
# /packs/ → Ruby on Rails + Webpacker
# /__nuxt/ → Nuxt.js (Vue)
```

### Stack → Primary Bug Class Map

| Stack | Hunt First | Hunt Second |
|---|---|---|
| Ruby on Rails | Mass assignment | IDOR (`:id` routes) |
| Django | IDOR (ModelViewSet, no object perms) | SSTI (mark_safe) |
| Flask | SSTI (render_template_string) | SSRF (requests lib) |
| Laravel | Mass assignment ($fillable) | IDOR (Eloquent, no ownership) |
| Express (Node.js) | Prototype pollution | Path traversal |
| Spring Boot | Actuator endpoints (/actuator/env) | SSTI (Thymeleaf) |
| ASP.NET | ViewState deserialization | Open redirect (ReturnUrl) |
| Next.js | SSRF via Server Actions | Open redirect via redirect() |
| GraphQL | Introspection → auth bypass on mutations | IDOR via node(id:) |
| WordPress | Plugin SQLi | REST API auth bypass | CORS credential reflect |

---

## CONTINUOUS MONITORING SETUP

Set up once per target. Alerts you before other hunters.

### New Subdomain Alerts (daily cron)

```bash
#!/bin/bash
TARGET="target.com"
KNOWN="/tmp/$TARGET-subs-known.txt"

subfinder -d $TARGET -silent > /tmp/$TARGET-subs-fresh.txt
curl --max-time 30 --connect-timeout 10 -s "https://dns.projectdiscovery.io/dns/$TARGET/subdomains" \
  -H "Authorization: $CHAOS_API_KEY" \
  | jq -r '.[]' >> /tmp/$TARGET-subs-fresh.txt

# Diff against known
NEW=$(comm -23 <(sort /tmp/$TARGET-subs-fresh.txt) <(sort $KNOWN 2>/dev/null))

if [ -n "$NEW" ]; then
  echo "NEW SUBDOMAINS: $NEW"
  echo "$NEW" >> $KNOWN
fi

# Schedule: crontab -e → 0 8 * * * /bin/bash ~/monitors/subs-watch.sh
```

### GitHub Commit Watch

```bash
#!/bin/bash
REPO="TargetOrg/target-app"
LAST_SHA="/tmp/$REPO-last-sha.txt"

CURRENT=$(curl --max-time 30 --connect-timeout 10 -s "https://api.github.com/repos/$REPO/commits?per_page=1" | jq -r '.[0].sha')
KNOWN=$(cat $LAST_SHA 2>/dev/null)

if [ "$CURRENT" != "$KNOWN" ]; then
  echo "New commit on $REPO: $CURRENT"
  echo $CURRENT > $LAST_SHA
  # Get changed files
  curl --max-time 30 --connect-timeout 10 -s "https://api.github.com/repos/$REPO/commits/$CURRENT" \
    | jq -r '.files[].filename' | grep -E "auth|middleware|route|permission|role|admin"
fi

# Schedule: */30 * * * * /bin/bash ~/monitors/github-watch.sh
```

---

## Port Scanning (often skipped — don't skip)

```bash
# naabu - fast port scanner from ProjectDiscovery
# nmap often fails with "nse_main.lua not found" on minimal containers — naabu works.
# Finds non-standard ports: 8080, 8443, 3000, 8888, 9000, etc.
cat /tmp/live.txt | awk '{print $1}' | naabu -port 80,443,8080,8443,3000,4000,5000,8000,8888,9000,9090,9200,6379 -silent | tee /tmp/open-ports.txt

# Why this matters: admin panels, debug services, internal APIs often run on alt ports
# Example wins: :8080/actuator/env (Spring Boot), :9200/_cat/indices (Elasticsearch), :6379 (Redis)
```

### Raw port connectivity test (when naabu unavailable)

```bash
# Quick single-port check via bash /dev/tcp — works anywhere bash is available
for port in 22 80 443 3306 5432 6379 8080 8081 8443 27017; do
  timeout 3 bash -c "echo >/dev/tcp/$TARGET/$port" 2>&1 && echo "PORT $port OPEN" || echo "PORT $port CLOSED/FILTERED"
done
```

## SECRET SCANNING IN JS BUNDLES

```bash
# trufflehog — high-signal secret detection with entropy analysis
# Scans JS files and git repos
pip install trufflehog3 2>/dev/null || true
trufflehog filesystem --only-verified recon/$TARGET/ 2>/dev/null

# SecretFinder — manual JS bundle scan (already intools/)
source ~/tools/SecretFinder/.venv/bin/activate
cat /tmp/urls.txt | grep "\\.js$" | head -100 | while read url; do
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done
deactivate

# Quick grep for common patterns in downloaded JS
wget -q -r -l 1 -A "*.js" -P /tmp/js-files/ "https://$TARGET" 2>/dev/null
grep -rn "api_key\\|apiKey\\|client_secret\\|access_token\\|private_key\\|AWS_SECRET\\|AKIA" /tmp/js-files/ 2>/dev/null
```

### JS bundle API key extraction (BusyBox-compatible fallback)

BusyBox grep does NOT support `-P` (PCRE/Perl regex). Use Python3 for regex matching on JS bundles in Alpine containers:

```bash
# Extract Firebase API keys from JS bundle
curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET/static/js/main.*.js" 2>/dev/null | python3 -c "
import sys, re
content = sys.stdin.read()
for k in re.findall(r'AIza[0-9A-Za-z_-]{35}', content):
    print(f'Firebase API Key: {k}')
for m in re.findall(r'(?:apiUrl|apiKey|authDomain|databaseURL|projectId)[\"\']?\s*[:=]\s*[\"]([^\"\']+)[\"]', content):
    print(f'Config: {m}')
for u in re.findall(r'https?://[a-zA-Z0-9._-]+\.(?:firebaseio|firestore|googleapis|herokuapp)\.com[^\"\\s,]*', content):
    print(f'URL: {u}')
for s in re.findall(r'(?:secret|jwt[_-]?secret|token)[\"\']?\s*[:=]\s*[\"]([a-zA-Z0-9_\-]{16,})[\"]', content):
    print(f'Potential secret: {s}')
" 2>/dev/null

# For React SPAs with chunked bundles — find the main bundle first
main_js=$(curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET:8080/" 2>/dev/null | grep -Eo 'src="([^"]+\.js)"' | sed 's/src="//;s/"//' | head -1)
[ -n "$main_js" ] && curl --max-time 30 --connect-timeout 10 -sk "https://$TARGET:8080/$main_js" | python3 -c "
import sys, re
content = sys.stdin.read()
for m in re.findall(r'https?://[^\"\\s,;\\)]+', content):
    if '://' in m and not 'fonts.' in m:
        print(f'URL: {m}')
for m in re.findall(r'apiUrl[\"\\']?\s*[:=]\s*[\"\\']([^\"\\']+)[\"\\']', content):
    print(f'apiUrl: {m}')
" 2>/dev/null
```

This technique can reveal API backends on non-standard ports that are absent
from navigation and DNS naming conventions.

## GITHUB DORKING FOR TARGET

```bash
# Search GitHub for hardcoded secrets before hunting the app
TARGET_ORG="TargetOrgName"  # Check their GitHub org

# Useful dorks (search on github.com):
# org:TARGET_ORG password
# org:TARGET_ORG api_key
# org:TARGET_ORG "Authorization: Bearer"
# org:TARGET_ORG .env
# org:TARGET_ORG "BEGIN RSA PRIVATE KEY"

# CLI with gh (GitHub CLI):
gh search code "api_key" --owner "$TARGET_ORG" --json path,repository 2>/dev/null | jq '.'
gh search code "password" --owner "$TARGET_ORG" --json path,repository 2>/dev/null | head -20

# GitDorker (if installed):
python3 ~/tools/GitDorker/GitDorker.py -t GITHUB_TOKEN -d ~/tools/GitDorker/Dorks/alldorksv3 -q "$TARGET" -org
```

### 30-MINUTE RECON PROTOCOL

## Dual-Track Parallel Recon (Proven Effective for Multi-Target Batches)

When testing 15-20+ targets across multiple sectors, use a **dual-track approach**:

**Track 1 — Manual Fast Probe (you do this while Track 2 runs)**
1. Probe each domain with `curl --max-time 10 --connect-timeout 5 -sI` for alive check + server headers (takes ~30s per 5 domains)
2. Immediately check promising signals: WordPress link headers, CORS origins, interesting cookies
3. Run subfinder on interesting domains while they're fresh in mind
4. Chase live subdomains immediately (app., dashboard., staging., etc.)

**Track 2 — Automated Scanner (background)**
- Launch a Python scanner with bounded delays and five parallel tasks.
- The scanner does the systematic work: WP detection, CORS test, sensitive file check, subdomain enum for every domain
- Check progress periodically; by the time it finishes you already have the high-signal findings

**Why this works:**
- Manual probes reveal high-value targets (CRITICAL CORS, WP users, exposed staging) in the first 5 minutes
- The automated scanner validates the rest without burning your attention on dead targets
- Subdomains found manually can be probed immediately while the scanner is still running
- In Wave 5 (20 targets, 4 sectors), this approach revealed 3 CRITICAL CORS + 11 exposed WP users + 95 subdomains within 15 minutes of manual work

### Minutes 0-5: Read Program Page

```
Note:
- ALL in-scope assets (every domain listed)
- Out-of-scope list (read carefully — common trap)
- Safe harbor statement
- Impact types accepted (some exclude "low")
- Average bounty amount (signals program generosity)
```

### Minutes 5-15: Asset Discovery

Run the standard pipeline above. Focus on live.txt output.

### Minutes 15-25: Surface Map

Run gf patterns and the interesting-params grep above.

### Minutes 25-30: Manual Exploration

Open Burp Suite. Browse the app with proxy on:
1. Register an account
2. Perform main user actions (create/read/update/delete resources)
3. Note all API calls in Burp history
4. Look for endpoints not in your URL list

### After 30 min: Prioritize

```
Priority 1: API endpoints with ID parameters → IDOR candidates
Priority 2: File upload features → XSS/RCE candidates
Priority 3: OAuth/SSO flows → auth bypass candidates
Priority 4: Search/filter with user input → SQLi/SSRF/SSTI candidates
Priority 5: Admin/debug endpoints → auth bypass candidates
```

---

## Toolchain fallback (when `dnsx` / `httpx` crash)

The projectdiscovery Go binaries (`dnsx`, `httpx`, `naabu`) occasionally `SIGSEGV` on macOS arm64 due to a cgo / system-resolver interaction. The crash signature is identical regardless of install method — both `brew install` and `go install github.com/projectdiscovery/<tool>@latest` produce binaries that segfault at the same address. Smoke-test once before relying on them in a real engagement:

```bash
dnsx -version   # if SIGSEGV: use the dig fallback below
httpx -version  # if SIGSEGV: use the curl fallback below
```

### `dnsx` (preferred) or `dig` fallback

```bash
# Preferred: dnsx (concurrent, 50-100x faster at scale)
dnsx -silent -l subs.txt -a -resp-only -o resolved.txt

# Fallback: dig (sequential, only if dnsx binary unavailable)
while read s; do
  ips=$(dig +short +tries=1 +time=3 "$s" \
    | grep -E '^[0-9.]+$' \
    | paste -sd, -)
  [ -n "$ips" ] && echo "$s|$ips"
done < subs.txt
```

### `httpx` → `curl` fallback

```bash
# Replaces: httpx -l subs.txt -silent -status-code -title -tech-detect
while read s; do
  resp=$(curl --max-time 30 --connect-timeout 10 -s -L -m 5 -o /tmp/body \
    -w "%{http_code}|%{url_effective}|%{header_server}" \
    "https://$s")
  code=$(echo "$resp" | cut -d'|' -f1)
  if [ "$code" != "000" ]; then
    title=$(grep -oE '<title[^>]*>[^<]*</title>' /tmp/body | head -1 | sed 's/<[^>]*>//g')
    echo "$s|$resp|$title"
  fi
done < subs.txt
```

**Trade-off:** Serial vs. concurrent. The fallback handles ~24 subdomains in 14 seconds; the same workload on `httpx` with default 50 threads finishes in 2-3 seconds. For VDP-scale recon (< 100 subdomains) the fallback is fine. For mass recon (1000+) fix the toolchain first.

(Verified against HackerOne's own VDP during skill development; the verification log is internal and not shipped with the repository.)

---

## API Spec / Swagger / OpenAPI Discovery (2024-2026 surface)

API spec endpoints are the single highest-leverage recon target on any modern .NET / Node / Python / Java backend. The spec discloses every endpoint, HTTP methods, parameter names + types + formats, models, validation rules — a complete attack-map in JSON. Default routes are commonly left enabled in production. **Add this wordlist to the directory-fuzzing phase** (after the standard `common.txt` pass).

### Default discovery path wordlist (paste into `swagger-paths.txt`)

```
# NSwag / Swashbuckle (ASP.NET Core)
/swagger
/swagger/
/swagger/index.html
/swagger/ui/index.html
/swagger/v1/swagger.json
/swagger/v2/swagger.json
/swagger/v3/swagger.json
/swagger/docs/v1
/swagger/docs/v2
/swagger-ui
/swagger-ui/
/swagger-ui.html
/swagger-resources
/swagger-resources/configuration/ui
/nswag
/nswag/index.html
/api/swagger
/api/swagger.json
/api/swagger/v1/swagger.json
/api/openapi
/api/openapi.json
/api/v1/swagger.json
/api/v2/swagger.json
/api-docs
/api-docs/swagger.json

# OpenAPI generic
/openapi
/openapi.json
/openapi.yaml
/openapi.yml
/openapi/v1.json
/openapi/v2.json
/openapi/v3.json
/.well-known/openapi.json

# Java / Spring (Springfox / springdoc)
/v2/api-docs
/v3/api-docs
/v3/api-docs.yaml
/v3/api-docs/swagger-config
/swagger-ui/index.html

# Python (FastAPI / Flask-RESTPlus / Connexion / DRF)
/docs
/docs/
/redoc
/redoc/
/openapi.json
/swagger.json
/swagger/?format=openapi
/swagger.yaml

# Express / Node / Hapi
/api-docs
/api-docs.json
/swagger.json
/swagger-stats
/graphql-docs

# GraphQL adjacent (often co-located)
/graphql
/graphiql
/playground
/altair
/voyager
/graphql/console
/graphql-explorer

# ReDoc / RapiDoc / Stoplight / alt UIs
/redoc
/redoc.html
/redoc-ui.html
/rapidoc
/rapidoc.html
/stoplight
/elements

# Misc / dev-leftover
/actuator
/actuator/openapi
/actuator/mappings
/q/openapi
/q/swagger-ui
/docs/swagger.json
/api/v1/docs
/api/v2/docs
/internal/swagger
/admin/swagger
/management/swagger
```

### Integration with the standard pipeline

```bash
# After live-hosts.txt is built (Phase 1 / 2), run:
ffuf -w swagger-paths.txt -u "https://FUZZ.target.com" -mc 200,302 -fs 0 -t 50 -o swagger-hits.json
# Or with httpx for content-aware filtering:
httpx -l live-hosts.txt -path swagger-paths.txt -mc 200 -mr "swagger|openapi" -json | tee swagger-hits.jsonl
# For every hit:
jq '.paths | keys' swagger.json > endpoints.txt
jq '.components.schemas' swagger.json > schemas.json   # mass-assignment field candidates
```

### Why this matters for recon-to-hunting handoff

- **Spec → mass IDOR/BOLA** — `jq '.paths | keys' swagger.json` becomes the input list for `Autorize`/`ffuf` per-user testing.
- **Spec → mass-assignment payload construction** — `components.schemas.UserUpdateDto` enumerates `isAdmin`, `emailVerified`, `tenantId`, `role`.
- **Spec → hidden endpoint discovery** — `/internal/*`, `/debug/*`, `/v0/*`, `/legacy/*` routes documented but never auth-gated.
- **Spec → injection-class seeding** — every parameter's type + format + enum + max-length means payloads pass validation before reaching the sink. Especially valuable against ASP.NET Core where the model binder rejects malformed input before any controller logic.

### Tools

- `kiterunner` — natively ingests OpenAPI spec, generates requests against the API.
- `sj` (Swagger Jacker) — purpose-built for Swagger spec exploitation.
- `apidetector` (brinhosa) — Swagger-UI mass scanner.
- `XSSwagger` (vavkamil) — detects vulnerable Swagger UI versions (CVE-2018-25031 family).
- `nuclei -t http/exposures/apis/` — built-in templates for default spec paths.

### Anti-pattern reminder

A 404/403 on `/swagger` does NOT mean no spec is exposed. Many .NET projects route the spec under `/api/swagger/v1/swagger.json` rather than `/swagger`. Always test the full path list, not just the root.

Full attack-chain analysis is in `hunt-api-misconfig` → `NSwag / Swagger / OpenAPI Spec Exposure`.

---

## Verification

1. **Core recon tools** — confirm key tools are installed:
   ```bash
   which subfinder httpx nuclei katana 2>/dev/null | wc -l | xargs -I{} echo "{} of 4 core tools found"
   ```
2. **HTTP probe** — confirm httpx works:
   ```bash
   echo "example.com" | httpx -silent -status-code 2>/dev/null && echo "PASS: httpx operational" || echo "NOTE: httpx not installed"
   ```
All tests verify web2 recon readiness.

---

## Pitfalls
- **Recon without triage** — collecting 10,000 subdomains without prioritizing which to test is data collection, not recon.
- **HTTP probe without HTTPS** — many services only respond on HTTPS. Test both protocols.
- **Screen shot collection without analysis** — automated screenshots are useful only if you review them. Unique login pages, error messages, and CMS identifiers are the value.
- **Port scanning without service identification** — open port 8443 might be anything. Banner grab and identify the actual service.
- **Stale recon data** — subdomain data older than 30 days is increasingly unreliable. Refresh recon for each engagement.


---

## Related Skills & Chains

- **`offensive-osint`** — When recon needs concrete probes / wordlists / regexes beyond the basic pipeline. Workflow primitive: this skill produces the URL set; `offensive-osint` provides the secret regexes, GraphQL/Swagger paths, and identity-fabric probes you apply to that URL set.
- **`osint-methodology`** — When you need a severity rubric for what you discovered. Workflow primitive: after recon outputs `subdomains.txt` / `live-hosts.txt` / `urls.txt`, score each asset against `osint-methodology`'s findings rubric to decide what gets a finding versus what stays in the asset graph.
- **`hunt-subdomain`** — When recon surfaces stale CNAMEs / dangling DNS. Workflow primitive: any subdomain in `subdomains.txt` whose CNAME points to S3 / GitHub Pages / Heroku / Shopify / Azure should auto-route to `hunt-subdomain` for takeover validation.
- **`security-arsenal`** — When the URL set is classified by `gf` and ready for active testing. Workflow primitive: `gf xss/ssrf/sqli/idor` output names become payload-class queries against `security-arsenal`'s payload library.
- **`bb-methodology`** — When recon completes and Phase 1 transitions to Phase 2 (Mapping). Workflow primitive: hand the live host + URL set back to `bb-methodology` Phase 2 for endpoint mapping and Phase 3 vulnerability discovery routing.

---
