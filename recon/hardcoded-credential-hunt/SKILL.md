---
name: hardcoded-credential-hunt
description: Detect hardcoded passwords in HTML forms, JavaScript, comments, and API responses.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, python3
metadata:
  hermes:
    tags: [recon, password, credential, hardcoded, HTML, javascript, API]
    category: recon
    related_skills:
      - api-noauth-hunt
      - js-secrets-extraction
      - source-leak-hunt
---

# Hardcoded Credential Hunt

Detect credentials baked into client-side code or HTML responses. Targets include master passwords in form `value` attributes, secret keys in inline scripts, API tokens in configuration endpoints, and plaintext credentials leaked through debug error pages. This class of vulnerability bypasses authentication entirely — no brute force required.

## When to Use

- An application serves HTML forms with pre-filled or hidden password fields.
- A configuration endpoint (`/api/config`, `/env`, `/settings`) returns JSON with credential-like strings.
- A debug/error page leaks application secrets in JavaScript variables.
- An unauthenticated API endpoint returns data that controls authentication (reset, exit registration, admin actions).
- JavaScript bundles contain string assignments matching password patterns.

## Prerequisites

- `terminal` tool with curl and python3.
- A target serving HTML, JSON, or JavaScript without proper authentication on configuration/settings endpoints.
- Access to at least one public page, form, or API endpoint.

## Quick Detection

```bash
# Scan HTML for password fields with pre-filled values
curl -sk "https://target.com/PATH" | grep -oPi '(?:password|passwd|senha|pass|pwd|secret)\s*[=:"]\s*"?[^"&\s]{4,30}"?' | head -10

# Scan JSON config endpoints for credential-like keys
curl -sk "https://target.com/api/config" | python3 -c "
import sys, json, re
try:
    data = json.load(sys.stdin)
    for k, v in data.items() if isinstance(data, dict) else []:
        if any(x in k.lower() for x in ['pass','secret','key','token','auth']):
            print(f'{k}: {v}')
except: pass
"

# Scan inline JavaScript for hardcoded secrets
curl -sk "https://target.com/" | grep -oP '(?:SECRET|PASSWORD|API_KEY|TOKEN)\s*=\s*"[^"]{8,}"' | head -10
```

## Procedure

### Phase 1 — HTML Form Inspection

Look for password fields with `value` attributes or hidden inputs containing credentials:

```bash
# Extract all password inputs
curl -sk "https://target.com/PATH" | python3 -c "
import sys, re
html = sys.stdin.read()
# Inputs with type=password and non-empty value
for m in re.finditer(r'<input[^>]*type\s*=\s*[\"\']password[\"\'][^>]*value\s*=\s*[\"\']([^\"\']+)[\"\']', html):
    print(f'PASSWORD FIELD: {m.group(1)}')
# Hidden inputs that look like passwords
for m in re.finditer(r'<input[^>]*type\s*=\s*[\"\']hidden[\"\'][^>]*name\s*=\s*[\"\']([^\"\']*(?:pass|senha|secret|token|key)[^\"\']*)[\"\'][^>]*value\s*=\s*[\"\']([^\"\']+)[\"\']', html, re.IGNORECASE):
    print(f'HIDDEN CREDENTIAL: {m.group(1)} = {m.group(2)}')
"
```

### Phase 2 — Configuration Endpoint Probing

Probe common config endpoints that may leak credentials:

```bash
for path in /api/config /api/settings /env /api/env /config.json /api/config.json \
            /api/v1/config /api/configuration /api/v2/settings /api/status; do
  result=$(curl -sk "https://target.com$path" -w "\n%{http_code}" 2>/dev/null)
  code=$(echo "$result" | tail -1)
  if [ "$code" = "200" ]; then
    echo "=== $path (200) ==="
    echo "$result" | python3 -c "
import sys, json, re
data = sys.stdin.read()
# Try JSON
try:
    obj = json.loads(data)
    for k, v in obj.items() if isinstance(obj, dict) else []:
        if any(x in str(k).lower() for x in ['pass','secret','key','token','auth','jwt']):
            print(f'  {k}: {v}')
except:
    # Try regex on plain text
    for m in re.finditer(r'(?:password|passwd|secret|token|api[_-]?key)\s*[=:]\s*[\"']([^\"']{4,})[\"']', data, re.I):
        print(f'  {m.group(0)}')
" | head -20
  fi
done
```

### Phase 3 — Debug Error Page Analysis

Werkzeug, Django, and Express debug pages often leak secrets in inline JavaScript:

```bash
# Trigger an error and check for credential leaks
curl -sk "https://target.com:PORT/ERROR_TRIGGER_PATH" | python3 -c "
import sys, re
html = sys.stdin.read()
# Werkzeug debugger SECRET
match = re.search(r'SECRET\s*=\s*[\"]([^\"\']+)[\"]', html)
if match: print(f'WERKZEUG_SECRET: {match.group(1)}')
# Django settings
for m in re.finditer(r'SECRET_KEY\s*=\s*[\"]([^\"\']+)[\"]', html):
    print(f'DJANGO_SECRET: {m.group(1)}')
# Generic credential patterns
for m in re.finditer(r'(?:PASSWORD|PASS|TOKEN|API_KEY)\s*=\s*[\"]([^\"\']{6,})[\"']", html, re.I):
    print(f'LEAKED: {m.group(0)}')
"
```

### Phase 4 — Authentication Bypass Testing

When a hardcoded password is found, test it against all authentication endpoints:

```bash
PASSWORD="found_password"
# Test against common auth endpoints
for endpoint in /login /api/login /api/auth/login /auth /admin /api/admin; do
  for user in admin administrator root; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" \
      -d "username=$user&password=$PASSWORD" \
      "https://target.com$endpoint")
    if [ "$code" = "302" ] || [ "$code" = "200" ]; then
      echo "SUCCESS: $user:$PASSWORD at $endpoint (HTTP $code)"
    fi
  done
done
```

## Pitfalls

- **Placeholder values look real.** Test `password123`, `changeme`, and empty strings before reporting — they are often development defaults.
- **The credential may be scoped.** A password for "exit registration" is not a full admin password. Map the credential to its actual permissions before scoring.
- **Form values may be dynamic.** Check if the password changes per session (CSRF token pattern) vs. being truly static.
- **Base64 is not encryption.** Decode any base64-looking strings found in JavaScript — they frequently contain credentials.
- **Rate limiting may block testing.** Space authentication attempts 2-3 seconds apart.

## Verification

1. **Confirm the credential is static:** fetch the page/endpoint three times and verify the password value is identical each time.
2. **Confirm it grants access:** use the credential at the intended endpoint and verify the response differs from a failed attempt (HTTP 200/302 vs 401/403).
3. **Map the privilege level:** test the credential against other endpoints to determine scope (read-only, write, admin, reset).
4. **Check for audit trail:** repeat the access with a unique identifier in the request to verify the action appears in logs (confirms real impact).

## Related Skills

- **`api-noauth-hunt`** — Exploiting API endpoints that lack authentication entirely.
- **`js-secrets-extraction`** — Finding API keys and tokens in JavaScript bundles.
- **`source-leak-hunt`** — Detecting exposed configuration files (.env, wp-config, etc.).
- **`flask-werkzeug-attack`** — Exploiting Werkzeug debugger SECRET leaks and traceback disclosure.
