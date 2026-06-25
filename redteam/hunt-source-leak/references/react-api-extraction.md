# React SPA Source Map — API Endpoint Extraction

When you find a React SPA with source maps enabled, the `.js.map` file can reconstruct the full application source — including all API endpoint calls, auth logic, and any hardcoded credentials.

## Detection

```bash
# Check for asset manifest
curl -sk "https://TARGET/asset-manifest.json" | python3 -m json.tool

# Check for source map reference in JS bundle
curl -sk "https://TARGET/static/js/main.*.js" | tail -1
# Look for: //# sourceMappingURL=main.xxx.js.map

# Check if .map is directly accessible
curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/static/js/main.xxx.js.map"
```

## Extraction

```python
import json, re

# Download the source map (can be 1-10MB)
# curl -sk "https://TARGET/static/js/main.xxx.js.map" -o /tmp/app.js.map

with open('/tmp/app.js.map') as f:
    data = json.load(f)

contents = data.get('sourcesContent', [])
sources = data.get('sources', [])

print(f'Sources: {len(contents)} files')
all_text = ' '.join([c for c in contents if c])

# 1. Find all API endpoint URLs
endpoints = re.findall(
    r'https?://[a-zA-Z0-9./_-]+(?:/api/|/v1/|/v2/|/graphql)[a-zA-Z0-9/._-]*',
    all_text
)
for ep in sorted(set(endpoints)):
    print(f'  API: {ep}')

# 2. Find specific platform API files
for src in sources:
    if any(x in src for x in ['api/', 'config', 'auth', 'service']):
        print(f'  SRC: {src}')

# 3. Find hardcoded strings that look like secrets
secrets = re.findall(
    r'(?:api[Kk]ey|api_key|secret|password|token|authToken|jwt|bearer)[\"\': ]+[\"\']([^\"\'\\s]{10,})[\"\']',
    all_text, re.IGNORECASE
)
for s in set(secrets):
    print(f'  SECRET: {s[:80]}')

# 4. Find API calls (axios/fetch patterns)
apis = re.findall(
    r'(?:axios|fetch)\([\"\']([^\"\']+)[\"\']',
    all_text
)
for a in sorted(set(apis)):
    print(f'  API_CALL: {a}')

# 5. Find configured endpoints/base URLs
endpoints2 = re.findall(
    r'(?:endpoint|baseURL|baseUrl|apiUrl)[\"\']?\s*[:=]\s*[\"\']([^\"\'\\s]+)[\"\']',
    all_text
)
for e in sorted(set(endpoints2)):
    print(f'  ENDPOINT: {e}')
```

## Key Source Files to Look For

| File Pattern | What It Reveals |
|-------------|-----------------|
| `api/AuthServiceApi.js` | Authentication endpoints, login/logout, token refresh |
| `api/Dashboard/index.js` | Dashboard data, user stats |
| `api/View/index.js` | View/CRUD operations on data entities |
| `api/Drugs/index.js` | Healthcare/pharmacy API endpoints |
| `api/Text/index.js` | Text/content processing endpoints |
| `slice/authService.js` | Auth state management, token storage |
| `components/Auth/*` | Login, forgot password, reset password forms |
| `config/index.js` or `config.js` | API base URL, environment config |
| Any file with `api/` in path | The application's API integration layer |

## Chain

Source map extraction → API endpoint discovery → test endpoints for:
- IDOR on numeric/UUID parameters
- Auth bypass on older API versions
- Missing rate limiting on auth endpoints
- Hardcoded credentials in configuration files
