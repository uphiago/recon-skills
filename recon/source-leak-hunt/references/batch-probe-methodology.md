# Batch Probe Methodology

**Covers:** WordPress detection, CORS credential reflection, XML-RPC,
user-enumeration, and source-leak probes across a bounded target list.

## Key Lessons

### 1. Catch-all 200 sites will inflate every metric
Salesforce Commerce Cloud, BigCommerce, Shopify, and SPA frameworks (React/Vue) return HTTP 200 for **any path** with the same homepage HTML. This causes false positives on:
- WP detection (wp-login.php, wp-content/ → both return 200)
- Source leaks (.env, .git/config → return homepage HTML)
- XMLRPC (returns homepage, not XML)

**Detection:** Check if response body contains `<!doctype`, `<html`, or `<!DOCTYPE` tags. If so, and body >500 bytes without sensitive keywords → it's a catch-all.

### 2. CORS may only exist on API endpoints, not root
Initial check: `curl -sI https://example.com/ -H "Origin: https://evil.com"` → no headers
But: `curl -sI https://example.com/wp-json/wp/v2/users -H "Origin: https://evil.com"` → **FULL CREDENTIAL REFLECTION**

**Always test:** `/wp-json/wp/v2/users`, `/wp-json/`, `/wp-json/wp/v2/posts`, `/api/me`, `/api/tokens`

### 3. Never use `-L` (redirect follow) for probe endpoints
Redirects can replace the endpoint response with a generic destination. Compare
the original response and the redirect target separately before classifying
XML-RPC behavior.

### 4. Security scanner may block `-k` flag
Do not pipe untrusted HTTP responses directly into an interpreter. Save the
response, inspect it, and process the local file. Avoid `-k` unless certificate
validation is explicitly outside the test objective.

## Probe Script Template

```python
#!/usr/bin/env python3
"""Batch web probe — WP detection, CORS, XMLRPC, users, source leaks."""
import subprocess, sys, time, json, re, os
from urllib.parse import urlparse

def curl(url, method="GET", data=None, headers=None, timeout=12, follow=True):
    """Run curl and return (exit_code, stdout, stderr)."""
    cmd = ["curl", "-s", "--max-time", str(timeout), "--connect-timeout", "5"]
    if not follow:
        cmd += ["-o", "/dev/null", "-w", "%{http_code}"]
    if data:
        cmd += ["-d", data]
    if headers:
        for k, v in headers.items():
            cmd += ["-H", f"{k}: {v}"]
    cmd.append(url)
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
    return r.returncode, r.stdout.strip(), r.stderr

def probe_target(domain):
    """Probe a single target and return findings dict."""
    findings = {"domain": domain, "wp": False, "users": 0, "users_list": [],
                "cors": {}, "xmlrpc": {"status": "unknown", "methods": 0},
                "leaks": [], "catchall": False, "tech": []}
    base = f"https://{domain}"

    # --- Catch-all detection ---
    _, body, _ = curl(f"{base}/nonexistent-check-xyz-abc", follow=False)
    code = body  # With follow=False, stdout is the HTTP status code
    try:
        code_num = int(code)
    except ValueError:
        code_num = 0

    if code_num == 200:
        # Check if it returned HTML
        _, full, _ = curl(f"{base}/nonexistent-check-xyz-abc", follow=True)
        is_html = any(m in full[:300].lower() for m in ['<!doctype', '<html', '<!DOCTYPE'])
        if is_html and len(full) > 500:
            findings["catchall"] = True

    # --- WordPress detection ---
    for wp_path in ["/wp-login.php", "/wp-admin/", "/wp-content/", "/wp-includes/"]:
        _, code, _ = curl(f"{base}{wp_path}", follow=False)
        try:
            if int(code) in (200, 301, 302, 403, 401):
                findings["wp"] = True
                findings["tech"].append("WordPress")
                break
        except ValueError:
            pass

    # --- XMLRPC ---
    xml_payload = '<?xml version="1.0"?><methodCall><methodName>demo.sayHello</methodName></methodCall>'
    _, resp, _ = curl(f"{base}/xmlrpc.php", data=xml_payload, follow=False)
    if "Hello" in resp:
        findings["xmlrpc"]["status"] = "OPEN"
        # Count methods
        _, methods_xml, _ = curl(f"{base}/xmlrpc.php",
            data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
            follow=False)
        methods = re.findall(r'<value><string>([^<]+)</string>', methods_xml)
        findings["xmlrpc"]["methods"] = len(methods)
    elif resp.isdigit() and int(resp) == 405:
        findings["xmlrpc"]["status"] = "BLOCKED_405"
    elif resp.isdigit() and int(resp) == 404:
        findings["xmlrpc"]["status"] = "NOT_FOUND"
    else:
        findings["xmlrpc"]["status"] = f"OTHER_{resp[:30]}"

    # --- CORS on API endpoints ---
    cors_endpoints = ["/", "/wp-json/", "/wp-json/wp/v2/users",
                      "/wp-json/wp/v2/posts", "/api/me"]
    for ep in cors_endpoints:
        _, headers, _ = curl(f"{base}{ep}",
            headers={"Origin": "https://evil.com"},
            follow=False)
        # Note: with follow=False and -o /dev/null -w %{http_code}, stdout is the status code
        # We need headers in stderr... but this pattern is limited.
        # Better: use -D- for full headers
        pass

    return findings

if __name__ == "__main__":
    domains = sys.argv[1:] if len(sys.argv) > 1 else sys.stdin.read().splitlines()
    for d in domains:
        if not d.strip():
            continue
        print(f"=== {d} ===")
        f = probe_target(d.strip())
        print(f"  WP: {f['wp']} | Catchall: {f['catchall']} | XMLRPC: {f['xmlrpc']['status']} ({f['xmlrpc']['methods']} methods)")
        time.sleep(3)  # Rate limiting
```

Use the script as a starting point, not as a finding generator. Its output
still requires content-aware verification for catch-all routes, CORS,
XML-RPC, and exposed files.
