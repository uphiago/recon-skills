#!/usr/bin/env python3
"""Reusable mass-recon scanner for US SMB sectors.

Tests domains for: WordPress detection → REST API users (wp-json/wp/v2/users) →
CORS credential reflection → XMLRPC multicall → sensitive file leaks (.env, .git, info.php).

Usage:
  python3 sector_mass_scan.py

Customize the TARGETS list with (domain, company_name, sector) tuples.
Customize OUTPUT_DIR for where findings go.

This script created during Wave 4 of US sector discovery (2026-06-24).
"""

import os, re, sys, json, time, random, socket, ssl
import urllib.request, urllib.error
import concurrent.futures
from datetime import datetime, timezone

OUTPUT_DIR = "./output"
ALREADY_TESTED_FILE = "/tmp/already_tested_domains.txt"
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/121.0.0.0 Safari/537.36",
]

def get_ua():
    return random.choice(USER_AGENTS)

def delay():
    time.sleep(2.0 + random.random())

def fetch(url, method="GET", data=None, extra_headers=None, timeout=10):
    headers = {"User-Agent": get_ua(), "Accept": "text/html,application/json,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5"}
    if extra_headers:
        headers.update(extra_headers)
    if data is not None:
        if isinstance(data, str):
            data = data.encode("utf-8")
        headers["Content-Type"] = "text/xml; charset=UTF-8"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.status, resp.headers, resp.read(), None
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read(), None
    except urllib.error.URLError as e:
        return 0, {}, b"", str(e.reason)
    except socket.timeout:
        return 0, {}, b"", "timeout"
    except Exception as e:
        return 0, {}, b"", str(e)

def check_alive(domain):
    for scheme in ["https", "http"]:
        code, headers, body, err = fetch(f"{scheme}://{domain}/")
        if code and code != 0:
            return True, code, body, headers, headers.get("Location", "")
    return False, 0, b"", {}, ""

def check_wp(body, headers):
    signals = []
    if b'wp-content' in body or b'/wp-json' in body or b'/wp-admin' in body:
        signals.append("wp-content")
    if b'WordPress' in body:
        signals.append("wordpress_string")
    if headers.get("X-Powered-By", "").find("WordPress") >= 0:
        signals.append("x-powered-by")
    if headers.get("X-Generator", "").find("WordPress") >= 0:
        signals.append("x-generator")
    return len(signals) > 0, signals

def check_wp_login(domain):
    delay()
    code, headers, body, err = fetch(f"https://{domain}/wp-login.php")
    return code not in (0, 404) and (b"wp-login" in body or b"user_login" in body or b"log" in body)

def check_wp_json_users(domain):
    delay()
    code, headers, body, err = fetch(f"https://{domain}/wp-json/wp/v2/users")
    users = []
    if code == 200 and body:
        try:
            data = json.loads(body)
            if isinstance(data, list):
                for u in data:
                    users.append({"id": u.get("id","?"), "name": u.get("name","?"), "slug": u.get("slug","?")})
        except: pass
    return code, users, headers

def check_cors(domain):
    delay()
    code, headers, body, err = fetch(f"https://{domain}/wp-json/wp/v2/users", extra_headers={"Origin": "https://evil.com"})
    acl = headers.get("Access-Control-Allow-Origin", "")
    creds = headers.get("Access-Control-Allow-Credentials", "")
    return {"acl": acl, "creds": creds, "reflected": acl == "https://evil.com",
            "credentialed": acl == "https://evil.com" and creds.lower() == "true", "wildcard": acl == "*"}

def check_xmlrpc(domain):
    delay()
    xml = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
    code, headers, body, err = fetch(f"https://{domain}/xmlrpc.php", method="POST", data=xml)
    methods = []
    multicall = False
    if code == 200 and body:
        s = body.decode("utf-8", errors="replace")
        methods = re.findall(r'<string>([^<]+)</string>', s)
        multicall = "system.multicall" in s
    return code, len(methods), multicall, methods[:8]

def check_leaks(domain):
    checks = {
        "/.env": ["app_", "db_", "key", "secret", "password", "token"],
        "/.git/config": ["[core]", "repositoryformatversion"],
        "/info.php": ["phpinfo", "php version"],
        "/phpinfo.php": ["phpinfo", "php version"],
        "/robots.txt": ["user-agent", "disallow", "sitemap"],
        "/sitemap.xml": ["urlset", "url>", "loc>"],
    }
    results = {}
    for path, keywords in checks.items():
        delay()
        code, headers, body, err = fetch(f"https://{domain}{path}")
        if code in (200, 301, 302) and body and len(body) > 30:
            bs = body.decode("utf-8", errors="replace").lower()
            if bs.strip().startswith(("<html", "<!doctype", "<script")) and path not in ("/robots.txt", "/sitemap.xml"):
                continue
            matched = [kw for kw in keywords if kw in bs]
            if matched or path in ("/robots.txt", "/sitemap.xml"):
                results[path] = {"code": code, "size": len(body), "keywords": matched}
    return results

def save_report(domain, company, sector, r):
    safe = domain.replace(".", "_")
    fp = os.path.join(OUTPUT_DIR, f"{safe}_findings.md")
    lines = [f"# Scan Findings: {company}", f"**Domain:** {domain}", f"**Sector:** {sector}",
             f"**Date:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}", "",
             "## Summary", "| Check | Result |", "|-------|--------|",
             f"| Alive | {r.get('alive',False)} |", f"| HTTP Code | {r.get('http_code','N/A')} |",
             f"| WordPress | {r.get('is_wp',False)} |"]
    if r.get('wp_users'):
        lines.append(f"| WP Users Exposed | {len(r['wp_users'])} |")
        for u in r['wp_users']:
            lines.append(f"| - {u['name']} | id={u['id']}, slug={u['slug']} |")
    else:
        lines.append(f"| WP Users Exposed | 0 |")
    lines.append(f"| XMLRPC | {r.get('xmlrpc_status',False)} |")
    lines.append(f"| XMLRPC Methods | {r.get('xmlrpc_count',0)} |")
    if r.get('xmlrpc_multicall'):
        lines.append(f"| XMLRPC Multicall | {r['xmlrpc_multicall']} |")
    cors = r.get('cors',{})
    if cors.get('credentialed'):
        lines.append("| CORS | CRITICAL: Credentialed reflection |")
    elif cors.get('reflected'):
        lines.append("| CORS | WARNING: Reflected origin (no creds) |")
    elif cors.get('wildcard'):
        lines.append("| CORS | WARNING: Wildcard |")
    else:
        lines.append("| CORS | SECURE |")
    lines.append(f"| Leaks Found | {len(r.get('leaks',{}))} |")
    lines.append("")
    if r.get('leaks'):
        lines.append("## Leaked Files")
        for p, info in r['leaks'].items():
            lines.append(f"- `{p}` (HTTP {info['code']}, {info['size']} bytes)")
            if info.get('keywords'):
                lines.append(f"  - Keywords: {', '.join(info['keywords'])}")
        lines.append("")
    if r.get('wp_users'):
        lines.append("## Exposed WordPress Users")
        for u in r['wp_users']:
            lines.append(f"- **{u['name']}** (id={u['id']}, slug={u['slug']})")
        lines.append("")
    if cors.get('credentialed'):
        lines.append("## CORS Vulnerability")
        lines.append("**CORS credential reflection detected!**")
        lines.append(f"- ACAO: {cors['acl']}, ACAC: {cors['creds']}")
        lines.append("Attack: fetch('https://TARGET/wp-json/wp/v2/users', {credentials:'include'})")
        lines.append("can exfiltrate authenticated user data cross-origin.")
        lines.append("")
    if r.get('xmlrpc_multicall'):
        lines.append("## XMLRPC Vulnerability")
        lines.append("**system.multicall enabled!** Attack surface: brute force, pingback SSRF, DDoS.")
        lines.append("")
    if r.get('sample_methods'):
        lines.append("## XMLRPC Methods (sample)")
        for m in r['sample_methods']:
            lines.append(f"- {m}")
        lines.append("")
    if r.get('headers'):
        lines.append("## Response Headers")
        for k, v in sorted(r['headers'].items()):
            if k.lower() in ('server','x-powered-by','x-generator','x-aspnet-version','x-runtime','set-cookie','cf-ray'):
                lines.append(f"- **{k}:** {v}")
        lines.append("")
    with open(fp, "w") as f:
        f.write("\n".join(lines))
    return fp

def scan_domain(domain, company, sector):
    r = {"domain": domain, "company": company, "sector": sector, "alive": False,
         "http_code": 0, "is_wp": False, "wp_signals": [], "wp_users": [], "wp_login": False,
         "users_code": 0, "cors": {}, "xmlrpc_status": False, "xmlrpc_count": 0,
         "xmlrpc_multicall": False, "sample_methods": [], "leaks": {}, "headers": {}, "error": None}
    print(f"\n{'='*60}\n[{sector}] Scanning: {domain} ({company})\n{'='*60}")

    alive, code, body, headers, redirect = check_alive(domain)
    if not alive:
        print(f"  [!] DEAD: {domain}"); r["error"] = "Not reachable"; return r

    r["alive"] = True; r["http_code"] = code; r["headers"] = dict(headers)
    print(f"  [OK] ALIVE (HTTP {code})" + (f" -> {redirect}" if redirect else ""))

    is_wp, signals = check_wp(body, headers); r["wp_signals"] = signals
    print(f"  [{'OK' if is_wp else 'NO'}] WP: {signals if is_wp else 'No'}")

    wp_login = check_wp_login(domain); r["wp_login"] = wp_login
    if wp_login or is_wp:
        r["is_wp"] = True

    if not r["is_wp"]:
        delay()
        wjc, wjh, wjb, wje = fetch(f"https://{domain}/wp-json/")
        if wjc == 200:
            try:
                if isinstance(json.loads(wjb), dict):
                    r["is_wp"] = True; r["wp_signals"].append("wp-json")
                    print(f"  [OK] /wp-json/ detected")
            except: pass

    if r["is_wp"]:
        uc, users, uh = check_wp_json_users(domain)
        r["users_code"] = uc; r["wp_users"] = users
        if users: print(f"  [VULN] {len(users)} users: {[u['name'] for u in users]}")
        else: print(f"  [INFO] /users: HTTP {uc}")

        cors_res = check_cors(domain); r["cors"] = cors_res
        status = "CRITICAL+CREDS" if cors_res.get("credentialed") else ("REFLECTED" if cors_res.get("reflected") else ("WILDCARD" if cors_res.get("wildcard") else "SECURE"))
        print(f"  [{'VULN' if cors_res.get('credentialed') else 'OK'}] CORS: {status}")

        xc, xcnt, xm, xmethods = check_xmlrpc(domain)
        r["xmlrpc_status"] = xc == 200; r["xmlrpc_count"] = xcnt; r["xmlrpc_multicall"] = xm; r["sample_methods"] = xmethods
        if xc == 200:
            print(f"  [{'VULN' if xm else 'INFO'}] XMLRPC: {xcnt} methods, multicall={xm}")

        leaks = check_leaks(domain); r["leaks"] = leaks
        if leaks: print(f"  [LEAK] {len(leaks)} leaks: {list(leaks.keys())}")
    else:
        leaks = check_leaks(domain); r["leaks"] = leaks
        if leaks: print(f"  [LEAK] {len(leaks)} leaks on non-WP: {list(leaks.keys())}")

    fp = save_report(domain, company, sector, r)
    print(f"  [SAVED] {fp}")
    return r


if __name__ == "__main__":
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ===================================================================
    # EDIT THIS TARGETS LIST for each new wave
    # Format: (domain, company_name, sector)
    # ===================================================================
    TARGETS = [
        ("example.com", "Example Company", "test_sector"),
    ]

    tested = set()
    if os.path.exists(ALREADY_TESTED_FILE):
        with open(ALREADY_TESTED_FILE) as f:
            for line in f:
                tested.add(line.strip().lower())
    for fname in os.listdir(OUTPUT_DIR):
        if fname.endswith("_findings.md"):
            d = fname.replace("_findings.md", "").replace("_", ".")
            tested.add(d.lower())
    print(f"Already tested: {len(tested)} domains")

    new_t = [(d,c,s) for d,c,s in TARGETS if d.lower() not in tested]
    print(f"New targets to scan: {len(new_t)}")
    if not new_t:
        print("All already tested!"); sys.exit(0)

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        fm = {ex.submit(scan_domain, d, c, s): d for d, c, s in new_t}
        for f in concurrent.futures.as_completed(fm):
            try: results.append(f.result())
            except Exception as e: results.append({"domain": fm[f], "error": str(e), "alive": False})

    print(f"\n{'='*60}\nSCAN COMPLETE: {len(results)} targets\n{'='*60}")
    alive = [r for r in results if r.get("alive")]
    wp = [r for r in alive if r.get("is_wp")]
    vuln = [r for r in wp if r.get("cors",{}).get("credentialed") or len(r.get("wp_users",[]))>0 or r.get("xmlrpc_multicall") or r.get("leaks")]
    print(f"Alive: {len(alive)}/{len(results)} | WP: {len(wp)}/{len(alive)} | Vuln: {len(vuln)}")
    if vuln:
        print("\n--- Vulnerable ---")
        for r in vuln:
            issues = []
            if r.get("cors",{}).get("credentialed"): issues.append("CORS+CREDS")
            if r.get("wp_users"): issues.append(f"USERS({len(r['wp_users'])})")
            if r.get("xmlrpc_multicall"): issues.append("MULTICALL")
            if r.get("leaks"): issues.append(f"LEAKS({len(r['leaks'])})")
            print(f"  [{r['sector']}] {r['domain']}: {', '.join(issues)}")
    print(f"\nSaved to {OUTPUT_DIR}/")
