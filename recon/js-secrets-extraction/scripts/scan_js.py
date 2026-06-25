#!/usr/bin/env python3
"""JavaScript bundle secret scanner — 11 regex patterns.
   Battle-tested on 7 deep targets across Wave7 recon.
   Usage: python3 scan_js.py <url_or_file>"""

import sys, re, os, requests
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()

PATTERNS = [
    (r'(?i)(?:api[_-]?key|apikey|api_key)\s*[=:]\s*["\x27]([^"\x27]{8,})["\x27]', "API Key"),
    (r'https?://[a-zA-Z0-9.-]+:[0-9]{2,5}', "Internal URL with port"),
    (r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', "JWT Token"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key"),
    (r'(?i)(?:firebase|supabase)_[a-z]+\s*[=:]\s*["\x27]([^"\x27]+)["\x27]', "Firebase/Supabase"),
    (r'(?i)(?:sk_live_|sk_test_|pk_live_|pk_test_)[A-Za-z0-9]+', "Stripe Key"),
    (r'(?i)ghp_[A-Za-z0-9]{36}', "GitHub Token"),
    (r'(?i)xox[baprs]-[0-9A-Za-z-]{10,}', "Slack Token"),
    (r'10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', "Internal IP (10.x)"),
    (r'172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}', "Internal IP (172.x)"),
    (r'192\.168\.[0-9]{1,3}\.[0-9]{1,3}', "Internal IP (192.168)"),
    (r'AIza[0-9A-Za-z_-]{35}', "Google API Key"),
    (r'https?://[a-zA-Z0-9.-]+\.(?:amazonaws\.com|cloudfront\.net)[^\s"\'<>]+', "AWS Resource URL"),
]

def scan_js(text, label=""):
    findings = []
    for pat, desc in PATTERNS:
        for m in re.findall(pat, text):
            s = str(m)[:100]
            prefix = f"[{label}] " if label else ""
            findings.append(f"{prefix}[{desc}] {s}")
    return findings

def extract_js_urls(html, base_url):
    urls = set()
    for m in re.finditer(r'src="([^"]*\.js[^"]*)"', html): urls.add(m.group(1))
    for m in re.finditer(r'href="([^"]*\.js[^"]*)"', html): urls.add(m.group(1))
    for m in re.finditer(r'["\x27](/[^"\x27 ]+\.js[^"\x27]*)', html): urls.add(m.group(1))
    absolute = []
    for u in urls:
        if u.startswith('http'): absolute.append(u)
        elif u.startswith('//'): absolute.append('https:' + u)
        elif u.startswith('/'): absolute.append(base_url.rstrip('/') + u)
        else: absolute.append(base_url.rstrip('/') + '/' + u)
    return absolute

def main():
    if len(sys.argv) < 2:
        print("Usage: scan_js.py <url>     — scan a webpage + all its JS bundles")
        print("       scan_js.py <file.js>  — scan a single JS file")
        sys.exit(1)

    source = sys.argv[1]
    all_findings = []

    if source.startswith('http'):
        print(f"[*] Fetching {source}...")
        r = requests.get(source, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,*/*"
        }, timeout=20, verify=False)

        if r.status_code == 200:
            html = r.text
            # Scan HTML itself
            html_findings = scan_js(html, "HTML")
            all_findings.extend(html_findings)

            # Extract JS URLs
            js_urls = extract_js_urls(html, source)
            print(f"[+] Found {len(js_urls)} JS bundle URLs")

            # Download and scan each (max 15)
            for i, js_url in enumerate(js_urls[:15]):
                try:
                    jr = requests.get(js_url, headers={
                        "User-Agent": "Mozilla/5.0 ...",
                    }, timeout=15, verify=False)
                    if jr.status_code == 200 and len(jr.text) > 50:
                        label = js_url.split('/')[-1][:40]
                        findings = scan_js(jr.text, label)
                        all_findings.extend(findings)
                        if findings:
                            print(f"  [{i+1}] {label}: {len(findings)} secrets")
                except Exception as e:
                    print(f"  [{i+1}] {js_url[:60]}: FAILED ({e})")
        else:
            print(f"[-] HTTP {r.status_code}")
            sys.exit(1)

    else:
        with open(source, 'r', errors='replace') as f:
            content = f.read()
        all_findings = scan_js(content, os.path.basename(source))

    # Report
    print(f"\n{'='*60}")
    print(f"SECRETS FOUND: {len(all_findings)}")
    print(f"{'='*60}")
    for f in all_findings:
        print(f"  {f}")

    seen = set()
    unique = []
    for f in all_findings:
        h = f[-60:]  # Deduplicate by last 60 chars (the secret itself)
        if h not in seen:
            seen.add(h)
            unique.append(f)
    print(f"\n[+] Unique secrets: {len(unique)} (from {len(all_findings)} total matches)")

if __name__ == "__main__":
    main()
