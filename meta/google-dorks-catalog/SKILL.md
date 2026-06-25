---
name: google-dorks-catalog
description: "High-precision Google dorks for exposed configs, secrets, and credentials -- real-world validated"
sources: field_ops, google_hacking
report_count: 100+
---

# Google Dorks Catalog -- Exposed Configs & Secrets

## When to Use

- During **passive reconnaissance** (Phase 1) on every target
- After crt.sh subdomain enumeration
- Before any active scanning
- Validated against 100+ real targets

## High-Precision Dorks

### Critical Exposed Files

```
site:$target "APP_KEY"
site:$target "DB_PASSWORD"
site:$target "-----BEGIN RSA PRIVATE KEY-----"
site:$target filetype:env
site:$target inurl:git/config
site:$target intitle:"index of" ".env"
site:$target "api_key" OR "apikey" OR "secret_key"
site:$target "firebase" "apiKey"
site:$target "supabase" "anon" "key"
site:$target inurl:"/.env" "DB_PASSWORD"
site:$target "client_secret" "redirect_uris" extension:json
site:$target "private_key" "client_email" extension:json
```

### Exposed Configuration Files (ALL Extensions)

```
site:target.com ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:backup | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess | ext:json
```

This covers:
- **logs** -- tokens, SQL queries, emails in plain text
- **txt/conf/cnf/ini** -- server configurations, DB hosts
- **env** -- environment variables with credentials
- **sh** -- scripts with hardcoded passwords
- **bak/backup/swp/old/~** -- backup files with old versions
- **git/svn** -- exposed versioned repositories
- **htpasswd/htaccess** -- access control with hashes
- **json** -- service accounts, Firebase configs, Supabase configs

### Service-Specific Dorks

#### Supabase
```
site:target.com "supabase.co" "anon_key" OR "SUPABASE_ANON_KEY"
```

#### Firebase
```
site:target.com "firebase-adminsdk" "private_key_id" extension:json
```

#### AWS
```
site:target.com "AKIA" filetype:env NOT example NOT test
```

#### SendGrid
```
site:target.com "SG." filetype:env NOT example
```

#### MongoDB
```
site:target.com "mongodb+srv://" "password"
```

#### PostgreSQL
```
site:target.com "postgresql://" "password" ext:env
```

#### JWT Secrets
```
site:target.com "JWT_SECRET" OR "jwt_secret" filetype:env
```

#### OpenAI API Keys
```
site:target.com "sk-" filetype:env OR filetype:txt
```

#### GitHub Tokens
```
site:target.com "ghp_" OR "gho_" OR "ghu_"
```

## GitHub Code Search Patterns

With GitHub personal token (much better results):

```python
headers = {"Authorization": "token GH_TOKEN"}
base = "https://api.github.com/search/code"

# SA Keys (Firebase/GCP) -- ~1 in 30 is valid
params = {"q": '"type": "service_account" "private_key" "project_id"'}

# .env with real credentials
params = {"q": 'DB_PASSWORD+DB_HOST+APP_KEY+filename:.env+NOT+example+NOT+your+NOT+test'}

# Supabase URLs + keys
params = {"q": 'supabase.co+SUPABASE_URL+SUPABASE_ANON_KEY+NOT+example+NOT+your'}

# AWS Keys
params = {"q": 'AKIA+filename:.env+NOT+example+NOT+your'}

# SendGrid keys
params = {"q": 'SG.+filename:.env+NOT+example'}

# MongoDB connection strings
params = {"q": 'mongodb+srv://+password+filename:.env'}
```

## Certificate SAN Discovery

```bash
# Extract SANs directly from the certificate
openssl s_client -connect target.com:443 -servername target.com </dev/null 2>/dev/null | \
  openssl x509 -noout -ext subjectAltName | grep -oP 'DNS:[^,]+' | cut -d: -f2 | sort -u
```

## Real-World Cases

**Real-world case MPF Argentina**: SSO certificate revealed fiscales.gob.ar, fiscales.gov.ar, mpf.gov.ar that didn't appear in conventional CT searches.

## Pitfalls

| Issue | Solution |
|-------|----------|
| Google rate limits | Space out searches, use incognito, rotate IP |
| GitHub API limits | Use personal token (5000 req/hr) |
| False positives from example repos | Append NOT example NOT test NOT your |

## Verification

```bash
# Test dork results manually
curl -sk "https://target.com/.env" | head -5
# Verify GitHub found secrets
python3 -c "import json; print(json.loads(open('result.json').read()))"
```
