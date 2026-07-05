---
name: github-secret-hunting
description: Find leaked API keys, tokens, and credentials in public GitHub repositories.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires python3, curl, git
metadata:
  tags: [recon, github, secret, API-key, token, dork, OSINT, trufflehog, credential]
  category: recon
  related_skills:
    - js-secrets-extraction
    - hardcoded-credential-hunt
    - source-leak-hunt
---

# GitHub Secret Hunting

Scan public GitHub repositories for leaked API keys, tokens, passwords, and internal infrastructure details. Developers accidentally push secrets constantly — this skill uses targeted dorking, automated scanning tools, and real-time monitoring to find credentials before the developer notices and revokes them.

## When to Use

- Target has public repositories under an organization account.
- JS bundle analysis reveals internal service names — search GitHub for related config files.
- Need to find valid API keys for cloud services, payment gateways, or third-party integrations.
- The target uses CI/CD systems that may leak tokens in build logs or workflow files.
- Want real-time monitoring for new secret leaks from the target org.

## Prerequisites

- `terminal` tool with python3, curl, git.
- GitHub Personal Access Token (only `public_repo` scope needed).
- Tool dependencies: TruffleHog, GitDorker, gitleaks.

## Quick Detection

```bash
# Basic GitHub code search for sensitive patterns in target repos
echo "target.com" | while read domain; do
  curl -s -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/search/code?q=$domain+filename:.env" \
    | jq '.items[]?.html_url'
done
```

## Procedure

### Phase 1 — Targeted Dorking with GitDorker

```bash
# Clone the dork collection and run against target
git clone https://github.com/Proviesec/github-dorks
python3 GitDorker.py \
  -tf $GITHUB_TOKEN \
  -q target.com \
  -d dorks/medium_dorks.txt \
  -o gitdorker_target.txt

# Also search by employee emails found in LinkedIn or metadata
python3 GitDorker.py \
  -tf $GITHUB_TOKEN \
  -q "john.doe@target.com" \
  -d dorks/medium_dorks.txt

# Custom dork: find env files
python3 GitDorker.py -tf $GITHUB_TOKEN \
  -q "org:target filename:.env DB_PASSWORD" -d dorks/medium_dorks.txt
```

### Phase 2 — TruffleHog Deep Scanning

```bash
# Scan a specific repo (finds secrets even in deleted commits)
trufflehog git https://github.com/target/repo --results=verified

# Scan entire GitHub org
trufflehog github --org=target --token=$GITHUB_TOKEN \
  --only-verified --threads=20 --json > trufflehog_org.json

# Docker variant
docker run --rm -it trufflesecurity/trufflehog:latest \
  github --only-verified --org=target

# Parse verified secrets
cat trufflehog_org.json | jq -r 'select(.Verified == true) | "\(.DetectorName): \(.RawV2)"'
```

### Phase 3 — Real-Time Monitoring with shhgit

```bash
# Monitor globally for secrets being pushed right now
shhgit --search-query \
  'path:*.env OR "DB_PASSWORD=" OR "AWS_ACCESS_KEY_ID=" OR "-----BEGIN RSA PRIVATE KEY-----"'

# Monitor specific org
shhgit --search-query \
  'target.com (path:*.env OR "DB_PASSWORD=" OR "api_key=")'
```

### Phase 4 — File Type and Extension Search

```bash
# git-wild-hunt: find specific file types
python3 git-wild-hunt.py \
  -s "org:Target extension:json filename:creds language:JSON"
python3 git-wild-hunt.py \
  -s "org:Target extension:sql filename:backup"
python3 git-wild-hunt.py \
  -s "target.com gitlab_token"

# Manual search patterns via GitHub API
for pattern in "filename:.env DB_PASSWORD" "filename:credentials.json" \
               "filename:config.json api_key" "filename:id_rsa" \
               "filename:.npmrc" "extension:pem BEGIN RSA" \
               "filename:service-account.json"; do
  curl -s -H "Authorization: token $GITHUB_TOKEN" \
    "https://api.github.com/search/code?q=target.com+$pattern" \
    | jq '.total_count, (.items[:3][].html_url)'
done
```

### Phase 5 — Hardcoded Credential Verification

```bash
# Pipeline: find → extract → verify
echo "target.com" | gau | grep -E '\.js$|\.json$|\.env$|\.config$' \
  | httpx -silent -mc 200 \
  | parallel -j 10 "curl -s {} | grep -oP \
    '(?:api[_-]?key|secret|token)[\"'\''']?\s*[:=]\s*[\"'\''']?([A-Za-z0-9_\-]{20,})' \
    | tee -a api_keys.txt"

# Verify found keys
for key in $(cat api_keys.txt | awk -F':' '{print $2}' | tr -d '"'\'' ' | sort -u); do
  # OpenAI
  curl -s "https://api.openai.com/v1/models" -H "Authorization: Bearer $key" | jq '.data[].id' 2>/dev/null && echo "VALID OPENAI: $key"
  # GitHub
  curl -s "https://api.github.com/user" -H "Authorization: token $key" | jq '.login' 2>/dev/null && echo "VALID GITHUB: $key"
done
```

### Phase 6 — GitLab Private Instances

```bash
# Discover self-hosted GitLab
# Check: gitlab.target.com, git.target.com, code.target.com
curl -sk "https://gitlab.target.com/api/v4/projects?visibility=public"

# With a found token
curl --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.target.com/api/v4/user"
curl --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
  "https://gitlab.target.com/api/v4/projects?membership=true&simple=true"

# Deep scan for secrets across accessible repos
gitleaks detect \
  --source https://gitlab.target.com \
  --access-token $GITLAB_TOKEN -v
```

### Phase 7 — Metadata Extraction from Public Documents

```bash
# metafinder: downloads public documents and extracts metadata
# Reveals usernames, software versions, internal file paths, email patterns
metafinder -d "target.com" -l 10 -go -bi -ba -o metadata_target.txt
metafinder -d "dev.target.com" -l 10 -go -bi -ba -o metadata_dev.txt

# Manual: check PDF metadata
curl -sk "https://target.com/document.pdf" -o doc.pdf
exiftool doc.pdf | grep -i "author\|creator\|producer"
```

## Pitfalls

- **Most search results are documentation and examples, not real leaks.** Focus on `.env`, `.config`, `.npmrc`, and CI/CD workflow files.
- **Rate limiting on GitHub API is strict.** Use multiple tokens or rotate IPs.
- **Verified secrets may already be revoked.** Always verify before reporting.
- **Self-hosted GitLab instances may block external scanning.** Test connectivity first.
- **Never use found credentials for unauthorized access.** Verify minimally, document, and report.

## Verification

1. TruffleHog or GitDorker identifies a potential secret with context.
2. Verify the secret by making a minimal API call (e.g., `GET /user` for GitHub tokens).
3. Confirm the secret was committed recently (check commit date) — stale secrets are lower priority.
4. Check if the repo is public and the secret grants meaningful access (admin vs read-only).
5. Document the exact file path, commit hash, and line number for the report.

## Related Skills

- **`js-secrets-extraction`** — Find API keys and endpoints in JavaScript bundles that may lead to GitHub repos.
- **`hardcoded-credential-hunt`** — Detect hardcoded passwords in HTML, JS, and API responses.
- **`source-leak-hunt`** — Find exposed config files (.env, .git) on live web servers.
