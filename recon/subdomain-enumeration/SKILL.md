---
name: subdomain-enumeration
description: Map subdomains via crt.sh and subfinder at recon kickoff.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  hermes:
    tags: [recon, subdomain, DNS, crt.sh, asset-discovery]
    category: recon
    related_skills:
      - wp-mass-recon
      - staging-subdomain-hunt
      - deep-invade
      - recon-playbook
---

# Subdomain Enumeration Skill

Comprehensive subdomain discovery using certificate transparency logs (crt.sh), DNS brute force, and passive sources. The first step in any recon pipeline — you can't attack what you don't know exists. Subdomain enumeration consistently reveals staging environments, internal admin panels, API gateways, and forgotten WordPress installs that are softer targets than the production site.

## When to Use

- Starting recon on any target domain.
- Production site is well-secured — find softer entry points.
- After `wp-mass-recon` — enumerate subdomains for each WordPress target.
- Building a complete asset inventory for a target organization.

## Prerequisites

- `terminal` tool with curl, httpx, dig, jq.
- `subfinder` available on the worker container.
- Wordlist for DNS brute force at `/root/tools/subdomains.txt`.

## How to Run

```bash
DOMAIN="example.com"

# Passive: crt.sh
curl -sk "https://crt.sh/?q=%25.$DOMAIN&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crtsh.txt

# Passive: subfinder
subfinder -d "$DOMAIN" -silent > subfinder.txt

# Merge and deduplicate
cat crtsh.txt subfinder.txt | sort -u > all_subs.txt

# Probe live hosts
httpx -silent -l all_subs.txt -threads 50 -status-code -tech-detect -title -o alive.txt
```

## Quick Reference

| Source | Method | Coverage | Speed |
|--------|--------|----------|-------|
| crt.sh | Certificate transparency | Excellent (most certs) | Fast (1-5s) |
| subfinder | Passive APIs (VirusTotal, Shodan, DNSdumpster, etc.) | Very good | Fast (30-60s) |
| dig bruteforce | DNS A/AAAA/CNAME resolution | Good (uncovers non-HTTP) | Medium (5-15 min) |
| httpx probe | Live HTTP/HTTPS check | Best for web attack surface | Fast (30-60s) |
| Google dork | `site:example.com` | Supplemental | Manual |

## Procedure

### Step 1 — Passive Enumeration (crt.sh + subfinder)

```bash
DOMAIN="$1"
OUTDIR="/root/output/subdomains/$DOMAIN"
mkdir -p "$OUTDIR"

echo "[*] Passive enumeration for $DOMAIN..."

# crt.sh — certificate transparency logs
echo "[*] crt.sh query..."
curl -sk --max-time 30 "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
  jq -r '.[].name_value' 2>/dev/null | \
  sed 's/\*\.//g' | \
  sed 's/^www\.//' | \
  sort -u > "$OUTDIR/crtsh.txt"

crt_count=$(wc -l < "$OUTDIR/crtsh.txt")
echo "  crt.sh: $crt_count entries"

# Also query with %25. (wildcard)
curl -sk --max-time 30 "https://crt.sh/?q=%25.%25.$DOMAIN&output=json" 2>/dev/null | \
  jq -r '.[].name_value' 2>/dev/null | \
  sed 's/\*\.//g' | \
  sort -u > "$OUTDIR/crtsh_wildcard.txt"

# subfinder — passive API aggregation
echo "[*] subfinder..."
subfinder -d "$DOMAIN" -silent -timeout 30 2>/dev/null | sort -u > "$OUTDIR/subfinder.txt"
subf_count=$(wc -l < "$OUTDIR/subfinder.txt")
echo "  subfinder: $subf_count entries"

# Merge all passive sources
cat "$OUTDIR"/crtsh.txt "$OUTDIR"/crtsh_wildcard.txt "$OUTDIR"/subfinder.txt 2>/dev/null | \
  sed 's/^www\.//' | \
  grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' | \
  sort -u > "$OUTDIR/all_passive.txt"

total=$(wc -l < "$OUTDIR/all_passive.txt")
echo ""
echo "[+] Total unique subdomains (passive): $total"
```

### Step 2 — DNS Resolution

```bash
DOMAIN="$1"
OUTDIR="/root/output/subdomains/$DOMAIN"

echo "[*] Resolving subdomains..."

# Batch resolve with dig (faster than individual lookups)
while read -r sub; do
  dig +short "$sub" A 2>/dev/null | grep -v '^$' | while read -r ip; do
    echo "$sub => $ip"
  done
done < "$OUTDIR/all_passive.txt" > "$OUTDIR/resolved.txt"

resolved=$(wc -l < "$OUTDIR/resolved.txt")
echo "[+] $resolved subdomains resolved to IPs"

# Count unique IPs
unique_ips=$(awk '{print $3}' "$OUTDIR/resolved.txt" | sort -u | wc -l)
echo "[+] $unique_ips unique IPs"

# Identify shared hosting (many subdomains → same IP)
echo ""
echo "[*] Shared hosting clusters:"
awk '{print $3}' "$OUTDIR/resolved.txt" | sort | uniq -c | sort -rn | head -10 | while read -r count ip; do
  [[ "$count" -gt 1 ]] && echo "  $ip: $count subdomains"
done
```

### Step 3 — Live Host Discovery

```bash
DOMAIN="$1"
OUTDIR="/root/output/subdomains/$DOMAIN"

echo "[*] Probing live hosts..."

# httpx with tech detection
httpx -silent -l "$OUTDIR/all_passive.txt" -threads 50 \
  -status-code -tech-detect -title -location \
  -o "$OUTDIR/alive.txt" 2>/dev/null

alive=$(wc -l < "$OUTDIR/alive.txt")
echo "[+] $alive live hosts"

# Categorize by status code
echo ""
echo "[*] By HTTP status:"
echo "  200: $(grep -c '\[200\]' "$OUTDIR/alive.txt")"
echo "  301/302: $(grep -cE '\[301\]|\[302\]' "$OUTDIR/alive.txt")"
echo "  403: $(grep -c '\[403\]' "$OUTDIR/alive.txt")"
echo "  404: $(grep -c '\[404\]' "$OUTDIR/alive.txt")"

# Categorize by technology
echo ""
echo "[*] By technology:"
grep -oP '\[[a-z-]+\]' "$OUTDIR/alive.txt" | tr -d '[]' | sort | uniq -c | sort -rn | head -15

# WordPress subdomains
echo ""
echo "[*] WordPress subdomains:"
grep -i 'wordpress' "$OUTDIR/alive.txt" | awk '{print $1}' | head -10

# Non-HTTP services (from DNS resolution)
echo ""
echo "[*] Interesting non-standard ports from DNS (MX, NS, etc.):"
dig +short "$DOMAIN" MX 2>/dev/null | head -5
dig +short "$DOMAIN" NS 2>/dev/null | head -5
dig +short "$DOMAIN" TXT 2>/dev/null | grep -i 'spf\|v=spf' | head -3
```

### Step 4 — Subdomain Categorization

```bash
DOMAIN="$1"
OUTDIR="/root/output/subdomains/$DOMAIN"

echo "[*] Categorizing subdomains..."

# Staging/Dev
echo ""
echo "=== STAGING / DEV ==="
grep -iE 'staging|stage|dev\.|development|test|uat|beta|sandbox|preview|qa' "$OUTDIR/all_passive.txt"

# Admin/Internal
echo ""
echo "=== ADMIN / INTERNAL ==="
grep -iE 'admin|portal|internal|dashboard|manage|cp\.|control|panel|cpanel|webmail|mail\.' "$OUTDIR/all_passive.txt"

# API
echo ""
echo "=== API ==="
grep -iE 'api|rest|graphql|ws\.|websocket' "$OUTDIR/all_passive.txt"

# Infrastructure
echo ""
echo "=== CDN / STATIC ==="
grep -iE 'cdn|static|assets|media|img|images|files|download|origin|proxy' "$OUTDIR/all_passive.txt"

# Email
echo ""
echo "=== EMAIL ==="
grep -iE 'mail\.|smtp|imap|pop|email|webmail|autodiscover' "$OUTDIR/all_passive.txt"

# Cloud
echo ""
echo "=== CLOUD ==="
grep -iE 'aws|azure|gcp|cloud|s3|bucket|firebase' "$OUTDIR/all_passive.txt"

# Legacy
echo ""
echo "=== LEGACY / OLD ==="
grep -iE 'old|old\.|v1|v2|legacy|archive|backup|bak' "$OUTDIR/all_passive.txt"
```

### Step 5 — Subdomain Takeover Check

```bash
DOMAIN="$1"
OUTDIR="/root/output/subdomains/$DOMAIN"

echo "[*] Checking for subdomain takeover opportunities..."

# Check for dangling CNAMEs (subdomains pointing to non-existent services)
while read -r sub; do
  cname=$(dig +short "$sub" CNAME 2>/dev/null)
  if [[ -n "$cname" ]]; then
    # Check if the CNAME target resolves
    cname_ip=$(dig +short "$cname" A 2>/dev/null)
    if [[ -z "$cname_ip" ]]; then
      echo "[TAKEOVER?] $sub => $cname (NOT RESOLVING)"

      # Identify provider from CNAME
      if echo "$cname" | grep -qi 'amazonaws.com'; then
        echo "  Provider: AWS (S3/CloudFront) — check if bucket/domain is claimable"
      elif echo "$cname" | grep -qi 'azure'; then
        echo "  Provider: Azure — check if resource is claimable"
      elif echo "$cname" | grep -qi 'github.io'; then
        echo "  Provider: GitHub Pages — check if repo name is available"
      elif echo "$cname" | grep -qi 'herokuapp.com'; then
        echo "  Provider: Heroku — check if app name is available"
      elif echo "$cname" | grep -qi 'vercel-dns.com'; then
        echo "  Provider: Vercel — check if project is claimable"
      elif echo "$cname" | grep -qi 'zendesk.com'; then
        echo "  Provider: Zendesk — check if help desk is claimable"
      fi
    fi
  fi
done < "$OUTDIR/all_passive.txt"
```

## Pitfalls

- **crt.sh rate limiting.** crt.sh may return empty JSON if rate-limited. Use delays or query the PostgreSQL dump directly.
- **subfinder requires API keys.** Some sources (VirusTotal, Shodan) require API keys in `~/.config/subfinder/provider-config.yaml`. Without them, results are limited.
- **Wildcard DNS.** If `*.example.com` resolves to the same IP, all subdomains will appear "live" in httpx. Check for wildcard by resolving a random string: `dig RANDOMSTRING.example.com`.
- **Cloudflare proxying.** Subdomains behind Cloudflare will show Cloudflare IPs, not origin IPs. Use SecurityTrails or DNSDumpster for historical DNS records.

## Verification

- Every subdomain MUST be probed with httpx to confirm it serves HTTP/HTTPS.
- Resolved IPs MUST be cross-referenced with known CDN IPs (Cloudflare, CloudFront, Fastly) to avoid mistaking CDN IPs for origin.
- Subdomain takeover candidates MUST have their CNAME target manually verified as unclaimed.
- All live subdomains should be documented with: URL, HTTP status, technology stack, and page title.
