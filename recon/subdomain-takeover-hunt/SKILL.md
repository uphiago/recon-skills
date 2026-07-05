---
name: subdomain-takeover-hunt
description: Detect and verify subdomain takeover via dangling CNAME to unclaimed services.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, python3, subfinder, dnsx
metadata:
  tags: [recon, subdomain, takeover, CNAME, DNS, cloud, Heroku, S3, Azure]
  category: recon
  related_skills:
    - subdomain-enumeration
    - origin-ip-discovery
    - port-service-discovery
---

# Subdomain Takeover Detection

Detect subdomains pointing to unregistered or unclaimed third-party cloud services. When a CNAME record points to a service that no longer exists, an attacker can register that resource and serve arbitrary content under the target's subdomain — enabling phishing, cookie theft, and full origin impersonation.

## When to Use

- Subdomain enumeration produces a large list — scan for lingering DNS records.
- Target uses cloud services with shared-namespace identifiers (Heroku, S3, Azure, Zendesk, Shopify).
- A subdomain returns NXDOMAIN, 404, or "no such app" error pages.
- The CNAME target is a service with user-registrable names.

## Prerequisites

- `terminal` tool with curl, dnsx, subfinder.
- `subzy` or `subjack` installed for automated detection.
- List of alive subdomains from `subdomain-enumeration`.

## Quick Detection

```bash
# DNS resolution with CNAME extraction
dnsx -retry 3 -a -cname -resp -silent -l alive_subs.txt | tee dns_records.txt

# Automated takeover scan
subzy run --targets alive_subs.txt --hide_fails --vuln
```

## Procedure

### Phase 1 — Extract CNAME Records

```bash
# Get all CNAME records
cat alive_subs.txt | dnsx -silent -cname -resp-only > cname_targets.txt

# Filter to suspicious services
grep -iE "heroku|s3\.amazonaws|azure|zendesk|shopify|github\.io|bitbucket|surge\.sh|netlify|vercel|ghost\.io|readme|statuspage|pantheon|desk\.com|campaignmonitor|intercom|unbounce|wordpress\.com|cargo\.collective" \
  cname_targets.txt > takeover_candidates.txt
```

### Phase 2 — Automated Detection

```bash
# subzy — fast, shows vulnerable + fingerprint
subzy run --targets alive_subs.txt --hide_fails --vuln

# subjack — with custom fingerprints
subjack -w alive_subs.txt -t 100 -timeout 30 -o takeover_results.txt \
  -ssl -c ~/subjack/fingerprints.json -v

# nuclei — takeover templates
nuclei -l alive_subs.txt \
  -t nuclei-templates/takeovers/ \
  -o nuclei_takeover_results.txt
```

### Phase 3 — Manual Verification

```bash
# For each candidate, verify the service is claimable
CANDIDATE="api.target.com"

# Check what the CNAME points to
dig $CANDIDATE CNAME +short

# Check HTTP response
curl -skI "https://$CANDIDATE" | head -10

# Key service-specific verification:

# Heroku: visit https://CANDIDATE — "no such app" = claimable
# S3: curl -s https://BUCKET_NAME.s3.amazonaws.com — 404 NoSuchBucket = claimable
# Zendesk: visit https://CANDIDATE — "account not found" = claimable
# GitHub Pages: dig CNAME returns user.github.io — 404 = claimable
# Azure: visit https://CANDIDATE — "tenant not found" = claimable
# Shopify: visit https://CANDIDATE — "Sorry, this shop is currently unavailable"
```

### Phase 4 — S3 Takeover Pipeline

```bash
subfinder -d target.com -silent \
  | dnsx -silent -cname \
  | grep "s3.amazonaws" \
  | while read line; do
      sub=$(echo "$line" | awk '{print $1}' | sed 's/\.$//')
      curl -sk "https://$sub" | grep -q "NoSuchBucket" && echo "CLAIMABLE: $sub"
    done
```

### Phase 5 — Service Fingerprint Reference

| Service | Error message or indicator | Claimable signal |
|---|---|---|
| Heroku | "No such app" / "There's nothing here" | Yes |
| S3 | "NoSuchBucket" / "The specified bucket does not exist" | Yes |
| Azure | "tenant not found" / "This tenant is not found" | Yes |
| Zendesk | "account not found" / "Help Center Closed" | Yes |
| GitHub Pages | 404 "There isn't a GitHub Pages site here" | Yes |
| Shopify | "Sorry, this shop is currently unavailable" | Yes |
| Netlify | "Not Found" / "Site not found" | Yes |
| Vercel | 404 — "DEPLOYMENT_NOT_FOUND" | Yes |
| Bitbucket | "Repository not found" | Yes |
| Surge.sh | "project not found" | Yes |
| Readme.io | "Project not found" | Yes |
| Statuspage | 404 — status page not found | Yes |
| Desk.com | "This site is currently not available" | Yes |
| Campaign Monitor | "Trying to get your email from" | Yes |
| Intercom | "This page is reserved for Intercom customers" | Yes |
| Unbounce | "The requested URL was not found" | Yes |
| WordPress.com | "Do you want to register domain.wordpress.com?" | Yes |

## Pitfalls

- **Resolving CNAME to a CDN service is not a finding.** Cloudflare/CloudFront/Akamai subdomains are not claimable.
- **The CNAME may point to a valid, in-use service.** Always verify the error page before claiming a finding.
- **Some services block automated scanners.** Visit the URL in a browser to confirm.
- **Subdomain takeover requires registration of the target resource.** Never register resources without explicit authorization.
- **Wildcard DNS (`*.target.com` → IP) produces false positives.** Filter out wildcard responses before scanning for takeover.

## Verification

1. `dig SUBDOMAIN CNAME +short` returns a service with user-registrable namespace.
2. `curl -sk https://SUBDOMAIN` returns the service-specific error page indicating the resource is available.
3. The CNAME target is NOT resolving to a CDN or load balancer.
4. Document the exact error message and service type before reporting.

## Related Skills

- **`subdomain-enumeration`** — Generate the subdomain list for takeover scanning.
- **`origin-ip-discovery`** — If takeover is found, check if the same IP hosts other services.
- **`port-service-discovery`** — Scan the CNAME-resolved IP for additional exposed services.
