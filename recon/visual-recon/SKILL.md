---
name: visual-recon
description: Screenshot all live hosts for rapid visual triage and technology fingerprinting.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires gowitness, httpx, python3
metadata:
  tags: [recon, screenshot, visual, triage, fingerprinting, technology]
  category: recon
  related_skills:
    - subdomain-enumeration
    - web-enumeration
    - cms-detection
    - port-service-discovery
---

# Visual Recon

Automatically screenshot every live host to triage hundreds of subdomains visually instead of manually opening each one. Combined with technology fingerprinting, this reveals technology stacks, default CMS install pages, admin panels, and misconfigured services at a glance. Process 500+ hosts in minutes and identify high-value targets by visual inspection.

## When to Use

- You have 100+ live subdomains and need to prioritize targets quickly.
- Manual browsing is too slow for bulk reconnaissance.
- Need to identify default install pages (WordPress setup, phpMyAdmin login, Jenkins dashboard).
- Want to compare visual fingerprints across subdomains (shared infrastructure).
- Target serves different content based on User-Agent or geolocation.

## Prerequisites

- `terminal` tool with gowitness, httpx, and curl.
- `gowitness` installed: `go install github.com/sensepost/gowitness@latest`.
- A list of alive subdomains from `subdomain-enumeration`.

## Quick Start

```bash
gowitness file -f alive_subs.txt -P ./screenshots/ --no-http
```

## Procedure

### Phase 1 — Mass Screenshot Capture

```bash
# gowitness — fast, Go-based screenshot tool
gowitness file -f alive_subs.txt \
  -P ./screenshots/ \
  --no-http \
  --timeout 15 \
  --resolution-x 1440 \
  --resolution-y 900

# With database for searchable results
gowitness file -f alive_subs.txt -P ./screenshots/ --no-http \
  --db gowitness.db --chrome-window-x 1440 --chrome-window-y 900

# Query results
gowitness report list --db gowitness.db
gowitness report generate --db gowitness.db

# eyewitness — with HTML report generation
python3 EyeWitness.py \
  -f alive_subs.txt \
  --web \
  -d ./eyewitness_output/ \
  --timeout 15 \
  --no-prompt
```

### Phase 2 — Headless Mode for JS-Rendered Sites

```bash
# Single-page applications need JS execution
gowitness single -u https://target-spa.com \
  -P ./screenshots/ \
  --chrome-window-x 1440 --chrome-window-y 900

# Batch headless capture
cat spa_urls.txt | while read url; do
  gowitness single -u "$url" -P ./screenshots/
done
```

### Phase 3 — Visual Analysis Patterns

Review screenshots for high-value patterns:

```bash
# Extract all titles from screenshots for quick filtering
gowitness report list --db gowitness.db \
  | grep -iE "login|admin|dashboard|setup|install|phpmyadmin|jenkins|grafana|api|dev|staging|test"

# Look for default error pages (identifies specific web servers)
gowitness report list --db gowitness.db \
  | grep -iE "404|403|502|503|default|maintenance|under construction"
```

**What to look for:**

| Screenshot shows | Meaning |
|---|---|
| WordPress install page | Fresh WordPress — test registration on /wp-admin/install.php |
| phpMyAdmin login | Database access panel — try default creds |
| Jenkins login | CI/CD server — check for unauthenticated access |
| Grafana/Prometheus | Monitoring dashboard — check for public data |
| IIS default page | Windows server — check for ASP.NET endpoints |
| Apache default page | Standard Linux server — check for server-status |
| Error stack traces | Debug mode enabled — extract server paths and versions |
| Directory listing | Readable file tree — check for config files |
| Login form on custom port | Internal admin panel — highest priority target |

### Phase 4 — Visual Diffing (Multi-Environment)

```bash
# Compare screenshots across subdomains to find shared infrastructure
# Same visual = shared server = if one is vulnerable, all are

ls screenshots/ | cut -d'-' -f1 | sort | uniq -c | sort -rn
# High count of identical-looking sites = mass vulnerability potential
```

### Phase 5 — Technology Fingerprinting from Screenshots

```bash
# whatweb — identifies CMS, frameworks, servers
whatweb -i alive_subs.txt -a 3 -t 50 --log-brief=cms_results.txt

# wappalyzer CLI — detailed tech stack
wappalyzer https://target.com

# httpx with tech detection built-in
cat alive_subs.txt | httpx -silent -tech-detect -o tech_detected.txt

# Extract unique technologies
cat tech_detected.txt | awk -F'[' '{print $2}' | tr -d ']' | tr ',' '\n' \
  | sort | uniq -c | sort -rn
```

### Phase 6 — Screenshot-Based Triage Pipeline

```bash
# Full pipeline: subdomains → alive → screenshot → filter → prioritize
cat all_subs.txt \
  | httpx -silent -mc 200 -o alive_200.txt

gowitness file -f alive_200.txt -P ./screenshots/ --no-http

# Generate report for manual review
gowitness report generate --db gowitness.db -o ./report/

# Extract login/admin pages for priority testing
gowitness report list --db gowitness.db \
  | grep -iE "login|admin|sign.?in|dashboard|panel|manage" \
  > priority_targets.txt
```

## Pitfalls

- **Large screenshot batches can overwhelm disk.** 500 screenshots at 1440x900 ≈ 300MB.
- **JS-heavy SPAs may render as blank.** Use headless mode with longer timeout.
- **Redirect chains produce screenshots of the redirect target.** This is correct — you want the final destination.
- **CAPTCHA pages waste screenshots.** Filter CAPTCHA hosts before screenshotting.
- **Timeout on slow servers.** `--timeout 15` is usually sufficient; increase for slow connections.

## Verification

1. Screenshots exist for all hosts in `alive_subs.txt`.
2. Visual inspection confirms each screenshot shows meaningful content (not blank, not error).
3. Technology detection matches the visual fingerprint (WordPress favicon = WordPress CMS).
4. Priority targets (login panels, admin dashboards, dev environments) are identified and moved to next phase.

## Related Skills

- **`subdomain-enumeration`** — Generate the list of alive subdomains.
- **`web-enumeration`** — Deep dive into individual hosts found via screenshots.
- **`cms-detection`** — Automated CMS and framework detection on discovered hosts.
