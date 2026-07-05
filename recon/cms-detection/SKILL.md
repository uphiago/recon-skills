---
name: cms-detection
description: Identify CMS, frameworks, and server technology stacks on live hosts.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires httpx, whatweb, wappalyzer, curl
metadata:
  tags: [recon, CMS, fingerprinting, technology, WordPress, Drupal, Joomla, Magento]
  category: recon
  related_skills:
    - web-enumeration
    - wordpress-plugin-hunt
    - visual-recon
    - wp-mass-recon
---

# CMS Detection

Identify the content management system, web framework, server software, and technology stack of every live host. Know which stack you're attacking before you attack it — a WordPress site needs different tests than a Laravel API or a Spring Boot microservice. Multi-CMS detection covers WordPress, Drupal, Joomla, Magento, Shopify, Wix, Squarespace, Laravel, Django, Express, Spring Boot, and more.

## When to Use

- You have a list of alive hosts and need to categorize them by technology.
- WordPress-specific tests produced false positives (the site uses Drupal).
- Need to identify which CMS version is running to match against known CVEs.
- A host returns generic 200 on all paths — technology detection tells you what it actually runs.
- Want to find sites running outdated versions of popular CMS platforms.

## Prerequisites

- `terminal` tool with httpx, whatweb, wappalyzer, and curl.
- A list of alive subdomains from `visual-recon` or `subdomain-enumeration`.

## Quick Detection

```bash
# Fastest: httpx with built-in tech detection
cat alive_subs.txt | httpx -silent -tech-detect -o tech_detect.txt

# Deep: whatweb with aggressive checks
whatweb -i alive_subs.txt -a 3 -t 50 --log-brief=cms_results.txt
```

## Procedure

### Phase 1 — Bulk Technology Fingerprinting

```bash
# httpx — fast tech detection using Wappalyzer signatures
cat alive_subs.txt | httpx -silent -tech-detect -o tech_httpx.txt

# Parse results: extract unique technologies with counts
cat tech_httpx.txt | awk -F' [' '{print $2}' | tr -d ']' | tr ',' '\n' \
  | sed 's/^ *//' | sort | uniq -c | sort -rn > tech_summary.txt

# whatweb — deeper, identifies specific CMS versions
whatweb -i alive_subs.txt -a 3 -t 50 \
  --log-brief=cms_results.txt \
  --log-json=cms_results.json

# Parse whatweb JSON for versioned findings
cat cms_results.json | jq -r '.[] | select(.version != null) | "\(.target): \(.plugin) \(.version)"' \
  | sort -u > versioned_cms.txt
```

### Phase 2 — CMS-Specific Version Detection

#### WordPress

```bash
# Generator meta tag
curl -sk "https://target.com" | grep -oP '<meta name="generator"[^>]*content="WordPress [^"]+' | head -1

# RSS feed
curl -sk "https://target.com/feed/" | grep -oP '<generator>https://wordpress.org/\?v=[^<]+' | head -1

# readme.html (often left accessible)
curl -sk "https://target.com/readme.html" | grep -oP "Version [0-9.]+" | head -1

# wp-json namespace
curl -sk "https://target.com/wp-json/" | jq -r '.namespaces[]' 2>/dev/null
```

#### Drupal

```bash
# CHANGELOG.txt (Drupal's canonical version leak)
curl -sk "https://target.com/CHANGELOG.txt" | head -5

# Drupal specific paths
curl -skI "https://target.com/user/login" | grep -i "drupal\|x-generator"
curl -skI "https://target.com/node/1"
```

#### Joomla

```bash
# Joomla version files
curl -sk "https://target.com/administrator/manifests/files/joomla.xml" | grep -oP '<version>[^<]+' | head -1
curl -sk "https://target.com/language/en-GB/en-GB.xml" | grep -oP '<version>[^<]+'

# Meta tag
curl -sk "https://target.com" | grep -oP '<meta name="generator"[^>]*content="Joomla[^"]+' | head -1
```

#### Magento

```bash
# Magento version file
curl -sk "https://target.com/magento_version" | head -1
# Composer lock
curl -sk "https://target.com/composer.lock" | jq -r '.packages[] | select(.name=="magento/magento2-base") | .version' 2>/dev/null
```

#### Laravel

```bash
# Laravel debug info
curl -sk "https://target.com" | grep -oP 'Laravel v[0-9.]+'
# Composer lock
curl -sk "https://target.com/composer.lock" | jq -r '.packages[] | select(.name=="laravel/framework") | .version' 2>/dev/null
```

### Phase 3 — Server and Framework Detection

```bash
# Server header — often removed but check anyway
for host in $(cat alive_subs.txt); do
  echo -n "$host: "
  curl -skI "https://$host" | grep -i "server:\|x-powered-by:" | tr '\n' ' '
  echo
done > server_headers.txt

# Common server signatures and what they mean
# nginx → likely PHP-FPM or Node.js proxy
# Apache → shared hosting, cPanel
# IIS → Windows, ASP.NET
# LiteSpeed → shared hosting, WordPress optimized
# cloudflare → CDN/WAF in front, need origin-ip-discovery
# Microsoft-IIS/10.0 → Windows Server 2016+

# Framework detection via specific paths
# Django admin: /admin/ → redirect to /admin/login/
# Rails: /assets/application-*.js pattern
# Express: X-Powered-By: Express
# Spring Boot: /actuator/health returns {"status":"UP"}
# Next.js: /_next/static/ chunks
```

### Phase 4 — Technology Stack Categorization

```bash
# Categorize hosts by CMS for targeted testing
echo "=== WORDPRESS ==="
grep -i "wordpress" tech_detect.txt

echo "=== DRUPAL ==="
grep -i "drupal" tech_detect.txt

echo "=== OTHER CMS ==="
grep -iE "joomla|magento|shopify|wix|squarespace|ghost" tech_detect.txt

echo "=== FRAMEWORKS ==="
grep -iE "laravel|django|rails|express|spring|next\.js|nuxt" tech_detect.txt

echo "=== E-COMMERCE ==="
grep -iE "woocommerce|magento|shopify|prestashop|opencart" tech_detect.txt

echo "=== NO CMS (Static/Custom) ==="
cat alive_subs.txt | httpx -silent -td \
  | grep -v -iE "wordpress|drupal|joomla|magento|laravel|django|rails"
```

### Phase 5 — Version → CVE Mapping

```bash
# Map detected versions to known CVEs
# WordPress: check https://wpscan.com/wordpress-security/vulnerability-database/
# Drupal: check https://www.drupal.org/security
# Magento: check https://magento.com/security/patches

# searchsploit — local ExploitDB search
searchsploit wordpress 6.5
searchsploit drupal 10.2
searchsploit joomla 5.1

# nuclei — automated CVE detection on detected CMS
nuclei -l wordpress_sites.txt -t nuclei-templates/http/cves/2024/
```

## Pitfalls

- **Generator meta tags can be spoofed.** A site claiming "WordPress 7.0" may be running 6.5. Cross-check with readme.html or RSS feed.
- **Technology detection is signature-based.** Custom themes may strip or modify signatures.
- **CDN caching may serve stale version info.** Force cache bypass with random query parameters.
- **whatweb can trigger WAF blocks on aggressive scans.** Use `-a 2` (less aggressive) on protected targets.
- **Headless CMS (Strapi, Contentful) has no version file.** Look for API endpoints instead.

## Verification

1. At least two independent methods confirm the same CMS/version (meta tag + readme + wp-json).
2. Version-specific paths exist (e.g., `/wp-admin/` for WordPress, `/user/login` for Drupal).
3. Framework-specific endpoints respond correctly (e.g., `/actuator/health` for Spring Boot).
4. Document: hostname, CMS, version, detection method, and whether the version has known CVEs.

## Related Skills

- **`web-enumeration`** — Once CMS is identified, enumerate its specific paths and endpoints.
- **`wordpress-plugin-hunt`** — Deep plugin version detection for WordPress targets.
- **`wp-mass-recon`** — Batch WordPress vulnerability scanning.
- **`visual-recon`** — Confirm CMS detection with visual screenshot verification.
- **`deep-invade`** — Run nuclei CVE scans against detected versions.
