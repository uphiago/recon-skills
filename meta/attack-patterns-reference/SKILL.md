---
name: attack-patterns-reference
description: "Catalog: 25 attacks, 18 WP, 8 CORS to match findings."
version: 1.1.0
author: uphiago
license: MIT
metadata:
  hermes:
    tags: [meta, reference, patterns, bypass, catalog]
    category: meta
    related_skills:
      - wp-mass-recon
      - cors-credential-wordpress
      - xmlrpc-exploitation
      - cross-attack-chains
      - deep-invade
      - error-log-mining
      - source-leak-hunt
      - phpinfo-to-rce
      - port-service-discovery
      - js-secrets-extraction
      - staging-subdomain-hunt
      - subdomain-enumeration
      - wordpress-plugin-hunt
      - web-enumeration
---

# Attack Patterns Reference Skill

Comprehensive reference catalog of 25 attack patterns (P-01 through P-25), 18 WordPress abuse patterns (WP-01 through WP-18), and 8 CORS bypass variants (V1 through V8). Distilled from 600+ targets across 28 sectors and 9 waves of reconnaissance. Use this as a lookup table when you encounter a specific scenario and need the right technique.

## When to Use

- You've found a specific vulnerability and need to know all exploitation paths.
- Cross-referencing findings to build attack chains.
- Learning — understand the full taxonomy of WordPress/web recon techniques.
- When `cross-attack-chains` skill needs the raw pattern catalog.
- After `wp-mass-recon` — match findings to pattern IDs for structured reporting.

## How to Run

This is a reference skill — it has no executable commands. Load it alongside any recon or chain skill to identify which attack patterns match your findings. Match pattern IDs from your findings report (e.g., "P-02 confirmed") against the catalog below to find exploitation paths, related patterns, and real-world examples.

## Prerequisites

- No specific tools required — this is a reference document.
- Pair with `security-arsenal` skill for actual payloads.

## Quick Reference

See the Pattern Catalog below for the full P-01 through P-25 attack pattern index with detection commands, frequency, severity ratings, and exploitation guidance. The WordPress Abuse Patterns (WP-01 to WP-18) table provides exact curl commands for each pattern. The CORS Bypass Variants (V1 to V8) table tracks confirmed targets across waves.

## Procedure

This is a reference skill with no executable commands:

1. Identify your finding's behavior against the P-01 through P-25 catalog.
2. Match WordPress-specific findings against the WP-01 through WP-18 table.
3. For CORS findings, classify the variant type using the V1 through V8 table.
4. Cross-reference patterns to build chains using `cross-attack-chains`.
5. Apply the Failed/Saturated Patterns list to avoid wasting time on dead ends.

## Pattern Catalog

### General Attack Patterns (P-01 to P-25)

| ID | Pattern | Severity | Skill |
|----|---------|----------|-------|
| P-01 | WP REST API User Enumeration | Medium | wp-mass-recon |
| P-02 | CORS Origin Reflection + Credentials | Critical | cors-credential-wordpress |
| P-03 | CORS Null Origin Trust | High | cors-credential-wordpress |
| P-04 | CORS Wildcard (No Credentials) | Info | cors-credential-wordpress |
| P-05 | CORS Credentialed Preflight Bypass | High | cors-credential-wordpress |
| P-06 | CORS on Auth-Protected Endpoints | Critical | cors-credential-wordpress |
| P-07 | XMLRPC system.multicall Brute Force | High | xmlrpc-exploitation |
| P-08 | XMLRPC pingback.ping SSRF | High | xmlrpc-exploitation |
| P-09 | XMLRPC IMDS Role Guessing | Critical | xmlrpc-exploitation |
| P-10 | Open Registration → Upload → RCE | Critical | xmlrpc-exploitation + phpinfo-to-rce |
| P-11 | Plugin REST Namespace Brute Force | Variable | wordpress-plugin-hunt |
| P-12 | Yoast Author Sitemap Enumeration | Low | wp-mass-recon |
| P-13 | Staging Weaker Security | Variable | staging-subdomain-hunt |
| P-14 | Staging WordPress Install Pages | Critical | staging-subdomain-hunt |
| P-15 | Error Log Credential Mining | High-Critical | error-log-mining |
| P-16 | PHPInfo Exec Function Check | High | phpinfo-to-rce |
| P-17 | Source Leak Mass Scan | Critical | source-leak-hunt, web-enumeration |
| P-18 | JS Bundle Secret Extraction | Critical | js-secrets-extraction |
| P-19 | MySQL Port 3306 Public | Critical | port-service-discovery |
| P-20 | Internal Microservice Ports Exposed | High | port-service-discovery + api-noauth-hunt |
| P-21 | WooCommerce API Presence | Medium | wordpress-plugin-hunt |
| P-22 | Elementor 500 Leak | Medium | wordpress-plugin-hunt |
| P-23 | Same-Hosting Clustering | Variable | recon-playbook |
| P-24 | IAM Role Brute Force via SSRF | Critical | xmlrpc-exploitation |
| P-25 | WP CORS on ALL REST Endpoints | Critical | cors-credential-wordpress |

Full descriptions, commands, and exploitation paths: [`references/p-patterns.md`](references/p-patterns.md)

### WordPress Abuse Patterns (WP-01 to WP-18) — with exact commands

| ID | Pattern | Exact Command | Skill |
|----|---------|---------------|-------|
| WP-01 | Direct REST user enum | `curl -sk "https://TARGET/wp-json/wp/v2/users" \| jq '.[] \| {id,name,slug}'` | wp-mass-recon |
| WP-02 | Auth user info leak | `curl -sk "https://TARGET/wp-json/wp/v2/users?context=edit"` | cors-credential-wordpress |
| WP-03 | Yoast sitemap author leak | `curl -sk "https://TARGET/author-sitemap.xml"` | wp-mass-recon |
| WP-04 | XMLRPC method enum | `curl -sk -X POST "https://TARGET/xmlrpc.php" -H "Content-Type: text/xml" -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'` | xmlrpc-exploitation |
| WP-05 | XMLRPC multicall BF | POST with `<methodName>system.multicall</methodName>` containing 100+ `wp.getUsers` calls (1000x amplification) | xmlrpc-exploitation |
| WP-06 | XMLRPC pingback SSRF | POST `<methodName>pingback.ping</methodName>` targeting IMDS/localhost | xmlrpc-exploitation |
| WP-07 | Open registration check | `curl -sk "https://TARGET/wp-login.php?action=register" \| grep -c "user_login"` (must also match "register" + "wp-submit") | wp-mass-recon |
| WP-08 | Plugin namespace discovery | Brute-force 40+ REST namespaces (`/wp-json/{plugin}/v1/`) | wordpress-plugin-hunt |
| WP-09 | Plugin version via readme | `curl -sk "https://TARGET/wp-content/plugins/PLUGIN/readme.txt" \| grep "Stable tag"` | wordpress-plugin-hunt |
| WP-10 | Plugin directory listing | `curl -sk "https://TARGET/wp-content/plugins/PLUGIN/"` | wordpress-plugin-hunt |
| WP-11 | Staging takeover | `curl -sk "https://staging.TARGET/wp-admin/install.php"` (check for "WordPress" + "installation" in body) | staging-subdomain-hunt |
| WP-12 | Debug log exposure | `curl -sk "https://TARGET/wp-content/debug.log"` | error-log-mining |
| WP-13 | Backup file discovery | `curl -sk "https://TARGET/backup.sql"` (verify DDL/DML content, not SPA catch-all) | source-leak-hunt |
| WP-14 | Site Health endpoint | `curl -sk "https://TARGET/wp-json/wp-site-health/v1"` | deep-invade |
| WP-15 | ACF plugin field probe | `curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/wp-json/acf/v3"` | wordpress-plugin-hunt |
| WP-16 | Redirection plugin log | `curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/wp-json/redirection/v1/log"` | error-log-mining |
| WP-17 | SolidWP Mail log export | `curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/wp-json/solidwp-mail/v1/logs"` | wordpress-plugin-hunt |
| WP-18 | Gravity Forms API | `curl -sk "https://TARGET/wp-json/gf/v2/"` | wordpress-plugin-hunt |

### CORS Bypass Variants (V1 to V8) — with real confirmed targets

| ID | Variant | Detection | Exploitability | Confirmed Target | Wave |
|----|---------|-----------|----------------|-----------------|------|
| V1 | Origin reflection + creds | `ACAO: evil.com` + `ACAC: true` | Critical — full credentialed cross-origin read | yardcare.com, restonic.com, toolking.com, wines.com | W1-W9 |
| V2 | Null origin reflection | `ACAO: null` + `ACAC: true` | High — sandboxed iframe bypass | familydental.com | W6 |
| V3 | Wildcard no creds | `ACAO: *` (no creds) | Info only — public data, no cookies | patientportal.com, nothingbundtcakes.com, autobell.com | W5 |
| V4 | Credentialed preflight | OPTIONS returns ACAC + valid origin | High — GET bypass when OPTIONS works | Multiple WP endpoints | W8 |
| V5 | Auth-endpoint CORS | CORS on endpoints returning 401/403 | Critical — cookie theft even from auth-gated APIs | restonic.com gf/v2 (401 but ACAO+ACAC reflect) | W7 |
| V6 | Multi-origin reflection | Any origin reflected | Critical — broadest attack surface | realpro.com | W6 |
| V7 | Plugin-specific CORS | CORS only on plugin namespace (not wp/v2) | Medium — plugin data only | defy.com gravity-pdf/v1 | W5 |
| V8 | Staging-only CORS | Production no CORS, staging reflects | Medium — dependent on staging access | staging.biglots.com | W5 |

### Non-Standard Pattern: Third-Party CORS Reflection
**moldmedics.com (Wave6):** ACAO reflects `https://octaneforms.com` — NOT evil.com. Indicates misconfigured third-party integration where the server hardcodes the wrong origin. Not directly exploitable but signals poor CORS hygiene and potential for exploitation of the third-party service instead.

## Sector Attack Matrices

### Tier 1 Sectors (Highest Yield: 15-25% vulnerability rate)

**Law Firms (25%):**
- Top patterns: WP-01 (user enum), P-06 (CORS auth endpoints), P-17 (source leaks).
- Common plugins: none (minimal, brochure sites).
- Notes: Often hosted on shared platforms. Check for attorney email exposure.

**Pest Control (20%):**
- Top patterns: WP-01, P-02 (CORS reflection), P-08 (XMLRPC SSRF).
- Notes: Franchise model → many subdomain targets.

**Landscaping (20-26%):**
- Top patterns: WP-01, P-02, P-17 (source leaks).
- Common plugins: Elementor, essential grid.
- Notes: Highest raw number of vulnerable targets due to sector size.

**Pool Services (20-25%):**
- Top patterns: WP-01, P-02, P-17.
- Notes: Similar profile to landscaping — small business, DIY WordPress.

### Tier 2 Sectors (Medium Yield: 10-15%)

**Dental Clinics (15%), Gyms (15%), Real Estate (15%), Roofing (15-18%), HVAC/Plumbing (14%), Auto Repair (11%), Photography (10%), Funeral Homes (10%):**
Funeral homes: WordPress + user enum (funeralwise.com: 7 users, memorialplanning.com: 4 users). CRUD at rest.

### Tier 3 Sectors (Low/Zero Yield)

**Car Dealerships (0%), Furniture Retail (0%), Insurance (0%), Travel Agencies (0%):**
Furniture retail: 11/15 major brands (Ashley, Wayfair, Crate&Barrel, Pottery Barn) behind Cloudflare/WAF returning 403/429. Only smaller brands (bassettfurniture.com, cityfurniture.com) alive — both clean.

## Cross-Wave Evolution

| Wave | Date | New Techniques | Key Discovery |
|------|------|---------------|---------------|
| 1-3 | Early | WP-01, WP-04, P-02 | WordPress + CORS is epidemic |
| 4 | Mid | 13 sector recon skills | Standardized skill format |
| 5 | Mid | P-13, P-18, P-11 | Staging is the soft underbelly |
| 6 | Late | P-08 (SSRF confirmed), P-15 | Error logs = treasure maps |
| 7 | Late | P-09 (IMDS guessing), P-12 | Deep probes beat surface scans |
| 8 | Late | P-14 (install pages), P-22 | Forgotten installs = free real estate |
| 9 | Mid | P-01 through P-25 catalogued | 25 patterns, 18 WP patterns, 8 CORS variants |\n| 10-12 | Current | Funeral homes (10% WP vuln rate), Furniture retail (0% — WAF wall) | Restonic/Realpro XMLRPC still active (false regression from curl -L); 6/7 critical targets persist |

## Pitfalls

- **Pattern IDs are for internal tracking, not for reporting.** Map patterns to CWE/CVSS IDs for client deliverables.
- **A pattern match is not a vulnerability.** You need exploitation and impact demonstration beyond detection.
- **CORS wildcard (V3) is not submittable alone.** Only valuable when chained with data exposure that proves impact.
- **Failed patterns are tested and confirmed dead ends.** Don't revisit them without new intelligence.
- **Cross-wave evolution means patterns age.** Pre-2024 patterns may no longer work on modern WP versions.

## Verification

- Every pattern must be matched against findings with the exact detection command.
- CORS variants must be confirmed with browser PoC (not just curl headers).
- Attack patterns are only useful when chained — see `cross-attack-chains` for combining patterns.
- A pattern without exploitation is reconnaissance, not a finding.

## Attack Chain Compositions (10 confirmed chains)

| Chain | Steps | Severity | Targets Confirmed | Difficulty |
|-------|-------|----------|-------------------|------------|
| CORS Phishing | CORS → browser PoC → data exfil | HIGH | 20+ targets | Trivial |
| CORS + User Enum → ATO | CORS → user list → spear-phish → admin hijack | HIGH-CRIT | 5 deep targets | Easy |
| XMLRPC multicall BF | multicall → 1000x brute → WP admin | HIGH | 10+ targets | Easy |
| SSRF → IMDS → AWS creds | pingback → IMDSv1 → IAM role → AWS takeover | CRITICAL | biglots staging, realpro | Medium |
| Open Reg → Upload → RCE | register → wp.uploadFile → webshell → shell_exec | CRITICAL | wines.com | Medium |
| CORS + Plugin CVE → RCE | CORS discover plugin → version detect → CVE exploit | CRITICAL | toolking.com SliderRev | Medium |
| Error Log → Creds → Admin | error_log mine → DB creds → WP admin login | HIGH | wines.com | Medium |
| Staging Takeover | crt.sh subdomain → install.php 200 → site seize | CRITICAL | biglots staging | Medium |
| MySQL Open + CORS | 3306 scan → brute MySQL → dump + API exfil | CRITICAL | patientportal.com | Easy |
| Yoast Sitemap + XMLRPC | author-sitemap.xml → user enum → XMLRPC BF → admin | HIGH | multiple | Medium |

## Failed/Saturated Patterns (8 — do NOT invest time on these)

1. **Default credential testing** — WordPress auto-generates random passwords since v5.0. admin:admin doesn't exist.
2. **.git/HEAD on SPA sites** — catch-all routing returns HTML, not git data. Always verify with `.git/config` content.
3. **CORS on non-WordPress sites** — ALL non-WP targets tested (Next.js, Shopify, Sitecore, Drupal, static) were CORS-SECURE. Don't waste time.
4. **SliderRev v1 REST exploitation** — v6.x renamed all endpoints. ALL v1 paths returned 404 on toolking.com. Probe both `/sliderrevolution/v1/` AND `/revslider/v1/`.
5. **Google API key exploitation** — Most JS bundle keys are restricted (all returned `REQUEST_DENIED` in Wave7). Only useful for footprinting, not exploitation.
6. **Gravity Forms unauth access** — v2.8+ requires authentication. The days of public `/gf/v2/forms` returning entries are over.
7. **IMDS data via pingback** — faultCode 0 confirms reachability but NEVER returns body data. Need OOB callback for proof.
8. **WP install page on production** — This is only found on STAGING environments. Production sites have it blocked or already configured.
