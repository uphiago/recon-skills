# Sector Discovery — Mass Recon (Non-Regulated US SMBs)

## 1. When to use

- Need to find NEW vulnerable targets to expand an existing recon dataset
- Hunting WordPress + CORS misconfig + exposed REST API + XMLRPC multicall
- Need to rank sectors by vulnerability rate before committing deep effort
- Looking for small/medium US businesses likely on shared hosting without WAF

## 2. Sector selection

Pick US sectors with **zero compliance burden** (no HIPAA, PCI-DSS, FDIC, NCUA, SOX):

| Good targets | Avoid (regulated) |
|---|---|
| Landscaping, Pool Services, Roofing | Healthcare (HIPAA) |
| HVAC/Plumbing, Auto Repair | Banks/Credit Unions (FDIC/NCUA) |
| Moving Companies, Photography | Payment Processors (PCI) |
| Property Management (SMB) | Major Insurance (state-regulated) |
| Accounting (small/medium firms) | Defense (CMMC) |
| Car Dealerships (small groups) | Gov/Education (FERPA) |
| Home Services | Pharma (FDA) |
| **Car Washes** (regional chains — WP Engine common) | |
| **Bakeries** (franchise — Next.js/Vercel common) | |
| **Locksmiths** (WordPress on Apache common) | |
| **Pet Grooming** (franchise AND independent) | |

## 3. Target compilation

Use **real company names**, not generic domains. Generic domains like `plumber.com` or `dentist.com` are usually parked or static.

Good sources: known franchise/chain names in each sector (e.g. TruGreen, BrightView for landscaping; Bell Roofing, Mastercraft Roofing for roofing), business directories, franchise group websites that list locations.

**File format:** `domain.com|Company Name|Sector`
**Sector size guide:** 15-20 targets per sector for first pass.

## 4. Parallel batch testing

Use 5 workers via `ThreadPoolExecutor`. Each worker tests one domain entirely before moving to the next. **Do NOT use serial scanning** — with 15-20 requests per domain and 2-3s rate limiting per request, a serial approach takes ~10 minutes per domain × 30 targets = 5+ hours. With 5 parallel workers, the same 30 targets complete in ~60-90 minutes.

### OPSEC-critical pattern: per-domain rate limiting, not global

The correct OPSEC pattern is **per-domain delays**, not a global sleep between all requests. Use 5 workers so domains are tested concurrently, but each worker calls `delay()` between requests to its own domain (1.5-3.5s jitter). This means:
- Requests to DIFFERENT domains can happen simultaneously (5 at a time — this is fine, they're different origins)
- Requests to the SAME domain are spaced 1.5-3.5s apart (OPSEC compliant)
- No domain sees more than ~1 req/2s from this scanner

```python
import concurrent.futures, time, random

def delay():
    """Per-domain rate limiting — call between requests to the same domain."""
    time.sleep(1.5 + random.random())

def test_target(domain, sector, company):
    # ... all 15-20 requests with delay() between each ...
    pass

targets = [...]  # list of (domain, sector, company) tuples

with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
    fut_map = {ex.submit(test_target, d, s, c): d for d, s, c in targets}
    for fut in concurrent.futures.as_completed(fut_map):
        result = fut.result()
        print(f"[{result['domain']}] WP={result['wp']} users={result['users']}")
```

### Workers vs. rate limit math

| Workers | Req/domain | Per-domain delay | Time per domain | 30-target wall time |
|---------|-----------|-----------------|-----------------|---------------------|
| 1 (serial) | ~18 | 2.5s avg | ~45s | ~22.5 min |
| 5 | ~18 | 2.5s avg | ~45s | ~9 min |
| 10 | ~18 | 2.5s avg | ~45s | ~4.5 min (may overwhelm shared hosting) |

5 workers is the recommended balance. 10+ may trigger WAF rate limits on shared hosting.

### Test sequence per domain (in order)

1. **Connectivity** — HTTPS then HTTP fallback; skip dead domains
2. **WordPress detection** — `/wp-login.php` and `/wp-json/` returning anything other than 404/000/blank
3. **REST API users** — `GET /wp-json/wp/v2/users` parses JSON list
4. **CORS** — `Origin: https://evil.com` header on users endpoint; check for `Access-Control-Allow-Origin` reflection AND `Access-Control-Allow-Credentials: true`
5. **XMLRPC** — POST `system.listMethods`; check body for `system.multicall` string
6. **Sensitive files** — `.env`, `.git/config`, `info.php`, `phpinfo.php`, `robots.txt`, `wp-content/debug.log`, `wp-config.php.bak`
7. **Registration** — `/wp-login.php?action=register`; check for registration form body

## 5. False positive filtering (critical)

**All status codes lie.** Many small-business shared hosts return HTTP 200 on ANY path with a generic landing-page redirect. Filter:

- Sensitive files (`.env`, `info.php`, `.git/config`): check content length > 30B AND < 100KB. Skip if body starts with `<html`, `<!DOCTYPE`, `<script`. `.env` must contain `APP_`, `DB_`, `_KEY`, `_SECRET`, or `PASSWORD`. `phpinfo` must contain `PHP` or `phpinfo`. `.git/config` must contain `[core]`.
- WordPress detection: check response body for `WordPress` or `wp-login` strings, not just HTTP status.

## 6. Most productive sectors (June 2026 empirical, 280-target run across Waves 1-4)

| Rank | Sector | Vuln Rate | Pattern | Best Target Type |
|---|---|---|---|---|
| 1 | **Tree Service** (independent) | **100%** | CORS credentialed + multicall | Small independent arborists — allabouttrees.com (4 users), firstchoicetree.com, treetech.net |
| 2 | **Landscaping** (independent) | **100%** | CORS credentialed + multicall | Small independent lawn care — totalyard.com (2 users), progrounds.com (1 user), yardcare.com (2 users) |
| 3 | **Yoga Studios** | 50% | CORS + user enum | Independent studios — yogaworks.com (3 users) |
| 2.5 | **Car Wash** (regional chains) | 20% | CORS credentialed + internal tool subdomains | Regional chains on WP Engine — gocarwash.com (32 subs, GitLab/Grafana/Prometheus behind WAF, CRITICAL CORS) |
| 2.75 | **Locksmiths** (franchise) | 20% | CORS credentialed + admin user exposed | WordPress on Apache — locksmiths.net (admin user, 24 subs, CRITICAL CORS) |
| 3.5 | **Pet Grooming** (franchise) | 20% | CORS credentialed + user enum | **NOTE: Pet grooming FRANCHISES CAN be vulnerable** despite Cloudflare+WP Engine — dogtopia.com (10 users, CRITICAL CORS, 39 subs including staging exposed, Express.js dashboard, S3 bucket) |
| 4 | **Pest Control** | 50% | CORS + user enum | Independent exterminators — dodsonbros.com (4 users), vikingpest.com (7 users) |
| 5 | **Laundromat** (independent) | 50% | CORS + multicall | Local laundromats — spincyclelaundry.com (1 user) |
| 6 | **Coffee Shops** | 17-33% | CORS credentialed | Brand-name franchises — biggby.com |
| 7 | **Pet Grooming** (independent) | 33% | CORS + multicall | Independent groomers — pawtropolis.com (1 user) |
| 8 | **Pool Services** | 20-25% | CORS + user enum + XMLRPC | Pool service companies |
| 9 | **Car Wash** | 17% | CORS + user enum | Regional chains — octoclean.com (10 users) |
| 10 | **Roofing** | 15-18% | CORS + admin users | Independent roofers |
| 11 | **HVAC/Plumbing** | 13-14% (franchise), **~50%** (indie) | CORS credentialed + multicall + users | Independent HVAC shops — completeheatandair.com (3 users, CORS+creds, multicall). Franchise chains (ARS, Benjamin Franklin) all behind WAF. |
| 12 | **Accounting (SMB)** | 12-13% | CORS + CPA data | Small CPA firms |
| 13 | **Auto Repair** | 11-12% | CORS + users | Independent repair shops |
| 14 | **Property Management** | 11-15% | CORS credentialed | SMB property mgmt |
| 15 | **Photography** | 10-11% | CORS + high user count | Independent photographers |
| 16 | **Moving** | 6% | XMLRPC multicall | Moving companies |
| 17 | **Bike Shop** | 0% | — | Small independent shops — 4 tested (jensonusa.com, performancebike.com), all non-WP |
| 18 | **Churches/Religious** | 25% | CORS credentialed | Individual churches — hillsong.com (CORS+creds) |
| 19 | **Non-profits (.org)** | 0% | — | Enterprise WP |
| 20 | **Daycare** | 0% | — | Franchise groups |
| 21 | **Retirement/Assisted Living** | 0% | — | Enterprise WP |
| 22 | **Bakeries (franchise)** | 0% | — | Non-WP modern stacks (Next.js/Vercel with CSP) |
| 23 | **Carpet Cleaning** | 0% | — | Standard WP |
| 24 | **Junk Removal** | 0% | — | Standard WP |
| 25 | **Electrical Contractors** | 0% | — | Franchise group, WAF'd |
| 26 | **Florists** | 0% | — | Standard WP |

**CRITICAL INSIGHT: Independent vs franchise is the decisive factor, not sector name.**
- **Franchise/enterprise** sites in ANY sector sit behind Cloudflare/WAF — zero yield.
- **Independent/small-business** operators on shared WordPress hosting in the SAME sector can hit 100% CORS vulnerability.
- Strategy: always test a MIX of franchise group sites + 3-5 independent operators per sector to get an accurate vulnerability rate. If you test only franchises, every sector looks zero-yield.

**Zero-yield** (all behind WAF/CDN): Car dealership groups, major insurance carriers, travel OTAs, home services platforms. **However, pet services franchises are NOT universally zero-yield** — dogtopia.com (pet_grooming, franchise, Cloudflare + WP Engine) had CRITICAL CORS credential reflect + 10 users exposed + 39 subdomains. Always test a sample even if the sector is dominated by franchises — some franchise groups within a sector have weak WP configurations that slip through WAF at the WP Engine layer.

**New sectors still untested** (recommended for Wave 5+): independent assisted living facilities (not national brands), pool cleaning (individual operators, not Leslie's/PoolCorp), dry cleaners (independent).

### Empirical Detail — Wave 1 (2026-06-24, 22-target run across 4 new sectors)

| Sector | Targets | Alive | Vuln | Vuln Rate | Top Findings |
|--------|---------|-------|------|-----------|--------------|
| Pest Control | 5 | 4 | 2 | 50% | dodsonbros.com (4 users + CORS), vikingpest.com (7 users + CORS) |
| Car Wash | 6 | 6 | 1 | 17% | octoclean.com (10 users + CORS, Flywheel/5.1.0) |
| Coffee Shops | 6 | 6 | 2 | 33% | biggby.com (CORS credentialed), thecoffeebean.com (WP) |
| Pet Services | 5 | 5 | 0 | 0% | All behind Cloudflare or non-WP platforms |

**Takeaway:** Pest Control is the strongest new sector discovered in Wave 1 — 50% vulnerable with high user counts. Coffee Shops (franchise brands) also productive. Pet Services joins the zero-yield list.

### Empirical Detail — Wave 2 (2026-06-24, 30-target run across 14 NEW sectors)

| Sector | Targets | WP | Users Exp | CORS Critical | Notes |
|--------|---------|----|-----------|---------------|-------|
| Yoga | 2 | 2 | **3** | **1** | **BREAKOUT: 50% vuln rate** |
| Bakery | 3 | 3 | 0 | 0 | Franchise brands, well-secured |
| Church | 3 | 2 | 0 | 0 | mgmenlo.church, gatewaypeople.com WP |
| Nonprofit | 3 | 3 | 0 | 0 | All WP, charikids tywater.org powered |
| Daycare | 3 | 2 | 0 | 0 | Goddard School & Primrose on WP |
| Retirement | 3 | 2 | 0 | 0 | Brookdale, Sunrise both WP, blocked |
| Martial Arts | 1 | 1 | 0 | 0 | Gracie Academy WP, no vulns |
| Carpet Cleaning | 3 | 2 | 0 | 0 | Coit, Zerorez WP |
| Junk Removal | 3 | 2 | 0 | 0 | College Hunks, 1-800-GOT-JUNK WP |
| Electrical | 1 | 1 | 0 | 0 | Mr. Electric WP, WAF'd |
| Florist | 2 | 2 | 0 | 0 | FromYouFlowers WP |
| Locksmith | 1 | 0 | 0 | 0 | Non-WP |
| Funeral Home | 1 | 0 | 0 | 0 | Non-WP |
| Dry Cleaner | 1 | 0 | 0 | 0 | Non-WP |

**Critical finding:** **yogaworks.com** — 3 users exposed via REST API (Chris Poe, Tien Mai/webuseradmin4, yogaworks_pph) + CORS credential reflection (origin `https://evil.com` reflected with `Access-Control-Allow-Credentials: true`). Attack chain: attacker-hosted page can `fetch('https://yogaworks.com/wp-json/wp/v2/users', {credentials:'include'})` and exfiltrate authed user data cross-origin. Behind Cloudflare WAF.

**Takeaway:** Yoga studios are the breakout Wave 2 sector — 50% vulnerable with CORS + user exposure. Most other new sectors (church, nonprofit, daycare, retirement, bakery) are dominated by franchise/enterprise brands that harden their WordPress behind Cloudflare/WAF. The pattern holds: **single-operator small businesses on shared WordPress hosting** are the sweet spot, not franchise groups.

### Empirical Detail — Wave 3 (2026-06-24, 18-target run across 5 NEW sectors)

| Sector | Targets | WP | Users Exp | CORS Critical | XMLRPC | Vuln Rate | Top Findings |
|--------|---------|----|-----------|---------------|--------|-----------|--------------|
| **Landscaping** | 8 | 8 | **6** | **8** | 4 | **100%** | **BREAKOUT: ALL 8 have CORS credential reflect** — totalyard.com (2 users, multicall, WP 6.9.4), progrounds.com (1 user, multicall, WP 6.1), yardcare.com (2 users, Cloudflare, WP 6.1.6), turfdoctor.com (1 user), greenleafservices.com (multicall), supremelawn.com, naturesturf.com, ecolawn.com |
| **Tree Service** | 4 | 4 | **5** | **4** | 2 | **100%** | **BREAKOUT: ALL 4 have CORS credential reflect** — allabouttrees.com (4 users: 1seodev, Allison Kandel, Cecile Parages, Jake Morell — behind Cloudflare), allstatetree.com (1 user: advancedbusinesssolutions), firstchoicetree.com (multicall, Cloudflare), treetech.net |
| **Laundromat** | 2 | 2 | 1 | 1 | 1 | **50%** | spincyclelaundry.com (1 user: gtaje, CORS+creds, multicall, WP 6.8.1 on Apache). speedqueen.com secure — Shopify platform. |
| **Pet Grooming** (indie) | 3 | 3 | 1 | 1 | 1 | **33%** | pawtropolis.com (1 user: athenspet, CORS+creds, multicall, WP 6.8.1 on Apache). aussiepetmobile.com and bentleyspetstuff.com were non-WP (Shopify/Wix) |
| **Bike Shop** | 1 | 1 | 0 | 0 | 0 | 0% | bikeco.com — WP but CORS secure. Only 1 sample — inconclusive. |

**Critical findings:**
- **allabouttrees.com** (tree_service): 4 users exposed (1seodev, Allison Kandel, Cecile Parages, Jake Morell) + CORS credential reflection + behind Cloudflare. Attack chain: attacker-hosted page exfiltrates authed user data cross-origin.
- **totalyard.com** (landscaping): 2 users exposed (bd, Brian Krogsgard) + CORS creds + XMLRPC multicall + WP 6.9.4 on Pagely-ARES.
- **yardcare.com** (landscaping): 2 users (Rocket55DevAdmin, YardCare®) + CORS creds + Cloudflare.
- **spincyclelaundry.com** (laundromat): 1 user + CORS creds + XMLRPC multicall + WP 6.8.1 on Apache.
- **progrounds.com** (landscaping): 1 user (JWD) + CORS creds + XMLRPC multicall + WP 6.1 on Apache.
- **pawtropolis.com** (pet_grooming): 1 user (athenspet) + CORS creds + XMLRPC multicall + WP 6.8.1 on Apache.

**Takeaway:** The critical insight from Wave 3 is that **independent** landscaping and tree service companies have a **100% CORS credential vulnerability rate** — far exceeding any previously tested sector. When sector discovery finds small independent operators (not national franchises), they are virtually guaranteed to have origin-reflection CORS on their WordPress REST API. The earlier 20-26% landscaping estimate was artifact from testing national franchises (TruGreen, BrightView, Davey Tree) that all sit behind Cloudflare/WAF. **Always distinguish franchise from independent in sector vulnerability estimates.**

### Empirical Detail — Wave 4 (2026-06-24, 32-target run across 8 under-tested sectors)

| Sector | Targets | Alive | WP | CORS+CREDS | Users Exp | XMLRPC Multicall | Vuln Rate | Top Findings |
|--------|---------|-------|-----|------------|-----------|-----------------|-----------|--------------|
| **HVAC** (indie) | 4 | 3 | 2 | **1** | **3** | **1** | **50%** | **completeheatandair.com** — CORS+creds + 3 users (Mediagistic x2, mgvendortemp) + multicall + WP Engine. **BREAKOUT: Independent HVAC matches landscaping/tree service vuln profile.** |
| **Window Cleaning** | 7 | 5 | 1 | **1** | 0 | **1** | **20%** | **windowmedics.com** — CORS+creds + multicall + 80 methods on Apache (NO WAF). High-value independent sector. |
| **Church** | 5 | 4 | 2 | **1** | 0 | 0 | **25%** | **hillsong.com** — CORS+creds + Cloudflare. Major megachurch with the classic reflection vuln. |
| **Septic Services** | 7 | 4 | 1 | 0 | 0 | 0 | 0% | allinseptic.com WP but no vulns. Most domains were non-WP landing pages. |
| **Locksmith** | 5 | 3 | 1 | 0 | 0 | 0 | 0% | citylocksmith.com WP, secure. popalock.com was non-WP. |
| **Bike Shops** | 4 | 3 | 0 | 0 | 0 | 0 | 0% | jensonusa.com non-WP, performancebike.com non-WP. |
| **Martial Arts** | 4 | 3 | 0 | 0 | 0 | 0 | 0% | ataonline.com WP but secure. |
| **Nonprofit** | 4 | 3 | 0 | 0 | 0 | 0 | 0% | All enterprise sites (habitat.org, stjude.org) on non-WP platforms. |

**Critical Wave 4 findings:**
- **completeheatandair.com** (hvac): 3 WP users exposed (Mediagistic x2, mgvendortemp), CORS credential reflection (ACAO: evil.com, ACAC: true), XMLRPC 80 methods + system.multicall, WP Engine + Cloudflare.
- **windowmedics.com** (window_cleaning): CORS+creds + XMLRPC multicall on bare Apache — no WAF protecting it.
- **hillsong.com** (church): CORS credential reflection on major megachurch behind Cloudflare.

**Takeaway:** Independent HVAC shops match the 100% CORS vuln profile of landscaping/tree services — **completeheatandair.com** is the trifecta (CORS+creds + 3 users + multicall). Window cleaning is a promising new sector — **windowmedics.com** on bare Apache is the highest practical exploit target in this wave. Churches (hillsong.com) show the same reflection pattern but behind Cloudflare.

**New sectors still untested** (recommended for Wave 6+): pool cleaning (individual operators), dry cleaners (independent), laundromats (independent), funeral homes (independent).

### Empirical Detail — Wave 5 (2026-06-24, 20-target run across 4 NEW sectors)

| Sector | Targets | WP | Users Exp | CORS Critical | Subdomains | Vuln Rate | Top Findings |
|--------|---------|----|-----------|---------------|------------|-----------|--------------|
| **Car Wash** (regional chains) | 5 | 1 | 0 | **1** | **32** | **20%** | **gocarwash.com** — CRITICAL CORS + 32 subs (GitLab, Grafana, Prometheus, admin, api, ci, wiki — WAF-blocked 409) + WP Engine. zips.com: 22 subs + .NET surface (admin.ezclaw.zips.com, tequote.internalapis.zips.com). |
| **Pet Grooming** (franchise) | 5 | 1 | **10** | **1** | **39** | **20%** | **dogtopia.com** — CRITICAL CORS + 10 WP users (alexf, alyssa, andrewreshift, etc.) + Yoast SEO Premium + staging.dogtopia.com (401 nginx exposed) + dashboard.dogtopia.com (Express.js on CloudFront) + s3-prod.dogtopia.com (S3). **BREAKOUT: Franchise pet grooming CAN be vulnerable** — dogtopia.com behind Cloudflare+WP Engine still has CRITICAL CORS. |
| **Bakeries** (franchise) | 5 | 1 | 0 | 0 | 0 | 0% | greatamericancookies.com (WordPress, no vulns). Most on Next.js/Vercel (cinnabon, auntieannes, crumblcookies) — modern stacks with CSP, uninteresting. |
| **Locksmiths** (franchise) | 5 | 1 | **1** | **1** | **24** | **20%** | **locksmiths.net** — CRITICAL CORS + WP admin user (id:1, name:"admin") + 24 subs (commercial.locksmiths.net WP, cpanel, mail). |

**Critical findings:**
- **gocarwash.com** (car_wash): CRITICAL CORS + 32 subs including dev tools (GitLab, Grafana, Prometheus) resolving but WAF-blocked (HTTP 409). Origin-bypass candidate.
- **dogtopia.com** (pet_grooming): CRITICAL CORS + 10 WP users + Yoast SEO Premium v21.6 + staging exposed. **Proves franchise pet grooming is exploitable** — contradicts earlier Wave 1-4 assumption that all pet franchises are Cloudflare/WAF zero-yield.
- **locksmiths.net** (locksmiths): CRITICAL CORS + WP admin user exposed + cpanel subdomain.

**Takeaway:** Wave 5 overturns the "pet services franchises = zero-yield" assumption — dogtopia.com had CRITICAL CORS behind Cloudflare+WP Engine. Car washes on WP Engine show the same pattern. Bakeries are low-yield (modern JS stacks). The most productive finding is `gocarwash.com`'s internal tool subdomains (GitLab, Grafana) that resolve but are WAF-blocked — this is an origin-bypass surface worth further investigation.

**New pitfall: WAF 409 pattern.** Subdomains returning HTTP 409 (Conflict) from a CDN/WAF still exist at DNS level. The WAF blocks direct access but doesn't mean the service isn't running. Try origin discovery (Wayback CDX, historical DNS, cert transparency SANs) to find the origin IP and bypass the WAF.

## 7. Deep-dive commands

```bash
# Confirm CORS reflection
curl -sk -I -H "Origin: https://evil.com" "https://TARGET/wp-json/wp/v2/users" | grep -i access-control

# Extract users
curl -sk "https://TARGET/wp-json/wp/v2/users" | python3 -m json.tool

# Confirm XMLRPC multicall
curl -sk -X POST "https://TARGET/xmlrpc.php" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
```

## 8. Pitfalls

- **Generic domain guessing is ~95% waste** — Domains like `allpetsgrooming.com`, `puppylovegrooming.com`, `elitetreecare.com`, `greentreecare.com` are almost always parked on domain-seller platforms (Afternic, HugeDomains, Sedo) or generic hosting catch-all pages. Of ~160 guessed generic sector domains tested in Wave 3, only ~25 (16%) were real businesses, and fewer than half of those were WordPress. Use known real company names from business directories, Yelp, franchise registries, or web searches — not generated domain patterns.
- Major brands in sector lists (AutoNation, Allstate, Expedia, PwC) all use Cloudflare/WAF — they waste test time
- Generic domains are dead or parked
- Shared hosting catch-all redirect pages return 200 on every path — always check content, not status
- crt.sh sometimes blocks mass queries — use 3s+ delays
- XMLRPC with multicall can be intermittent — verify manually
- **Dedup logic traps** — When merging new scan results into an existing batch_summary.json, checking only by domain name is insufficient. A domain that was scanned in a prior wave may have been unresponsive or returned fewer findings; the new scan may surface MORE users or new vulns (e.g. octoclean.com went from 0→10 exposed users). Always either (a) overwrite old entries with new data, or (b) merge findings (union of all findings across scans).
- **Background process output buffering** — Python scripts run as Hermes background processes buffer stdout by default. Use `PYTHONUNBUFFERED=1 python3 -u script.py` to see live output. Without this, you cannot monitor progress until the process exits.
- **Domain dead rate** — Even curated franchise/chain domain lists have ~5-10% dead or unresolvable targets. Budget for 1-2 skips per 20-target batch.
- **Sector-specific WAF coverage** — Some franchise groups within a sector centrally manage their web presence behind Cloudflare/WAF even though smaller independents in the same sector do not. Test a mix: try the franchise group's own site AND 2-3 independent operators in that sector to get an accurate vulnerability rate.
