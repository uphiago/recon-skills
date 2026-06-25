# Wave 9 — Sector Vulnerability Rankings & Empirical Data

**Source:** Wave9 recon analysis across 600+ US SMB domains, 28+ sectors
**Updated:** 2026-06-24

---

## Sector Vulnerability Rankings (by breach rate)

| Rank | Sector | Vulnerability Rate | Key Weakness |
|------|--------|-------------------|--------------|
| 1 | **Locksmiths** | 66% (2/3) | Old WP sites, XMLRPC, CORS, no WAF |
| 2 | **HVAC** | 33% (1/3) | WordPress + CORS + XMLRPC complete chain |
| 3 | **Churches** | 25% (1/4) | Hillsong CORS, others Cloudflare-protected |
| 4 | **Window cleaning** | 25% (1/4) | WordPress + CORS + XMLRPC |
| 5 | **Septic services** | 25% (1/4) | Heavy source leaks, CORS reflect |
| 6 | **Law firms** | 25% (5/20) | Shared hosting, no WAF, WP user dump |
| 7 | **Pest control** | 20% (3/15) | WP + CORS credential reflection |
| 8 | **Bakery** | 18% (2/11) | Mainly Cloudflare-protected, LOW findings only |
| 9 | **Fire restoration** | 17% (1/6) | rainbowrestores.com — WP exposed |
| 10 | **Carpet cleaning** | 17% (1/6) | chemdry.com — WP exposed |

**ZERO vulnerability sectors** (compliance works):
- Banks (0/20) — FDIC/OCC compliance
- Credit unions (0/19) — NCUA compliance
- Major healthcare (0/20) — HIPAA compliance
- Insurance (0/10) — State insurance regulation

**Key insight:** Vulnerability correlates more with **hosting provider** than sector. GoDaddy shared hosting = worst posture. Cloudflare/WP Engine = REST blocked but CORS may still work. Enterprise hosting = generally secure.

---

## Empirical Rate Limiting Data

| Action | Likelihood | Details |
|--------|-----------|---------|
| REST /wp/v2/users x 20/min | Low | No limits on GoDaddy/Hostinger |
| REST /wp/v2/* x 50/min | Medium | ~100/min triggers Jetpack/WP Engine throttle |
| XMLRPC system.listMethods | Very Low | Almost never rate limited |
| XMLRPC system.multicall | Very Low | Single request even with 1000 passwords |
| Source leak paths | Low | Different URLs per request — hard to detect as pattern |
| XMLRPC brute force sequential | High | Many sequential POSTs to same endpoint trigger limits |
| Error log download | Very Low | Single GET request |
| Cloudflare REST endpoint | Always blocked | 429 on wp-json/wp/v2/users — no bypass found |

---

## User Agent Block Rates (empirical, 200+ targets)

| User Agent | Block Rate | Notes |
|-----------|-----------|-------|
| Chrome/125 macOS | 0% (0/200) | Best overall — never blocked |
| Chrome/125 Windows | 0% (0/200) | Tied with macOS |
| Firefox/126 | 0% (0/50) | Small sample |
| Safari/17.4 | 0% (0/50) | Small sample |
| curl/8.4 | 5% (10/200) | Blocked by GoDaddy/Cloudflare |
| Python urllib | 15% (30/200) | Blocked by Cloudflare/WP Engine |
| Googlebot | 0% (0/200) | But returns different content on some sites |

---

## Most Exploitable Vulnerability Combinations

| Combo | Impact | Examples | Difficulty |
|-------|--------|---------|------------|
| WP Users + CORS + XMLRPC multicall | Full ATO | completeheatandair, restonic | Easy |
| WP Users + CORS (alone) | Data exfiltration | 20+ targets | Trivial |
| Open Reg + wp.uploadFile + exec | RCE | wines.com | Medium |
| XMLRPC multicall brute (1000x) | Credential discovery | 10+ targets | Medium |
| MySQL open + CORS | Full data breach | patientportal.com | Easy |
| Error log credential mining | Credential discovery | wines.com | Medium |
| Staging install page | Staging takeover | biglots staging | Medium |
| CORS + corporate email | Spear-phishing | defy.com, vikingpest | Medium |

---

## Top Leakiest Sites (10+ leaked files)

| Domain | Sector | Leaked Files |
|--------|--------|-------------|
| maaco.com | Auto repair | 20 |
| ridx.com | (unknown) | 20 |
| septictank.com | Septic services | 20 |
| gerbercollision.com | Auto body | 18 |
| fishwindowcleaning.com | Window cleaning | 17 |
| windowcleaner.com | Window cleaning | 4 |
| windowgang.com | Window cleaning | 3 |
| septic.com | Septic services | 3 |

---

## Technique Inventory — Success/Failure

| Technique | Status | Notes |
|-----------|--------|-------|
| WP REST user enum | ✅ Working | No auth needed on shared hosting |
| CORS origin reflection | ✅ Working | 20+ targets confirmed |
| CORS null origin reflection | ✅ New (Wave6) | familydental.com confirmed |
| XMLRPC system.multicall brute | ✅ Working | 10+ confirmed |
| XMLRPC pingback SSRF | ✅ Working (IMDS = WIP) | faultCode 0 but no body return |
| Plugin REST namespace probe | ✅ Working (Wave8) | Confirms plugin even on 401/404 |
| Error log deep mining | ✅ Working (Wave8) | PII+SQL from wines.com 896MB log |
| MySQL banner grab | ✅ Working (Wave8) | Version + OS from patientportal.com |
| Staging install page check | ✅ Working (Wave8) | biglots staging install.php exposed |
| JS API key extraction | ✅ Working (Wave7) | patientportal.com AIzaSy key |
| .git/HEAD .git/config | ❌ False positives | SPA catch-all routing returns HTML |
| IMDS via pingback | ❌ No body return | pingback doesn't relay SSRF response |
| Default credential testing | ❌ 0/200+ targets | Passwords extinct since WP 5.0+ |
