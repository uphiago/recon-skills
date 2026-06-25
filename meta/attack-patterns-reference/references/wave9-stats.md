# Wave 9 Recon Statistics — Reference Data

**Source:** 146 domains across 20 sectors, 331 findings files, 7 deep targets (9 waves).
**Used with:** `attack-patterns-reference` skill for pattern frequency context.

## Per-Sector Target Count (from all_targets.txt)

| Sector | Targets |
|--------|---------|
| travel_agencies | 10 |
| roofing | 10 |
| property_management | 10 |
| plumbing_hvac | 10 |
| photography | 10 |
| moving_companies | 10 |
| landscaping | 10 |
| insurance | 10 |
| car_dealerships | 10 |
| accounting | 10 |
| auto_repair | 10 |
| bakery | 10 |
| window_cleaning | 4 |
| septic_services | 4 |
| church | 4 |
| martial_arts | 3 |
| locksmith | 3 |
| hvac | 3 |
| bike_shop | 3 |
| nonprofit | 2 |

## Pattern Frequency

| Pattern | Rate | Notes |
|---------|------|-------|
| WP REST users (P-01) | ~9% of all targets, ~25% of WP sites | Most consistent finding |
| CORS credential reflection (P-02) | ~7-8% of WP sites | ~20+ confirmed across waves |
| CORS wildcard (P-04) | ~3% of all sites | Info only |
| XMLRPC open (P-07) | ~52% of WP sites | SHUTTING DOWN — most regressions W8->W9 |
| Source leaks 3+ files (P-17) | ~7% | nothingbundtcakes.com had 28 |

## Cross-Wave Findings Evolution

| Wave | Key Discovery |
|------|--------------|
| 1-3 | WordPress + CORS is epidemic |
| 4 | 13 sector recon skills, standardized format |
| 5 | Staging is the soft underbelly (staging.biglots.com) |
| 6 | SSRF confirmed via pingback, error logs = treasure |
| 7 | IMDS role guessing, Yoast sitemap fallback enum |
| 8 | WP install pages, Elementor 500 leak |
| 9 | 25 patterns cataloged, 8 CORS variants, 10 chains |

## CORS Variant Confirmation Spread

| Variant | Confirmed On |
|---------|-------------|
| V1 (Origin reflection + creds) | yardcare.com, restonic.com, toolking.com, wines.com, realpro.com, defy.com |
| V2 (Null origin) | familydental.com |
| V3 (Wildcard no creds) | patientportal.com, nothingbundtcakes.com, autobell.com |
| V4 (Credentialed preflight) | Multiple WP endpoints |
| V5 (Auth-endpoint CORS) | restonic.com gf/v2 |
| V6 (Multi-origin) | realpro.com |
| V7 (Plugin-specific) | defy.com gravity-pdf/v1 |
| V8 (Staging-only) | staging.biglots.com |
