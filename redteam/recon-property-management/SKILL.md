---
name: recon-property-management
description: "Sector-specific recon for property management, apartment rental, and real estate management company websites — typically WordPress on shared hosting with rental listings, tenant portals, maintenance request systems, and online rent payment integrations. Built from a 20-target batch recon across US property management companies. Use when the target scope includes property management firms, apartment communities, rental agencies, real estate management, or HOA management company domains."
sources: field_recon, sector_mass_recon
report_count: 20
---

# RECON-PROPERTY-MANAGEMENT — Sector-Specific Recon for Property Management Company Sites

## When to Use

Use when the target scope includes property management companies, apartment rental agencies, real estate management firms, HOA management, or multi-family property group domains. These sites typically run WordPress on shared hosting with rental property listings (photos, floor plans, pricing, availability), tenant portals for maintenance requests and payments (storing PII including SSN on credit applications, bank account info for rent payment), and vacancy/availability data. Major PM software includes AppFolio, Buildium, Yardi, Entrata, ResMan, and Propertyware; but many smaller firms use WordPress with various plugins. Common vulnerabilities: tenant portal auth bypass, rent payment API exposure, maintenance request data leakage, and CORS credential reflection.

## Quick Reference

```bash
for t in $(cat pm-targets.txt); do
  echo "=== $t ==="
  curl -skI "https://$t/" | grep -iE "wordpress|php|wp-"
  curl -sk -o /dev/null -w "%{http_code}" "https://$t/wp-json/wp/v2/users" -H "Origin: https://evil.com"
  curl -skI "https://$t/wp-json/" -H "Origin: https://evil.com" | grep -i "access-control"
  curl -sk -o /dev/null -w "%{http_code}" "https://$t/xmlrpc.php"
  curl -sk -o /dev/null -w "%{http_code}" "https://$t/wp-content/debug.log"
  echo "---"
done
```

## Step-by-Step

### Phase 1 — Domain Discovery
```bash
# Common patterns: <name>properties.com, <name>propertymanagement.com
# <name>apts.com, <name>rentals.com, <name>pm.com, <city>propertymgt.com
# <name>living.com, liveat<name>.com, <name>communities.com

# Find via crt.sh
curl -sk "https://crt.sh/?q=%25.$TARGET&output=json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    domains = sorted(set(d['name_value'] for d in data))
    for d in domains: print(d)
except: pass
" | tee pm-subdomains-$TARGET.txt
```

### Phase 2 — Tenant Portal Recon (Highest Priority)
```bash
# Tenant portals contain: tenant PII, lease terms, payment history, maintenance records
for path in /portal /tenant /resident /login /my-account /account \
  /pay-rent /online-rent /make-payment /maintenance-request /submit-request \
  /tenant-portal /resident-portal; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path" 2>/dev/null)
  size=$(curl -sk "https://$TARGET$path" 2>/dev/null | wc -c)
  [ "$code" != "404" ] && echo "[+] Tenant portal: $path (HTTP $code, ${size}b)"
done

# Check for tenant portal platform fingerprints
curl -sk "https://$TARGET/" | grep -iE "appfolio|buildium|yardi|entrata|resman|propertyware|tenantcloud" | head -10
```

### Phase 3 — Property Listing & API Recon
```bash
# Property listing APIs often leak data without auth
for path in /properties /listings /rentals /apartments /available \
  /api/properties /api/listings /wp-json/rentals/v1 /api/units \
  /properties.json /listings.json; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path" 2>/dev/null)
  [ "$code" != "404" ] && echo "[+] Listings: $path (HTTP $code)"
done

# Test property API without auth
curl -sk "https://$TARGET/api/properties?limit=100" 2>/dev/null | jq '.' 2>/dev/null | head -50
curl -sk "https://$TARGET/properties.json" 2>/dev/null | jq '.' 2>/dev/null | head -50
```

### Phase 4 — WordPress Standard Recon
```bash
# CORS credential reflection
curl -skI "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com"

# User enumeration
curl -sk "https://$TARGET/wp-json/wp/v2/users" | jq '.[] | {id, name, slug, email}'

# REST API namespace enumeration
curl -sk "https://$TARGET/wp-json/" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for ns in d.get('namespaces', []):
        print(f'  {ns}')
except: pass
"

# Debug log — may contain tenant application PII
curl -sk "https://$TARGET/wp-content/debug.log" -o /tmp/pm_debug.log 2>/dev/null
if [ -s /tmp/pm_debug.log ]; then
  echo "[!!!] Debug log found ($(wc -c < /tmp/pm_debug.log) bytes)"
  grep -oP 'SSN|social.security|bank.account|routing|credit.card|lease|rent|deposit' /tmp/pm_debug.log | sort -u | head -20
fi

# Directory listing on uploads
curl -sk "https://$TARGET/wp-content/uploads/" | grep -oP 'href="[^"]+\.(pdf|csv|xlsx|doc|docx)"' | head -20
```

### Phase 5 — Maintenance Request Recon
```bash
# Maintenance request endpoints — may expose unit entry access codes, tenant contact info
for path in /maintenance /maintenance-request /service-request /work-order \
  /repair /emergency-repair; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path" 2>/dev/null)
  [ "$code" != "404" ] && echo "[+] Maintenance: $path (HTTP $code)"
done
```

### Phase 6 — Plugin Vulnerability Scan
```bash
for plugin in "elementor" "wordpress-seo" "contact-form-7" "gravityforms" \
  "wpforms" "formidable" "fluentform" "woocommerce" "jetpack" \
  "advanced-custom-fields" "estatik" "easy-property-listings" "wp-property"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/wp-content/plugins/$plugin/readme.txt" 2>/dev/null)
  if [ "$code" != "404" ] && [ -n "$code" ]; then
    echo "[+] Plugin: $plugin (HTTP $code)"
  fi
done
```

## Attack Surface Signals

- CMS: WordPress (dominant), AppFolio/Buildium SaaS, custom PHP
- Hosting: Shared hosting, SaaS property management platforms
- Stack: PHP + MySQL, Tenant/resident portals, Rent payment integrations, Property listing APIs, Maintenance request systems
- Typical findings: CORS credential reflection, Debug log PII (SSN, bank account), Tenant portal auth bypass, Property API without auth, Directory listing with lease documents

## Common Root Causes

1. **Tenant portal PII storage** — lease agreements, credit applications with SSN, bank accounts for ACH stored in unprotected directories
2. **Debug log with financial data** — rent payment transactions, tenant contact info, maintenance access codes logged by WP_DEBUG
3. **Property listing API without auth** — rental data, floor plans, pricing, occupancy rates exposed without authentication
4. **Maintenance request access** — work orders with tenant unit access codes (key codes, garage codes, gate codes) exposed

## Related Skills

- recon-smb-services — broader SMB methodology
- hunt-wordpress — primary CMS for most PM sites
- hunt-cors — CORS credential reflection
- hunt-source-leak — debug.log, config exposure
- hunt-idor — sequential tenant IDs in portals
- hunt-file-upload — lease document upload features
- hunt-brute-force — weak tenant portal auth

## Bypass Techniques

- Tenant portals often have IDOR on resident IDs — iterate `/portal/resident/1`, `/2`, `/3` to find other tenants
- Property listing APIs may accept `?per_page=500` to dump full portfolio
- Maintenance request endpoints may expose unit entry codes (garage codes, gate codes, lockbox combinations)
- Lease agreement PDFs are often named sequentially (`LEASE-2026-001.pdf`, `LEASE-2026-002.pdf`)
- Yardi/AppFolio portals sometimes have a `/docs` or `/files` path with uploaded lease documents accessible without auth

## Real Examples

From a 20-target batch recon across US property management companies:
- A property management company had CORS credential reflection on the WP REST API users endpoint — tenant and property manager usernames exposed cross-origin
- An apartment community site had XMLRPC with system.multicall active — full brute-force amplification chain available
- A PM firm had debug.log exposed containing SQL queries with tenant lease information including monthly rent amounts, security deposit data, and tenant contact details
- A rental agency WordPress site had directory listing on `/wp-content/uploads/` revealing signed lease agreement PDFs with tenant SSNs and bank account numbers for ACH payments
