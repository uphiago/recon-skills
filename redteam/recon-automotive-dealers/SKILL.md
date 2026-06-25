---
name: recon-automotive-dealers
description: "Sector-specific recon for car dealership and automotive retail websites — typically WordPress or custom PHP on shared hosting with inventory listings, financing applications, service booking, and OEM-branded portals. Built from a 20-target batch recon across US auto dealer networks where WordPress was the dominant platform. Use when the target scope includes car dealerships, auto retailer groups, automotive service centers, or OEM franchise dealer networks."
sources: field_recon, sector_mass_recon
report_count: 20
---

# RECON-AUTOMOTIVE-DEALERS — Sector-Specific Recon for Car Dealership Sites

## When to Use

Use when the target scope includes car dealerships, auto retail groups, automotive service centers, or OEM franchise dealer network domains. These sites typically run WordPress on shared hosting with vehicle inventory management systems, VDP (Vehicle Detail Page) listings, financing applications (credit apps with SSN/income data), service scheduling, and OEM-branded dealer portals. Major dealer groups (AutoNation, Lithia, Sonic) use Cloudflare/WAF, but small/medium independent dealers are on shared hosting with minimal security. Common platforms include Dealer.com, DealerOn, CDK Global, Reynolds & Reynolds, and WordPress with inventory plugins.

## Quick Reference

```bash
for t in $(cat dealership-targets.txt); do
  echo "=== $t ==="
  curl -skI "https://$t/" | grep -iE "wordpress|php|wp-"
  curl -sk -o /dev/null -w "%{http_code}" "https://$t/wp-json/wp/v2/users" -H "Origin: https://evil.com"
  curl -sk -o /dev/null -w "%{http_code}" "https://$t/xmlrpc.php"
  curl -sk -o /dev/null -w "%{http_code}" "https://$t/wp-content/debug.log"
  curl -sk -o /dev/null -w "%{http_code}" "https://$t/wp-content/uploads/"
  echo "---"
done
```

## Step-by-Step

### Phase 1 — Domain Discovery
```bash
# Common patterns: <dealership>cars.com, <brand>of<city>.com, <city>auto.com
# <name>motors.com, <name>auto-group.com, <name>automotive.com
# CDK/Dealer.com sites: d2.dealer.com, <name>.dealerdot.com, <name>.dealersites.com

# Find dealer domains via crt.sh
curl -sk "https://crt.sh/?q=%25.$TARGET&output=json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    domains = sorted(set(d['name_value'] for d in data))
    for d in domains: print(d)
except: pass
" | tee dealer-subdomains-$TARGET.txt
```

### Phase 2 — WordPress Recon
```bash
# CORS credential reflection
curl -skI "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com"

# User enumeration
curl -sk "https://$TARGET/wp-json/wp/v2/users" | jq '.[] | {id, name, slug, email}'

# XMLRPC method enumeration
curl -sk -X POST "https://$TARGET/xmlrpc.php" -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' | \
  python3 -c "
import sys, re
methods = re.findall(r'<string>([^<]+)</string>', sys.stdin.read())
dangerous = ['system.multicall', 'wp.uploadFile', 'pingback.ping']
for m in methods:
    if any(d in m for d in dangerous):
        print(f'  [!] DANGEROUS: {m}')
"

# Debug log
curl -sk "https://$TARGET/wp-content/debug.log" | head -30
```

### Phase 3 — VDP (Vehicle Detail Page) & Inventory Recon
```bash
# Dealer.com / DealerOn inventory endpoints often leak stock data
for path in /api/inventory /api/vehicles /inventory.json /vdp/ /cars/ \
  /new-inventory /used-inventory /api/v1/vehicles /api/stock; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path" 2>/dev/null)
  [ "$code" != "404" ] && [ -n "$code" ] && echo "[+] Inventory: $path (HTTP $code)"
done

# Check for VIN enumeration
curl -sk "https://$TARGET/api/vehicles?limit=100" | jq '.' 2>/dev/null | head -50
```

### Phase 4 — Financing & Credit Application Recon
```bash
# Financing portals often contain PII-heavy credit applications
for path in /finance /financing /credit-application /apply /pre-approval \
  /credit-app /finance-application /payment-calculator /trade-in; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path" 2>/dev/null)
  [ "$code" != "404" ] && echo "[+] Finance: $path (HTTP $code)"
done

# Check for unprotected credit application submissions
curl -sk "https://$TARGET/wp-content/uploads/credit-apps/" | grep -oP 'href="[^"]+\.(pdf|csv|xlsx|txt)"' | head -20
```

### Phase 5 — Plugin Vulnerability Scan
```bash
for plugin in "elementor" "wordpress-seo" "contact-form-7" "gravityforms" \
  "woocommerce" "wpforms" "formidable" "revslider" "elementskit" \
  "advanced-custom-fields" "all-in-one-seo-pack" "sitepress-multilingual-cms"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/wp-content/plugins/$plugin/readme.txt" 2>/dev/null)
  if [ "$code" != "404" ] && [ -n "$code" ]; then
    version=$(curl -sk "https://$TARGET/wp-content/plugins/$plugin/readme.txt" 2>/dev/null | grep -i "stable tag\|version" | head -1)
    echo "[+] Plugin: $plugin (HTTP $code) $version"
  fi
done
```

## Attack Surface Signals

- CMS: WordPress (dominant), custom PHP for dealer groups
- Hosting: Shared hosting, CDK/Dealer.com SaaS, OEM-partner hosting
- Stack: PHP + MySQL, Vehicle inventory integrations, Financing APIs, Service scheduling
- Typical findings: CORS credential reflection on REST API, XMLRPC open, Debug log with PII, Directory listing on uploads, VIN enumeration via unauthenticated APIs

## Common Root Causes

1. **Dealer.com/CDK WordPress templates** — cookie-cutter dealer sites with identical plugin sets across hundreds of dealerships
2. **Financing portal PII storage** — credit applications (SSN, income, address, DOB) stored in unprotected upload directories
3. **Inventory API without auth** — VDP stock data, VINs, and dealer cost information exposed
4. **Multi-location dealer groups** — same credentials across all locations, one breach = all sites compromised

## Related Skills

- recon-smb-services — broader SMB recon methodology
- hunt-wordpress — primary CMS for small/medium dealers
- hunt-cors — CORS credential reflection on WP REST API
- hunt-source-leak — debug.log, config exposure, JS secret extraction
- hunt-business-logic — coupon/pricing manipulation in service booking
- hunt-subdomain — staging/dev dealer instances

## Bypass Techniques

- Major dealer groups (AutoNation, Lithia, Sonic) use Cloudflare/WAF — find origin IP via historical DNS or SecurityTrails
- CDK/Dealer.com sites often have API endpoints at predictable paths — test `/api/inventory`, `/api/vehicles`
- Inventory APIs frequently have no rate limiting — VIN enumeration via sequential IDs
- Service booking portals often expose internal dealership contact data (service advisor names, email, phone)
- Credit application submissions may be stored as PDFs with sequential filenames in `/wp-content/uploads/credit-apps/`

## Real Examples

From a 20-target batch recon across US auto dealer networks:
- Several independent dealership WordPress sites had CORS credential reflection on the WP REST API users endpoint — admin usernames and email addresses exposed cross-origin
- A used car dealership had XMLRPC with system.multicall available — 80+ methods including wp.uploadFile
- An auto service center had directory listing on `/wp-content/uploads/` revealing service invoices with customer names, vehicle VINs, and payment details
- Debug.log exposure on a dealer WordPress site contained SQL queries with dealer inventory cost data and customer contact information
