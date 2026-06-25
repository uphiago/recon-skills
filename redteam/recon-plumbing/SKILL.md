---
name: recon-plumbing
description: "Sector-specific recon for plumbing company websites — plumbing repair, drain cleaning, water heater installation, emergency service. Typically WordPress on shared hosting with emergency booking, estimate request forms, and photo galleries."
sources: field_recon, sector_mass_recon
report_count: 7
---

# RECON-PLUMBING — Sector-Specific Recon for Plumbing Company Sites

## When to Use

Use when the target scope includes plumbing, drain cleaning, water heater, or emergency plumbing company domains. Plumbing companies share the SMB service provider profile but have specific characteristics: high-volume emergency calls (means urgency in data capture), drain camera inspection videos/photos (stored on server), water heater specs and pricing pages, and financing/credit application portals that collect sensitive financial information.

## Quick Reference

```bash
for t in $(cat plumbing-targets.txt); do
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
# Common patterns: <city>plumbing.com, <name>plumber.com, <area>drain cleaning.com
curl -sk "https://crt.sh/?q=%25.$TARGET&output=json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    domains = sorted(set(d['name_value'] for d in data))
    for d in domains: print(d)
except: pass
" | tee plumbing-subdomains-$TARGET.txt
```

### Phase 2 — WordPress Recon + PII Discovery
```bash
# Debug log (plumbing sites often capture emergency contact info in logs)
curl -sk "https://$TARGET/wp-content/debug.log" -o /tmp/plumb_debug.log 2>/dev/null
if [ -s /tmp/plumb_debug.log ]; then
  grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' /tmp/plumb_debug.log | sort -u | head -20
  grep -oP '(address|phone|street|zip|SSN|card|CC|credit).{0,80}' /tmp/plumb_debug.log | head -10
fi

# Contact form PII (plumbing leads — names, addresses, phone, sewer issues)
for path in /wp-content/uploads/wpforms/ /wp-content/uploads/formidable/ \
  /wp-content/uploads/fluentform/ /wp-content/uploads/gravity_forms/ \
  /wp-content/uploads/cf7_uploads/; do
  body=$(curl -sk "https://$TARGET$path" 2>/dev/null)
  if echo "$body" | grep -q "Index of"; then
    echo "[!!!] DIR LISTING: $path"
    echo "$body" | grep -oP 'href="[^"]+\.(csv|xlsx|txt|pdf)"' | head -20
  fi
done

# CORS on REST API
curl -skI "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com"
```

### Phase 3 — Financing & Payment Recon
```bash
# Plumbing companies offer financing for water heaters, repipes, sewer lines
for path in /financing /credit-application /apply /pay /payment /billing /estimate; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[+] Finance/Payment endpoint: $path (HTTP $code)"
done

# Check for payment integrations
curl -sk "https://$TARGET/" | grep -oP 'stripe\.com|squareup\.com|paypal\.com|authorize\.net|credit' | sort -u
```

### Phase 4 — Gallery + Media Discovery
```bash
# Drain camera inspection photos/videos
for path in /wp-content/uploads/ /images/inspections/ /drain-camera/ /sewer-inspection/ \
  /videos/ /wp-content/uploads/videos/; do
  body=$(curl -sk "https://$TARGET$path" 2>/dev/null)
  if echo "$body" | grep -q "Index of"; then
    echo "[!!!] DIR LISTING: $path"
    echo "$body" | grep -oP 'href="[^"]+\.(jpg|png|mp4|avi|mov)"' | head -20
  fi
done
```

## Attack Surface Signals

- CMS: WordPress (dominant), some Wix/Squarespace
- Hosting: Shared hosting, aggressive SEO partner hosting
- Stack: PHP + MySQL, Emergency booking, Credit/financing applications, Drain camera videos, Online payment
- Typical findings: Debug log with emergency service requests (name, address, phone, issue), Contact form CSV exposure, Directory listing of drain inspection videos, CORS credential reflection

## Common Root Causes

1. **Emergency service => data urgency** — emergency plumber booking forms capture PII with zero validation
2. **Financing applications** — plumbing companies increasingly offer financing through third-party partners, creating integration points
3. **Drain camera media** — inspection videos stored in publicly accessible directories with no auth
4. **Agency-maintained sites** — same SEO agencies building hundreds of identical plumbing sites with identical misconfigurations

## Bypass Techniques

- Emergency plumber booking forms often skip validation — test with malformed addresses, special characters in phone fields
- Drain camera inspection videos often have predictable filenames (inspection_001.mp4, inspection_002.mp4)
- Credit application forms may submit PII over HTTP if the site has mixed content
- Same SEO agency builds hundreds of identical plumbing sites — common admin paths may use same credentials
- Financing page APIs often expose credit application endpoints without rate limiting
- Water heater sizing forms with numeric inputs (BTU, square footage) often have injection potential

## Real Examples

From cross-sector mass recon observation:
- A plumbing company had debug.log at /wp-content/debug.log containing 2MB of emergency service requests with customer names, addresses, phone numbers, and sewer issue descriptions
- Another plumber had directory listing on /wp-content/uploads/ revealing drain camera inspection videos with metadata showing homeowner addresses
- A drain cleaning service had a credit application form at /financing that POSTed SSN and DOB in plaintext over HTTP (mixed content)
- An emergency plumber's site had a Bookly booking tool with webhook URLs pointing to an internal server — SSRF through CSRF modification

## Related Skills

- recon-smb-services — broader SMB recon methodology
- recon-hvac — similar emergency-service profile
- recon-roofing — similar financing patterns
- hunt-wordpress — primary CMS
- hunt-cors — CORS credential reflection
- hunt-source-leak — debug.log, config exposure
- hunt-file-upload — form submissions, video uploads
