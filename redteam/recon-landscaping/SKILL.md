---
name: recon-landscaping
description: "Sector-specific recon for landscaping company websites — lawn care, tree service, irrigation, hardscaping, snow removal. Typically WordPress on shared hosting with photo galleries, booking tools, and seasonal service pages."
sources: field_recon, sector_mass_recon
report_count: 6
---

# RECON-LANDSCAPING — Sector-Specific Recon for Landscaping Company Sites

## When to Use

Use when the target scope includes landscaping, lawn care, tree service, irrigation, or hardscaping company domains. These sites are characterized by WordPress on shared hosting with photo galleries of work, online booking/estimating features, and seasonal service page structures. Common vulnerabilities: directory listing on work photo galleries with EXIF data, exposed debug logs, CORS credential reflection, and booking plugin vulnerabilities.

## Quick Reference

```bash
for t in $(cat landscaping-targets.txt); do
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
# Common naming: <city>landscaping.com, <name>lawncare.com, <area>treeservice.com
# crt.sh enumeration
curl -sk "https://crt.sh/?q=%25.$TARGET&output=json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    domains = sorted(set(d['name_value'] for d in data))
    for d in domains: print(d)
except: pass
" | tee landscaping-subdomains-$TARGET.txt
```

### Phase 2 — WordPress Recon + Gallery Discovery
```bash
# CORS on REST API
curl -skI "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com"

# Gallery directory listing (landscaping companies heavily rely on before/after photos)
for path in /wp-content/uploads/ /images/gallery/ /galleries/ /portfolio/ /our-work/ /projects/; do
  body=$(curl -sk "https://$TARGET$path" 2>/dev/null)
  if echo "$body" | grep -q "Index of"; then
    echo "[!!!] DIRECTORY LISTING: $path"
    echo "$body" | grep -oP 'href="[^\"]+\.(jpg|png|gif|pdf)"' | head -20
  fi
done

# Debug log
curl -sk "https://$TARGET/wp-content/debug.log" -o /tmp/landscape_debug.log 2>/dev/null
if [ -s /tmp/landscape_debug.log ]; then
  echo "[!!!] Debug log found ($(wc -c < /tmp/landscape_debug.log) bytes)"
  grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' /tmp/landscape_debug.log | sort -u | head -20
  grep -oP '(DB_PASSWORD|DB_USER|DB_NAME|API_KEY).{0,80}' /tmp/landscape_debug.log | head -10
fi
```

### Phase 3 — Plugin Scan (Landscaping-Specific)
```bash
for plugin in "bookly-responsive-appointment-booking-tool" "wpforms" \
  "formidable" "elementor" "wordpress-seo" "google-reviews" \
  "business-reviews-bundle" "strong-testimonials" "site-reviews" \
  "woocommerce" "woocommerce-bookings" "tablepress"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/wp-content/plugins/$plugin/readme.txt")
  if [ "$code" != "404" ]; then
    version=$(curl -sk "https://$TARGET/wp-content/plugins/$plugin/readme.txt" | grep -i "stable tag\|version" | head -1)
    echo "[+] Plugin: $plugin ($code) $version"
  fi
done
```

### Phase 4 — Booking & Estimate Tool Recon
```bash
for path in /book-appointment /schedule /booking /get-a-quote /estimate /free-estimate /quote; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[+] Booking endpoint: $path (HTTP $code)"
done

# Webhook URLs in source (SSRF potential)
curl -sk "https://$TARGET/" | grep -oP 'https?://[^"\\x27]+(webhook|hook|callback|zapier|make\.com)' | sort -u
```

### Phase 5 — Photo EXIF Analysis
```bash
curl -sk "https://$TARGET/" | grep -oP 'src="[^"]+\.(jpg|jpeg|png)"' | sed 's/src="//;s/"//' | \
  while read img; do
    curl -sk "https://$TARGET$img" -o /tmp/exif_check.jpg 2>/dev/null
    exiftool /tmp/exif_check.jpg 2>/dev/null | grep -iE "gps|latitude|longitude|camera|model|software|create|date" | head -5
  done
```

## Attack Surface Signals

- CMS: WordPress (dominant), Wix, Squarespace
- Hosting: Shared hosting (GoDaddy, HostGator, SiteGround), rarely any WAF
- Stack: PHP + MySQL, Photo galleries (before/after), Booking/estimation plugins, Google Reviews badges
- Typical findings: Directory listing on uploads with EXIF data, Debug log with PII, CORS credential reflection, Booking plugin SSRF via webhook URLs, Outdated page builder plugins

## Common Root Causes

1. **Photo gallery directory listing** — before/after photos stored in /wp-content/uploads/ with Indexes enabled, EXIF data leaks camera info, geolocation
2. **DIY website builder** — small landscaping company owner builds own site, no security knowledge
3. **Seasonal business, seasonal maintenance** — site built for spring rush, never updated through winter
4. **Google Reviews badge** — third-party JS with no SRI, introduces client-side injection surface
5. **Estimate/quote forms** — custom-coded PHP calculators with SQLi potential

## Bypass Techniques

- Gallery images often have predictable URLs (IMG_0001.jpg, IMG_0002.jpg)
- Seasonal path structures: /uploads/spring-2024/, /uploads/fall-promo/
- Google dork: `site:target.com inurl:wp-content/uploads filetype:jpg "before" OR "after"`
- Staging subdomains: staging.target.com, dev.target.com

## Real Examples

From cross-sector mass recon observation:
- A landscaping company had full directory listing on /wp-content/uploads/ exposing 500+ before/after photos with EXIF geolocation data revealing exact homeowner addresses
- Another landscaper had debug.log available with SQL queries containing customer names, addresses, and phone numbers from contact form submissions
- A lawn care company's Bookly booking plugin had webhook URLs pointing to Zapier — modifiable via CSRF, enabling SSRF to internal services
- A hardscaping company's Elementor page builder was outdated (CVE-2023-6851), allowing SQL injection through the booking form

## Related Skills

- recon-smb-services — broader SMB recon methodology
- recon-churches — similar WordPress-on-shared-hosting profile
- hunt-wordpress — primary CMS for landscaping sites
- hunt-cors — CORS credential reflection
- hunt-source-leak — debug.log, config exposure
- hunt-file-upload — photo upload features, form submissions
