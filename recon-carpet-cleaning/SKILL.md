---
name: recon-carpet-cleaning
description: "Sector-specific recon for carpet cleaning company websites — steam cleaning, stain removal, upholstery cleaning, flood restoration. Typically WordPress on shared hosting with service booking forms, emergency water damage response, and seasonal special offers. Built from mass recon patterns across SMB service sectors where low-budget agency-built sites share identical vulnerability profiles."
sources: field_recon, sector_mass_recon
report_count: 5
---

# RECON-CARPET-CLEANING — Sector-Specific Recon for Carpet Cleaning Sites

## When to Use

Use when the target scope includes carpet cleaning, rug cleaning, upholstery cleaning, or water damage restoration company domains. Carpet cleaners share the SMB service provider vulnerability profile with specific characteristics: emergency water extraction features (urgent booking with lower security), before/after photo galleries with EXIF metadata, sanitizer/disinfectant product pages with embedded third-party data, and aggressive local SEO that produces many cookie-cutter agency-built sites with identical vulnerabilities.

## Quick Reference

```bash
for t in $(cat carpet-targets.txt); do
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
# Common patterns: <city>carpetcleaning.com, <area>carpetcleaners.com, <name>steamcleaning.com
# SEO-driven: best-<city>-carpet-cleaning.com, <city>-carpet-cleaning-pros.com
curl -sk "https://crt.sh/?q=%25.$TARGET&output=json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    domains = sorted(set(d['name_value'] for d in data))
    for d in domains: print(d)
except: pass
" | tee carpet-subs-$TARGET.txt
```

### Phase 2 — WordPress Recon
```bash
# CORS user enumeration
curl -sk "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com" | jq '.[] | {id, name, slug}' 2>/dev/null

# Debug log (carpet cleaning sites often log form submissions with customer addresses)
curl -sk "https://$TARGET/wp-content/debug.log" -o /tmp/carpet_debug.log 2>/dev/null
if [ -s /tmp/carpet_debug.log ]; then
  grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' /tmp/carpet_debug.log | sort -u | head -20
  grep -oP 'address|phone|street|zip|carpet|room' /tmp/carpet_debug.log | sort -u | head -10
fi

# Before/after photo gallery PII
for path in /gallery /before-after /our-work /photo-gallery /portfolio /carpet-cleaning-photos; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[+] Gallery: $path (HTTP $code)"
done
```

### Phase 3 — Emergency Service Recon
```bash
for path in /emergency /water-damage /flood /24-hour /emergency-service /fire-restoration /mold-remediation; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[+] Emergency endpoint: $path (HTTP $code)"
done
```

### Phase 4 — Plugin Vulnerability Scan
```bash
for plugin in "bookly-responsive-appointment-booking-tool" "wpforms" \
  "formidable" "elementor" "wordpress-seo" "google-reviews" \
  "woocommerce" "contact-form-7" "envira-gallery" "nextgen-gallery"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/wp-content/plugins/$plugin/readme.txt")
  if [ "$code" != "404" ]; then
    echo "[+] Plugin: $plugin"
  fi
done
```

## Attack Surface Signals

- CMS: WordPress (dominant), some Wix/Squarespace for newer small businesses
- Hosting: Shared hosting, local web agencies (GoDaddy, Bluehost, SiteGround common)
- Stack: PHP + MySQL, Emergency booking forms, Before/after photo galleries, Customer review widgets
- Typical findings: Debug log with customer PII, Contact form CSV exposure in uploads, EXIF geo data in gallery photos, CORS credential reflection

## Common Root Causes

1. **Emergency response prioritization** — water damage pages built for speed, security skipped
2. **Photo-heavy sites** — gallery plugins with EXIF metadata leaking customer home GPS coordinates
3. **Agency reuse** — local marketing agencies deploy identical WP templates across dozens of carpet cleaners
4. **Quote forms** — "Get a Free Quote" forms often store estimates in publicly accessible `/wp-content/uploads/` directories
5. **Seasonal promotions** — coupon code pages built by junior devs with debug mode left on

## Bypass Techniques

- Before/after photo galleries often use plugins that store GPS coordinates in EXIF — check with `exiftool`
- Emergency contact forms may have SMS notification webhooks with API keys in page source
- "Areas We Serve" pages often embed Google Maps with unrestricted API keys
- Coupon/promotion pages (`/spring-cleaning-special`, `/carpet-cleaning-coupon`) built in a hurry may have debug output enabled
- Many carpet cleaners share hosting with other local businesses — check for cross-site contamination

## Real Examples

From cross-sector mass recon observation:
- A carpet cleaning company's debug log contained full customer names, addresses, and phone numbers from online quote forms — 400+ entries in a 2MB file
- Gallery plugin at `/wp-content/uploads/envira/` had directory listing enabled, revealing before/after photos with EXIF GPS data showing customer home locations
- An emergency water damage form's AJAX endpoint accepted requests without nonce validation, allowing CSRF-based service booking that triggered SMS dispatch
- Google Maps API key found in page source was unrestricted, allowing use for any Google Maps API service

## Related Skills

- recon-smb-services — broader SMB recon methodology
- recon-hvac — similar emergency-service profile
- recon-plumbing — similar emergency-service booking patterns
- recon-roofing — similar insurance-claim related service patterns
- hunt-wordpress — primary CMS
- hunt-cors — CORS credential reflection
- hunt-source-leak — debug.log, config exposure, EXIF analysis
- hunt-file-upload — gallery upload features
