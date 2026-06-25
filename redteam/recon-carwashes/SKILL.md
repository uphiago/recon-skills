---
name: recon-carwashes
description: "Sector-specific recon for car wash and auto detailing company websites — typically WordPress on shared hosting with membership plans, pricing menus, booking/scheduling tools, and customer account portals. Common platforms include EverWash, Washify, DRB Systems, and NTI for membership management."
sources: field_recon, sector_mass_recon
report_count: 3
---

# RECON-CARWASHES — Sector-Specific Recon for Car Wash & Auto Detailing Sites

## When to Use

Use when the target scope includes car wash, auto detailing, or car care company domains. These small-to-medium businesses typically run WordPress or custom PHP on shared hosting with membership/subscription portals, pricing menus, and online booking systems. Common vulnerabilities: exposed membership databases via debug logs, booking plugin CVEs, directory listing on photo galleries (before/after detailing work), and exposed payment processing endpoints.

## Quick Reference

```bash
for t in $(cat carwash-targets.txt); do
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
# Common naming: <city>carwash.com, <name>detail.com, <area>autocare.com
# Membership portals often on subdomains: members., portal., washclub.
curl -sk "https://crt.sh/?q=%25.$TARGET&output=json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    domains = sorted(set(d['name_value'] for d in data))
    for d in domains: print(d)
except: pass
" | tee carwash-subdomains-$TARGET.txt
```

### Phase 2 — Membership Portal Recon
```bash
# Car wash membership/subscription portals
for path in /membership /members /pricing /plans /wash-club /my-account /login /portal; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[+] Portal endpoint: $path (HTTP $code)"
done

# Check for EverWash, Washify, or DRB integration
curl -sk "https://$TARGET/" | grep -iE "everwash|washify|drbsystems|nti|carwash|washclub" | head -10
```

### Phase 3 — WordPress Recon + PII Discovery
```bash
# Debug log (car wash sites often capture member PII in logs)
curl -sk "https://$TARGET/wp-content/debug.log" -o /tmp/cw_debug.log 2>/dev/null
if [ -s /tmp/cw_debug.log ]; then
  grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' /tmp/cw_debug.log | sort -u | head -20
  grep -oP '(membership|phone|address|license|card|plate).{0,80}' /tmp/cw_debug.log | head -10
fi

# CORS on REST API
curl -skI "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com"
```

### Phase 4 — Booking & Scheduling Recon
```bash
for path in /book /schedule /appointment /booking /book-now /online-booking /reserve; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[+] Booking endpoint: $path (HTTP $code)"
done

# Check for third-party booking platforms
curl -sk "https://$TARGET/" | grep -oP 'acuityscheduling|calendly|squareup|setmore|bookly' | sort -u
```

### Phase 5 — Plugin Vulnerability Scan
```bash
for plugin in "elementor" "elementskit" "contact-form-7" "wpforms" "woocommerce" \
  "wordpress-seo" "bookly-responsive-appointment-booking-tool" "strong-testimonials" \
  "site-reviews" "business-reviews-bundle"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/wp-content/plugins/$plugin/readme.txt")
  if [ "$code" != "404" ]; then
    version=$(curl -sk "https://$TARGET/wp-content/plugins/$plugin/readme.txt" | grep -i "stable tag\|version" | head -1)
    echo "[+] Plugin: $plugin ($code) $version"
  fi
done
```

## Attack Surface Signals

- CMS: WordPress (dominant), Wix, Squarespace
- Hosting: Shared hosting (GoDaddy, HostGator, SiteGround)
- Stack: PHP + MySQL, Membership/subscription portals, Photo galleries (detailing work), Online booking
- Typical findings: Debug log with member PII (names, addresses, vehicle info, payment methods), CORS credential reflection, Directory listing on detailing photo galleries, Booking plugin vulnerabilities

## Common Root Causes

1. **Membership portal data persistence** — monthly subscription models store customer vehicle info, license plates, payment methods that accumulate over years
2. **Detailing photo galleries with EXIF data** — before/after photos stored in public upload dirs with geolocation and customer vehicle info
3. **SEO agency-built sites** — local marketing agencies build cookie-cutter car wash sites with identical vulnerabilities
4. **Third-party booking integrations** — embedded Calendly, Acuity, or Bookly widgets create SSRF surface through webhook URLs

## Bypass Techniques

- Membership portals often have predictable numeric IDs — iterate /members/1, /members/2
- Detailing photo galleries with sequential filenames (IMG_0001.jpg, IMG_0002.jpg)
- Check for staging subdomains: staging.carwash.com, dev.carwash.com
- Google dork: `site:target.com inurl:wp-content/uploads filetype:jpg detailing`

## Real Examples

From cross-sector mass recon observation:
- A car wash chain had debug.log exposed at /wp-content/debug.log containing 1MB+ of SQL queries with customer membership data including names, addresses, phone numbers, and vehicle license plates
- Another car wash had directory listing on /wp-content/uploads/ revealing detailing before/after photos with EXIF data showing customer addresses
- A car detailing company had Bookly plugin with webhook URLs pointing to a Zapier integration, modifiable via CSRF enabling SSRF

## Related Skills

- recon-smb-services — broader SMB recon methodology
- recon-gyms — similar membership/subscription portal profile
- hunt-wordpress — primary CMS for car wash sites
- hunt-cors — CORS credential reflection on WP REST API
- hunt-source-leak — debug.log, config backups
- hunt-file-upload — photo gallery uploads
- hunt-subdomain — membership portal subdomains
