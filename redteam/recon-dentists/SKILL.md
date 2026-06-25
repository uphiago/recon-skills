---
name: recon-dentists
description: "Sector-specific recon for dentist, orthodontist, and dental practice websites — typically WordPress on shared hosting with online booking, patient portal integrations, and insurance verification pages. Common platforms include Dentrix Ascend, Eaglesoft, Open Dental, Curve Dental, and PatientConnect for practice management; typically WordPress or custom PHP on shared hosting with minimal security posture."
sources: field_recon, sector_mass_recon
report_count: 12
---

# Recon: Dental Practice Websites

Sector-specific recon for dentist, orthodontist, and dental practice websites.

## When to Use

Use when the target scope includes dentist offices, dental clinics, orthodontic practices, oral surgery centers, or dental group practices. These sites typically handle protected health information (PHI), patient intake forms, and insurance verification data with minimal security investment.

Common sectors: dentistry, orthodontics, oral surgery, pediatric dentistry, periodontics, endodontics.

## Quick Reference

| Aspect | Typical Profile |
|--------|----------------|
| CMS | WordPress (80%+), custom PHP, Squarespace |
| Hosting | Shared hosting (GoDaddy, HostGator, SiteGround) |
| Booking | Dentrix Ascend, Eaglesoft, Open Dental, Solutionreach |
| Patient Portal | PatientConnect, Lighthouse 360, RevenueWell |
| Common Plugins | WPForms, Gravity Forms, Elementor, Bookly |
| Top Findings | Debug log PII, CORS credential reflection, open registration, outdated plugins |

## Step-by-Step

### Phase 1 — Domain Discovery

```bash
# Google dorks for dental practice websites
# site:*.com "dentist" "patient portal" - Use in Google search
# site:*.com "dental" "new patient" "online booking"

# crt.sh certificate search
curl -sk "https://crt.sh/?q=%25.dental%25&output=json" | jq -r '.[].name_value' | sort -u

# Find dental practice domains from sector lists
# Common naming patterns:
#   smilesforlife-dental.com, drsmithdental.com, citydentalgroup.com
#   northstardentistry.com, familydentalcare.com, dentistdowntown.com
```

### Phase 2 — CMS Recon

```bash
# WordPress detection
curl -skI "https://$TARGET/" | grep -iE "x-powered-by.*php|set-cookie.*wordpress|set-cookie.*wp-"
curl -sk "https://$TARGET/" | grep -iE "generator.*WordPress|wp-content|wp-json|wp-includes"

# REST API user enumeration
curl -sk "https://$TARGET/wp-json/wp/v2/users" | python3 -m json.tool 2>/dev/null

# XMLRPC check
code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/xmlrpc.php")
[ "$code" = "200" ] && echo "[XMLRPC] $TARGET"
```

### Phase 3 — Config Exposure

```bash
# Debug log — often contains PHI (patient names, phone numbers, emails)
curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/wp-content/debug.log"

# Common sensitive paths
for path in /.env /wp-config.php.bak /backup.sql /info.php /phpinfo.php; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[$code] $TARGET$path"
done
```

### Phase 4 — Plugin & Booking System Scan

```bash
for plugin in "gravityforms" "wpforms" "elementor" "bookly" "contact-form-7" "woocommerce"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/wp-content/plugins/$plugin/readme.txt" 2>/dev/null)
  [ "$code" != "404" ] && [ -n "$code" ] && echo "[PLUGIN] $plugin (HTTP $code)"
done
```

### Phase 5 — Attack Chains

```bash
# Chain A: Debug log PII + CORS -> PHI exposure
# Dental practice debug.log often contains patient intake form submissions
# including full name, DOB, phone, address, insurance ID, dental history notes

# Chain B: Open registration + outdated plugins -> RCE
# Many dental WP sites have open registration for "new patient forms"
# and outdated Gravity Forms / Contact Form 7 -> file upload bypass

# Chain C: Booking API IDOR -> Patient data
# Dentrix Ascend / PatientConnect APIs often use sequential patient IDs
# IDOR on appointment view -> full patient record
```

## Attack Surface Signals

- Online booking forms with GPDR/privacy policy checkboxes
- "New Patient" registration pages
- Patient portal login pages (subdomain or /portal path)
- Insurance verification upload forms
- Treatment plan PDF generation
- Before/after photo galleries with EXIF data
- Contact forms submitting to email-to-SMTP gateways
- Online bill payment portals

## Common Root Causes

1. **Debug.log enabled on production** — patient form submissions logged with full PII
2. **CORS credential reflection on WP REST API** — PHI exfiltratable cross-origin
3. **Outdated booking plugins** — critical CVEs in Gravity Forms, Contact Form 7
4. **Open registration enabled** — anyone creates account, then uploads webshell
5. **Photo gallery directory listing** — EXIF data contains GPS coordinates from dental office
6. **Patient portal weak auth** — simple passwords, no MFA, session tokens in URL

## Bypass Techniques

| Defense | Bypass |
|---------|--------|
| Cloudflare WAF | Find origin IP via Historical DNS / crt.sh |
| Booking system with rate limits | Slow enumeration (1 req/5s), rotate IP headers |
| Patient portal login | Test common credentials (admin/admin, password/password, demo/demo) |
| Contact form CAPTCHA | Find underlying form handler API endpoint |
| SSL/TLS on main site | Check subdomains without HTTPS (dev, staging, portal) |

## Real Examples

**Dental practice patient portal with CORS credential reflection on /wp-json/wp/v2/users endpoint. Authenticated admin browsing while logged into WordPress would have their user list (including email addresses of patient-facing staff) exposed cross-origin. CORS headers allowed credentialed reads from any attacker origin.**

**Dentist office debug.log exposed patient intake form submissions including full name, DOB, phone, email, dental insurance ID, and medical history notes. The debug.log was world-readable at /wp-content/debug.log.**

## Related Skills

- **`hunt-wordpress`** — Primary CMS for most dental practices; XMLRPC, user enum, CORS reflection
- **`hunt-cors`** — CORS credential reflection on WP REST API is the most common high-value finding
- **`hunt-source-leak`** — Debug log exposure containing PHI from patient intake forms
- **`hunt-file-upload`** — Outdated booking plugins with file upload bypass → RCE
- **`hunt-idor`** — Sequential patient IDs in booking APIs
- **`hunt-brute-force`** — Weak auth on patient portals
- **`wp-plugin-automation`** — Batch CVE scanning for Gravity Forms, Contact Form 7
- **`hunt-lfi`** — PHP file inclusion in outdated booking plugins
- **`hunt-subdomain`** — Staging/dev subdomains with less hardened security
- **`recon-smb-services`** — SMB service sector methodology (dental practices are SMBs)
