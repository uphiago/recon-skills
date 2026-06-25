---
name: recon-fire-restoration
description: "Sector-specific recon for fire damage restoration, water damage restoration, and disaster cleanup company websites — typically WordPress on shared hosting with emergency service pages, insurance claim assistance, and photo galleries. Common platforms include ServiceTitan, Jobber, and Housecall Pro for CRM/job management; typically WordPress with Elementor/WP Bakery on shared hosting."
sources: field_recon, sector_mass_recon
report_count: 8
---

# Recon: Fire & Water Damage Restoration Company Websites

Sector-specific recon for fire damage restoration, water damage restoration, mold remediation, and disaster cleanup company websites.

## When to Use

Use when the target scope includes fire restoration companies, water damage restoration services, mold remediation contractors, disaster cleanup services, or restoration franchise locations (Servpro, ServiceMaster, Paul Davis, Belfor, AdvantaClean). These sites handle emergency response intake that frequently captures customer PII (property addresses, insurance claims, photos of damaged interiors, emergency contact info) through intake forms and claim portals.

Common sectors: fire restoration, water damage restoration, mold remediation, disaster cleanup, biohazard remediation, hoarding cleanup.

## Quick Reference

| Aspect | Typical Profile |
|--------|----------------|
| CMS | WordPress (80%+), custom PHP, franchise-specific platforms |
| Hosting | Shared hosting (GoDaddy, HostGator, SiteGround) |
| CRM | ServiceTitan, Jobber, Housecall Pro, Franchise-specific platforms |
| Emergency Intake | 24/7 live chat, emergency call-to-action forms |
| Photo Galleries | Before/after damage gallery with EXIF data (property addresses) |
| Common Plugins | Elementor, WPForms, Gravity Forms, Yoast SEO, Strong Testimonials |
| Top Findings | Debug log PII, CORS credential reflection, open registration, photo gallery directory listing |

## Step-by-Step

### Phase 1 — Domain Discovery

```bash
# Google dorks
# site:*.com "fire damage" "restoration" "24/7"
# site:*.com "water damage" "emergency" "insurance claim"
# site:*.com "mold remediation" "free estimate"

# crt.sh
curl -sk "https://crt.sh/?q=%25.restoration%25&output=json" | jq -r '.[].name_value' | sort -u

# Common naming patterns:
#   servpro.com, servicemaster.com, pauldavis.com, belfor.com
#   citywaterdamage.com, fire-damage-experts.com
#   disaster-cleaning-services.com
```

### Phase 2 — CMS Recon

```bash
# WordPress detection
curl -skI "https://$TARGET/" | grep -iE "x-powered-by.*php|set-cookie.*wordpress|set-cookie.*wp-"
curl -sk "https://$TARGET/" | grep -iE "generator.*WordPress|wp-content|wp-json|wp-includes"

# CORS credential reflection
curl -sk -I "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com" | grep -iE "access-control"

# REST API namespace enumeration
curl -sk "https://$TARGET/wp-json/" | python3 -m json.tool 2>/dev/null
```

### Phase 3 — Config Exposure

```bash
# Debug log — emergency intake PII
curl -sk "https://$TARGET/wp-content/debug.log" | head -100

# Sensitive paths
for path in /.env /wp-config.php.bak /info.php /phpinfo.php /backup.sql; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[$code] $TARGET$path"
done
```

### Phase 4 — Attack Chains

```bash
# Chain A: Emergency intake form PII -> Home address + insurance data
# Restoration intake forms collect: property address, insurance company, claim #
# If debug.log captures submissions -> property-level PII

# Chain B: Photo gallery directory listing -> Property address disclosure
# Before/after damage photos often have EXIF GPS coordinates
# Directory listing on uploads -> browse all project photos

# Chain C: CORS + franchise portal -> Multi-franchise data access
# Franchise systems share backend; CORS on parent brand's portal
# could expose data across franchise locations
```

## Attack Surface Signals

- 24/7 emergency service call-to-action forms
- Insurance claim number intake fields
- "We work with all insurance companies" pages with partner lists
- Before/after photo galleries (EXIF data with GPS coordinates)
- Emergency response area coverage maps (reveals service radius)
- Customer portal login (franchise-specific platforms)
- Free estimate/quote request forms (address, phone, photos of damage)

## Common Root Causes

1. **Emergency intake form PII in debug.log** — full address, insurance claim data, photos
2. **CORS credential reflection** — franchise staff user enumeration
3. **Photo gallery directory listing** — EXIF GPS data from job sites
4. **Open registration on franchise portal** — anyone creates account, accesses franchise resources
5. **Outdated Elementor/WP Bakery** — common page builder CVEs
6. **Staging subdomain exposure** — test environments with copy of production data

## Related Skills

- **`hunt-wordpress`** — Primary CMS; XMLRPC, CORS reflection, user enumeration
- **`hunt-cors`** — CORS credential reflection on WP REST API
- **`hunt-source-leak`** — Debug log exposure of emergency intake PII
- **`hunt-file-upload`** — Photo upload in gallery features
- **`hunt-idor`** — Sequential job/claim IDs in franchise portals
- **`hunt-subdomain`** — Staging/dev subdomains with customer data
- **`recon-hvac`** — Adjacent sector (home services, emergency dispatch)
- **`recon-plumbing`** — Adjacent sector (water-related service, same CRM tools)
