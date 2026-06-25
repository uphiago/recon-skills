---
name: recon-laundromats
description: "Sector-specific recon for laundromat, dry cleaning, and laundry service company websites — typically WordPress or custom PHP on shared hosting with pricing calculators, service area pages, pickup/delivery booking, and customer account portals. Common platforms include Cents, LaundryLocker, Washlava, and CleanCloud for POS/business management."
sources: field_recon, web_recon
report_count: 3
---

# RECON-LAUNDROMATS — Sector-Specific Recon for Laundromat & Dry Cleaning Sites

## When to Use

Use when the target scope includes laundromat, dry cleaning, laundry delivery/pickup, or linen service company domains. These small local businesses typically have minimal-security web presences with online ordering, pricing calculators, and customer account portals. Common findings: exposed customer order data in debug logs, price calculator injection vulnerabilities, directory listing on uploaded receipts/invoices, and booking system CVEs.

## Quick Reference

- **Common CMS**: WordPress (dominant), custom PHP, Wix, Squarespace
- **Common platforms**: Cents, LaundryLocker, Washlava, CleanCloud, Spynr, Laundroworks
- **Key endpoints**: `/order`, `/schedule-pickup`, `/menu`, `/pricing`, `/service-area`, `/track-order`, `/portal`
- **Key findings**: Debug log with customer PII, price calculator injection, directory listing of invoices/receipts, booking plugin vulnerabilities

## Step-by-Step

1. **CMS Detection**
   ```bash
   curl -skI "https://$TARGET/" | grep -iE "x-powered-by|set-cookie|server"
   curl -sk "https://$TARGET/" | grep -iE "generator|wp-content|wp-json"
   ```

2. **Order/Pickup Booking Recon**
   ```bash
   for path in "/schedule-pickup" "/request-pickup" "/order" "/order-online" \
     "/track" "/track-order" "/status" "/delivery" "/pricing" "/services"; do
     code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
     [ "$code" != "404" ] && echo "[+] Service endpoint: $path ($code)"
   done
   ```

3. **Customer Data Exposure**
   ```bash
   # Debug log — often contains customer orders with PII
   curl -sk "https://$TARGET/wp-content/debug.log" | grep -iE "name|address|phone|order|pickup|delivery" | head -30

   # Contact form submission storage
   for path in /wp-content/uploads/wpforms/ /wp-content/uploads/formidable/ \
     /wp-content/uploads/cf7_uploads/; do
     body=$(curl -sk "https://$TARGET$path" 2>/dev/null)
     if echo "$body" | grep -q "Index of"; then
       echo "[!!!] DIR LISTING: $path"
       echo "$body" | grep -oP 'href="[^\"]+\.(csv|xlsx|txt|pdf)"' | head -20
     fi
   done
   ```

4. **Price Calculator Probe**
   ```bash
   # Interactive pricing calculators often have injection potential
   curl -sk "https://$TARGET/pricing" | grep -oE 'name="[^"]*"' | sort -u
   curl -sk "https://$TARGET/api/calculate" -d "pounds=100&service=wash-fold" | jq '.' 2>/dev/null
   ```

5. **Third-Party Platform Detection**
   ```bash
   curl -sk "https://$TARGET/" | grep -iE "cents|laundrylocker|washlava|cleancloud" | head -5
   ```

## Attack Surface Signals

- URLs with `/schedule-pickup`, `/order-online`, `/pricing-calculator`
- WordPress + booking/customer portal plugins
- Third-party platform integrations (Cents, LaundryLocker)
- Customer order tracking pages with numeric IDs
- Price calculators with weight/item count inputs

## Common Root Causes

1. **Customer order data in debug logs** — every pickup/delivery order generates log entries with full PII
2. **Price calculator injection** — PHP calculators with numeric inputs (pounds, items) often have no validation
3. **Third-party integration misconfig** — API keys for payment/booking platforms exposed in JS bundles
4. **Invoice/receipt PDFs in public dirs** — generated invoices with customer info stored in webroot

## Related Skills

- **recon-smb-services** — General SMB recon methodology
- **recon-pools** — Similar booking/scheduling service profile
- **hunt-wordpress** — WordPress-specific vulnerability hunting
- **hunt-source-leak** — API key discovery in JS and config files
- **hunt-source-leak** — debug.log, invoice PDF exposure

## Bypass Techniques

- Price calculator endpoints often accept POST data without server-side validation — test with negative quantities, decimal overflows, and special characters
- Order tracking at `/track-order?id=1` often iterates sequential order IDs
- Google Maps API keys on service-area pages frequently unrestricted
- Cents/LaundryLocker integrations may expose API tokens in page source
