---
name: recon-cafes
description: "Sector-specific recon for coffee shop, cafe, and tea house websites — typically WordPress on shared hosting with online ordering for pickup/delivery, loyalty/rewards programs, catering menus, and location/store finders. Common platforms include Toast POS, Square Online, ChowNow, and Olo for online ordering."
sources: field_recon, web_recon
report_count: 4
---

# RECON-CAFES — Sector-Specific Recon for Coffee Shop & Cafe Sites

## When to Use

Use when the target scope includes coffee shops, cafes, tea houses, or coffee roaster company domains. These small businesses run marketing sites with online ordering systems, loyalty programs (often custom or third-party), catering menus, and multiple location finders. Common vulnerabilities: online ordering API exposure, loyalty points manipulation, exposed Toast/Square API keys in JS bundles, store locator data leakage, and third-party integration misconfigurations.

## Quick Reference

- **Common CMS**: WordPress (dominant), Squarespace, Wix
- **Common platforms**: Toast POS, Square Online, ChowNow, Olo, Clover, Upserve, Bbot, Ritual
- **Key endpoints**: `/order`, `/menu`, `/catering`, `/locations`, `/rewards`, `/loyalty`, `/gift-cards`, `/shop`
- **Key findings**: Toast POS API keys in JS bundles, online ordering API IDOR, loyalty program manipulation, store locator data exposure

## Step-by-Step

1. **Platform Fingerprinting**
   ```bash
   # Toast POS — look for toasttab.com or toastep hostnames
   curl -sk "https://$TARGET/" | grep -iE "toasttab|toast\.pos|squareup|chownow|olo|ritual"
   # Square Online
   curl -skI "https://$TARGET/" | grep -i "square"
   # Clover
   curl -sk "https://$TARGET/" | grep -i "clover"
   ```

2. **Online Ordering API Recon**
   ```bash
   # Toast backend — often at toastep.com
   curl -sk "https://$TARGET.toastep.com/api/" | head -20
   # Check for exposed API endpoints in JS
   curl -sk "https://$TARGET/" | grep -oP 'src="[^"]*\.js"' | while read js; do
     curl -sk "https://$TARGET/$(echo $js | sed 's/src="//;s/"//')" | grep -oP 'api[^"\'"'"']+' 2>/dev/null
   done
   ```

3. **Loyalty/Rewards Recon**
   ```bash
   # Loyalty program endpoints often have IDOR
   for path in "/loyalty" "/rewards" "/points" "/my-rewards" "/check-in" "/stamp-card"; do
     code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
     [ "$code" != "404" ] && echo "[+] Loyalty endpoint: $path ($code)"
   done
   # Test for points manipulation
   curl -sk "https://$TARGET/api/loyalty/earn" -d "points=1000&action=earn" -H "Cookie: $SESSION"
   ```

4. **Store Locator Probe**
   ```bash
   # Multi-location coffee chains
   for path in "/locations" "/find-us" "/stores" "/cafes" "/api/locations"; do
     curl -sk "https://$TARGET$path" | jq '.' 2>/dev/null | head -20
   done
   # Google Maps API key extraction
   curl -sk "https://$TARGET/" | grep -oP 'AIza[a-zA-Z0-9_-]{35,}' | head -5
   ```

5. **Gift Card / Payment Recon**
   ```bash
   for path in "/gift-cards" "/giftcard" "/gift" "/e-gift" "/balance"; do
     code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
     [ "$code" != "404" ] && echo "[+] Gift card endpoint: $path ($code)"
   done
   # Test gift card balance enumeration
   curl -sk "https://$TARGET/api/gift-card/balance" -d "card_number=4111111111111111"
   ```

## Attack Surface Signals

- Toast POS integration at `toasttab.com` or `toastep.com` subdomains
- Square Online ordering via `squareup.com` or `square.site`
- Online ordering with numeric menu/item IDs (IDOR on prices)
- Loyalty/rewards program endpoints with points balance manipulation
- Store locator with Google Maps API keys
- Multi-location franchise sites with shared backend

## Common Root Causes

1. **Toast/Square API keys in JS bundles** — POS integration keys exposed in frontend code
2. **Online ordering API IDOR** — Menu prices and order data accessible by incrementing IDs
3. **Loyalty points manipulation** — Earn/redeem endpoints without server-side validation
4. **Unrestricted Google Maps API keys** — Keys on store locator pages usable from any referrer
5. **Gift card balance enumeration** — Card balance endpoints without rate limiting or auth
6. **Multi-location data sharing** — Franchise sites sharing backend → one location's vulnerability affects all

## Related Skills

- **recon-bakeries** — Similar online ordering/e-commerce profile
- **recon-smb-services** — General SMB recon methodology
- **recon-mattress-stores** — Similar gift card/e-commerce patterns
- **hunt-api-misconfig** — Exposed POS/ordering APIs
- **hunt-idor** — Order/menu/loyalty IDOR
- **hunt-source-leak** — API keys in JS bundles
- **hunt-business-logic** — Loyalty points/gift card manipulation

## Bypass Techniques

- Toast POS API keys in JS bundles can be used to query the Toast API directly — test `GET https://api.toast.com/api/v1/menus` with the key
- Loyalty programs often accept arbitrary points values in POST bodies — test `points=-1000` to drain balances
- Online ordering menu item IDs are often simple integers — attempt `?menu_item_id=9999&price=0.01`
- Multi-location ordering platforms sometimes share customer databases — test cross-location order access
- Google Maps API keys from store locator pages frequently lack referrer restrictions — test against Google Maps API
