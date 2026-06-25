---
name: recon-breweries
description: "Sector-specific recon for craft brewery, brewpub, and distillery websites — common e-commerce platforms (Untappd, Shopify, WooCommerce), age-gate patterns, event calendars, beer menu APIs, and online ordering systems. Typically WordPress, Shopify, or custom sites on shared hosting with taproom menus and merchandise stores."
sources: field_recon, web_recon
report_count: 5
---

# RECON-BREWERIES — Craft Brewery Recon

## When to Use
Use when the target scope includes craft breweries, brewpubs, distilleries, cideries, or meaderies. These businesses typically have a marketing site + e-commerce store + Untappd integration. The age-gate bypass, menu API exposure, and e-commerce misconfigs are common findings in this sector.

## Quick Reference
- **Common CMS**: WordPress (WooCommerce), Shopify, Squarespace
- **Common platforms**: Untappd, Shopify, WooCommerce, Toast POS, Square, BeerMenus
- **Key endpoints**: `/shop`, `/menu`, `/beer`, `/events`, `/age-gate`, `/verify`, `/order`
- **Age gates**: Often JavaScript-only redirects or cookie-based (bypassable)
- **Key findings**: Age-gate bypass, Untappd API key exposure, menu API without auth, WooCommerce misconfig

## Step-by-Step

1. **Age-Gate Detection & Bypass**
   ```bash
   # Check if age gate exists
   curl -skI "https://$TARGET/" | grep -i "age\|verify\|21\|drink"
   curl -sk "https://$TARGET/" | grep -iE "age-gate|verify-age|are-you-21|drink-aware"
   # Common bypasses
   curl -sk "https://$TARGET/?age_verified=1"
   curl -sk "https://$TARGET/" -H "Cookie: age_verified=true"
   curl -sk "https://$TARGET/" -d "age=21&verified=true"
   # Direct access to /shop or /menu bypasses gate
   curl -sk "https://$TARGET/shop"
   curl -sk "https://$TARGET/menu"
   ```

2. **Platform Fingerprinting**
   ```bash
   # Untappd integration — check for untappd.com links
   curl -sk "https://$TARGET/" | grep -iE "untappd|untp\.it|untappd\.com/api"
   # Shopify — check for myshopify.com or Shopify headers
   curl -skI "https://$TARGET/" | grep -iE "x-shopify|myshopify"
   # WooCommerce — check for /wp-json/wc/
   curl -sk "https://$TARGET/wp-json/wc/" | head -5
   # Toast POS — look for /toast/ paths
   curl -sk "https://$TARGET/" | grep -i "toast"
   ```

3. **Menu/Beer API Discovery**
   ```bash
   # Untappd embedded menus
   curl -sk "https://$TARGET/" | grep -oP 'https://untappd\.com/v/[^"'"'"']+' | sort -u
   # Beer menu endpoints
   for path in "/menu" "/beer" "/beers" "/tap-list" "/on-tap" "/api/beer" "/api/menu"; do
     code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
     [ "$code" != "404" ] && echo "[+] $path ($code)"
   done
   # Check for JSON menu endpoints
   curl -sk "https://$TARGET/api/beer/menu" | jq '.' 2>/dev/null | head -20
   ```

4. **E-Commerce Recon**
   ```bash
   # WooCommerce API discovery
   for path in "/wp-json/wc/v3/products" "/wp-json/wc/v3/orders" "/wp-json/wc/v3/customers"; do
     curl -sk "https://$TARGET$path" | jq '.' 2>/dev/null | head -5
   done
   # Shopify store info
   curl -sk "https://$TARGET/products.json" | jq '.' 2>/dev/null | head -20
   curl -sk "https://$TARGET/collections.json" | jq '.' 2>/dev/null | head -10
   # Check for discount code leakage
   curl -sk "https://$TARGET/wp-json/wc/v3/coupons" | jq '.' 2>/dev/null
   ```

5. **Event Calendar Probe**
   ```bash
   for path in "/events" "/calendar" "/taproom" "/events-calendar" "/api/events"; do
     code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
     [ "$code" != "404" ] && echo "[+] $path ($code)"
   done
   # Test for event submission without auth
   curl -sk -X POST "https://$TARGET/api/events" \
     -H "Content-Type: application/json" \
     -d '{"title":"Test Event","date":"2026-07-04"}'
   ```

## Attack Surface Signals
- Age-gate popup on homepage (JavaScript-only verification is trivially bypassed)
- Untappd badges/menus embedded (may expose API tokens)
- WooCommerce REST API (`/wp-json/wc/v3/`) accessible without auth
- Shopify store at `[brewery].myshopify.com` with exposed products/collections JSON
- Beer menu APIs returning pricing or inventory data
- Event calendar with user-submission capability

## Common Root Causes
1. **Client-side age-gate only** — Cookie or sessionStorage-based age verification bypassed by direct URL access or cookie manipulation
2. **Exposed WooCommerce API** — Order/customer endpoints accessible without authentication
3. **Untappd API key in JS/HTML** — Integration keys discoverable on menu pages
4. **Online ordering auth gap** — Order placement without account creation or payment validation
5. **Event calendar injection** — Public submission forms without sanitization

## Related Skills
- **recon-smb-services** — General SMB recon methodology
- **hunt-wordpress** — WordPress/WooCommerce vulnerability hunting
- **hunt-auth-bypass** — Age-gate bypass is a common finding
- **hunt-api-misconfig** — Exposed API endpoints in menu/ordering systems
- **hunt-business-logic** — E-commerce flow manipulation for merchandise

## Bypass Techniques

- Age gates are almost exclusively JavaScript-only or cookie-based — bypass by setting `age_verified=true` cookie, appending `?age_verified=1`, or accessing `/shop` directly
- Untappd API tokens are often in HTML `data-*` attributes on menu badge elements — search `data-untappd` or `data-menu`
- WooCommerce coupon endpoints at `/wp-json/wc/v3/coupons` may return discount codes even when the API is "protected" — test with `per_page=100`
- Shopify stores often have `/products.json?limit=250` exposing full product catalog including hidden/archived items
- Event calendar POST endpoints may accept submissions from unauthenticated users — test with a simple CORS preflight

## Real Examples

From cross-sector mass recon observation:
- A craft brewery's age gate was a JavaScript redirect only — accessing `/shop` directly bypassed the gate entirely, exposing the full WooCommerce store
- A brewpub's Untappd integration revealed the business API key in an HTML `data-menu` attribute, allowing querying of all Untappd check-in data for the venue
- A distillery's WooCommerce REST API at `/wp-json/wc/v3/orders` was fully accessible without authentication, exposing customer names, addresses, and purchase history
- A brewery event calendar had a public event submission endpoint at `/api/events` — a simple POST created events without any moderation
