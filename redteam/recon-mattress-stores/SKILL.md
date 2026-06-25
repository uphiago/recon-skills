---
name: recon-mattress-stores
description: "Sector-specific recon for mattress retailer and bedding store websites — common e-commerce platforms (Shopify, WooCommerce, BigCommerce), financing integration patterns (Affirm, Klarna, Bread, Synchrony), and mattress-in-a-box brand sites. Typically Shopify or WordPress/WooCommerce with product catalogs, financing calculators, and store locators."
sources: field_recon, web_recon
report_count: 4
---

# RECON-MATTRESS-STORES — Mattress Retailer Recon

## When to Use
Use when the target scope includes mattress retailers, bedding stores, furniture-with-mattress retailers, or DTC mattress-in-a-box brands. These businesses typically operate e-commerce stores with financing options and store locators. The e-commerce misconfigurations, financing API exposure, and store locator data leakage are common findings.

## Quick Reference
- **Common CMS**: Shopify (dominant), WordPress/WooCommerce, BigCommerce, Magento
- **Common platforms**: Shopify, WooCommerce, Affirm, Klarna, Bread, Synchrony, Financing
- **Key endpoints**: `/products`, `/collections`, `/cart`, `/checkout`, `/financing`, `/store-locator`
- **Financing APIs**: Affirm pre-qualification API, Klarna checkout API, Bread API
- **Key findings**: WooCommerce API exposure, financing API misconfig, store locator data, coupon code manipulation

## Step-by-Step

1. **Platform Fingerprinting**
   ```bash
   # Shopify detection
   curl -skI "https://$TARGET/" | grep -iE "x-shopify|myshopify|shopify"
   curl -sk "https://$TARGET/products.json" | jq '.' 2>/dev/null | head -5
   # WooCommerce detection
   curl -sk "https://$TARGET/wp-json/wc/v3/" | jq '.' 2>/dev/null | head -5
   # BigCommerce detection
   curl -skI "https://$TARGET/" | grep -i "bigcommerce"
   ```

2. **E-Commerce API Recon**
   ```bash
   # WooCommerce — test for unauthenticated access
   for path in "/wp-json/wc/v3/products" "/wp-json/wc/v3/orders" "/wp-json/wc/v3/customers" "/wp-json/wc/v3/coupons"; do
     result=$(curl -sk -o /tmp/wc_test -w "%{http_code}" "https://$TARGET$path")
     [ "$result" != "404" ] && echo "[+] WC: $path ($result)"
   done
   # Shopify store info
   curl -sk "https://$TARGET/collections.json" | jq '.collections | length'
   curl -sk "https://$TARGET/products.json?limit=250" | jq '.products | length'
   # Shopify checkout/policy endpoints
   curl -skI "https://$TARGET/checkout" | grep -i "location\|http"
   ```

3. **Financing API Discovery**
   ```bash
   # Affirm — check for affirm.js or affirm.com
   curl -sk "https://$TARGET/" | grep -iE "affirm|\.com/js/v2/affirm"
   # Klarna — check for klarna.com
   curl -sk "https://$TARGET/" | grep -i "klarna"
   # Bread — check for breadpayments.com
   curl -sk "https://$TARGET/" | grep -i "bread"
   # Look for financing pre-qualification endpoints
   for path in "/financing" "/financing-options" "/affirm" "/as-low-as" "/monthly-payments"; do
     curl -sk "https://$TARGET$path" | grep -oE 'api[^"'"'"']*key[^"'"'"']*|public_key[^"'"'"']*'
   done
   ```

4. **Store Locator Recon**
   ```bash
   # Store locators often leak internal store IDs, emails, phone numbers
   curl -sk "https://$TARGET/store-locator" | grep -oE 'email[^"'"'"']*|phone[^"'"'"']*|[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
   # Test store locator API
   curl -sk "https://$TARGET/api/stores" | jq '.' 2>/dev/null
   curl -sk "https://$TARGET/api/locations" | jq '.' 2>/dev/null
   curl -sk "https://$TARGET/wp-json/wc/v3/products/categories" | jq '.' 2>/dev/null
   # Check for directory listing on store images
   curl -sk "https://$TARGET/wp-content/uploads/" | head -50
   ```

5. **Coupon/Discount Probe**
   ```bash
   # WooCommerce coupons (if exposed)
   curl -sk "https://$TARGET/wp-json/wc/v3/coupons" | jq '.' 2>/dev/null
   # Shopify discount codes
   curl -sk "https://$TARGET/discounts/" | head -20
   # Common coupon code testing
   for code in "SAVE10" "SAVE20" "WELCOME10" "FIRSTORDER" "FREESHIPPING" "MEMORIAL2026"; do
     curl -sk "https://$TARGET/cart/update?discount=$code" | grep -i "valid\|applied\|success"
   done
   ```

## Attack Surface Signals
- Shopify store at `[brand].myshopify.com` with products.json/collections.json exposed
- WooCommerce `/wp-json/wc/v3/` API accessible without authentication
- Affirm/Klarna/Bread financing API keys in JS bundles
- Store locator pages returning internal location data (store IDs, manager emails, phone numbers)
- Product review/testimonial pages with customer PII
- `/financing` or `/as-low-as` pages with embedded financing calculators (API endpoints visible)

## Common Root Causes
1. **Exposed WooCommerce API** — Customer and order data accessible via REST API
2. **Store locator data leakage** — API returns manager names, emails, phone numbers without auth
3. **Financing API keys in frontend** — Affirm/Klarna public keys embedded in JS without referrer restriction
4. **Coupon code bruteforce** — No rate limiting on discount code validation endpoints
5. **Product review PII** — Customer names and emails in public-facing reviews
6. **Checkout bypass** — Payment step-skip or price manipulation on financing orders

## Related Skills
- **hunt-wordpress** — WordPress/WooCommerce vulnerability hunting (dominant for non-Shopify mattress sites)
- **hunt-api-misconfig** — Exposed e-commerce and financing APIs
- **hunt-business-logic** — Coupon/pricing manipulation in checkout flows
- **recon-smb-services** — General SMB recon methodology
- **hunt-source-leak** — API keys and secrets in JS bundles and config files

## Bypass Techniques

- Financing pre-qualification API endpoints often don't require authentication — test `/api/financing/check` with arbitrary data
- Store locator APIs at `/api/stores` or `/api/locations` may return internal manager emails and phone numbers without auth
- WooCommerce coupons exposed via API — iterate numeric coupon IDs at `/wp-json/wc/v3/coupons/1`, `/2`, `/3` etc.
- Shopify product JSON at `/products.json` often reveals inventory counts and pricing for hidden/out-of-stock items
- Checkout flow may accept `POST /cart/update.js` with arbitrary discount codes — test rate limits on coupon validation
- Store locator search by ZIP code can leak all store data — try `?zip=90210&radius=10000`

## Real Examples

From cross-sector mass recon observation:
- A mattress retailer's Affirm financing API key was exposed in the page source at `/financing`, allowing pre-qualification lookups on arbitrary customers
- A bedding store's WooCommerce REST API at `/wp-json/wc/v3/coupons` returned 47 active discount codes including `FREESHIPPING` and `FRIENDSANDFAMILY20`
- A mattress-in-a-box brand had `/api/stores` returning full location data including manager names, direct phone numbers, and email addresses for all 200+ retail locations
- A furniture retailer's store locator API accepted any ZIP code and returned all store manager PII without authentication
