---
name: recon-bakeries
description: "Sector-specific recon for bakery, pastry shop, and cake shop websites — typically WordPress on shared hosting with e-commerce (WooCommerce, Shopify), online ordering for cakes/pastries, catering pages, and store locators. Common platforms include EatStreet, Toast POS, Upserve, and Slice for online ordering."
sources: field_recon, web_recon
report_count: 4
---

# RECON-BAKERIES — Sector-Specific Recon for Bakeries & Pastry Shop Sites

## When to Use

Use when the target scope includes bakeries, pastry shops, cake shops, donut shops, or dessert company domains. These small businesses typically run e-commerce sites for cake/pastry ordering with custom order forms for special occasions (weddings, birthdays), catering menus, and store locators. Common vulnerabilities: e-commerce API exposure (WooCommerce/Shopify), custom order form injection, coupon code enumeration, exposed delivery addresses in order tracking, and CSV export leakage of customer orders.

## Quick Reference

- **Common CMS**: WordPress/WooCommerce (dominant), Shopify, Squarespace
- **Common platforms**: WooCommerce, Shopify, EatStreet, Toast POS, Slice, Upserve
- **Key endpoints**: `/shop`, `/order`, `/cake`, `/catering`, `/menu`, `/delivery`, `/store-locator`
- **Key findings**: WooCommerce API exposure, coupon code enumeration, custom order form injection, order data CSV export

## Step-by-Step

1. **Platform Fingerprinting**
   ```bash
   # WooCommerce detection
   curl -sk "https://$TARGET/wp-json/wc/v3/" | head -5
   # Shopify detection
   curl -sk "https://$TARGET/products.json" | jq '.' 2>/dev/null | head -5
   # EatStreet/Toast detection
   curl -sk "https://$TARGET/" | grep -iE "eatstreet|toast\.tab|slice|order\.here"
   ```

2. **E-Commerce API Recon**
   ```bash
   # WooCommerce — test for unauthenticated access
   for path in "/wp-json/wc/v3/products" "/wp-json/wc/v3/orders" "/wp-json/wc/v3/customers" "/wp-json/wc/v3/coupons"; do
     result=$(curl -sk -o /tmp/wc_test -w "%{http_code}" "https://$TARGET$path")
     [ "$result" != "404" ] && echo "[+] WC: $path ($result)"
   done
   # Shopify
   curl -sk "https://$TARGET/collections.json" | jq '.collections | length'
   curl -sk "https://$TARGET/products.json?limit=250" | jq '.products | length'
   ```

3. **Custom Order Form Recon**
   ```bash
   # Cake/pastry order forms often have custom fields
   curl -sk "https://$TARGET/order-cake" | grep -oE 'name="[^"]*"' | sort -u
   curl -sk "https://$TARGET/custom-order" | grep -oE 'action="[^"]*"' | head -5
   # Test for injection in custom fields
   curl -sk "https://$TARGET/wp-content/plugins/woocommerce-custom-order-forms/" | head -20
   ```

4. **Coupon/Discount Probe**
   ```bash
   # WooCommerce coupon enumeration
   for code in "SAVE10" "FREESHIP" "CAKEDAY" "BIRTHDAY" "NEWCUSTOMER" \
     "HOLIDAY2026" "FALL2026" "WELCOME10" "FREEDELIVERY"; do
     curl -sk "https://$TARGET/cart/?coupon=$code" | grep -i "applied\|success\|discount"
   done
   ```

5. **Store Locator Recon**
   ```bash
   # Store locator APIs often leak internal data
   curl -sk "https://$TARGET/store-locator" | grep -oE 'email[a-zA-Z0-9@._-]+|phone[^"]*'
   curl -sk "https://$TARGET/api/locations" | jq '.' 2>/dev/null
   ```

## Attack Surface Signals

- Online ordering for cakes/pastries with custom forms
- WooCommerce REST API endpoints (`/wp-json/wc/v3/`)
- Shopify storefront at `[name].myshopify.com`
- Catering menus and wholesale order pages
- Store locator with location details and manager contact info
- Custom cake/pastry order forms with free-text fields

## Common Root Causes

1. **Exposed WooCommerce API** — Customer orders and PII accessible via REST API
2. **Custom form injection** — Cake order forms with free-text fields (message, instructions) lacking sanitization
3. **Coupon code brute-force** — No rate limiting on discount code validation endpoints
4. **Store locator data leakage** — API returns manager emails, phone numbers without auth
5. **Delivery address exposure** — Order tracking pages accessible without auth exposing customer addresses

## Related Skills

- **recon-mattress-stores** — Similar e-commerce/financing patterns
- **recon-smb-services** — General SMB recon methodology
- **hunt-wordpress** — WordPress/WooCommerce vulnerability hunting
- **hunt-api-misconfig** — Exposed e-commerce APIs
- **hunt-business-logic** — Coupon/pricing manipulation in checkout flows
- **hunt-source-leak** — API keys in JS bundles

## Bypass Techniques

- WooCommerce orders endpoint at `/wp-json/wc/v3/orders` often exposes customer data without auth — test with `?per_page=100`
- Custom cake order forms often POST to unprotected PHP scripts — test for SQLi in message/instructions fields
- Store locator APIs at `/api/locations` may return internal manager data without auth
- Google Maps API keys on store locator pages are frequently unrestricted
- Check for `/wp-content/uploads/` directory listing containing order-related PDFs or images
