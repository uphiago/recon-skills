---
name: recon-gyms
description: "Sector-specific recon for gym, fitness center, and health club websites — common platforms include Mindbody, Mariana Tek, ClubReady, Glofox, PushPress, and Wodify for scheduling/booking; typically WordPress or custom PHP on shared hosting with member portals, class schedules, and payment integration."
sources: field_recon, web_recon
report_count: 5
---

# RECON-GYMS — Gym/Fitness Center Recon

## When to Use
Use when the target scope includes gyms, fitness centers, health clubs, CrossFit boxes, yoga studios, or boutique fitness studios. These businesses typically use third-party SaaS platforms for scheduling and payments (Mindbody, ClubReady, Mariana Tek) with a separate marketing website. The booking/scheduling APIs and member portals often have authentication and authorization gaps.

## Quick Reference
- **Common CMS**: WordPress, custom PHP, Wix, Squarespace
- **Common platforms**: Mindbody, Mariana Tek, ClubReady, Glofox, PushPress, Wodify, Zen Planner, Vagaro
- **Key endpoints**: `/schedule`, `/book`, `/classes`, `/membership`, `/pricing`, `/sign-in`
- **API surfaces**: Mindbody API (v6), Mariana Tek API, ClubReady API
- **Key findings**: Booking API IDOR, member portal access without auth, payment processing misconfig, class capacity bypass

## Step-by-Step

1. **Platform Fingerprinting**
   ```bash
   # Mindbody — look for /clientsite/ or mindbodyonline.com references
   curl -sk "https://$TARGET/" | grep -iE "mindbody|mbo|clientsite|mindbodyonline"
   # Mariana Tek — look for marianatek.com or /schedule/ paths
   curl -sk "https://$TARGET/schedule" | grep -i "mariana"
   # ClubReady — look for clubready.com
   curl -sk "https://$TARGET/" | grep -i "clubready"
   # Check booking page headers for platform signatures
   curl -skI "https://$TARGET/schedule" | grep -iE "server|x-powered-by"
   ```

2. **Booking API Discovery**
   ```bash
   # Mindbody API (v6) — staff/public endpoints
   curl -sk "https://api.mindbodyonline.com/public/v6/" -H "API-Key: test"
   curl -sk "https://$TARGET/clientsite/" | head -30
   # Mariana Tek API
   curl -sk "https://$TARGET.marianatek.com/api/" | head -20
   # Look for API keys in JS bundles
   curl -sk "https://$TARGET/" | grep -oP 'src="[^"]*\.js"' | while read js; do
     curl -sk "https://$TARGET/$(echo $js | sed 's/src="//;s/"//')" | grep -oP '(mindbody|mariana|clubready)_?api[^"'"'"']+' 2>/dev/null
   done
   ```

3. **Member Portal Recon**
   ```bash
   # Check for member login pages
   for portal in "/member-login" "/member-portal" "/my-account" "/login" "/portal" "/sign-in" "/account"; do
     code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$portal")
     [ "$code" != "404" ] && echo "[+] Portal: $portal ($code)"
   done
   # Test for registration without paying
   curl -sk -X POST "https://$TARGET/api/members/register" \
     -H "Content-Type: application/json" \
     -d '{"email":"test@test.com","plan":"unlimited","payment_method":"none"}'
   ```

4. **Class Schedule API Probe**
   ```bash
   # Check for API endpoints returning class data without auth
   curl -sk "https://$TARGET/api/classes" | jq '.' 2>/dev/null | head -20
   curl -sk "https://$TARGET/api/schedule" | jq '.' 2>/dev/null | head -20
   # Try IDOR on class/booking endpoints
   curl -sk "https://$TARGET/api/bookings/1" -H "Cookie: $SESSION"
   curl -sk "https://$TARGET/api/members/1/profile" | jq '.' 2>/dev/null
   ```

5. **Payment Integration Recon**
   ```bash
   # Check for exposed payment processing endpoints
   curl -sk "https://$TARGET/checkout" | grep -oE 'stripe|braintree|square|paypal'
   # Test webhook endpoints
   curl -sk "https://$TARGET/webhook/stripe" -X POST -d '{}'
   curl -sk "https://$TARGET/api/payment/webhook" -X POST -d '{}'
   ```

## Attack Surface Signals
- Mindbody-powered booking at `clientsite.mindbodyonline.com` or embedded iframes
- Mariana Tek scheduling at `schedule.[gym-name].com` or `[gym].marianatek.com`
- Class capacity and booking APIs returning member PII
- Member portals on subdomains like `members.`, `portal.`, `schedule.`, `book.`
- API keys in JS bundles for Mindbody/Mariana Tek integrations
- Payment webhook endpoints without HMAC validation

## Common Root Causes
1. **Booking API IDOR** — Class schedule API returns member names, emails, phone numbers without auth
2. **Free registration bypass** — Membership registration accepts signup without payment step
3. **Exposed API keys** — Mindbody API keys and Mariana Tek keys hardcoded in JS bundles
4. **Member portal no-auth access** — Profile endpoints accessible with any session cookie or none
5. **Payment webhook trust** — Webhook endpoints accept fake success notifications

## Related Skills
- **hunt-idor** — Booking/member IDOR is the most common finding in this sector
- **hunt-api-misconfig** — API key discovery in JS bundles, mass assignment on registration
- **hunt-business-logic** — Payment bypass, free-trial abuse, class capacity manipulation
- **recon-smb-services** — General SMB recon methodology
- **hunt-source-leak** — API key and secret discovery in JS bundles

## Bypass Techniques

- Free trial registrations often accept fake payment details or `payment_method: none` in POST body
- Class schedule APIs frequently return data without any session cookie — test with empty `Cookie:` header
- Staff member IDs are often sequential integers — iterate `/api/staff/1`, `/api/staff/2` etc.
- Gym check-in QR codes are sometimes static images that can be shared or replayed
- Booking widget iframes may bypass the main site's CSP, allowing clickjacking on embedded scheduling flows
- Test `/api/classes?date=2026-01-01` for historical data leakage (member check-in patterns)

## Real Examples

From cross-sector mass recon observation:
- A boutique fitness studio's Mindbody API key was hardcoded in `app.js` bundle, allowing full read access to the business's client database via `api.mindbodyonline.com/public/v6/client/clients`
- A CrossFit gym had class schedule API at `/api/schedule` returning member full names, email addresses, and check-in history without any authentication
- A yoga studio's Mariana Tek booking page allowed enumerating all appointments by incrementing numeric booking IDs — each returned client name, phone, and email
- A gym chain's member portal at `members.target.com` had no auth on profile endpoint — any session cookie (or none) returned the first member's profile
