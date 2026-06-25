---
name: recon-salons
description: "Sector-specific recon for salon, barbershop, nail salon, and spa websites — common booking platforms include Booksy, Vagaro, Square Appointments, Mindbody, Fresha, and StyleSeat. Typically WordPress or custom PHP on shared hosting with online booking, service menus, and customer account portals."
sources: field_recon, web_recon
report_count: 5
---

# RECON-SALONS — Salon/Barbershop Recon

## When to Use
Use when the target scope includes hair salons, barbershops, nail salons, spas, waxing studios, or med-spas. These businesses rely heavily on third-party booking platforms that handle customer PII (names, phone numbers, email addresses). The booking API exposure, customer data leakage, and authentication gaps are common findings in this sector.

## Quick Reference
- **Common CMS**: WordPress, custom PHP, Wix, Squarespace
- **Common platforms**: Booksy, Vagaro, Square Appointments, Mindbody, Fresha, StyleSeat, Timely
- **Key endpoints**: `/book`, `/booking`, `/appointments`, `/services`, `/pricing`, `/staff`
- **API surfaces**: Booksy API, Vagaro API, Square API, Mindbody API v6
- **Key findings**: Booking API exposing customer PII, appointment data without auth, staff schedule IDOR

## Step-by-Step

1. **Booking Platform Fingerprinting**
   ```bash
   # Booksy — look for booksy.com or booksy pages
   curl -sk "https://$TARGET/" | grep -iE "booksy|book\.booksy\.com"
   # Vagaro — look for vagaro.com
   curl -sk "https://$TARGET/" | grep -i "vagaro"
   # Square Appointments — look for squareup.com or square.site
   curl -sk "https://$TARGET/" | grep -iE "squareup|square\.site"
   # Fresha — look for fresha.com
   curl -sk "https://$TARGET/" | grep -i "fresha"
   # StyleSeat — look for styleseat.com
   curl -sk "https://$TARGET/" | grep -i "styleseat"
   ```

2. **Booking Page Recon**
   ```bash
   # Find booking endpoints
   for path in "/book" "/booking" "/appointments" "/schedule" "/book-now" "/services" "/online-booking"; do
     code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
     [ "$code" != "404" ] && echo "[+] Booking: $path ($code)"
   done
   # Extract API endpoints from booking page
   curl -sk "https://$TARGET/book" | grep -oE 'api[^"'"'"']*' | sort -u
   curl -sk "https://$TARGET/book" | grep -oE 'https?://[^"'"'"']*/(api|v[0-9])[^"'"'"']*' | sort -u
   ```

3. **Customer Data Exposure Testing**
   ```bash
   # Test booking API for customer data leakage
   for path in "/api/appointments" "/api/bookings" "/api/staff" "/api/customers" "/api/clients"; do
     curl -sk "https://$TARGET$path" | jq '.' 2>/dev/null | head -10
     echo "---"
   done
   # IDOR on booking IDs
   curl -sk "https://$TARGET/api/appointments/1" | jq '.' 2>/dev/null
   curl -sk "https://$TARGET/api/bookings/2026/06/24" | jq '.' 2>/dev/null
   ```

4. **Third-Party Platform API Tests**
   ```bash
   # Booksy — if embedded, try Booksy API endpoints
   curl -sk "https://book.booksy.com/api/v2/business/$BUSINESS_ID/appointments"
   # Vagaro API
   curl -sk "https://api.vagaro.com/v1/businesses/$BUSINESS_ID/appointments"
   # Square Appointments
   curl -sk "https://$TARGET.square.site/book" | grep -oE 'api[^"'"'"']*'
   ```

5. **Staff Schedule Recon**
   ```bash
   # Staff profiles often list schedules without auth
   for path in "/staff" "/team" "/our-staff" "/stylists" "/barbers"; do
     curl -sk "https://$TARGET$path" | grep -oE '[A-Z][a-z]+\s[A-Z][a-z]+' | sort -u | head -10
   done
   # Check for staff booking links (IDOR on staff IDs)
   curl -sk "https://$TARGET/api/staff/1/schedule"
   curl -sk "https://$TARGET/api/staff/1/bookings"
   ```

## Attack Surface Signals
- Embedded Booksy/Vagaro/Square booking widgets with API calls visible in network tab
- `book.booksy.com`, `vagaro.com`, `square.site` subdomain redirects
- Customer booking confirmation pages with PII in URL parameters
- Staff profiles with embedded schedule availability (IDOR on staff IDs)
- Testimonials/reviews with customer names, services, and dates
- API keys for booking platforms in JS bundles

## Common Root Causes
1. **Booking API without auth** — Appointment data accessible with sequential IDs
2. **Customer PII in URLs** — Booking confirmation pages with name/phone in query parameters
3. **Embedded API keys** — Booksy/Vagaro/Square API keys in frontend code
4. **Staff schedule enumeration** — Staff member IDs are sequential and schedules are public
5. **Review/testimonial PII** — Customer names + service details in public gallery
6. **Cancellation/modification without auth** — Booking changes via booking ID only

## Related Skills
- **hunt-idor** — Booking and customer IDOR is the primary finding in this sector
- **recon-gyms** — Overlapping sector (many platforms used by both)
- **recon-smb-services** — General SMB recon methodology
- **hunt-api-misconfig** — Booking API and key exposure
- **hunt-source-leak** — API keys in JS bundles

## Bypass Techniques

- Booking platforms often expose appointment data via API endpoints with sequential numeric IDs — try `/api/appointments/1`, `/2`, `/3`
- Customer PII is frequently in URL parameters on booking confirmation pages — check for `?name=`, `?phone=`, `?email=` in query strings
- Staff schedule APIs may return data without any session cookie — test with empty `Cookie:` header
- Some booking widgets pass business ID in a `data-business-id` attribute — this ID can be used to access other businesses' bookings
- Cancellation endpoints often require only a booking ID (no auth) — test `/api/bookings/{id}/cancel`
- Search for embedded API keys in JS bundles: `grep -oP 'pk_(live|test)_[a-zA-Z0-9]{24,}'` for Square/Stripe keys

## Real Examples

From cross-sector mass recon observation:
- A salon chain using Booksy had appointment data accessible at `/api/v2/business/{id}/appointments` — incrementing the business ID revealed booking data for 40+ other salons
- A barbershop's Vagaro booking page passed customer full name and phone number in URL parameters on the confirmation page
- A med-spa had a Square Appointments integration with the public API key hardcoded in JS, exposing all appointment data for the business
- A nail salon's `/api/staff` endpoint returned all staff schedules without authentication, revealing working hours and personal contact info
