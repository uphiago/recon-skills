---
name: recon-tree-services
description: "Sector-specific recon for tree service company websites — arborist, tree removal, stump grinding, tree trimming. Common platforms include Arborgold, ArborNote, SingleOps, and Jobber for CRM/estimating; typically WordPress on shared hosting with photo galleries, service area pages, and free estimate forms."
sources: field_recon, web_recon
report_count: 4
---

# RECON-TREE-SERVICES — Tree Service Company Recon

## When to Use
Use when the target scope includes tree service, arborist, tree removal, stump grinding, or landscaping-with-tree-work company domains. These small-to-medium businesses typically run WordPress or custom PHP on shared hosting with minimal security posture, often exposing customer PII via estimate forms, CRM portals, and photo galleries.

## Quick Reference
- **Common CMS**: WordPress (dominant), custom PHP, Wix, Squarespace
- **Common platforms**: Arborgold, ArborNote, SingleOps, Jobber, GorillaDesk
- **Key endpoints**: `/estimate`, `/free-estimate`, `/contact`, `/request-quote`, `/service-area`
- **Customer portals**: Arborgold client login, Jobber client portal (often accessible via subdomain)
- **Key findings**: Contact form PII leakage, debug logs, directory listing on uploads, outdated plugins

## Step-by-Step

1. **CMS Detection**
   ```bash
   curl -skI "https://$TARGET/" | grep -iE "x-powered-by|set-cookie|server"
   curl -sk "https://$TARGET/" | grep -iE "generator|wp-content|wp-json"
   ```

2. **CRM/Estimating Platform Detection**
   ```bash
   # Arborgold — look for /arborgold/ paths
   curl -sk "https://$TARGET/arborgold/" | head -20
   # SingleOps — look for /ordering/ or api.singleops.com references
   curl -sk "https://$TARGET/" | grep -i "singleops\|arborgold\|arbornote\|gorilladesk"
   # Jobber — look for getjobber.com or client.jobber.com redirects
   curl -skI "https://$TARGET/client" | grep -i "jobber"
   ```

3. **Estimate Form Recon**
   ```bash
   # Free estimate forms often POST PII in plaintext
   curl -sk "https://$TARGET/estimate" -o /tmp/estimate.html
   grep -oE 'name="[^"]*"' /tmp/estimate.html | sort -u
   grep -oE 'action="[^"]*"' /tmp/estimate.html
   # Check for exposed form submission data
   curl -sk "https://$TARGET/wp-content/debug.log" | grep -i "estimate\|contact\|submission" | head -20
   ```

4. **Photo Gallery / Uploads Recon**
   ```bash
   # Before/after photo galleries often have directory listing
   curl -sk "https://$TARGET/wp-content/uploads/" | head -50
   curl -sk "https://$TARGET/gallery/" | head -50
   curl -sk "https://$TARGET/images/" | head -50
   grep -oP 'src="[^"]+\.(jpg|png|webp)"' /tmp/estimate.html | sort -u | head -20
   ```

5. **Service Area Pages**
   ```bash
   # City/service area pages often contain embedded Google Maps API keys
   curl -sk "https://$TARGET/service-areas" | grep -oP 'AIza[a-zA-Z0-9_-]{35,}' | head -5
   curl -sk "https://$TARGET/service-areas" | grep -oP 'key=([^"& ]+)' | head -5
   ```

6. **Customer Portal Probe**
   ```bash
   # Arborgold client portals
   curl -sk "https://client.$TARGET/" | head -20
   curl -sk "https://$TARGET.arborgold.net/" | head -20
   # Jobber client portal
   curl -sk "https://$TARGET.jobber.com/" | head -20
   ```

## Attack Surface Signals
- URLs with `/estimate`, `/free-estimate`, `/request-quote`, `/service-areas`
- Google Maps API keys embedded in service-area or contact pages
- WordPress + third-party CRM/estimating plugins
- Before/after photo gallery pages with directory listing enabled
- Arborgold login page at `/arborgold/login` or `client/<company>.arborgold.net`
- Subdomains like `estimates.`, `portal.`, `schedule.`, `book.`, `client.`

## Common Root Causes
1. **CRM integration PII leakage** — Estimate form submissions stored in plaintext or accessible via IDOR in CRM portals
2. **Google Maps API key over-exposure** — Keys embedded on service-area pages without referrer restriction
3. **Outdated WordPress plugins** — Tree service sites rarely update plugins; photo gallery and contact form plugins are common vulnerabilities
4. **Debug log exposure** — `wp-content/debug.log` with form submissions, SQL queries, and API keys
5. **Directory listing on uploads** — Before/after photo galleries often leave directory listing enabled

## Related Skills
- **recon-landscaping** — Overlapping sector (many companies do both tree and lawn services)
- **recon-smb-services** — General SMB recon methodology for local service businesses
- **hunt-wordpress** — WordPress-specific vulnerability hunting (dominant CMS for this sector)
- **hunt-source-leak** — API key and secret discovery in JS and config files
- **hunt-file-upload** — Photo gallery upload vulnerabilities

## Bypass Techniques

- Arborgold client portals at `/arborgold/` often have default credentials or no login required — try accessing directly
- Google Maps API keys on service-area pages are frequently unrestricted — test key against Google Maps API without referrer
- Estimate form submissions are sometimes stored as PDFs in `/estimates/` or `/proposals/` directories with sequential filenames
- Free estimate forms that POST via AJAX may not have CSRF tokens — try direct POST from another origin
- CRM portal subdomains like `client.target.com` or `estimates.target.com` often have weaker auth than the main site
- Photo galleries with numbered filenames (IMG_0001.jpg, IMG_0002.jpg) — iterate to find all photos including those not linked from pages

## Real Examples

From cross-sector mass recon observation:
- A tree service company's Arborgold CRM portal at `/arborgold/` was accessible without authentication, exposing all customer estimates including names, addresses, phone numbers, and tree service quotes
- Another tree service had debug.log exposed at `/wp-content/debug.log` containing 500+ form submissions with full customer PII — names, addresses, phone numbers, property descriptions
- A tree removal company had a Google Maps API key on service-area pages that was unrestricted — any referrer could use it to query Google Maps API at $200/day cost to the business
- An arborist's Jobber client portal at `client.jobber.com/business-name` had weak authentication — iterating booking IDs returned customer service history
