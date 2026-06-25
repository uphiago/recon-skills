# General Attack Patterns (P-01 to P-25)

Detailed descriptions, detections, frequencies, severities, exploitation paths, and bypass techniques for all 25 confirmed attack patterns.

## P-01: WordPress REST API User Enumeration
**Detection:** `curl -sk "TARGET/wp-json/wp/v2/users"` returns JSON with `id`, `name`, `slug`.
**Frequency:** ~9% of all targets.
**Severity:** Medium (Low if only usernames, Medium if emails/roles exposed).
**Exploitation:**
- Map usernames to email format (first.last@domain, admin@domain).
- Spear-phishing against exposed users.
- Brute force login with enumerated usernames.
- Cross-reference with HaveIBeenPwned for password reuse.
**Bypass:** Some WP setups restrict `/wp/v2/users` to authenticated users. Fall back to Yoast sitemaps (P-12) or author archive enumeration (`/?author=1`).

## P-02: CORS Origin Reflection with Credentials
**Detection:** `curl -skI "TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com"` returns `Access-Control-Allow-Credentials: true` + mirrored origin.
**Frequency:** ~3.3% overall, ~7-8% of WordPress targets.
**Severity:** Critical when confirmed exploitable.
**Exploitation:** See `cors-credential-wordpress` skill for full browser PoC.
**Root cause:** WordPress `rest_send_cors_headers()` mirrors the `Origin` header and sets `Access-Control-Allow-Credentials: true` by default.

## P-03: CORS Null Origin Trust
**Detection:** `curl -skI "TARGET/api" -H "Origin: null"` returns `Access-Control-Allow-Origin: null`.
**Severity:** High (exploitable via sandboxed iframe).
**Exploitation:** `iframe sandbox="allow-scripts"` sends `Origin: null`. Use for data exfiltration from sandboxed contexts.

## P-04: CORS Wildcard (No Credentials)
**Detection:** `curl -skI "TARGET/api" -H "Origin: https://evil.com"` returns `Access-Control-Allow-Origin: *`.
**Severity:** Info (no credentials, public data only). Not submittable as a standalone finding.
**Exception:** Valuable when chained — public API data reveals internal structure, endpoints, or user IDs.

## P-05: CORS Credentialed Preflight Bypass
**Detection:** OPTIONS preflight returns 200 with ACAC, but GET without preflight also works.
**Severity:** High.
**Exploitation:** Simple GET requests don't trigger CORS preflight. If the endpoint allows GET and reflects origin, exfiltration works without OPTIONS support.

## P-06: CORS on Auth-Protected Endpoints
**Detection:** Endpoint requires auth, but CORS allows credentialed cross-origin access.
**Severity:** Critical — attacker page steals authenticated data.
**Exploitation:** Victim must be logged in. Create phishing page that fetches auth-protected data and exfiltrates.

## P-07: XMLRPC system.multicall Brute Force
**Detection:** `system.listMethods` includes `system.multicall`. Sending 100+ `wp.getUsers` calls in one request.
**Severity:** High (1000x amplification over sequential requests).
**Exploitation:** See `xmlrpc-exploitation` Phase 4 for full payload.

## P-08: XMLRPC pingback.ping SSRF
**Detection:** Send pingback to your Collaborator URL. If callback received, SSRF confirmed.
**Severity:** High (SSRF to internal network, IMDS).
**Exploitation:** Probe AWS IMDS (`169.254.169.254`), internal IPs, localhost services.
**Real Confirmation:** staging.biglots.com — 15 IMDS paths all returned faultCode 0 in Wave6.

## P-09: XMLRPC IMDS Role Guessing
**Detection:** After confirming pingback SSRF, probe specific IAM role paths.
**Severity:** Critical if credentials retrieved.
**IMDS paths:** `/latest/meta-data/iam/security-credentials/`, `/latest/user-data/`, `/latest/meta-data/public-keys/0/openssh-key`.
**Note:** IMDSv2 requires token (`X-aws-ec2-metadata-token` header), which pingback cannot set. Only works on IMDSv1.

## P-10: Open Registration → Upload → RCE
**Detection:** `/wp-login.php?action=register` shows registration form.
**Severity:** Critical (RCE chain).
**Chain:** Open registration → get subscriber account → XMLRPC `wp.uploadFile` → upload PHP webshell → RCE.
**Requirements:** Default WP role must allow uploads (Subscriber cannot by default; requires misconfigured roles).
**Confirmed on:** wines.com.

## P-11: Plugin REST Namespace Brute Force
**Detection:** Probe 40+ known plugin REST namespaces to identify installed plugins.
**Severity:** Variable (depends on plugin vulnerabilities).
**Exploitation:** See `wordpress-plugin-hunt` for full namespace list and CVE matching.

## P-12: Yoast Author Sitemap Enumeration
**Detection:** `curl -sk "TARGET/author-sitemap.xml"` returns XML with author emails.
**Severity:** Low (email disclosure).
**Value:** Provides email format for spear-phishing, username format for brute force.

## P-13: Staging Weaker Security
**Detection:** crt.sh subdomain discovery → httpx probe → compare headers.
**Severity:** Variable (staging often has debug, no WAF, CORS, install pages).
**Exploitation:** See `staging-subdomain-hunt` for full procedure.

## P-14: Staging WordPress Install Pages
**Detection:** On staging subdomains, check `/wp-admin/install.php`, `/wp-admin/upgrade.php`, `/wp-admin/setup-config.php` for HTTP 200.
**Severity:** Critical (site takeover).
**Exploitation:** `install.php` with HTTP 200 means WordPress is not configured — you can set it up with your own admin account.
**Confirmed on:** staging.biglots.com (Wave8).

## P-15: Error Log Credential Mining
**Detection:** `curl -sk "TARGET/error_log"` returns PHP errors (not SPA catch-all).
**Severity:** High to Critical (depends on what's exposed).
**Exploitation:** See `error-log-mining` for full extraction commands.
**Confirmed on:** wines.com — 1.7MB error_log with 47 server paths, 879 SQL queries.

## P-16: PHPInfo Exec Function Check
**Detection:** `curl -sk "TARGET/info.php"` returns PHP configuration.
**Severity:** High (if exec functions available).
**Exploitation:** See `phpinfo-to-rce` for the full chain.
**Confirmed on:** wines.com — ALL exec functions available (exec, system, passthru, shell_exec, popen, proc_open).

## P-17: Source Leak Mass Scan
**Detection:** Parallel curl for 20+ sensitive file paths with content verification.
**Severity:** Critical (`.env`/`wp-config`), High (`debug.log`/`backup.sql`), Medium (others).
**Exploitation:** See `source-leak-hunt` for full procedure.

## P-18: JavaScript Bundle Secret Extraction
**Detection:** Download JS files, grep with 11 regex patterns.
**Severity:** Critical (AWS keys, JWT tokens, Stripe live keys).
**Exploitation:** See `js-secrets-extraction` for full procedure.

## P-19: MySQL Port 3306 Public
**Detection:** `nmap -F TARGET` shows 3306 open, banner grab confirms MySQL.
**Severity:** Critical (database exposed to internet).
**Exploitation:** Attempt connection with common credentials (root:root, root:password, admin:admin).
**Confirmed on:** patientportal.com — MySQL 8.0.46 open for 4 consecutive waves.

## P-20: Internal Microservice Ports Exposed
**Detection:** Ports 8080-8089, 3000, 5000, 9000 open with HTTP responses.
**Severity:** High (internal APIs, admin panels).
**Exploitation:** Probe for Swagger, GraphQL, health endpoints.
**Confirmed on:** patientportal.com — ports 8080, 8081, 8082, 8084 all open.

## P-21: WooCommerce API Presence
**Detection:** `/wp-json/wc/v3/` returns 200 or 401.
**Severity:** Medium (API presence, data behind auth).
**Value:** Indicates e-commerce target with customer PII, orders, payment data.
**Frequency:** ~42% of deep WP targets.

## P-22: Elementor 500 Leak
**Detection:** Sending malformed request to `/wp-json/elementor/v1/globals` returns HTTP 500 with stack trace.
**Severity:** Medium (server path disclosure).
**Exploitation:** Stack trace reveals full server paths, plugin versions, and sometimes DB queries.
**Confirmed on:** toolking.com (Wave8).

## P-23: Same-Hosting Clustering
**Detection:** Multiple target domains resolve to the same IP.
**Severity:** Variable.
**Exploitation:** If one site on shared hosting is compromised, all sites on that IP are at risk (lateral movement, cross-site contamination).

## P-24: IAM Role Brute Force via SSRF
**Detection:** After confirming XMLRPC SSRF to IMDS, enumerate common IAM role paths.
**Severity:** Critical if credentials retrieved.
**Exploitation:** See `xmlrpc-exploitation` Phase 3 for the full list of 14 IAM role names.

## P-25: WordPress CORS on ALL REST Endpoints
**Detection:** CORS confirmed on `/wp/v2/users` → test 10+ endpoints.
**Severity:** Critical (full site data exfiltration).
**Exploitation:** Every WP REST endpoint is accessible cross-origin: users, posts, pages, media, settings, plugins, themes.
**Confirmed on:** restonic.com — CORS credential reflection on ALL 7 tested endpoints.
