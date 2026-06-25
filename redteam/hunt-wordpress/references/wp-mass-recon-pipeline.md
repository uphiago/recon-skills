# WordPress Mass Recon Pipeline

Batch WordPress vulnerability detection across hundreds of domains, combining CORS credential reflection, XMLRPC exploitation, and plugin CVE matching.

## Multi-Vuln Sweep Script

```bash
#!/bin/bash
# wp-mass-sweep.sh — CORS + XMLRPC + debug log + plugins in one pass
# Usage: ./wp-mass-sweep.sh targets.txt

TARGETS="$1"
while read t; do
  echo "=== $t ==="
  # CORS credential reflection on WP REST API
  cors=$(curl -skI "https://$t/wp-json/wp/v2/users" -H "Origin: https://evil.com" 2>/dev/null | \
    grep -c "Access-Control-Allow-Credentials: true")
  [ "$cors" -gt 0 ] && echo "  [CRIT] CORS credential reflection ($cors hits)"

  # XMLRPC
  xrpc=$(curl -sk -o /dev/null -w "%{http_code}" "https://$t/xmlrpc.php" 2>/dev/null)
  [ "$xrpc" = "200" ] && echo "  [HIGH] XMLRPC active (HTTP 200)"

  # Debug log exposure
  dlog=$(curl -sk -o /dev/null -w "%{size_download}" "https://$t/wp-content/debug.log" 2>/dev/null)
  [ "$dlog" -gt 100 ] && echo "  [HIGH] Debug log exposed ($dlog bytes)"

  # Cross-subdirectory WordPress installs
  for sub in /blog /wp /shop /staging /beta /old /test /dev; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$t${sub}/xmlrpc.php" 2>/dev/null)
    [ "$code" = "200" ] && echo "  [WP] Cross-subdirectory install at ${sub}"
  done

  # Plugin detection
  for plugin in revslider elementskit elementor woocommerce gravityforms jetpack; do
    v=$(curl -sk "https://$t/wp-content/plugins/$plugin/readme.txt" 2>/dev/null | \
      grep -i "stable tag" | grep -oP '[\d.]+')
    [ -n "$v" ] && echo "  Plugin: $plugin v$v"
  done
done < "$TARGETS"
```

## CVE Matching Matrix

| Plugin | Threshold | CVE | Type |
|--------|-----------|-----|------|
| revslider | < 6.6.20 | CVE-2024-2534 | RCE |
| revslider | < 6.5.8 | CVE-2022-2944 | SQLi |
| elementskit | < 2.9.4 | CVE-2023-6851 | SQLi |
| elementskit | < 2.9.4 | CVE-2023-6853 | File Upload |
| elementskit | < 2.9.8 | CVE-2024-2117 | XSS |
| gravityforms | < 2.8.2 | CVE-2024-6115 | PHP Object Inj |
| jetpack | < 13.1 | CVE-2024-1782 | SSRF |
| contact-form-7 | < 5.6 | — | File Upload Bypass |
| wp-file-manager | all | CVE-2020-25213 | RCE |

## Key Statistics (from 58-company mass recon across 28 sectors)

- **#1 Finding**: CORS credential reflection on WP REST API (~35% of critical findings)
- **#2 Finding**: XMLRPC system.multicall enabled (~25%)
- **#3 Finding**: Debug log exposure with SQL queries (~15%)
- **5/7 deep targets** had CORS credential reflection on WP REST API
- **7/58 targets** had ElementsKit < 2.9.4 (SQLi + File Upload CVEs)

## Chain Priority

1. CORS credential reflection → user/PII exfil → often chains to ATO
2. XMLRPC multicall + open registration → webshell upload → RCE
3. Debug log → SQL queries / DB creds → data breach
4. Plugin CVE → varies by plugin (RCE, SQLi, XSS)
