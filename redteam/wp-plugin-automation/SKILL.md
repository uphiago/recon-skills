---
name: wp-plugin-automation
description: "Scripts and workflows to batch-test popular WordPress plugin CVEs across hundreds of domains. Covers automated plugin detection, version extraction from readme.txt, CVE matching against a curated matrix of high-impact plugin vulnerabilities (ElementsKit, Revslider, WPDM, Gravity Forms, Contact Form 7, Jetpack, WP File Manager, GSpeech), and exploitation PoC generation. Use after initial WordPress detection recon — when you have a target list of WP domains and need to find which specific plugin CVEs are exploitable at scale."
sources: field_recon, hackerone_public, cve_database
report_count: 14
---

# WP-PLUGIN-AUTOMATION — Batch WordPress Plugin CVE Testing

## When to Use

Use after initial WordPress detection recon (hunt-wordpress Phase 1). You have a list of confirmed WP domains and need to find which specific plugin CVEs are exploitable. This skill automates plugin detection, version extraction, CVE matching, and exploitation PoC generation at scale.

## Quick Reference

```bash
# One-shot: detect all plugin versions on a target
cat targets.txt | while read t; do
  echo "=== $t ==="
  # Extract plugin readme versions
  for p in revslider elementskit elementor woocommerce gravityforms jetpack; do
    v=$(curl -sk "https://$t/wp-content/plugins/$p/readme.txt" | grep -i "stable tag\|version" | head -1)
    [ -n "$v" ] && echo "PLUGIN: $p=$v"
  done
  # REST API namespace enumeration
  curl -sk "https://$t/wp-json/" | python3 -c "import sys,json; d=json.load(sys.stdin); [print('REST:',n) for n in d.get('namespaces',[])]" 2>/dev/null
done
```

## Step-by-Step

### Phase 1 — Automated Plugin Detection
```bash
#!/bin/bash
# wp-plugin-scan.sh - Scan target list for WP plugin versions
TARGETS="$1"
PLUGINS=(
  "revslider:slider-revolution"
  "elementskit:elementskit-lite"
  "elementor:elementor"
  "woocommerce:woocommerce"
  "gravityforms:gravityforms"
  "contact-form-7:contact-form-7"
  "jetpack:jetpack"
  "wp-file-manager:wp-file-manager"
  "wordpress-seo:wordpress-seo"
  "give:give"  # Donation plugin
  "wp-sermons:wp-sermons"
  "simple-bible-embed:simple-bible-embed"
)

while read t; do
  echo "=== Scanning $t ==="
  for plugin_entry in "${PLUGINS[@]}"; do
    IFS=':' read -r slug dir <<< "$plugin_entry"
    readme=$(curl -sk -o /dev/null -w "%{http_code}" "https://$t/wp-content/plugins/$dir/readme.txt")
    [ "$readme" != "404" ] && [ "$readme" != "000" ] && \
      version=$(curl -sk "https://$t/wp-content/plugins/$dir/readme.txt" | grep -i "stable tag\|version" | head -1 | grep -oP '[\d.]+') && \
      echo "  [+] $slug: v$version"
  done
done < "$TARGETS"
```

### Phase 2 — CVE Matching Matrix
```bash
#!/bin/bash
# cve-matcher.sh - Match plugin versions against known CVEs
# Usage: echo "revslider 6.6.19" | ./cve-matcher.sh

while read plugin version; do
  case "$plugin" in
    revslider)
      [ "$(printf '%s\n' '6.6.20' "$version" | sort -V | head -1)" != "$version" ] && \
        [ "$version" != "6.6.20" ] && echo "  [!] Revslider < 6.6.20 → CVE-2024-2534 RCE"
      [ "$(printf '%s\n' '6.5.8' "$version" | sort -V | head -1)" != "$version" ] && \
        [ "$version" != "6.5.8" ] && echo "  [!] Revslider < 6.5.8 → CVE-2022-2944 SQLi"
      ;;
    elementskit)
      [ "$(printf '%s\n' '2.9.4' "$version" | sort -V | head -1)" != "$version" ] && \
        [ "$version" != "2.9.4" ] && echo "  [!] ElementsKit < 2.9.4 → CVE-2023-6851 SQLi, CVE-2023-6853 File Upload"
      [ "$(printf '%s\n' '2.9.8' "$version" | sort -V | head -1)" != "$version" ] && \
        [ "$version" != "2.9.8" ] && echo "  [!] ElementsKit < 2.9.8 → CVE-2024-2117 XSS"
      ;;
    gravityforms)
      [ "$(printf '%s\n' '2.8.2' "$version" | sort -V | head -1)" != "$version" ] && \
        [ "$version" != "2.8.2" ] && echo "  [!] Gravity Forms < 2.8.2 → CVE-2024-6115 PHP Object Injection"
      ;;
    jetpack)
      [ "$(printf '%s\n' '13.1' "$version" | sort -V | head -1)" != "$version" ] && \
        [ "$version" != "13.1" ] && echo "  [!] Jetpack < 13.1 → CVE-2024-1782 SSRF"
      ;;
    contact-form-7)
      echo "  [!] CF7 < 5.6 → File upload bypass (no CVE)"
      ;;
    wp-file-manager)
      echo "  [!] WP File Manager → multiple CVEs (CVE-2020-25213 RCE, etc)"
      ;;
  esac
done
```

### Phase 3 — Bulk CORS + XMLRPC + Debug Log Check
```bash
#!/bin/bash
# wp-bulk-vuln-check.sh - Multi-vuln sweep across all WP targets
TARGETS="$1"

while read t; do
  echo "=== $t ==="
  
  # CORS credential reflection
  cors=$(curl -skI "https://$t/wp-json/wp/v2/users" -H "Origin: https://evil.com" 2>/dev/null | grep -c "Access-Control-Allow-Credentials: true")
  [ "$cors" -gt 0 ] && echo "  [CRIT] CORS credential reflection!"
  
  # XMLRPC
  xrpc=$(curl -sk -o /dev/null -w "%{http_code}" "https://$t/xmlrpc.php" 2>/dev/null)
  [ "$xrpc" = "200" ] && echo "  [HIGH] XMLRPC active"
  
  # Debug log
  dlog=$(curl -sk -o /dev/null -w "%{http_code}" "https://$t/wp-content/debug.log" 2>/dev/null)
  [ "$dlog" = "200" ] && echo "  [HIGH] Debug log exposed"
  
  # PHPInfo
  for p in /info.php /phpinfo.php /test.php; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$t$p" 2>/dev/null)
    [ "$code" = "200" ] && echo "  [HIGH] PHPInfo at $p"
  done
  
  # Open registration
  reg=$(curl -sk "https://$t/wp-login.php?action=register" 2>/dev/null | grep -c "multipart")
  [ "$reg" -gt 0 ] && echo "  [HIGH] Open registration"
  
  echo "---"
done < "$TARGETS"
```

### Phase 4 — Exploitation PoC Generation
```bash
# WooCommerce API discovery
for path in /wp-json/wc/v3/ /wp-json/wc/v3/products /wp-json/wc/v3/orders /wp-json/wc/v3/customers; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  [ "$code" != "404" ] && echo "[+] $path — HTTP $code"
done

# Application Passwords endpoint
code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET/wp-admin/authorize-application.php")
[ "$code" != "404" ] && echo "[+] Application Passwords endpoint accessible"

# Check for REST API user enumeration
curl -sk "https://$TARGET/wp-json/wp/v2/users?per_page=100" | jq '.[] | {id, name, slug}'
```

## Attack Surface Signals

- Plugin readme.txt accessible at `/wp-content/plugins/<slug>/readme.txt`
- REST API namespace reflects enabled plugins via `/wp-json/`
- Plugin assets (CSS, JS, images) accessible at `/wp-content/plugins/<slug>/assets/`
- WooCommerce endpoints at `/wp-json/wc/v3/`

## Common Root Causes

1. **Plugin auto-update disabled** — admin turns off auto-updates to avoid breaking customizations
2. **Abandoned plugins** — developer stops maintaining, no patches for CVEs
3. **Nulled/premium plugins** — pirated plugins with backdoors installed on budget sites
4. **Plugin bloat** — 50+ plugins installed, impossible to track CVEs manually

## Real Examples

From 58-company mass recon:
- 7/58 targets had ElementsKit < 2.9.4 (SQLi + File Upload CVEs)
- 5/58 had Revslider installed (potential RCE via CVE-2024-2534)
- 5/7 deep targets had CORS credential reflection on WP REST API
- 2/7 had open registration + XMLRPC upload → full RCE chain

## Related Skills

- hunt-wordpress — primary skill for WordPress recon
- recon-churches — church sites have highest plugin vulnerability rate
- hunt-rce — plugin CVEs are a primary RCE path
- hunt-file-upload — file upload CVEs from plugin vulnerabilities
- hunt-sqli — SQL injection CVEs from plugin SQLi flaws
- hunt-source-leak — debug.log/reveals plugin version info
