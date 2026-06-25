---
name: wordpress-plugin-hunt
description: Hunt WP plugins via REST, exploit CVEs when version known.
version: 1.0.0
author: agentiko
license: MIT
platforms: [linux]
compatibility: Requires agentiko worker (curl, nmap, python3, masscan, subfinder, httpx, nuclei)
metadata:
  hermes:
    tags: [recon, wordpress, plugins, CVE, exploitation]
    category: recon
    related_skills:
      - wp-mass-recon
      - deep-invade
      - cross-attack-chains
      - wordpress-full-compromise
      - staging-subdomain-hunt
      - xmlrpc-exploitation
---

# WordPress Plugin Hunt Skill

Discover installed WordPress plugins through REST API namespace probing, readme.txt version detection, and HTML/JS source analysis. Cross-reference discovered versions against known CVEs for exploitation. WordPress plugin vulnerabilities are one of the most reliable paths to RCE — confirmed CVEs include Elementor, Slider Revolution, ElementsKit, Gravity Forms, Jetpack, WooCommerce, and LiteSpeed Cache.

## When to Use

- WordPress confirmed on target (via `wp-mass-recon`).
- Running `deep-invade` Phase 3.
- You need an exploitation vector beyond CORS/XMLRPC.
- Target has a plugin-heavy WordPress site (e-commerce, page builder, forms).

## Prerequisites

- `terminal` tool with curl, python3.
- WordPress target confirmed (`/wp-json/` or `/wp-login.php` accessible).
- For CVE exploitation: knowledge of specific CVE PoCs (reference `security-arsenal` skill).

## How to Run

```bash
# Quick plugin namespace scan (30+ plugins)
TARGET="example.com"
for ns in "revslider/v1" "elementskit/v1" "elementor/v1" "gf/v2" "wc/v3" \
  "jetpack/v4" "litespeed/v1" "yoast/v1" "acf/v3" "contact-form-7/v1" \
  "solidwp-mail/v1" "wpsl/v1" "redirection/v1" "rankmath/v1"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "https://$TARGET/wp-json/$ns")
  [[ "$code" != "404" ]] && echo "FOUND: /wp-json/$ns (HTTP $code)"
done
```

## Quick Reference

### Top Exploitable Plugins (US SMB targets — confirmed CVEs from mass recon)

| Plugin | Vulnerable Version | CVE | Impact | Frequency |
|--------|-------------------|-----|--------|-----------|
| Slider Revolution | < 6.6.20 | CVE-2024-2534 | RCE via file upload | ~10% |
| ElementsKit | < 2.9.4 | CVE-2023-6851 | SQLi | ~5% |
| ElementsKit | < 2.9.4 | CVE-2023-6853 | File Upload (unauthenticated) | ~5% |
| Gravity Forms | < 2.8.2 | CVE-2024-6115 | PHP Object Injection → Auth Bypass | ~8% |
| Jetpack | < 13.1 | CVE-2024-1782 | SSRF | 28% |
| Elementor | < 3.24.0 | CVE-2024-xxxx | Info disclosure → Auth bypass | 28% |
| LiteSpeed Cache | < 6.5.0 | CVE-2024-50550 | Privilege escalation | ~15% |
| WooCommerce | N/A (API exposure) | N/A | Order/customer data | 42% |
| Yoast SEO | N/A (sitemap enum) | N/A | Author email leak | 42% |

### Detection Methods

| Method | What It Reveals | Reliability |
|--------|----------------|-------------|
| REST namespace probe | Plugin presence + data | High (if plugin registers REST routes) |
| readme.txt version | Exact version number | Medium (many sites block readme.txt) |
| HTML source grep | Plugin CSS/JS handles | Medium |
| robots.txt | Plugin-generated entries | Low (only if plugin adds entries) |
| `/wp-content/plugins/<slug>/` | Directory listing or assets | Medium |

## Procedure

### Step 1 — REST Namespace Brute Force (40+ plugins)

```bash
TARGET="$1"
OUTDIR="/root/output/plugins/$TARGET"
mkdir -p "$OUTDIR"

# Comprehensive plugin namespace list
declare -A PLUGIN_NAMESPACES
PLUGIN_NAMESPACES["revslider"]="revslider/v1/slides"
PLUGIN_NAMESPACES["elementskit"]="elementskit/v1/layouts"
PLUGIN_NAMESPACES["elementor"]="elementor/v1/globals"
PLUGIN_NAMESPACES["gravityforms"]="gf/v2/forms"
PLUGIN_NAMESPACES["woocommerce"]="wc/v3/products"
PLUGIN_NAMESPACES["jetpack"]="jetpack/v4/settings"
PLUGIN_NAMESPACES["litespeed"]="litespeed/v1/token"
PLUGIN_NAMESPACES["yoast"]="yoast/v1/indexing"
PLUGIN_NAMESPACES["acf"]="acf/v3/posts"
PLUGIN_NAMESPACES["contactform7"]="contact-form-7/v1/contact-forms"
PLUGIN_NAMESPACES["solidwp"]="solidwp-mail/v1/export"
PLUGIN_NAMESPACES["wpsl"]="wpsl/v1/locations"
PLUGIN_NAMESPACES["redirection"]="redirection/v1/redirect"
PLUGIN_NAMESPACES["rankmath"]="rankmath/v1/getHead"
PLUGIN_NAMESPACES["fusionbuilder"]="fusion-builder/v1/elements"
PLUGIN_NAMESPACES["visualcomposer"]="visualcomposer/v1/posts"
PLUGIN_NAMESPACES["ninjaforms"]="ninja-forms/v1/forms"
PLUGIN_NAMESPACES["wpforms"]="wpforms/v1/forms"
PLUGIN_NAMESPACES["mailchimp"]="mailchimp-for-woocommerce/v1"
PLUGIN_NAMESPACES["automatewoo"]="automatewoo/v1"
PLUGIN_NAMESPACES["give"]="give-api/v1/forms"
PLUGIN_NAMESPACES["buddypress"]="buddypress/v1/members"
PLUGIN_NAMESPACES["learndash"]="ldlms/v1/courses"
PLUGIN_NAMESPACES["restrictcontent"]="rcp/v1/memberships"
PLUGIN_NAMESPACES["eventscalendar"]="tribe/events/v1/events"
PLUGIN_NAMESPACES["woosubscriptions"]="wc/v1/subscriptions"
PLUGIN_NAMESPACES["woomemberships"]="wc/v1/memberships"
PLUGIN_NAMESPACES["wpml"]="wpml/v1/languages"
PLUGIN_NAMESPACES["polylang"]="pll/v1/languages"
PLUGIN_NAMESPACES["translatepress"]="trp/v1/languages"
PLUGIN_NAMESPACES["nextgen"]="nextgen-gallery/v1"
PLUGIN_NAMESPACES["envira"]="envira-gallery/v1"
PLUGIN_NAMESPACES["essentialgrid"]="essential-grid/v1/grids"
PLUGIN_NAMESPACES["thegrid"]="the-grid/v1/grids"
PLUGIN_NAMESPACES["masterslider"]="masterslider/v1/sliders"
PLUGIN_NAMESPACES["smartslider3"]="smart-slider-3/v1/sliders"
PLUGIN_NAMESPACES["metaslider"]="ml-slider/v1/slideshows"
PLUGIN_NAMESPACES["duplicator"]="duplicator/v1"
PLUGIN_NAMESPACES["updraft"]="updraftplus/v1"
PLUGIN_NAMESPACES["backupbuddy"]="backupbuddy/v1"
PLUGIN_NAMESPACES["aioseo"]="aioseo/v1/settings"
PLUGIN_NAMESPACES["seopress"]="seopress/v1/settings"

echo "[*] Probing ${#PLUGIN_NAMESPACES[@]} plugin namespaces on $TARGET..."
echo ""

for plugin in "${!PLUGIN_NAMESPACES[@]}"; do
  ns="${PLUGIN_NAMESPACES[$plugin]}"
  resp=$(curl -sk --max-time 5 -o /tmp/plugin_check_$$.tmp -w "%{http_code}" "https://$TARGET/wp-json/$ns" 2>/dev/null)

  if [[ "$resp" == "200" ]]; then
    size=$(wc -c < /tmp/plugin_check_$$.tmp)
    # Check if response is real plugin data, not SPA catch-all
    if grep -qiE 'id|slides|forms|products|settings|locations|name' /tmp/plugin_check_$$.tmp 2>/dev/null; then
      echo "[PLUGIN] $plugin — REST API active (${size} bytes)"
      cp /tmp/plugin_check_$$.tmp "$OUTDIR/${plugin}_rest.json"
    fi
  elif [[ "$resp" == "401" ]]; then
    echo "[PLUGIN] $plugin — requires auth (HTTP 401)"
  elif [[ "$resp" == "403" ]]; then
    echo "[PLUGIN] $plugin — access forbidden (HTTP 403)"
  fi
done

rm -f /tmp/plugin_check_$$.tmp
```

### Step 2 — Version Detection via readme.txt

```bash
TARGET="$1"
OUTDIR="/root/output/plugins/$TARGET"

# Common plugin slugs to check
SLUGS=(
  "elementor" "revslider" "js_composer" "wp-rocket" "wordfence"
  "woocommerce" "jetpack" "litespeed-cache" "yoast-seo" "advanced-custom-fields"
  "contact-form-7" "gravityforms" "ninja-forms" "wpforms-lite"
  "all-in-one-wp-migration" "updraftplus" "duplicator" "backupbuddy"
  "essential-grid" "smart-slider-3" "masterslider" "metaslider"
  "fusion-builder" "visualcomposer" "elementor-pro" "essential-addons-for-elementor-lite"
  "redux-framework" "buddypress" "learndash" "give"
  "the-events-calendar" "events-manager" "wpml-string-translation"
  "mailchimp-for-woocommerce" "automatewoo" "woocommerce-subscriptions"
  "woocommerce-memberships" "restrict-content-pro" "easy-digital-downloads"
  "rank-math-seo" "seo-by-rank-math" "all-in-one-seo-pack" "wp-seopress"
  "monsterinsights" "pixel-caffeine" "facebook-for-woocommerce"
  "popup-maker" "optinmonster" "mailpoet" "fluentform"
  "wp-fastest-cache" "w3-total-cache" "sg-cachepress" "autoptimize"
  "redirection" "better-wp-security" "sucuri-scanner" "wp-cerber"
  "solid-security" "solidwp-mail" "post-smtp" "wp-mail-smtp"
)

echo "[*] Checking readme.txt for ${#SLUGS[@]} plugins..."
echo ""

for slug in "${SLUGS[@]}"; do
  readme=$(curl -sk --max-time 5 "https://$TARGET/wp-content/plugins/$slug/readme.txt" 2>/dev/null)

  if [[ -n "$readme" ]]; then
    version=$(echo "$readme" | grep -i "stable tag:" | sed 's/.*: //' | tr -d '\r' | head -1)
    name=$(echo "$readme" | grep -i "=== .* ===" | head -1 | sed 's/=== //;s/ ===//')

    if [[ -n "$version" ]]; then
      echo "[VERSION] $slug: $version ($name)"

      # Check for known vulnerable versions
      case "$slug" in
        revslider)
          [[ "$version" < "6.6.20" ]] && echo "  [VULN] Slider Revolution < 6.6.20 — CVE-2024-2534 (RCE)" ;;
        elementskit|elementskit-lite)
          [[ "$version" < "2.9.4" ]] && echo "  [VULN] ElementsKit < 2.9.4 — CVE-2023-6851/6853 (RCE)" ;;
        litespeed-cache)
          [[ "$version" < "6.5.0" ]] && echo "  [VULN] LiteSpeed Cache < 6.5.0 — CVE-2024-50550 (priv esc)" ;;
        elementor|elementor-pro)
          [[ "$version" < "3.24.0" ]] && echo "  [VULN] Elementor < 3.24.0 — info disclosure / auth bypass" ;;
        gravityforms)
          [[ "$version" < "2.8.2" ]] && echo "  [VULN] Gravity Forms < 2.8.2 — CVE-2024-6115 (auth bypass)" ;;
        jetpack)
          [[ "$version" < "13.1" ]] && echo "  [VULN] Jetpack < 13.1 — CVE-2024-1782 (info disc)" ;;
      esac
    fi
  fi
done
```

### Step 3 — HTML/JS Source Plugin Detection

```bash
TARGET="$1"

echo "[*] Scanning HTML source for plugin fingerprints..."

PAGE=$(curl -sk --max-time 10 "https://$TARGET/" 2>/dev/null)

# CSS/JS handles
echo "$PAGE" | grep -oP "(?:/wp-content/plugins/|/wp-content/themes/)[a-zA-Z0-9_-]+" | sort -u | while read -r path; do
  plugin=$(echo "$path" | grep -oP 'plugins/\K[a-zA-Z0-9_-]+|themes/\K[a-zA-Z0-9_-]+')
  echo "  [SOURCE] $plugin (found in HTML)"
done

# Elementor specific
if echo "$PAGE" | grep -q "elementor-element\|data-elementor-id"; then
  echo "  [SOURCE] Elementor (page builder in use)"
fi

# WooCommerce specific
if echo "$PAGE" | grep -q "woocommerce\|wc-forward\|add_to_cart_button"; then
  echo "  [SOURCE] WooCommerce (e-commerce active)"
fi

# WP Rocket
if echo "$PAGE" | grep -q "wpr-minify\|rocket-lazyload"; then
  echo "  [SOURCE] WP Rocket (caching plugin)"
fi

# Cloudflare
if echo "$PAGE" | grep -q "cloudflare\|cf-browser-verification"; then
  echo "  [SOURCE] Cloudflare (CDN/WAF detected)"
fi
```

### Step 4 — CVE Exploitation Quick Reference

When a vulnerable plugin version is confirmed:

```bash
TARGET="$1"

# Slider Revolution CVE-2024-2534 (RCE via file upload)
# Requires: revslider < 6.6.20
# Attack: POST to /wp-json/revslider/v1/upload with ZIP containing PHP
# See: security-arsenal skill for full PoC

# ElementsKit CVE-2023-6853 (RCE via file upload, unauthenticated)
# Requires: elementskit < 2.9.4
# Attack: POST to /wp-json/elementskit/v1/upload with specially crafted file
# See: security-arsenal skill for full PoC

# Gravity Forms CVE-2024-6115 (auth bypass)
# Requires: gravityforms < 2.8.2
# Attack: Unauthenticated access to form entries via REST API
curl -sk "https://$TARGET/wp-json/gf/v2/forms" 2>/dev/null | python3 -m json.tool | head -20

# LiteSpeed Cache CVE-2024-50550 (privilege escalation)
# Requires: litespeed < 6.5.0
# Attack: Crawler token manipulation to gain admin access
curl -sk "https://$TARGET/wp-json/litespeed/v1/token" 2>/dev/null
```

## Pitfalls

- **REST namespace 200 ≠ plugin present.** Some themes and security plugins return 200 for all `/wp-json/` paths. Verify response content has actual plugin data (JSON with `id`, `name`, or `slug` fields).
- **readme.txt blocked on many hosts.** WP Engine, Hostinger, and Cloudflare often block `readme.txt` at the CDN level. Fall back to REST namespaces or HTML source grep.
- **Custom plugin slugs.** Premium plugins may have custom directory names. `gravityforms` may be `gravityforms-clientsite`. Check HTML source for actual slugs via `wp-content/plugins/` paths.
- **SliderRev v1 endpoints 404 on 6.x.** Slider Revolution renamed its REST endpoints — toolking.com confirmed that ALL v1 paths return 404 while the plugin is still active. Probe non-v1 paths too: `/wp-json/sliderrevolution/sliders/`.
- **Plugin version comparison needs semantic versioning.** Bash string comparison (`<`) fails on `10.x` vs `2.x`. Use `sort -V` or python for complex comparisons.
- **Elementor 500 leak = info disclosure.** `/wp-json/elementor/v1/favorites` returning HTTP 500 with stack trace (Wave8, toolking.com) reveals server paths and internal structure even without plugin exploitation.

## Hosting Provider Pattern (P-23 — critical for plugin detection)

Different hosting providers have distinct vulnerability profiles for plugin detection:

| Host | REST Users | readme.txt | CORS | XMLRPC | Best Plugin Detection Method |
|------|-----------|------------|------|--------|------------------------------|
| GoDaddy | Usually exposed | Usually accessible | Often reflects | Usually open | readme.txt (most accessible) |
| Cloudflare + WP Engine | Usually blocked | Blocked at CDN | May work | Blocked | HTML source grep + REST namespace brute force |
| Hostinger | Exposed | Accessible | Often reflects | Open | readme.txt + REST namespace |
| WP Engine (direct) | Blocked (401) | Blocked | Mixed | Blocked | HTML source only |
| Bluehost | Exposed | Accessible | Often reflects | Open | All methods work |
| SiteGround | Mixed | Often accessible | Mixed | Mixed | REST namespace + readme.txt |

## Verification

- Every detected plugin MUST be confirmed via at least 2 detection methods (REST + readme, or REST + HTML source).
- Every CVE MUST be matched against the exact version number, not just plugin presence.
- CVE exploitation MUST be verified with a PoC that demonstrates impact (not just version detection).
- Plugin vulnerabilities that require authentication must have a credential acquisition path (CORS, brute force, open reg) documented.
