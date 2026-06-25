# CORS 8-Variant Catalog & Detection Matrix

**Source:** Cross-wave analysis of 600+ US SMB domains across 28 sectors
**Confirmed in:** Deep Wave 1-9 + new_targets expansion
**Last updated:** 2026-06-24

---

## The 8 CORS Misconfiguration Variations

### V1 — Origin Reflection + Credentials (Classic)
**ACAO:** `<reflected origin>` | **ACAC:** `true`
**Detection:**
```bash
curl -sk -I "https://TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com" | grep -iE "access-control"
# Expect: ACAO: https://evil.com + ACAC: true
```
**Frequency:** ~7-8% of WP sites | **First seen:** Wave1 | **Impact:** HIGH-CRITICAL
**Examples:** yardcare.com, restonic.com, wines.com, realpro.com, defy.com, toolking.com, williambrown.com, zenfolio.com, windowmedics.com, completeheatandair.com, hillsong.com, septictank.com, greekmoving.com, leonsautobody.com

### V2 — Null Origin Reflection (Sandboxed Iframe Bypass)
**ACAO:** `null` | **ACAC:** `true`
**Detection:**
```bash
curl -sk -I "https://TARGET/wp-json/wp/v2/users" -H "Origin: null" | grep -iE "access-control"
```
**Frequency:** Rare (~1 in 20 CORS vulns) | **First seen:** Wave6 | **Impact:** HIGH
**Examples:** familydental.com
**Exploitation:** Sandboxed `<iframe>` with `data:` URI or `file://` protocol sends `Origin: null`

### V3 — Wildcard (No Credentials)
**ACAO:** `*` | **ACAC:** `false` (or absent)
**Detection:**
```bash
curl -sk -I "https://TARGET/" -H "Origin: https://evil.com" | grep -i "access-control"
```
**Frequency:** ~3% of all sites | **First seen:** Wave5 | **Impact:** MEDIUM (read-only, no authd data)
**Examples:** patientportal.com, nothingbundtcakes.com, brighthorizons.com

### V4 — Credentialed Preflight (OPTIONS Only)
**ACAO:** Reflected on OPTIONS | **ACAC:** `true` on OPTIONS only
**Detection:**
```bash
curl -sk -X OPTIONS "https://TARGET/wp-json/wp/v2/users" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET" | grep -iE "access-control"
```
**Frequency:** Unknown (under-tested) | **First seen:** Wave8 | **Impact:** HIGH-CRITICAL
**Note:** GET may not reflect CORS, but OPTIONS preflight does — enabling cross-origin reads when paired with appropriate Content-Type.

### V5 — Auth-Required Endpoint Leak (401/403 Still Emit CORS)
**ACAO:** Reflected | **ACAC:** `true` (on 401/403 responses)
**Detection:**
```bash
curl -sk -I "https://TARGET/wp-json/gf/v2/forms" -H "Origin: https://evil.com" | grep -iE "access-control"
# 401 HTTP status but CORS headers present = data exfiltratable when admin auth'd
```
**Frequency:** ~100% of CORS-vulnerable sites | **First seen:** Wave7 | **Impact:** HIGH
**Examples:** restonic.com (gf/v2, solidwp-mail/v1), toolking.com (elementor/v1)

### V6 — Multi-Origin Reflection
**ACAO:** Multiple reflected origins work | **ACAC:** `true`
**Detection:** Test 3+ different origins; if all reflect, it's multi-origin
```bash
for origin in "https://evil.com" "https://attacker.com" "https://not-trusted.com"; do
  curl -sk -I "https://TARGET/wp-json/wp/v2/users" -H "Origin: $origin" | grep -i "access-control"
done
```
**Frequency:** Common | **First seen:** Wave6 | **Impact:** HIGH
**Examples:** realpro.com

### V7 — Plugin-Specific CORS
**ACAO:** Reflected | **ACAC:** `true` (on plugin REST namespaces only)
**Detection:** Test plugin-specific REST namespaces alongside standard ones
```bash
for ep in /wp-json/wp/v2/users /wp-json/gravity-pdf/v1/ /wp-json/solidwp-mail/v1/logs; do
  curl -sk -I "https://TARGET${ep}" -H "Origin: https://evil.com" | grep -iE "access-control"
done
```
**Frequency:** Varies by plugin | **First seen:** Wave5 | **Impact:** HIGH (plugin-specific data)
**Examples:** defy.com (gravity-pdf/v1)

### V8 — Staging-Environment-Only CORS
**ACAO:** Reflected | **ACAC:** `true` (on staging only, not production)
**Detection:** Test staging subdomain vs production
```bash
curl -sk -I "https://staging.TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com" | grep -iE "access-control"
curl -sk -I "https://TARGET/wp-json/wp/v2/users" -H "Origin: https://evil.com" | grep -iE "access-control"
```
**Frequency:** Unknown (under-tested) | **First seen:** Wave5 | **Impact:** HIGH (depending on staging data)
**Examples:** staging.biglots.com

---

## Complete CORS Detection Matrix (All 8 Variants)

```bash
#!/bin/bash
# cors-full-matrix.sh - Test ALL 8 CORS variations on a target
# Usage: ./cors-full-matrix.sh target.com

TARGET="$1"
echo "=== CORS Full Matrix for $TARGET ==="

# Endpoints to test (expand as needed)
ENDPOINTS=(
  "/wp-json/wp/v2/users"
  "/wp-json/wp/v2/posts"
  "/wp-json/wp/v2/pages"
  "/wp-json/wp/v2/media"
  "/wp-json/wp/v2/comments"
  "/wp-json/wp/v2/settings"
  "/wp-json/wp/v2/statuses"
  "/wp-json/wp/v2/tags"
  "/wp-json/wp/v2/categories"
  "/wp-json/wp-site-health/v1"
  "/wp-json/wc/v3/products"
  "/wp-json/gf/v2/forms"
)

# Origins to test
ORIGINS=(
  "https://evil.com"
  "null"
  "https://TARGET.evil.com"
  "https://eviltarget.com"
)

echo "V1/V2/V3/V6 — Standard GET CORS Reflection"
for ep in "${ENDPOINTS[@]}"; do
  for origin in "${ORIGINS[@]}"; do
    origin_url="${origin/TARGET/$TARGET}"
    cors=$(curl -sk -I "https://$TARGET${ep}" -H "Origin: $origin_url" 2>/dev/null | grep -iE "access-control-allow-origin|access-control-allow-credentials")
    [ -n "$cors" ] && echo "[$ep] [$origin_url] $cors"
  done
done

echo "V4 — OPTIONS Preflight CORS"
for ep in "${ENDPOINTS[@]}"; do
  cors=$(curl -sk -X OPTIONS "https://$TARGET${ep}" \
    -H "Origin: https://evil.com" \
    -H "Access-Control-Request-Method: GET" 2>/dev/null | grep -iE "access-control")
  [ -n "$cors" ] && echo "[OPTIONS $ep] $cors"
done

echo "V8 — Staging CORS Comparison"
for prefix in "staging" "dev" "stage" "test" "admin" "api"; do
  cors=$(curl -sk -I "https://${prefix}.${TARGET}/wp-json/wp/v2/users" -H "Origin: https://evil.com" 2>/dev/null | grep -iE "access-control")
  [ -n "$cors" ] && echo "[${prefix}.${TARGET}] $cors"
done
```

---

## Cross-Reference

- `cors-chain-automation/SKILL.md` — Main automation skill
- `hunt-cors` — Underlying CORS hunting methodology
- `hunt-wordpress` — WordPress REST API (most common CORS source)
- `/root/output/recon_us/techniques/wave9_techniques.md` — 25 pattern catalog including CORS variants
- `/root/output/recon_us/techniques/wave-analysis-20260624-1349.md` — Cross-wave intelligence report
