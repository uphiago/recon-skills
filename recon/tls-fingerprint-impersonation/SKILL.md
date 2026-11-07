---
name: tls-fingerprint-impersonation
description: Spoof TLS ClientHello and JA4 fingerprints for browser impersonation.
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, httpx, python3
metadata:
  tags: [recon, TLS, JA3, JA4, fingerprint, impersonation, HTTP, browser]
  category: recon
  related_skills:
    - http2-header-impersonation
    - stealth-browser-launch
    - humanize-automation
    - evasion-stack-guide
---

# TLS Fingerprint Impersonation

Spoof TLS ClientHello parameters — cipher suites, key exchange groups, signature algorithms, and extension order — to match real browsers at the JA3/JA4 fingerprint level. Uses patched rustls to rebuild the TLS layer with browser-identical configurations. Bypasses TLS fingerprinting detection (Cloudflare, Akamai, F5) that flags non-browser TLS stacks. Supports 20 browser profiles including Chrome 100-142, Firefox 128-144, Safari iOS 18, and OkHttp 3-5 (Android).

## When to Use

- Target returns 403/blocked on curl/httpx even with correct User-Agent headers.
- Cloudflare or Akamai is fingerprinting TLS ClientHello (JA3/JA4 mismatch with browser).
- API probing requires mobile-app impersonation (OkHttp fingerprint for Android).
- Need high-throughput HTTP requests that pass TLS fingerprint checks without running a full browser.
- Target shows different behavior based on TLS fingerprint (mobile vs desktop endpoints).

## How to Run

```bash
# Check if a target blocks non-browser TLS
curl --max-time 30 --connect-timeout 10 -sk https://target.com | head -1
# If 403, test with browser impersonation:
python3 -c "
from impit import Impit
impit = Impit.builder().with_fingerprint('chrome142').build()
r = impit.get('https://target.com').text
print(r[:200])
"
```

## Prerequisites

- `terminal` with python3.
- Python: `pip install impit` (wraps the Rust library via PyO3).
- Or Node.js: `npm install impit` (native binding).
- Or Rust: `impit` crate with patched dependencies in Cargo.toml.

## Quick Detection

```bash
# Check if a target blocks non-browser TLS
curl --max-time 30 --connect-timeout 10 -sk https://target.com | head -1
# If 403, test with browser impersonation:
python3 -c "
from impit import Impit
impit = Impit.builder().with_fingerprint('chrome142').build()
r = impit.get('https://target.com').text
print(r[:200])
"
```

## Procedure

### Phase 1 — Browser Profile Selection

Choose the right fingerprint for your target:

| Profile | Use case | Key differentiator |
|---|---|---|
| `chrome142` | Modern desktop | Latest Chrome, post-quantum KEX (X25519MLKEM768), GREASE |
| `chrome100` | Legacy systems | Older cipher suites, no GREASE in key exchange |
| `firefox144` | Firefox desktop | Different pseudo-header order, FFDHE groups, SHA-1 signatures |
| `safari_ios18` | iOS mobile | 3DES ciphers, duplicate signature algorithm, no session tickets |
| `okhttp4` | Android apps | BoringSSL profile, no GREASE, no ECH, simpler cipher suites |
| `chrome124` | Common default | Good balance of modern compatibility and detection pass rate |

```python
from impit import Impit

# Chrome 142 (latest)
client = Impit.builder().with_fingerprint("chrome142").build()

# Firefox 144
client = Impit.builder().with_fingerprint("firefox144").build()

# Safari iOS 18 (mobile API endpoints)
client = Impit.builder().with_fingerprint("ios18").build()

# OkHttp 4 (Android app impersonation)
client = Impit.builder().with_fingerprint("okhttp4").build()
```

### Phase 2 — Basic Request

```python
from impit import Impit

impit = (
    Impit.builder()
    .with_fingerprint("chrome142")
    .with_ignore_tls_errors(True)  # for self-signed certs during recon
    .with_http3()                   # HTTP/3 support
    .with_fallback_to_vanilla(True) # retry without fingerprint if blocked
    .build()
)

response = impit.get("https://target.com")
print(response.status_code)
print(response.headers)
print(response.text()[:500])
```

### Phase 3 — With Proxy

```python
impit = (
    Impit.builder()
    .with_fingerprint("chrome142")
    .with_proxy("http://user:pass@residential-proxy:8080")
    .with_default_timeout(15_000)  # 15 seconds in milliseconds
    .build()
)

response = impit.get("https://target.com/api/endpoint")
```

### Phase 4 — Custom Headers

```python
# Custom headers are merged with fingerprint defaults
# Fingerprint headers have lower priority — custom headers win on conflict
response = impit.get(
    "https://target.com/api/v1",
    headers={
        "X-Forwarded-For": "203.0.113.42",
        "Authorization": "Bearer token",
    }
)
```

### Phase 5 — Cookie Session

```python
from impit.cookie import Jar

impit = (
    Impit.builder()
    .with_fingerprint("chrome142")
    .with_cookie_store(Jar())  # persistent cookie jar
    .build()
)

# Login
impit.post("https://target.com/login", json={
    "username": "admin", "password": "admin"
})

# Authenticated request — cookies preserved automatically
response = impit.get("https://target.com/dashboard")
```

### Phase 6 — Fingerprint Selection Logic

Choose based on target characteristics:

```python
def select_fingerprint(target_url):
    """Auto-select browser fingerprint based on target."""
    if "mobile" in target_url or "api/v2" in target_url:
        return "ios18"
    elif "android" in target_url or "play.google" in target_url:
        return "okhttp4"
    elif target_url.startswith("https://"):
        return "chrome142"  # default for modern HTTPS
    return "chrome124"
```

### Phase 7 — JA4 Hash Validation

Verify your TLS fingerprint is working correctly:

```bash
# Test against a site that returns JA4 hash in response headers
python3 -c "
from impit import Impit
impit = Impit.builder().with_fingerprint('chrome142').build()
r = impit.get('https://cloudflare.com/cdn-cgi/trace')
print(r.text())
# Look for JA4 hash in trace output or response headers
"
```

## Browser Fingerprint Reference

### TLS Configuration per Browser

| Feature | Chrome 142 | Firefox 144 | Safari iOS 18 | OkHttp 4 |
|---|---|---|---|---|
| TLS versions | 1.3 + 1.2 | 1.3 + 1.2 | 1.3 + 1.2 | 1.3 + 1.2 |
| GREASE cipher | ✅ (pos 1) | ❌ | ✅ | ❌ |
| GREASE key exchange | ✅ (pos 1) | ❌ | ✅ | ❌ |
| Post-quantum (MLKEM768) | ✅ | ✅ | ✅ | ❌ |
| FFDHE groups | ❌ | ✅ (2048/3072) | ❌ | ❌ |
| SHA-1 signatures | ❌ | ✅ | ✅ (legacy) | ✅ (RSA only) |
| ECH GREASE | ✅ | ✅ | ❌ | ❌ |
| 3DES ciphers | ❌ | ❌ | ✅ | ❌ |
| Certificate compression | Brotli | Zlib+Brotli+Zstd | Zlib | ❌ |
| Delegated credentials | ❌ | ✅ | ❌ | ❌ |
| Session tickets | ✅ | ✅ | ❌ | ✅ |
| Duplicate signatures | ❌ | ❌ | ✅ (RsaPssRsaSha384) | ❌ |

### HTTP/2 Settings per Browser

| Browser | Stream Window | Connection Window | Pseudo-Header Order |
|---|---|---|---|
| Chrome | 6,291,456 | 15,663,105 | `:method :authority :scheme :path` |
| Firefox | 131,072 | 12,517,377 | `:method :path :authority :scheme` |
| Safari iOS | 2,097,152 | 10,485,760 | `:method :scheme :authority :path` |
| OkHttp | 16,777,216 | 16,777,216 | `:method :path :authority :scheme` |

### Multipart Boundary Format

| Browser | Format | Example |
|---|---|---|
| Chrome | `----WebKitFormBoundary` + 16 alphanumeric | `----WebKitFormBoundaryx8fH3kLm9pQr2sTv` |
| Firefox | `----geckoformboundary` + hex u64 values | `----geckoformboundary3fa8c10e5d6b2904` |
| OkHttp | UUID v4 | `550e8400-e29b-41d4-a716-446655440000` |

## Pitfalls

- **Not all sites use TLS fingerprinting.** Test with curl first — if it works, TLS fingerprinting is not the blocker.
- **Fingerprint must match User-Agent.** Using Chrome TLS with Firefox UA headers will be detected.
- **HTTP/1.1-only sites don't use HTTP/2 impersonation.** The `with_http3()` flag only matters for sites that support it.
- **OkHttp 3 is TLS 1.2 only.** Some modern servers reject TLS 1.2 connections.
- **TLS fingerprint caching means first request is slowest.** `CryptoProvider` instances are cached per fingerprint — subsequent requests are fast.
- **Vanilla fallback may leak your real TLS fingerprint.** Disable `vanilla_fallback` if stealth is critical.

## Verification

1. Confirm TLS fingerprint matches target browser using `https://www.howsmyssl.com/` or Cloudflare trace endpoint.
2. Check `cf-ja4` response header when hitting Cloudflare-protected sites.
3. Verify response status changes from 403 → 200 when using browser fingerprint vs vanilla curl.
4. Test with multiple browser profiles to find the one that passes the target's detection.

## Related Skills

- **`http2-header-impersonation`** — HTTP/2 pseudo-header ordering and SETTINGS frame matching.
- **`stealth-browser-launch`** — Full browser automation with C++ fingerprint patches for JS-heavy targets.
- **`humanize-automation`** — Human-like interaction patterns for behavioral detection bypass.
