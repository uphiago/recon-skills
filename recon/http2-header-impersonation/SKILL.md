---
name: http2-header-impersonation
description: Spoof HTTP/2 SETTINGS frames and pseudo-header order per browser profile.
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, httpx, python3
metadata:
  tags: [recon, HTTP2, headers, fingerprint, impersonation, browser, JA4]
  category: recon
  related_skills:
    - tls-fingerprint-impersonation
    - stealth-browser-launch
    - evasion-stack-guide
---

# HTTP/2 Header Impersonation

Spoof HTTP/2 SETTINGS frames, pseudo-header ordering, and browser-specific HTTP headers to match real browsers at the protocol level. Targets the detection gap between TLS fingerprinting (ClientHello) and JavaScript fingerprinting — the HTTP/2 connection setup and header structure that anti-bot systems analyze. Matches Chrome, Firefox, Safari iOS, and OkHttp (Android) profiles with exact window sizes, header list limits, and header ordering.

## When to Use

- TLS fingerprint is correct but target still detects non-browser HTTP behavior.
- Target uses HTTP/2-specific detection (SETTINGS frame analysis, pseudo-header order).
- Need browser-accurate `sec-ch-ua`, `Accept`, `Accept-Encoding`, `Priority`, and `sec-fetch-*` headers.
- Mobile API endpoints require Android OkHttp header profiles.
- Combining with TLS impersonation for a complete network-level browser profile.

## How to Run

```bash
# Check if target sends different responses based on HTTP headers
# Compare browser-like headers vs curl defaults

python3 -c "
import requests

# curl default headers
r1 = requests.get('https://target.com')
print(f'Default: {r1.status_code}')

# Browser-like headers
r2 = requests.get('https://target.com', headers={
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.7444.176 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
# ... (continues in Procedure)
```

## Prerequisites

- `terminal` with python3.
- `pip install impit` (includes HTTP/2 impersonation via patched h2 library).
- Or standalone: use the header lists below to configure curl/httpx manually.

## Quick Detection

```bash
# Check if target sends different responses based on HTTP headers
# Compare browser-like headers vs curl defaults

python3 -c "
import requests

# curl default headers
r1 = requests.get('https://target.com')
print(f'Default: {r1.status_code}')

# Browser-like headers
r2 = requests.get('https://target.com', headers={
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.7444.176 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br, zstd',
    'sec-ch-ua': '\"Chromium\";v=\"142\", \"Google Chrome\";v=\"142\"',
    'sec-ch-ua-platform': '\"Windows\"',
    'sec-ch-ua-mobile': '?0',
})
print(f'Browser: {r2.status_code}')
"
```

## Procedure

### Phase 1 — Full Browser Profile via impit

The impit library applies HTTP/2 SETTINGS, pseudo-header order, and HTTP headers from a single profile:

```python
from impit import Impit

# Chrome 142 — complete HTTP/2 + TLS + headers profile
impit = (
    Impit.builder()
    .with_fingerprint("chrome142")
    .build()
)

response = impit.get("https://target.com")
# Headers sent: sec-ch-ua, User-Agent, Accept, Accept-Encoding, Accept-Language,
#              sec-ch-ua-platform, sec-ch-ua-mobile, Priority, sec-fetch-*
# HTTP/2 SETTINGS: stream_window=6291456, conn_window=15663105, max_header=262144
# Pseudo-header order: :method :authority :scheme :path :protocol :status
```

### Phase 2 — Manual Header Configuration

For curl/httpx without impit, configure headers manually to match browser profiles:

#### Chrome 142 Desktop Headers

```bash
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.7444.176 Safari/537.36" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br, zstd" \
  -H "sec-ch-ua: \"Chromium\";v=\"142\", \"Google Chrome\";v=\"142\", \"Not?A_Brand\";v=\"99\"" \
  -H "sec-ch-ua-arch: \"x86\"" \
  -H "sec-ch-ua-bitness: \"64\"" \
  -H "sec-ch-ua-full-version-list: \"Chromium\";v=\"142.0.7444.176\", \"Google Chrome\";v=\"142.0.7444.176\", \"Not?A_Brand\";v=\"99.0.0.0\"" \
  -H "sec-ch-ua-mobile: ?0" \
  -H "sec-ch-ua-model: \"\"" \
  -H "sec-ch-ua-platform: \"Windows\"" \
  -H "sec-ch-ua-platform-version: \"15.0.0\"" \
  -H "sec-ch-ua-wow64: ?0" \
  -H "sec-fetch-dest: document" \
  -H "sec-fetch-mode: navigate" \
  -H "sec-fetch-site: none" \
  -H "sec-fetch-user: ?1" \
  -H "Upgrade-Insecure-Requests: 1" \
  -H "Priority: u=0, i"
```

#### Firefox 144 Desktop Headers

```bash
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:144.0) Gecko/20100101 Firefox/144.0" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.5" \
  -H "Accept-Encoding: gzip, deflate, br, zstd" \
  -H "sec-ch-ua: \"Firefox\";v=\"144\", \"Not?A_Brand\";v=\"99\"" \
  -H "sec-ch-ua-mobile: ?0" \
  -H "sec-ch-ua-platform: \"Windows\"" \
  -H "sec-fetch-dest: document" \
  -H "sec-fetch-mode: navigate" \
  -H "sec-fetch-site: none" \
  -H "sec-fetch-user: ?1" \
  -H "TE: trailers" \
  -H "Upgrade-Insecure-Requests: 1" \
  -H "Priority: u=0, i"
```

#### Safari iOS 18 Headers

```bash
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" \
  -H "User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7 Mobile/15E148 Safari/604.1" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -H "sec-fetch-dest: document" \
  -H "sec-fetch-mode: navigate" \
  -H "sec-fetch-site: none"
```

#### OkHttp 4 (Android) Headers

```bash
curl --max-time 30 --connect-timeout 10 -sk "https://target.com" \
  -H "User-Agent: okhttp/4.12.0" \
  -H "Accept: application/json, text/plain, */*" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -H "Connection: Keep-Alive"
```

### Phase 3 — HTTP/2 SETTINGS Frame Spoofing

HTTP/2 SETTINGS frames are sent during connection setup. curl doesn't expose them — use impit or a patched HTTP client:

```python
from impit import Impit

# Chrome HTTP/2 SETTINGS:
#   SETTINGS_MAX_CONCURRENT_STREAMS: 1000
#   SETTINGS_INITIAL_WINDOW_SIZE: 6291456
#   SETTINGS_MAX_HEADER_LIST_SIZE: 262144
# Firefox HTTP/2 SETTINGS:
#   SETTINGS_MAX_CONCURRENT_STREAMS: 125
#   SETTINGS_INITIAL_WINDOW_SIZE: 131072

impit = Impit.builder().with_fingerprint("chrome142").build()
response = impit.get("https://target.com")
```

### Phase 4 — Pseudo-Header Order

Browsers send HTTP/2 pseudo-headers in specific orders. This is enforced at the h2 library level:

| Browser | Pseudo-Header Order |
|---|---|
| Chrome | `:method`, `:authority`, `:scheme`, `:path`, `:protocol`, `:status` |
| Firefox | `:method`, `:path`, `:authority`, `:scheme`, `:protocol`, `:status` |
| Safari iOS | `:method`, `:scheme`, `:authority`, `:path`, `:protocol`, `:status` |
| OkHttp | `:method`, `:path`, `:authority`, `:scheme`, `:protocol`, `:status` |

**Detection:** Some reverse proxies inspect pseudo-header order to distinguish browsers. Firefox places `:path` before `:authority` — a unique fingerprint. Safari places `:scheme` second — another differentiator.

### Phase 5 — Header Prioritization

Custom headers take priority over fingerprint defaults to avoid conflicts:

```python
impit = Impit.builder().with_fingerprint("chrome142").build()

# Custom headers WIN over fingerprint defaults for same header name
response = impit.get("https://target.com", headers={
    "Authorization": "Bearer custom-token",
    "X-Custom-Header": "value",
})
# Authorization is added; all fingerprint headers still applied for unset names
```

### Phase 6 — Accept-Encoding Strategy

Browser Accept-Encoding values differ significantly:

| Browser | Accept-Encoding |
|---|---|
| Chrome 142 | `gzip, deflate, br, zstd` |
| Chrome 100-116 | `gzip, deflate, br` |
| Firefox | `gzip, deflate, br, zstd` |
| Safari iOS | `gzip, deflate, br` |
| OkHttp 4 | `gzip, deflate, br` |

**Detection:** Some CDNs return different content based on Accept-Encoding (brotli vs zstd capability profiling). Match encoding capabilities to your target browser.

## Pitfalls

- **curl cannot spoof HTTP/2 SETTINGS frames.** Only use curl-based headers for HTTP/1.1 targets or when TLS fingerprinting is the primary concern, not HTTP/2.
- **Header order matters in HTTP/2.** Some detectors check the order of header fields, not just their presence.
- **`sec-ch-ua` must match User-Agent.** Using Chrome headers with Firefox UA creates an inconsistency that detectors flag.
- **`sec-ch-ua` format is version-specific.** Chrome 100+ uses different brand strings than Chrome 124+.
- **Mobile headers without TLS matching is detectable.** Using Safari iOS headers over a desktop TLS fingerprint is flagged.
- **Custom headers are deduplicated case-insensitively.** Adding `User-Agent` as custom overrides the fingerprint's User-Agent.

## Verification

1. Test against `https://httpbin.org/headers` — verify all sent headers match the intended browser profile.
2. For HTTP/2 SETTINGS verification, use `https://nghttp2.org/httpbin/headers` or a local nghttp2 server.
3. Compare response size/content between browser-impostor and real browser — identical responses indicate the headers are accepted.
4. Check Cloudflare `cf-ja4` header — it encodes HTTP/2 fingerprint along with TLS.

## Related Skills

- **`tls-fingerprint-impersonation`** — TLS ClientHello and JA3/JA4 fingerprint spoofing.
- **`stealth-browser-launch`** — Full browser automation with C++ fingerprint patches.
