---
name: stealth-browser-launch
description: Launch stealth Chromium with C++ fingerprint patches for anti-bot bypass.
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, httpx, nuclei, python3
metadata:
  tags: [recon, stealth, browser, anti-bot, fingerprint, chromium, playwright]
  category: recon
  related_skills:
    - humanize-automation
    - tls-fingerprint-impersonation
    - http2-header-impersonation
    - ops-proxyns
    - evasion-stack-guide
---

# Stealth Browser Launch

Launch a patched Chromium binary with C++ source-level fingerprint modifications that bypass anti-bot detection. The binary spoofs canvas, WebGL, audio, GPU, screen, WebRTC, network timing, and automation signals at the binary level — not via JavaScript injection or config patches that break with Chrome updates. Passes Cloudflare Turnstile, reCAPTCHA v3 (0.9 score), FingerprintJS, BrowserScan, and 30+ detection sites.

## When to Use

- Target blocks curl/httpx/nuclei with Cloudflare, Akamai, DataDome, or Kasada.
- Need full browser JavaScript execution for form submission, login, or XSS testing.
- Target returns 403 on all unauthenticated requests even with proper headers.
- Need to access reCAPTCHA-protected endpoints without solving CAPTCHAs.
- Running automated recon behind residential proxies — stealth browser prevents IP+UA correlation.

## Prerequisites

- `terminal` with python3 and pip.
- `playwright` installed: `pip install playwright && playwright install-deps chromium`.
- Residential proxy (datacenter IPs are reputation-blocked regardless of browser fingerprint).
- Optional: `cloakbrowser[geoip]` for automatic timezone/locale resolution from proxy exit IP.

## How to Run

```bash
pip install cloakbrowser
python3 -c "
from cloakbrowser import launch
browser = launch()
page = browser.new_page()
page.goto('https://target.com')
print(page.title())
browser.close()
"
```

## Quick Start

```bash
pip install cloakbrowser
python3 -c "
from cloakbrowser import launch
browser = launch()
page = browser.new_page()
page.goto('https://target.com')
print(page.title())
browser.close()
"
```

## Procedure

### Phase 1 — Basic Stealth Launch

The binary auto-generates a random fingerprint seed per launch. No flags needed for basic stealth:

```python
from cloakbrowser import launch

browser = launch(
    headless=True,
    proxy="http://user:pass@residential-proxy:port",
    geoip=True,    # auto-detect timezone/locale from proxy exit IP
)
page = browser.new_page()
page.goto("https://target.com")
# Standard Playwright API from here
page.locator("input[name='username']").fill("test")
page.locator("button[type='submit']").click()
browser.close()
```

### Phase 2 — Persistent Identity

Use a fixed fingerprint seed when revisiting the same target to appear as a returning visitor:

```python
browser = launch(
    proxy="http://user:pass@residential-proxy:port",
    geoip=True,
    args=["--fingerprint=42069"],  # fixed seed = same fingerprint every launch
)
```

### Phase 3 — Headed Mode for Maximum Stealth

Some sites detect headless even with C++ patches. Run headed with a virtual display:

```bash
# Start virtual display
Xvfb :99 -screen 0 1920x1080x24 &
export DISPLAY=:99
```

```python
browser = launch(
    headless=False,  # real rendering
    proxy="http://residential-proxy:port",
    geoip=True,
    humanize=True,   # human-like mouse/keyboard/scroll
)
```

### Phase 4 — Fingerprint Customization

Override specific fingerprint values to match a target environment:

```python
browser = launch(stealth_args=False, args=[
    "--fingerprint=42069",
    "--fingerprint-platform=windows",
    "--fingerprint-gpu-vendor=NVIDIA Corporation",
    "--fingerprint-gpu-renderer=NVIDIA GeForce RTX 3060/PCIe/SSE2",
    "--fingerprint-hardware-concurrency=16",
    "--fingerprint-device-memory=16",
    "--fingerprint-screen-width=2560",
    "--fingerprint-screen-height=1440",
    "--fingerprint-timezone=America/Sao_Paulo",
    "--fingerprint-locale=pt-BR",
    "--fingerprint-webrtc-ip=auto",
    "--fingerprint-noise=false",  # disable noise for FingerprintJS ML bypass
])
```

### Phase 5 — Persistent Profile

Maintain cookies and localStorage across sessions to bypass "first-visit" challenges:

```python
from cloakbrowser import launch_persistent_context

ctx = launch_persistent_context(
    "./target-profile",
    headless=False,
    proxy="http://residential-proxy:port",
    geoip=True,
)
page = ctx.new_page()
page.goto("https://target.com")
# Session persists across restarts
ctx.close()
```

### Phase 6 — Multi-Identity via CDP Multiplexer

Run multiple browser identities from a single container using cloakserve:

```bash
docker run -d --name cloak -p 127.0.0.1:9222:9222 cloakhq/cloakbrowser cloakserve
```

```python
from playwright.sync_api import sync_playwright

pw = sync_playwright().start()

# Each unique fingerprint seed spawns separate Chrome process with independent identity
b1 = pw.chromium.connect_over_cdp("http://localhost:9222?fingerprint=11111")
b2 = pw.chromium.connect_over_cdp("http://localhost:9222?fingerprint=22222")

# Full identity control via query params
b3 = pw.chromium.connect_over_cdp(
    "http://localhost:9222?fingerprint=33333"
    "&timezone=America/New_York&locale=en-US&platform=windows"
    "&hardware-concurrency=4&device-memory=8"
)

# Each browser has independent cookies, localStorage, canvas noise
```

### Phase 7 — Anti-Bot Font Setup

For aggressive sites (Kasada, Akamai) that check canvas emoji rendering:

```bash
apt install -y fonts-noto-color-emoji fonts-freefont-ttf fonts-unifont \
    fonts-ipafont-gothic fonts-wqy-zenhei fonts-tlwg-loma-otf
```

For CreepJS font enumeration evasion, install Windows fonts:

```bash
# Copy from Windows machine: C:\Windows\Fonts\
mkdir -p ~/.local/share/fonts/windows
cp /path/to/windows/fonts/SegoeUI*.ttf ~/.local/share/fonts/windows/
fc-cache -f

# Then launch with:
# browser = launch(args=["--fingerprint-fonts-dir=/home/user/.local/share/fonts/windows"])
```

## Fingerprint Flag Reference

| Flag | Default | What it controls |
|---|---|---|
| `--fingerprint=SEED` | Random 5-digit | Master seed for canvas/WebGL/audio/fonts |
| `--fingerprint-platform` | `windows`/`macos` | `navigator.platform`, UA OS, GPU pool |
| `--fingerprint-gpu-vendor` | Auto | WebGL UNMASKED_VENDOR_WEBGL |
| `--fingerprint-gpu-renderer` | Auto | WebGL UNMASKED_RENDERER_WEBGL |
| `--fingerprint-hardware-concurrency` | 8 | `navigator.hardwareConcurrency` |
| `--fingerprint-device-memory` | 8 | `navigator.deviceMemory` |
| `--fingerprint-screen-width` | 1920/1440 | Screen width |
| `--fingerprint-screen-height` | 1080/900 | Screen height |
| `--fingerprint-timezone` | — | IANA timezone |
| `--fingerprint-locale` | — | BCP 47 locale |
| `--fingerprint-webrtc-ip` | — | WebRTC ICE IP (`auto` for proxy exit IP) |
| `--fingerprint-noise=false` | true | Disable canvas/WebGL/audio noise |
| `--fingerprint-fonts-dir` | — | Target platform fonts path |
| `--fingerprint-windows-font-metrics` | — | Align font metrics to Windows (v148+) |
| `--fingerprint-storage-quota` | Auto | Storage quota in MB |
| `--fingerprint-taskbar-height` | 48/95/0 | Taskbar height spoofing |

## Pitfalls

- **Datacenter IPs get blocked regardless of browser fingerprint.** Always use residential proxies.
- **`page.wait_for_timeout()` leaks CDP traffic that reCAPTCHA detects.** Use `time.sleep()` instead.
- **Puppeteer sends more CDP traffic than Playwright.** Use Playwright for reCAPTCHA-heavy targets.
- **Missing fonts cause canvas hash mismatches on Kasada/Akamai.** Install the font packages listed in Phase 7.
- **`--fingerprint-noise=false` can cause ML-based detection on FingerprintJS.** Only disable noise when specifically blocked by it.
- **Headless mode can be detected even with C++ patches.** Use headed mode (`headless=False`) for maximum stealth on aggressive sites.
- **Binary auto-updates are cached ~24h.** Pin with `browser_version=` if you need reproducibility.

## Verification

1. Test against `https://browserscan.net` — all 4 bot checks should show NORMAL.
2. Test against `https://demo.fingerprint.com/playground` — should not show "nodriver" or "bot" detection.
3. Test against reCAPTCHA v3: `https://antcpt.com/eng/information/demo-form/recaptcha-3-test-score.html` — score should be ≥ 0.7.
4. Test against `https://deviceandbrowserinfo.com` — `isBot` should be false with 0 true flags.
5. Verify `navigator.webdriver` is `false` with `page.evaluate("navigator.webdriver")`.

---

## Related Skills

- **`humanize-automation`** — Human-like mouse/keyboard/scroll for behavioral bypass.
- **`tls-fingerprint-impersonation`** — TLS/JA4 fingerprint spoofing at the HTTP client level.
- **`http2-header-impersonation`** — Browser-specific HTTP/2 pseudo-header ordering and SETTINGS frames.
