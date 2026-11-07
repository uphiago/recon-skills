---
name: humanize-automation
description: Human-like mouse, keyboard and scroll behavior for behavioral bot bypass.
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires python3
metadata:
  tags: [recon, humanize, behavioral, anti-bot, mouse, keyboard, automation]
  category: recon
  related_skills:
    - stealth-browser-launch
    - tls-fingerprint-impersonation
    - evasion-stack-guide
---

# Humanize Automation

Replace instant programmatic interactions with human-like mouse movements, keyboard typing, and scroll patterns. Patches Playwright's API at the class level — `page.click()`, `page.type()`, `page.fill()`, and Locator methods are automatically replaced with Bézier-curved mouse paths, per-character typing with mistypes, and multi-phase scroll acceleration. One flag (`humanize=True`) enables all behavioral patches. No code changes required.

## When to Use

- Target uses behavioral bot detection (mouse trajectory analysis, typing speed profiling).
- reCAPTCHA v3 scores are low (<0.3) despite correct browser fingerprint.
- Target times out or challenges after rapid form submissions.
- Need to simulate a real user browsing session for login or account creation.
- Target uses `requestAnimationFrame`-based mouse movement tracking.

## How to Run

```bash
export TARGET="example.test"
export OUTPUT_DIR="${OUTPUT_DIR:-./output}"
mkdir -p "$OUTPUT_DIR"
# Then follow the steps in Procedure.
```

## Prerequisites

- `terminal` with python3.
- `cloakbrowser` installed: `pip install cloakbrowser`.
- Or standalone Playwright with custom patching: import `patch_page` from the humanize module.

## Quick Start

```python
from cloakbrowser import launch

browser = launch(humanize=True)
page = browser.new_page()
page.goto("https://target.com/login")

# All interactions are automatically humanized
page.locator("#email").fill("user@example.com")     # per-character timing
page.locator("#password").fill("password123")       # with thinking pauses
page.locator("button[type=submit]").click()         # Bézier curve movement
browser.close()
```

## Procedure

### Phase 1 — Default Humanization

One flag enables all behavior patches:

```python
browser = launch(
    headless=False,
    proxy="http://residential-proxy:port",
    geoip=True,
    humanize=True,  # enables all behavioral patches
)
page = browser.new_page()
page.goto("https://target.com")

# All Playwright interactions are replaced with human-like equivalents
page.locator("input[name='search']").fill("restricted query")
page.locator("button[type='submit']").click()
```

### Phase 2 — Careful Mode (Slower, More Deliberate)

For sites that profile interaction speed:

```python
browser = launch(
    humanize=True,
    human_preset="careful",  # slower typing, more idle pauses
)
```

Careful preset changes: typing 100±50ms (vs 70±40ms), click aim 80-180ms (vs 60-140ms), `idle_between_actions` enabled with 0.4-1.0s pauses.

### Phase 3 — Custom Behavior Profile

Override individual parameters for site-specific tuning:

```python
from cloakbrowser import HumanConfig

custom = HumanConfig(
    typing_delay=150,
    typing_delay_spread=60,
    typing_pause_chance=0.15,
    mistype_chance=0.03,
    mouse_wobble_max=2.0,
    click_aim_delay_input=(100, 200),
    scroll_delta_base=(60, 100),
    idle_between_actions=True,
    idle_between_duration=(0.5, 1.5),
)

browser = launch(humanize=True, human_config=custom)
```

### Phase 4 — Per-Call Overrides

Override behavior for individual interactions:

```python
# Slow, careful typing for password field
page.locator("#password").fill("secret", human_config={"typing_delay": 200})

# Fast click (bypass aim delay)
page.locator("#submit").click(human_config={"click_aim_delay_input": (0, 0)})
```

### Phase 5 — Standalone Humanization (Without CloakBrowser)

Patch an existing Playwright page:

```python
from playwright.sync_api import sync_playwright
from cloakbrowser.human import patch_page, resolve_config

pw = sync_playwright().start()
browser = pw.chromium.launch()
page = browser.new_page()

# Apply humanization to an existing page
config = resolve_config("default")
patch_page(page, config)

# All interactions now humanized
page.locator("#email").fill("user@example.com")
```

## Behavioral Parameters Reference

### Mouse Movement

| Parameter | Default | Effect |
|---|---|---|
| `mouse_steps_divisor` | 8 | Controls smoothness (lower = smoother, more steps) |
| `mouse_min_steps` | 25 | Minimum steps per movement |
| `mouse_max_steps` | 80 | Maximum steps per movement |
| `mouse_wobble_max` | 1.5 px | Sideways sinusoidal wobble amplitude |
| `mouse_overshoot_chance` | 0.15 | Probability of overshooting target |
| `mouse_overshoot_px` | (3, 6) px | Overshoot distance |

**Movement algorithm:** Cubic Bézier curve with 2 random perpendicular control points → ease-in-out cubic easing → sinusoidal wobble → 15% overshoot chance with correction.

### Keyboard Typing

| Parameter | Default | Effect |
|---|---|---|
| `typing_delay` | 70 ms | Average per-character delay |
| `typing_delay_spread` | 40 ms | Random spread around delay |
| `typing_pause_chance` | 0.10 | Thinking pause probability per character |
| `typing_pause_range` | (400, 1000) ms | Thinking pause duration |
| `mistype_chance` | 0.02 | Typo probability per character |
| `mistype_delay_notice` | (100, 300) ms | Time before noticing typo |
| `mistype_delay_correct` | (50, 150) ms | Time to correct typo |
| `field_switch_delay` | (800, 1500) ms | Delay when switching between form fields |

**Typing algorithm:** Per-character delay with random spread → 10% pause chance → 2% typo chance (nearby key → notice → backspace → retype) → Shift symbols via CDP `Input.dispatchKeyEvent` for `isTrusted=true`.

### Scrolling

| Parameter | Default | Effect |
|---|---|---|
| `scroll_delta_base` | (80, 130) px | Scroll distance per step |
| `scroll_accel_steps` | (2, 3) | Acceleration phase steps |
| `scroll_decel_steps` | (2, 3) | Deceleration phase steps |
| `scroll_overshoot_chance` | 0.10 | Probability of overshooting |
| `scroll_overshoot_px` | (50, 150) px | Overshoot distance |
| `scroll_target_zone` | (0.20, 0.80) | Target zone in viewport |
| `scroll_settle_delay` | (300, 600) ms | Delay after reaching target |

**Scroll algorithm:** Accelerate (2-3 steps, 80-100px) → cruise (80-130px, burst into 20-40px wheel chunks at 8-20ms intervals) → decelerate (2-3 steps, 60-90px) → 10% overshoot chance with correction.

### Click Behavior

| Parameter | Default | Effect |
|---|---|---|
| `click_aim_delay_input` | (60, 140) ms | Delay before clicking input elements |
| `click_aim_delay_button` | (80, 200) ms | Delay before clicking buttons |
| `click_hold_input` | (40, 100) ms | Hold duration on inputs |
| `click_hold_button` | (60, 150) ms | Hold duration on buttons |
| `click_input_x_range` | (0.05, 0.30) | Click position within input (left side) |

### Idle Behavior

| Parameter | Default | Effect |
|---|---|---|
| `idle_between_actions` | False | Enable micro-movements between actions |
| `idle_between_duration` | (0.3, 0.8) sec | Idle duration between actions |
| `idle_drift_px` | 3 px | Random cursor drift during idle |
| `idle_pause_range` | (300, 1000) ms | Idle pause duration |
| `initial_cursor_x` | (400, 700) px | Starting cursor X (address bar area) |
| `initial_cursor_y` | (45, 60) px | Starting cursor Y (address bar area) |

### Presets

| Preset | Typing | Aim Delay | Idle Between | Use Case |
|---|---|---|---|---|
| `default` | 70±40ms | 60-140ms | No | Normal human speed |
| `careful` | 100±50ms | 80-180ms | Yes (0.4-1.0s) | Slower, more deliberate |

## Pitfalls

- **Humanize requires the wrapper.** Connecting via CDP without the wrapper loses humanization — only fingerprint patches work over raw CDP.
- **ElementHandle objects bypass humanization in Playwright.** Use `page.click(selector)` or `page.locator(selector).*` — avoid `query_selector()` handles.
- **`page.fill()` with humanize clears existing content and types character by character.** This is intentional but slower than raw `fill()`.
- **Typing speed profiling exists.** Some sites measure ms-between-keystrokes. Use `careful` preset or increase `typing_delay` for suspicious targets.
- **Scroll-to-element is automatic.** On click/hover, the element is scrolled into view with human scroll before interaction.
- **CDP Isolated Worlds are used for stealth DOM queries.** This prevents monkey-patch detection in the main JavaScript context.

## Verification

1. Test against `https://deviceandbrowserinfo.com` — should show 24/24 behavioral signals passed.
2. Compare reCAPTCHA v3 scores with and without `humanize=True` — humanize should increase score by 0.2-0.4.
3. Use browser DevTools Performance tab to record a session — mouse events should show realistic timing curves, not instant jumps.
4. Verify `Input.dispatchKeyEvent` events have `isTrusted: true` in the event listener.

## Related Skills

- **`stealth-browser-launch`** — Launch the patched Chromium binary with C++ fingerprint modifications.
- **`tls-fingerprint-impersonation`** — TLS/JA4 fingerprint spoofing for HTTP-level evasion.
