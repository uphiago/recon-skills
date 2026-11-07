---
name: evasion-stack-guide
description: Use when choosing which browser, TLS, HTTP/2, or behavior impersonation layer applies to a blocked probe.
version: 1.0.0
license: MIT
platforms: [linux]
metadata:
  tags: [meta, evasion, anti-bot, fingerprint, decision-guide]
  category: meta
  related_skills:
    - tls-fingerprint-impersonation
    - http2-header-impersonation
    - stealth-browser-launch
    - humanize-automation
    - ops-proxyns
---

# Evasion Stack Guide

Four skills cover four different layers of client impersonation. They are
complementary, not interchangeable. Pick the lowest layer that explains the
block, verify it fixes the response, and only then add the next layer.

## When to Use

- Requests are blocked or challenged even though the URL and method are correct.
- A WAF/CDN returns a challenge page, 403 with no body, or a bot score wall.
- You are unsure whether the block is IP-based, TLS-based, HTTP/2-based, or behavioral.

## Prerequisites

- Authorization for the target and an understanding of its rate limits.
- A control request that shows *what* the block looks like (status, body, headers).

## How to Run

Diagnose the layer, then load the owning skill:

| Symptom | Layer | Skill |
|---|---|---|
| Block follows your IP; rotating egress changes the result | Network | `ops-proxyns` |
| `curl` blocked but a real browser passes; block independent of headers | TLS (JA3/JA4) | `tls-fingerprint-impersonation` |
| TLS matches but H2 frames/headers give you away (Akamai, some CF setups) | HTTP/2 | `http2-header-impersonation` |
| Requests pass but JS challenge/fingerprint flags automation | Browser binary | `stealth-browser-launch` |
| Page loads but interactions score as bot (reCAPTCHA v3, Turnstile) | Behavior | `humanize-automation` |

## Procedure

1. **Establish the baseline.** Send the same request with `curl`, with the
   impersonated stack, and (if possible) with a real browser. Compare status,
   body, and `Set-Cookie`/challenge markers.
2. **Rotate egress first** (`ops-proxyns`). If the block disappears, it was
   IP-reputation; stop here.
3. **Match TLS** (`tls-fingerprint-impersonation`). If `curl` fails but a
   browser passes with identical headers, the TLS ClientHello is the tell.
4. **Match HTTP/2** (`http2-header-impersonation`). Pseudo-header order and
   SETTINGS frames are a separate fingerprint from TLS.
5. **Match the browser binary** (`stealth-browser-launch`) when a JS challenge
   must execute: fingerprint flags, WebGL, WebRTC, timezone.
6. **Match behavior** (`humanize-automation`) last: mouse paths, typing cadence,
   scroll. Behavioral scoring only matters after the lower layers pass.

## Pitfalls

- **Layer confusion.** Adding browser stealth when the block is TLS-level
  wastes hours; always identify the failing layer with the baseline comparison.
- **Stacking everything by default.** Each layer adds brittleness and
  detectability surface. Add layers only when the previous one is verified clean.
- **Evasion is not authorization.** Defeating a bot wall does not change scope;
  rate limits and authorization rules still apply.

## Verification

- The impersonated request returns the same status/body class as the real
  browser control, not merely a different error.
- Each added layer is justified by a failed test at the layer below.
