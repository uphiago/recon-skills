---
name: cross-wave-delta-analysis
description: Compare recon waves to find NEW, REGRESSED, PERSISTENT findings.
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: N/A (analysis methodology)
metadata:
  tags: [meta, wave, delta, comparison, analysis]
  category: meta
  related_skills:
    - recon-playbook
    - cross-attack-chains
    - cors-credential-wordpress
    - xmlrpc-exploitation
    - attack-patterns-reference
---

# Cross-Wave Delta Analysis Skill

Methodology for comparing findings across multiple recon waves on the same target set. Detects NEW findings, REGRESSIONS (previously open now blocked), PERSISTENT vulnerabilities, and CHANGES over time. Distilled from 9 waves across 7 deep targets that revealed missed CORS findings, new port exposures, and infrastructure drift.

## When to Use

- Running repeated recon on the same target set (Wave N+1 after Wave N).
- You want to know if a vulnerability was PATCHED since last wave.
- You want to know if a NEW surface appeared (new ports, new subdomains, new endpoints).
- After completing a deep recon wave — produce the delta report before next wave.
- Before reporting — confirm findings are still valid (not regressed).

## Prerequisites

- Prior assessment output beneath `${OUTPUT_DIR:-./output}/baseline/`.
- Current assessment output beneath `${OUTPUT_DIR:-./output}/current/`.
- Structured findings per target (at minimum: ports, CORS status, WP users, XMLRPC status, sensitive paths).

## How to Run

```bash
# Produce a delta report comparing WaveN to WaveN+1
# Read wave outputs, compare per-target, classify findings
```

## Quick Reference

### Delta Categories

| Category | Label | Meaning | Example |
|----------|-------|---------|---------|
| NEW | ++ | Finding that didn't exist in any prior wave | `Port 3306 (MySQL) now OPEN` |
| REGRESSION | -- | Service that was accessible but is now blocked | `XMLRPC 200 -> 405 (hardened)` |
| PERSISTENT | == | Vulnerability unchanged across all waves | `CORS still reflecting since wave6` |
| CHANGE | ~ | Configuration changed but not a regression | `WP users: 10 in wave7, 9 in wave9` |
| REVERSED | -> | A regression that was later undone (mitigation removed) | `XMLRPC 405 (W9) -> 200 active (W10)` |

### REVERSED — Special Category

Reversed findings are regressions that later reverted to the original vulnerable state. This happens when:
- A WAF rule was applied temporarily then removed (common on GoDaddy/Cloudflare shared hosting)
- A plugin security update was rolled back
- Infrastructure was redeployed without the hardening

**Treat REVERSED as actionable**: the security team either doesn't know or doesn't care. These targets are high-priority because their protection is unreliable.

### Fields to Compare Per Target

| Field | How to Check | What Delta Means |
|-------|-------------|------------------|
| XMLRPC status | HTTP status of POST /xmlrpc.php | 200 -> 405 = REGRESSION (hardened) |
| CORS headers | ACAO + ACAC on /wp/v2/users | Reflecting -> No headers = REGRESSION |
| WP Users | Count from /wp/v2/users | Count change = CHANGE |
| Open ports | nmap or naabu output | New port = NEW (surface expanded) |
| Subdomains | subfinder output | New subs = NEW |
| Sensitive paths | HTTP status for .env, info.php, etc | Previously 200 -> 403 = REGRESSION |

## Procedure

### Step 1 — Gather Both Waves' Data

```bash
WAVE_OLD="${OUTPUT_DIR:-./output}/baseline"
WAVE_NEW="${OUTPUT_DIR:-./output}/current"
echo "=== Comparing $WAVE_OLD vs $WAVE_NEW ==="
```

### Step 2 — Produce Per-Target Delta Table

For each target present in both waves, compare XMLRPC status, CORS headers, open ports, WP users, and subdomains. Flag findings as NEW (not in prior wave), REGRESSION (previously working, now blocked), PERSISTENT (unchanged), or CHANGE (different but not blocked).

### Step 3 — Classify & Flag Critical Deltas

Signal critical deltas: new port 3306 (MySQL), new CORS credential reflections, new WP install pages, new subdomains with admin/staging patterns.

## Pitfalls

- **False REGRESSION.** A 403 may be rate limiting, not patching. Retry 3x with different IPs/delays.
- **False PERSISTENT.** A 200 endpoint may still be live but the underlying vulnerability (e.g., multicall) may be disabled.
- **Timing matters.** Waves must use the same methodology or deltas are meaningless.
- **Don't confuse "not documented" with "not present."** A finding may have existed but was simply missed.

## Verification

- Every delta must be reproducible with the exact same command on both waves' output.
- NEW findings should be re-tested immediately — they may be transient.
- PERSISTENT findings across 3+ waves are the most reliable (no security team, no patching cadence).

---

## Related Skills

- `attack-patterns-reference` — match findings to pattern IDs (P-01 to P-25)
- `recon-playbook` — the 4-phase pipeline that produces wave data
- `cross-attack-chains` — chain NEW findings into critical impact
- `cors-credential-wordpress` — verify CORS findings classification
- `xmlrpc-exploitation` — verify XMLRPC regression status
