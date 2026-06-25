---
name: cross-wave-delta-analysis
description: Compare recon waves to find NEW, REGRESSED, PERSISTENT findings.
version: 1.0.0
author: agentiko
license: MIT
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

- Prior wave output files in `/root/output/recon_us/deep/waveN/`.
- Current wave output files in `/root/output/recon_us/deep/waveN+1/`.
- Structured findings per target (at minimum: ports, CORS status, WP users, XMLRPC status, sensitive paths).

## How to Run

```bash
# Produce a delta report comparing WaveN to WaveN+1
python3 scripts/wave_delta.py --wave-old /root/output/recon_us/deep/wave6/ --wave-new /root/output/recon_us/deep/wave7/
```

## Quick Reference

### Delta Categories

| Category | Label | Meaning | Example |
|----------|-------|---------|---------|
| NEW | ++ | Finding that didn't exist in any prior wave | `Port 3306 (MySQL) now OPEN` |
| REGRESSION | -- | Service that was accessible but is now blocked | `XMLRPC 200 -> 405 (hardened)` |
| PERSISTENT | == | Vulnerability unchanged across all waves | `CORS still reflecting since wave6` |
| CHANGE | ~ | Configuration changed but not a regression | `WP users: 10 in wave7, 9 in wave9` |

### Fields to Compare Per Target

| Field | How to Check | What Delta Means |
|-------|-------------|------------------|
| XMLRPC status | HTTP status code of POST /xmlrpc.php | 200 -> 405 = REGRESSION (hardened) |
| CORS headers | ACAO + ACAC on /wp/v2/users | Reflecting -> No headers = REGRESSION |
| WP Users | Count from /wp/v2/users | Count change = CHANGE (user added/removed) |
| Open ports | nmap or naabu output | New port = NEW (surface expanded) |
| Subdomains | subfinder output | New subs = NEW (recon expansion) |
| Sensitive paths | HTTP status for .env, info.php, etc | Previously accessible now 403 = REGRESSION |

## Procedure

### Step 1 — Gather Both Waves' Data

```bash
WAVE_OLD="/root/output/recon_us/deep/wave6"
WAVE_NEW="/root/output/recon_us/deep/wave7"
OUTDIR="/root/output/recon_us/deep/delta"
mkdir -p "$OUTDIR"

echo "=== Comparing Wave6 vs Wave7 ==="
```

### Step 2 — Produce Per-Target Delta Table

For each target present in both waves, build a comparison:

```bash
for target in wines.com restonic.com realpro.com toolking.com biglots.com defy.com patientportal.com; do
  echo ""
  echo "### $target"
  echo "| Check | Wave6 | Wave7 | Delta |"
  echo "|-------|-------|-------|-------|"

  # Compare XMLRPC
  old_xml=$(grep -A3 "XMLRPC" "$WAVE_OLD/${target}_wave6.md" 2>/dev/null | grep -oP 'HTTP \d+' | head -1)
  new_xml=$(grep -A3 "XMLRPC" "$WAVE_NEW/${target}_wave7.md" 2>/dev/null | grep -oP 'HTTP \d+' | head -1)
  if [ "$old_xml" != "$new_xml" ]; then
    echo "| XMLRPC | $old_xml | $new_xml | DELTA |"
  fi

  # Compare CORS
  old_cors=$(grep -i "access-control" "$WAVE_OLD/${target}_wave6.md" 2>/dev/null | head -1)
  new_cors=$(grep -i "access-control" "$WAVE_NEW/${target}_wave7.md" 2>/dev/null | head -1)
  if [ "$old_cors" != "$new_cors" ]; then
    echo "| CORS | $old_cors | $new_cors | DELTA |"
  fi

  # Compare ports (nmap output)
  old_ports=$(grep -oP '\d+/tcp' "$WAVE_OLD/nmap-${target}.txt" 2>/dev/null | tr '\n' ' ')
  new_ports=$(grep -oP '\d+/tcp' "$WAVE_NEW/nmap-${target}.txt" 2>/dev/null | tr '\n' ' ')
  if [ "$old_ports" != "$new_ports" ]; then
    echo "| Ports | $old_ports | $new_ports | DELTA |"
  fi
done
```

### Step 3 — Flag Critical Deltas

```bash
echo ""
echo "=== CRITICAL NEW FINDINGS ==="

# Signal: port 3306 (MySQL) open
echo "==> New MySQL 3306 open:"
grep -r "3306.*open" "$WAVE_NEW/" 2>/dev/null | grep -v "$WAVE_OLD"

# Signal: CORS newly discovered
echo "==> New CORS credential reflections:"
grep -ri "access-control-allow-credentials: true" "$WAVE_NEW/" 2>/dev/null | grep -v "already known\|not found"

# Signal: New WordPress installs
echo "==> New WP install/upgrade pages:"
grep -rl "install.php" "$WAVE_NEW/" 2>/dev/null | grep -v "$WAVE_OLD"
```

### Step 4 — Classify All Findings

```bash
echo ""
echo "=== CLASSIFICATION SUMMARY ==="
echo "| Target | NEW | REGRESSION | PERSISTENT | CHANGE |"

for target in wines.com restonic.com toolking.com realpro.com biglots.com defy.com patientportal.com; do
  new_count=0
  reg_count=0
  per_count=0
  chg_count=0

  # Count each category (populate from delta analysis above)
  # NEW: previously not documented
  # REGRESSION: was working, now blocked
  # PERSISTENT: same across both waves
  # CHANGE: different but not regression

  echo "| $target | $new_count | $reg_count | $per_count | $chg_count |"
done
```

## Real-World Example

### Wave9 Delta Results (7 targets, comparing Wave8 to Wave9)

| Target | Wave8 | Wave9 Delta | Category |
|--------|-------|-------------|----------|
| wines.com | XMLRPC 200 (76 methods) | 200->301 redirect | REGRESSION |
| wines.com | CORS known | Still reflecting | PERSISTENT |
| wines.com | 11 users | 11 confirmed | PERSISTENT |
| wines.com | No ports reported | MySQL 3306 + FTP 21 + IMAP 143 + SMTP 587 OPEN | **NEW** (6 new ports) |
| restonic.com | XMLRPC open | HTTP 405 | REGRESSION |
| restonic.com | NOT documented as CORS target | ALL endpoints reflect | **NEW** (missed W6-8) |
| realpro.com | CORS known | Still reflecting | PERSISTENT |
| realpro.com | No infra | Exchange OWA + SSH 22 + VPN portal | **NEW** (10+ subdomains) |
| toolking.com | SliderRev known | CORS discovered on ALL endpoints | **NEW** (missed W6-8) |
| toolking.com | No subdomains | admin/ci/vendors/ftp/wms.toolking.com | **NEW** |
| patientportal.com | MySQL 3306 open | Still OPEN | PERSISTENT (4 waves!) |
| patientportal.com | Port 8080 open | 8081 ALSO open | NEW |

### Key Insight
CORS was MISSED on restonic.com and toolking.com across 3 waves (W6-W8) because only `/wp/v2/users` was tested. **Test ALL endpoints for CORS, not just the users endpoint.**

## Pitfalls

- **False REGRESSION.** A 403 on a path doesn't mean it's patched — it may mean rate limiting kicked in. Retry with fresh IP/delay.
- **False PERSISTENT.** A 200 on an endpoint doesn't mean it's still exploitable — the underlying vulnerability may be patched while the endpoint remains (e.g., XMLRPC returns 200 but multicall disabled).
- **Timing matters.** Waves must use the same methodology or deltas are meaningless. Don't compare a deep wave to a surface wave.
- **Nmap new ports** may be stateful firewalls rather than new services. Verify with a banner grab.
- **Don't confuse "not documented" with "not present."** A finding may have existed in prior waves but was simply missed. Flag as "NEW TO DOCUMENTATION" not "NEW TO TARGET."

## Verification

- Every delta must be verifiable by re-running the exact same command on both waves' output.
- NEW findings should be re-tested immediately — they may be transient (firewall rules, temporary services).
- PERSISTENT findings across 3+ waves are the most reliable — they indicate no security team, no WAF, no patching cadence.
- REGRESSIONS are good news (security hardening) but verify by testing 3 times with different IPs/US.
