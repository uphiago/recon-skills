# 🛡️ Recon & Pentest Skill Pack

**148 skills** for autonomous offensive reconnaissance at scale. Built from **600+ company targets**, **12 rounds of field recon**, and a **pentest playbook** validated across government, healthtech, fintech, e-commerce, ISP, and SMB sectors.

> 📖 **Blog & research**: [hiago.sh](https://hiago.sh) — Pentest Playbook, field notes, and tooling.



---

## 📦 What's Inside (148 skills)

```
recon-skills/
├── SOUL.md                  — Philosophy & agent operating instructions
├── AGENTS.md                — Complete catalog + HARDLINE skill standards
├── recon/          (24)     — WordPress/CORS/XMLRPC recon, source leaks, JS secrets, web enum, email sec, staging hunt, port scans
├── redteam/        (107)    — 54 hunt-* (xss, sqli, ssrf, rce, ato, idor, cors, firebase, supabase, schema-enum, write-gap, metrics, k8s, etc) + 24 sector recon + 29 methodology/ops
├── meta/           (6)      — Recon playbook, sector methodology, attack patterns, wave delta, google dorks, pentest playbook
├── chains/         (2)      — Cross-attack chaining, WordPress full compromise
├── auth/           (1)      — SAML SSO attacks
├── infra/          (1)      — Docker privilege escalation
├── attacks/        (2)      — Flask Werkzeug debugger RCE
├── agentiko-hermes/        — Hermes agent operating spec
└── agentiko-worker/         — Worker runtime spec + references
```

## 🔥 Key Skills

| Category | Skill | What It Does |
|----------|-------|-------------|
| **meta** | `recon-playbook` | 4-phase pipeline: target gen → quick filter → WP deep check → deep invade |
| **recon** | `cors-credential-wordpress` | 8 CORS variants (V1-V8) with real confirmed targets |
| **recon** | `xmlrpc-exploitation` | System.multicall, pingback SSRF, IMDS role guessing, wp.uploadFile |
| **recon** | `web-enumeration` | 200+ sensitive file paths, .env extraction, path traversal, vhost enum |
| **recon** | `js-secrets-extraction` | 12 regex patterns for API keys, JWTs, Firebase, Supabase in JS bundles |
| **recon** | `email-security` | DMARC/SPF/DKIM checks, SMTP spoofing, header analysis |
| **chains** | `cross-attack-chains` | Attack chain methodology — CORS+XMLRPC→RCE, SSRF→IMDS, etc |
| **chains** | `wordpress-full-compromise` | Kill chains for full WordPress takeover |
| **meta** | `attack-patterns-reference` | 25 patterns (P-01 to P-25), 18 WP abuse patterns, 8 CORS variants |
| **meta** | `cross-wave-delta-analysis` | Compare waves → NEW / REGRESSION / PERSISTENT / CHANGE |
| **meta** | `sector-recon-methodology` | Tier-based sector selection + per-sector vulnerability baselines |
| **meta** | `google-dorks-catalog` | 100+ dork patterns by service type + GitHub code search |
| **redteam** | `hunt-*` (54 skills) | One per vuln class: xss, sqli, ssrf, rce, ato, idor, cors, firebase, supabase, schema-enum, write-gap, metrics, k8s, llm-ai, etc |
| **redteam** | `hunt-schema-enumeration` | API error hint enumeration — discover hidden tables via PostgREST/Zod/FastAPI validation leaks |
| **redteam** | `hunt-write-gap` | Read-protected but write-open endpoints — PATCH/POST/DELETE privilege escalation |
| **redteam** | `hunt-metrics-exposure` | Public /metrics, /health, actuator — AI usage, DB pools, operational intel |
| **redteam** | `parallel-recon-triad` | 3 parallel subagents every 20min: Deep Invade + Expand + Skill Evolution |
| **redteam** | `ops-proxyns` | Kernel-level proxy via network namespaces — Tor for all traffic |
| **redteam** | `cloud-iam-deep` | AWS/GCP/Azure IAM enumeration, SA key abuse, Cloud Run, Artifact Registry |

## 📊 Field Results

| Metric | Value |
|--------|-------|
| Unique domains tested | **600+** |
| Vulnerable companies found | **80+** |
| Sectors tested | **45+** |
| CORS variants cataloged | **8** (V1-V8) |
| Attack patterns cataloged | **25** (P-01 to P-25) |
| WP abuse patterns | **18** (WP-01 to WP-18) |
| Attack chains confirmed | **10** |
| Recon rounds completed | **12** |
| Executable scripts | **48** (40 .py, 7 .sh, 1 .js) |
| Hunt skills expanded (2025-2026) | **10** (schema-enum, write-gap, metrics, smuggling, mfa, saml, ato, api, llm, race) |

### Finding Distribution

| Severity | Count | Common Patterns |
|----------|-------|-----------------|
| Critical | 14 | RLS write gap (tier upgrade, balance injection), MySQL exposed, PHPInfo + open reg, CORS + XMLRPC + upload → RCE, price tampering |
| High | 30 | CORS credential reflection, XMLRPC multicall, staging takeover, schema enumeration, metrics exposure |
| Medium | 18 | WP user enum, WooCommerce API, plugin version disclosure |

### Top Patterns by Sector

| Sector | Vuln Rate | Top Finding |
|--------|-----------|-------------|
| Law Firms | ~25% | WP REST API user enumeration |
| Landscaping | ~20% | CORS credential reflection |
| Pool Services | ~20% | CORS + XMLRPC open |
| Pest Control | ~20% | CORS credential reflection |
| HVAC/Plumbing | ~14% | CORS + WP user enumeration |
| Locksmiths | ~33% | WP REST API + XMLRPC |
| Window Cleaning | ~25% | CORS + XMLRPC |
| Bakeries | ~18% | Source leaks + CORS wildcard |
| Septic Services | ~25% | Source leaks + CORS |

## 🚀 Getting Started

```bash
git clone git@github.com:uphiago/recon-skills.git
cd recon-skills
cat SOUL.md          # Read the philosophy
cat AGENTS.md        # Read the standards & catalog
ls recon/            # Browse recon skills
ls redteam/          # Browse hunt skills
```

Each skill directory has a `SKILL.md` with:
- When to Use
- Prerequisites
- How to Run (copy-paste commands)
- Procedure (numbered steps with exact commands)
- Pitfalls
- Verification

## 🧠 Design Principles

- **Terminal-native** — every command runs via curl, nmap, python3. No browser automation.
- **Self-contained** — each SKILL.md is a complete operational package.
- **Field-validated** — techniques confirmed on real targets before shipping.
- **Chain everything** — one finding is Medium. Two chained is Critical.
- **Cross-reference, don't duplicate** — hosting tables belong in one place.

## ⭐ Star History

<a href="https://www.star-history.com/?type=date&repos=uphiago%2Frecon-skills">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=uphiago/recon-skills&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=uphiago/recon-skills&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=uphiago/recon-skills&type=date&legend=top-left" />
 </picture>
</a>

## 📄 License

MIT — Use freely, contribute back.
