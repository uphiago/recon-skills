# 🛡️ Recon & Pentest Skill Pack

**169 offensive security skills** for recon and pentest. Field-validated techniques from **600+ company targets** across **45+ sectors**. Updated with browser fingerprint evasion, anti-bot bypass, hardcoded credential hunting, SCADA/ICS enumeration.

> 📖 **Blog & research**: [hiago.sh](https://hiago.sh) — Pentest Playbook, field notes, and tooling.



---

## 📦 What's Inside (169 skills)

```
recon-skills/
├── SOUL.md                  — Philosophy & agent operating instructions
├── AGENTS.md                — Complete catalog + HARDLINE skill standards
├── recon/          (41)     — WordPress/CORS/XMLRPC recon, source leaks, JS secrets, web enum, email sec, staging hunt, port scans, hardcoded creds, S3/MinIO XSS, API flow hijack, SCADA Hikvision ISAPI, browser evasion, origin IP discovery, subdomain takeover, vhost enum, GitHub secrets, ASN mapping, visual recon, CMS detection
├── redteam/        (116)    — 61 hunt-* (xss, sqli, ssrf, rce, ato, idor, cors, firebase, supabase, schema-enum, write-gap, metrics, k8s, mass-assignment, prototype-pollution, bfla, info-disclosure, django, fastapi, nestjs, etc) + 24 sector recon + 29 methodology/ops
├── meta/           (6)      — Recon playbook, sector methodology, attack patterns, wave delta, google dorks, pentest playbook
├── chains/         (2)      — Cross-attack chaining, WordPress full compromise
├── auth/           (1)      — SAML SSO attacks
├── infra/          (1)      — Docker privilege escalation
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
| **recon** | `hardcoded-credential-hunt` | Detect hardcoded passwords in HTML forms, JavaScript, API config endpoints, debug pages |
| **recon** | `s3-minio-content-type-xss` | Content-Type override on public S3/MinIO buckets → stored XSS on target origin |
| **recon** | `unauth-api-flow-hijack` | Exploit multi-step API flows without auth: start→submit→upload→export |
| **recon** | `scada-hikvision-isapi` | Enumerate Hikvision ISAPI endpoints, cameras, RTSP on SCADA/IoT web interfaces |
| **recon** | `stealth-browser-launch` | C++ patched Chromium — 18 fingerprint flags, bypass Cloudflare/reCAPTCHA/FingerprintJS |
| **recon** | `humanize-automation` | Bézier mouse, mistype keyboard, accel-cruise-decel scroll for behavioral bypass |
| **recon** | `tls-fingerprint-impersonation` | 20 browser profiles (Chrome/Firefox/Safari/OkHttp) with JA4 TLS validation |
| **recon** | `http2-header-impersonation` | HTTP/2 SETTINGS spoofing, pseudo-header order, browser sec-ch-ua headers |
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

## 📄 License

MIT — Use freely, contribute back.
