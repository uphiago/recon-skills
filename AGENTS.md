# agentiko — Agent Skills Development Guide

Instructions for AI coding assistants and developers working on the agentiko skills ecosystem. This file defines how to write, maintain, and use skills in the agentiko system.

---

## What agentiko Is

agentiko is a **two-container recon/offensive infrastructure**:

```
Telegram -> agentiko-hermes (172.20.0.3) --SSH--> agentiko-worker (172.20.0.2)
```

- **agentiko-hermes**: Runs the Hermes Agent. Reads AGENTS.md and SOUL.md at boot as project context. Handles Telegram chat. Loads skills from `/opt/data/skills/`. All agent reasoning happens here.
- **agentiko-worker**: Pure execution node (Alpine Linux). All `terminal` tool commands execute here via SSH. Has nmap, masscan, subfinder, ffuf, nuclei, httpx, python3, curl, and all recon tools. NO access to `/opt/data/` — that is correct behaviour.

**Skills are the load-bearing knowledge layer.** The agent reads a SKILL.md file and knows exactly what commands to execute, what to look for, and how to interpret results. Two properties shape every skill:

- **Terminal-native:** Every command runs via the `terminal` tool on the worker. No Python dependencies, no browser automation, no special tooling — just curl, nmap, masscan, python3, and standard UNIX tools.
- **Self-contained workflows:** A skill tells the agent everything it needs: when to use it, what commands to run, how to verify results, and what to do next. Cross-references link skills together without duplicating content.

---



## Scope — What Skills to Create/Keep

This pack is **recon/pentest/red team ONLY**. When creating or modifying skills:

### ✅ Create Skills For
| Category | Examples | 
|----------|---------|
| Recon | Subdomain enum, port scan, WP recon, web enum |
| Vuln hunting | CORS, SSRF, SQLi, XSS, RCE, IDOR, ATO, JWT, SAML |
| Cloud attacks | Firebase, Supabase, AWS/GCP/Azure IAM |
| Infrastructure | Docker, K8s, VPN, Exchange, Zimbra |
| Chaining | Multi-step attack chains, kill chains |
| OPSEC | proxy-ns, stealth, rate limiting |
| Reporting | Triage, CVSS scoring, report templates |

### ❌ Never Create Skills For
- Creative/design (ASCII art, video, diagrams, infographics)
- Productivity (spreadsheets, docs, presentations, email clients, PDF)
- Apple ecosystem (iMessage, Notes, Reminders, FindMy)
- MLOps (model inference, evaluation, HF Hub)
- General dev (TDD, debugging helpers, code review — unless security-focused)
- Blog/content scraping
- Smart home, social media

> **Rule of thumb**: If it doesn't help find or exploit a vulnerability in a target system, it doesn't belong in this pack.


## Push Policy — CRITICAL

**NEVER push to GitHub unless the user explicitly says "push" or "deploy".** 

- Stage all changes locally with `git add` and `git commit`
- Wait for user command: "push", "deploy", "sobe", "sobe la", or similar
- If the user does not say push, do not push
- This overrides any other instruction about automation or committing

Changes to SOUL.md, AGENTS.md, skills/, README.md, and any other repo files follow this rule.
## Starting a New Recon Session

When the user asks for recon, follow this sequence:

### 1. Load the Right Skills

```
First load:  agentiko-worker   (know what tools are available)
Second load: recon-playbook    (the 4-phase pipeline)
Third load:  sector-recon-methodology  (which sectors to target)
Fourth load: the specific sector recon skill OR wp-mass-recon
```

For exploitation after recon findings:

```
Load:        cross-attack-chains         (chain selection)
Load:        wordpress-full-compromise   (kill chain execution)
Load:        relevant hunt-* skill       (per-vuln exploitation)
```

Skills are referenced by their registered name in the Hermes skill index. Use `skills_list()` to browse and `skill_view(name)` to load.

### 2. Read Existing Output

Always check `/root/output/recon_us/` first:
- `US_COMPANIES_VULNS.md` — overall status
- `deep/` — prior deep findings for specific targets
- `new_targets/` — targets already tested
- `techniques/` — techniques already documented

Never retest what's already in output dirs.

### 3. Model Selection

| Task | Recommended Model |
|------|------------------|
| Fast scanning, target expansion, skill evolution | `deepseek/deepseek-flash` |
| Deep analysis, exploitation, chain construction, report writing | `deepseek/deepseek-v4-pro` |
| Parallel triad orchestration | V4 Pro for orchestrator, Flash for agents |

Switch models mid-conversation with `/model <name>`.

### 4. Choose Phase Based on Data Available

- **No data / fresh targets:** Phase 0 (Target Generation) + Phase 1 (Quick Filter)
- **WP targets identified:** Phase 2 (WP Deep Check)
- **High-value targets (score >= 6):** Phase 3 (Deep Invade)
- **Multiple findings on same target:** Build attack chain (cross-attack-chains skill)
- **All done:** Write report to `US_COMPANIES_VULNS.md`

### 5. Every Session Must Produce Output

Always save to `/root/output/recon_us/`. Every finding, every scan, every report.

---

## Complete Skill Catalog (207 skills)

### agentiko Custom Skills (33)

| Path | Skills | Description |
|------|--------|-------------|
| `recon/wp-mass-recon` | Batch WordPress mass scanning | Users, CORS, XMLRPC, source leaks, open reg |
| `recon/deep-invade` | Deep pentest methodology | SSRF, error logs, plugins, JS, ports, staging, APIs |
| `recon/cors-credential-wordpress` | CORS exploit on WP REST API | Origin reflection, credential theft |
| `recon/xmlrpc-exploitation` | XMLRPC attack vectors | Multicall, pingback SSRF, upload, brute force |
| `recon/source-leak-hunt` | Sensitive file detection | .env, .git, backups, wp-config |
| `recon/error-log-mining` | Error log credential mining | PHP errors with creds |
| `recon/js-secrets-extraction` | JS bundle secret extraction | API keys, JWTs, internal URLs |
| `recon/phpinfo-to-rce` | PHPInfo -> RCE chain | Exec check, upload vector |
| `recon/subdomain-enumeration` | Subdomain discovery | crt.sh, subfinder |
| `recon/port-mass-scan` | Masscan + port discovery | Fast port scanning |
| `recon/port-service-discovery` | Service fingerprinting | MySQL, Redis, FTP, SSH |
| `recon/wordpress-plugin-hunt` | Plugin CVE detection | readme.txt, CVE matching |
| `recon/staging-subdomain-hunt` | Staging via crt.sh | Staging takeover, install.php |
| `recon/cache-attack` | CDN cache poison | Cache deception, poisoning |
| `recon/firebase-supabase-attack` | Firebase/Supabase exploit | Anon key, Firestore, Storage |
| `recon/exchange-owa-attack` | Exchange/OWA NTLM leak | AD disclosure, spray |
| `recon/zimbra-attack` | Zimbra SOAP attacks | User enum, CVEs, SSRF |
| `recon/api-noauth-hunt` | No-auth API exploitation | Data theft, CRUD |
| `recon/gitlab-public-recon` | GitLab secrets mining | CI tokens, repos |
| `recon/jwt-attack` | JWT analysis | Decode, forge, brute |
| `recon/iot-camera-recon` | IP camera recon | RTSP, ONVIF, Axis |
| `meta/recon-playbook` | **4-phase pipeline** | Orchestration master skill |
| `meta/sector-recon-methodology` | Sector selection | Target compilation, baseline stats |
| `meta/attack-patterns-reference` | Attack pattern catalog | 25 patterns + 18 WP patterns |
| `meta/pentest-playbook` | 7-phase methodology | Full pentest pipeline |
| `chains/cross-attack-chains` | **Vuln chaining** | 5 chains (A-E), Critical impact |
| `chains/wordpress-full-compromise` | **WP kill chains** | 7 chains for full WP compromise |
| `auth/saml-sso-attack` | SAML attacks | XSW, signature strip, metadata |
| `infra/docker-privesc` | Container escape | 5 escape techniques |
| `apple/apple-notes` | iCloud Notes read | Read/search notes |
| `apple/apple-reminders` | iCloud Reminders | List/manage reminders |
| `apple/findmy` | FindMy location | Track devices, people |
| `apple/imessage` | iMessage send/read | Message via macOS |
| `sector/recon-carpet-cleaning` | Carpet cleaning sector | Sector-specific WP recon |
| `sector/recon-solar-installers` | Solar installers sector | Sector-specific WP recon |

### redteam/ — Per-Class Vulnerability Hunting (104 skills)

**hunt-* skills (51):** One skill per vulnerability class. Each is built from public bug bounty reports (10-174 per class) and includes detection methodology, exploitation techniques, bypass tables, and real paid examples.

| Skill | Reports Referenced | Primary Coverage |
|-------|-------------------|-----------------|
| `hunt-wordpress` | 58 companies | REST API users, XMLRPC, plugin CVEs, CORS |
| `hunt-cors` | Research | Origin reflection, null, subdomain-regex |
| `hunt-xss` | 174 reports | Reflected, stored, DOM, blind XSS |
| `hunt-sqli` | 12 reports | SQLi + NoSQLi + ORM injection |
| `hunt-ssrf` | 15 reports | IMDS, gopher, DNS rebinding |
| `hunt-rce` | 67 reports | Unauthenticated RCE, deserialization |
| `hunt-ato` | 9 paths | Password reset, MFA bypass, OAuth, session |
| `hunt-idor` | 26 reports | BOLA, mass assignment |
| `hunt-auth-bypass` | 6 reports | SAML, JWT, SSO |
| `hunt-firebase` | Field | Anon key, Firestore, Storage |
| `hunt-supabase` | Field | RLS bypass, RPC abuse |
| `hunt-graphql` | 12 reports | Introspection, IDOR, batching |
| `hunt-grpc` | Research | Reflection, plaintext |
| `hunt-lfi` | Research | Path traversal, PHP wrappers, RFI |
| `hunt-ssti` | Research | Jinja2, Twig, Freemarker, ERB |
| `hunt-oauth` | 19 reports | CSRF, redirect_uri, token theft |
| `hunt-csrf` | 15 reports | SameSite bypass, GraphQL GET |
| `hunt-http-smuggling` | Research | CL.TE, TE.CL, H2.CL |
| `hunt-file-upload` | Research | RCE, XSS, XXE, bypass tables |
| `hunt-race-condition` | 12 reports | Single-packet, TOCTOU |
| `hunt-mfa-bypass` | 7 patterns | OTP brute, step skip, race |
| `hunt-host-header` | Research | Password reset, cache poison |
| `hunt-cache-poison` | 10 reports | WCD, CDN bypass |
| `hunt-llm-ai` | OWASP | Prompt injection, ASCII smuggling |
| `hunt-business-logic` | 12 reports | Coupon race, negative quantity |
| `hunt-brute-force` | Research | Rate limit, OTP brute |
| `hunt-dom` | Research | DOM clobbering, postMessage |
| `hunt-saml` | Research | XSW, signature strip |
| `hunt-session` | Research | Fixation, invalidation, JWT |
| `hunt-subdomain` | Research | Takeover, CNAME checks |
| `hunt-websocket` | Research | CSWSH, Origin validation |
| `hunt-k8s` | Research | API exec, kubelet, etcd |
| `hunt-springboot` | Research | Actuator, heapdump, SpEL |
| `hunt-nextjs` | Research | Server Actions, ISR, RSC |
| `hunt-laravel` | Research | Debug mode, Telescope |
| `hunt-nodejs` | Research | Prototype pollution, SSTI |
| `hunt-nosqli` | Research | MongoDB $where, $regex |
| `hunt-ldap` | Research | Auth bypass, attribute exfil |
| `hunt-xxe` | 10 reports | OOB, SVG, DOCX |
| `hunt-deserialization` | Research | Java, PHP, Python, .NET |
| `hunt-cicd` | Research | GitHub Actions, Jenkins |
| `hunt-cloud-misconfig` | Research | S3, GCS, Azure, IMDS |
| `hunt-source-leak` | Research | .js.map, Swagger, configs |
| `hunt-ntlm-info` | Research | Anonymous NTLM leak |
| `hunt-sharepoint` | Research | SOAP, ToolShell, NTLM |
| `hunt-aspnet` | Research | ViewState, ELMAH, trace |
| `hunt-tls-network` | Research | HSTS, SPF/DKIM/DMARC |
| `hunt-api-misconfig` | Research | Mass assignment, JWT |
| `hunt-open-redirect` | Research | URL param, JS redirect |
| `hunt-misc` | 225 reports | Catch-all |
| `hunt-dispatch` | Internal | Skill-set loader for /hunt |

**recon-* sector skills (27):** Sector-specific recon for automotive-dealers, bakeries, breweries, cafes, carwashes, churches, daycare, dentists, fire-restoration, gyms, hvac, landscaping, laundromats, mattress-stores, moving-companies, pet-grooming, plumbing, pools, property-management, roofing, salons, smb-services, tree-services, sector-expansion.

**Methodology skills (6):** bb-methodology, bb-local-toolkit, bug-bounty, web2-recon, osint-methodology, offensive-osint.

**Operations skills (9):** parallel-recon-triad, ops-proxyns, evidence-hygiene, triage-validation, report-writing, redteam-report-template, bugcrowd-reporting, security-arsenal, redteam-mindset.

**Infrastructure skills (13):** cloud-iam-deep, enterprise-vpn-attack, m365-entra-attack, okta-attack, vmware-vcenter-attack, supply-chain-attack-recon, meme-coin-audit, mid-engagement-ir-detection, cors-chain-automation, wp-plugin-automation, wp-plugin-cve-hunt, wordpress-cors-xmlrpc-rce-chain, apk-redteam-pipeline, web3-audit.

### Agentiko Environment (2 skills)

- **agentiko-hermes**: Hermes Agent features guide — delegation, memory, YOLO mode, slash commands, Telegram setup.
- **agentiko-worker**: Worker container environment — tools, paths, usage patterns, known pitfalls.

### Built-in Skills (~70+)

See Hermes Agent docs for the full list. Key categories:
- **Creative (17):** architecture-diagram, ascii-art, claude-design, comfyui, excalidraw, p5js, sketch
- **GitHub (6):** github-auth, github-pr-workflow, github-code-review, github-issues
- **Software Dev (10):** plan, spike, systematic-debugging, test-driven-development
- **MLOps (6):** huggingface-hub, llama-cpp, vllm, evaluating-llms-harness
- **Productivity (8):** airtable, google-workspace, notion, powerpoint

---

## Skill Authoring Standards (HARDLINE)

Every skill MUST meet these standards. Reviewers reject PRs that violate them.

### 1. Frontmatter

```yaml
---
name: skill-name
description: One sentence, <=60 chars, ends with period. No marketing words.
version: 1.0.0
author: agentiko
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [recon, wordpress, cve]   # lowercase, no spaces, no hyphens in single tag
    category: recon                  # recon, meta, chains, auth, infra, redteam
    related_skills:                  # bidirectional cross-references
      - other-skill-name
---
```

**Rules:**
- `description` <= 60 characters, one sentence, ends with period.
- No marketing words ("powerful", "comprehensive", "seamless", "advanced").
- Don't repeat the skill name in the description.
- `tags` are lowercase, hyphenated, no spaces within a tag.
- `category` must match the parent directory structure.
- `related_skills` must be bidirectional — if A references B, B must reference A.

### 2. Modern Section Order

Every SKILL.md must follow this exact order:

```
# Skill Title
2-3 sentence intro stating what it does and doesn't do.
Avoid marketing prose — state the capability, not the implementation.

## When to Use
Bullet list of trigger conditions.

## Prerequisites
What the agent needs before executing this skill.

## How to Run
Quick copy-paste command(s) to execute the skill immediately.

## Quick Reference
Tables and quick lookups — the "cheat sheet" section.

## Procedure
Numbered steps with full bash commands. This is the main body.
Every command must be copy-paste ready.

## Pitfalls
Common mistakes, false positives, edge cases.

## Verification
How to confirm success. Every finding type must have a verification step.
```

**Line count:** ~200 lines for complex skills, ~100 lines for simple ones.

### 3. Tools Referenced in Prose

Reference native Hermes tools in backticks:
- `` `terminal` `` — command execution
- `` `web_extract` `` — web content fetching
- `` `read_file` `` — reading files
- `` `search_files` `` — grep/find operations

Do NOT name shell utilities the agent already has wrapped:
- `grep` -> `` `search_files` ``
- `cat`/`head`/`tail` -> `` `read_file` ``
- `sed`/`awk` -> `` `patch` ``

### 4. Scripts, References, Templates

- `scripts/` — executable Python/bash scripts referenced by the skill
- `references/` — static reference documents (wordlists, payload catalogs)
- `templates/` — template files (report templates, PoC HTML, payload templates)

Scripts must be referenced by relative path from the skill directory:
```markdown
Run with `scripts/scanner.py targets.txt 20`.
```

### 5. Real-World Examples

Every skill SHOULD include a `## Real Production Results` section with:
- At least one confirmed target name
- What was found
- Severity level
- Real commands that worked (redact secrets)

### 6. Cross-References

- `related_skills` in frontmatter must be bidirectional
- Within prose, cross-reference other skills in backticks: `` `other-skill` ``
- Don't duplicate content that belongs in another skill — cross-reference instead
- Use `skill_view()` to load the full content of a referenced skill

---

## How to Write a New Skill

1. Choose the right category directory: `recon/`, `chains/`, `meta/`, `redteam/`, `auth/`, `infra/`, `apple/`

2. Create the directory and SKILL.md:
   ```bash
   mkdir -p skills/<category>/<skill-name>/scripts
   ```

3. Write SKILL.md following the HARDLINE standards above.

4. Add `related_skills` frontmatter referencing at least one existing skill.

5. Add a reciprocal cross-reference in the referenced skill (update its SKILL.md).

6. If the skill uses scripts, place them in `scripts/` and reference by relative path.

7. Verify: description <= 60 chars, no marketing words, bidirectional cross-references, all sections present.

### Naming Conventions

- **recon skills**: `noun-verb` format (e.g., `source-leak-hunt`, `js-secrets-extraction`)
- **hunt skills**: `hunt-vulnclass` format (e.g., `hunt-xss`, `hunt-sqli`)
- **meta skills**: `methodology-type` format (e.g., `recon-playbook`, `sector-recon-methodology`)
- **chain skills**: `purpose-format` format (e.g., `cross-attack-chains`, `wordpress-full-compromise`)
- **sector recon**: `recon-sectorname` format (e.g., `recon-plumbing`, `recon-dentists`)
- **infrastructure**: `platform-attack` format (e.g., `docker-privesc`, `enterprise-vpn-attack`)

### Category Conventions

| Category | When to Use |
|----------|-------------|
| `recon/` | Discovery, fingerprinting, batch scanning, service detection |
| `chains/` | Multi-step attack chains that combine multiple vulns |
| `meta/` | Orchestration playbooks, methodology references, sector selection |
| `redteam/` | Per-class vulnerability hunting, operations, infrastructure attacks |
| `auth/` | Authentication-specific attacks (SAML, SSO, OAuth) |
| `infra/` | Infrastructure-level attacks (Docker, K8s, VPN) |
| `apple/` | Apple ecosystem interaction (iMessage, Notes, FindMy) |

---
---

## Output File Conventions

### Directory Structure

```
/root/output/recon_us/
+-- US_COMPANIES_VULNS.md         Consolidated master report
+-- deep/                         Agent Pro findings
|   +-- SUMMARY_DEEP_PENTEST.md
|   +-- target.com_findings.md
+-- new_targets/                  Agent Flash discoveries
|   +-- all_targets.txt           |domain|sector|
|   +-- YYYYMMDD_WAVEN_REPORT.md
+-- targets/                      Per-target deep dives
|   +-- target.com.md
+-- techniques/                   Reusable technique docs
|   +-- cors_credential_scan.md
+-- skills/                       Generated skill files
+-- scripts/                      Python .py helper scripts
```

### Per-Target Deep-Dive Format

Each `targets/target.com.md` must contain:

```markdown
# TARGET.COM — Security Assessment

## Summary
| Field | Value |
|-------|-------|
| Sector | [sector] |
| Hosting | [GoDaddy/Cloudflare/Bluehost] |
| Overall Score | [N] |
| Status | [Vulnerable/Hardened/Unknown] |

## Findings
| Finding | Severity | Endpoint | PoC |
|---------|----------|----------|-----|
| CORS credential reflection | High | /wp-json/wp/v2/users | curl command |
| XMLRPC open | Medium | /xmlrpc.php | curl command |

## Attack Chain
Step 1: ... Step 2: ... Full chain: [chain name]

## Security Contact
[if found]
```

### Cross-Wave Delta Report

When running repeated recon on the same target set, produce a comparison:

```markdown
| Check | Prior Wave | Current Wave | Delta |
|-------|-----------|-------------|-------|
| XMLRPC status | 200 (79 methods) | 405 | REGRESSION |
| CORS /wp/v2/users | Not documented | ACAO: evil.com + ACAC: true | NEW |
| WP Users | 3 confirmed | 3 confirmed | PERSISTENT |
| Port 3306 (MySQL) | Not found | OPEN | NEW |
```

Categories: **NEW** / **REGRESSION** / **PERSISTENT** / **CHANGE**

---

## Common Pitfalls

### Worker Environment

- **AGENTS.md/SOUL.md not found on worker**: CORRECT. They're at `/opt/data/` on the Hermes host (172.20.0.3). The worker (172.20.0.2) is a pure execution node.
- **`hermes` CLI not available on worker**: Use slash commands in Telegram (`/model`, `/reset`, `/config`).
- **nmap broken on Alpine**: `nmap -sV` fails with "nse_main.lua". Use naabu instead, or nmap without `-sV`.
- **BusyBox grep — no `-P`**: Use `grep -E` or pipe through `python3 -c "import sys, re; ..."`.
- **`write_file` blocks .sh scripts**: Use `execute_code` with Python `open() + os.chmod()`.
- **`&` backgrounding blocked in terminal**: Write a script and run with `terminal(background=True)`.

### Skill Authoring

- **Large heredocs (200+ lines) fail**: Use `execute_code` with Python to write large files.
- **Bidirectional cross-references**: If A references B, B MUST reference A.
- **Description > 60 chars**: Gets rejected. Keep it tight.

### Recon Operations

- **Rate limiting**: 1 req per 3s minimum. Never parallel to same domain.
- **403 = stop**: WAF triggered. Don't escalate.
- **Source leak verification**: Leak must contain actual sensitive content (DB_, APP_, KEY patterns), not just an accessible path with empty content.
- **CORS false positive**: `Access-Control-Allow-Origin: *` alone is NOT a finding. Must include `Access-Control-Allow-Credentials: true` with reflected origin.
- **Nuclei false positives**: Always verify nuclei findings manually — templates fire on headers alone sometimes.

---

## Contributing a New Skill

1. Create the skill directory under the appropriate category:
   ```bash
   mkdir -p skills/<category>/<skill-name>/scripts
   ```

2. Write `SKILL.md` following the HARDLINE standards (Section 2 above).

3. Add at least one cross-reference in `related_skills` to an existing skill.

4. Add a reciprocal cross-reference in the referenced skill.

5. If the skill uses scripts, place them in `scripts/` and reference by relative path.

6. Verify: description <= 60 chars, no marketing words, bidirectional cross-references, all sections present.

7. Use `skill_manage(action='create', name=..., content=..., category=...)` to add it to the system.

---

## Toolkit Summary (Worker)

| Tool | Purpose | Command |
|------|---------|---------|
| **nmap** 7.95 | Port scanning, service detection | `nmap -sV -sC target.com` |
| **masscan** 1.3.2 | Ultra-fast mass scanning | `masscan --rate=1000 target/24 -p80,443` |
| **subfinder** 2.14 | Passive subdomain discovery | `subfinder -d target.com` |
| **httpx** 1.9 | HTTP probing + tech detection | `httpx -l targets.txt -tech-detect` |
| **nuclei** 3.9 | Template-based vuln scanning | `nuclei -l targets.txt -t ~/nuclei-templates/` |
| **ffuf** 2.1 | Web fuzzing | `ffuf -u https://target.com/FUZZ -w wordlist.txt` |
| **katana** 1.6 | JS/URL crawling | `katana -u https://target.com -d 3` |
| **naabu** 2.6 | Fast port scanning | `naabu -host target.com -top-ports 100` |
| **amass** 5.1 | Deep subdomain enum | `amass enum -d target.com` |
| **curl** 8.14 | HTTP requests | `curl -sk https://target.com/path` |
| **python3** 3.12 | Scripting, regex, data processing | `python3 -c "..."` |

**Python libraries installed:** requests, httpx, aiohttp, beautifulsoup4, lxml, pyyaml, dnspython, rich, impacket.
