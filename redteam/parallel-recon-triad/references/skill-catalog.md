# agentiko — Complete Skill Catalog (207 skills)

Comprehensive catalog of all skills in the agentiko ecosystem. Generated from field analysis of the complete Hermes skill index at `~/.hermes/skills/`.

---

## 1. agentiko Custom Skills (33)

### recon/ (21) — Discovery, fingerprinting, batch scanning

| Skill | Description |
|-------|-------------|
| `wp-mass-recon` | Batch WordPress scanning: users, CORS, XMLRPC, source leaks, open reg |
| `deep-invade` | Deep pentest: SSRF, error logs, plugins, JS, ports, staging, APIs |
| `cors-credential-wordpress` | CORS credential reflection on WP REST API |
| `xmlrpc-exploitation` | XMLRPC: multicall, pingback SSRF, upload, brute force |
| `source-leak-hunt` | Sensitive file detection: .env, .git, backups, wp-config |
| `error-log-mining` | Error log credential extraction |
| `js-secrets-extraction` | JS bundle secret extraction: API keys, JWTs, internal URLs |
| `phpinfo-to-rce` | PHPInfo exploitation chain |
| `subdomain-enumeration` | Subdomain discovery: crt.sh, subfinder |
| `port-mass-scan` | Masscan + port discovery |
| `port-service-discovery` | Service fingerprinting: MySQL, Redis, FTP, SSH |
| `wordpress-plugin-hunt` | Plugin CVE detection via readme.txt |
| `staging-subdomain-hunt` | Staging takeover via crt.sh |
| `cache-attack` | CDN cache poisoning and deception |
| `firebase-supabase-attack` | Firebase/Supabase: anon key, Firestore, Storage |
| `exchange-owa-attack` | Exchange/OWA: NTLM leak, credential spray |
| `zimbra-attack` | Zimbra: SOAP enum, CVEs, SSRF |
| `api-noauth-hunt` | No-auth API: data theft, CRUD |
| `gitlab-public-recon` | GitLab: secrets, CI tokens |
| `jwt-attack` | JWT: decode, forge, brute force |
| `iot-camera-recon` | IP camera: RTSP, ONVIF, Axis |

### meta/ (4) — Orchestration, playbooks, methodology

| Skill | Description |
|-------|-------------|
| `recon-playbook` | **4-phase pipeline**: Phase 0-3, scoring, rate limiting, hosting clustering |
| `sector-recon-methodology` | Sector selection: Tier 1/2/3, target compilation, baseline stats |
| `attack-patterns-reference` | 25 attack patterns + 18 WP-specific patterns catalog |
| `pentest-playbook` | 7-phase master pentest pipeline |

### chains/ (2) — Attack chain methodology

| Skill | Description |
|-------|-------------|
| `cross-attack-chains` | **5 confirmed chains (A-E)**: CORS→RCE, PHPInfo→RCE, CORS+Plugin→RCE, CORS→ATO, MySQL→Data Breach |
| `wordpress-full-compromise` | **7 kill chains**: full WP compromise from any entry point |

### auth/ (1) — Authentication attacks

| Skill | Description |
|-------|-------------|
| `saml-sso-attack` | SAML: XSW, signature strip, metadata extraction |

### infra/ (1) — Infrastructure attacks

| Skill | Description |
|-------|-------------|
| `docker-privesc` | Container escape: 5 techniques |

### apple/ (4) — macOS/iCloud interaction

| Skill | Description |
|-------|-------------|
| `apple-notes` | Read, search, manage iCloud Notes |
| `apple-reminders` | List, manage iCloud Reminders |
| `findmy` | Track devices and people via FindMy |
| `imessage` | Send and read iMessages |

### sector/ (2) — Sector-specific recon templates

| Skill | Description |
|-------|-------------|
| `recon-carpet-cleaning` | Carpet cleaning company WP recon patterns |
| `recon-solar-installers` | Solar installer company WP recon patterns |

### Environment (2)

| Skill | Description |
|-------|-------------|
| `agentiko-hermes` | Hermes Agent guide: cron, delegation, YOLO, slash commands |
| `agentiko-worker` | Worker environment: tools, paths, pitfalls |

---

## 2. redteam/ (104 skills)

### hunt-* (51) — Per-vuln-class hunting, each built from 10-174 public bug bounty reports

| Skill | Report Count | Primary Coverage |
|-------|-------------|------------------|
| `hunt-wordpress` | 58 companies | REST users, XMLRPC, plugin CVEs, CORS |
| `hunt-cors` | Research | Origin reflection, null, subdomain-regex |
| `hunt-xss` | 174 reports | Reflected, stored, DOM, blind |
| `hunt-sqli` | 12 reports | SQLi + NoSQLi + ORM injection |
| `hunt-ssrf` | 15 reports | IMDS, gopher, DNS rebinding |
| `hunt-rce` | 67 reports | Unauthenticated RCE, deserialization |
| `hunt-ato` | 9 paths | Reset, MFA bypass, OAuth, session, email change |
| `hunt-idor` | 26 reports | BOLA, mass assignment |
| `hunt-auth-bypass` | 6 reports | SAML XSW, JWT confusion, SSO |
| `hunt-firebase` | Field | Anon key, Firestore enum, Storage buckets |
| `hunt-supabase` | Field | RLS bypass, RPC abuse, multi-tenant |
| `hunt-graphql` | 12 reports | Introspection, IDOR via node(), batching |
| `hunt-grpc` | Research | Server reflection, plaintext, proto leak |
| `hunt-lfi` | Research | Path traversal, PHP wrappers, RFI |
| `hunt-ssti` | Research | Jinja2, Twig, Freemarker, ERB |
| `hunt-oauth` | 19 reports | CSRF, redirect_uri, token theft |
| `hunt-csrf` | 15 reports | SameSite bypass, GraphQL GET, OAuth state |
| `hunt-http-smuggling` | Research | CL.TE, TE.CL, H2.CL |
| `hunt-file-upload` | Research | RCE via webshell, SVG XSS, DOCX XXE, 10 bypasses |
| `hunt-race-condition` | 12 reports | Single-packet, TOCTOU, MFA race |
| `hunt-mfa-bypass` | 7 patterns | OTP brute, step skip, recovery code |
| `hunt-host-header` | Research | Password reset poisoning, cache poison |
| `hunt-cache-poison` | 10 reports | WCD, XFH, session token |
| `hunt-llm-ai` | OWASP | Prompt injection, ASCII smuggling, tool exfil |
| `hunt-business-logic` | 12 reports | Coupon race, negative quantity, price swap |
| `hunt-brute-force` | Research | Login, OTP, rate-limit bypass |
| `hunt-dom` | Research | DOM clobbering, postMessage, CSS exfil |
| `hunt-saml` | Research | XSW, signature strip, replay |
| `hunt-session` | Research | Fixation, invalidation, JWT |
| `hunt-subdomain` | Research | Takeover, CNAME fingerprints |
| `hunt-websocket` | Research | CSWSH, Origin, per-message auth |
| `hunt-k8s` | Research | API exec, kubelet, etcd, RBAC |
| `hunt-springboot` | Research | Actuator, heapdump, SpEL, Jolokia |
| `hunt-nextjs` | Research | Server Actions, ISR, RSC, Middleware |
| `hunt-laravel` | Research | Debug mode, Telescope, Signed URLs |
| `hunt-nodejs` | Research | Prototype pollution, SSTI, path traversal |
| `hunt-nosqli` | Research | MongoDB $where, $regex, auth bypass |
| `hunt-ldap` | Research | Auth bypass, char-by-char exfil |
| `hunt-xxe` | 10 reports | OOB, SVG, DOCX, blind |
| `hunt-deserialization` | Research | Java, PHP, Python pickle, .NET |
| `hunt-cicd` | Research | GitHub Actions, Jenkins, GitLab CI |
| `hunt-cloud-misconfig` | Research | S3, GCS, Azure, IMDS |
| `hunt-source-leak` | Research | JS maps, Swagger, .env |
| `hunt-ntlm-info` | Research | Anonymous NTLM Type-2 capture |
| `hunt-sharepoint` | Research | SOAP, ToolShell, NTLM, Forms |
| `hunt-aspnet` | Research | ViewState, ELMAH, machineKey |
| `hunt-tls-network` | Research | HSTS, SPF/DKIM, zone transfer |
| `hunt-api-misconfig` | Research | Mass assignment, JWT, prototype pollution |
| `hunt-open-redirect` | Research | URL param, JS redirect, meta refresh |
| `hunt-misc` | 225 reports | Catch-all for non-classified |
| `hunt-dispatch` | Internal | Skill-set loader for /hunt orchestrator |

### recon-* (27) — Sector-specific WordPress recon

| Skill | Sector | Expected WP Rate | Top Finding |
|-------|--------|-----------------|-------------|
| `recon-automotive-dealers` | Car dealerships | 0% (enterprise) | Skip — enterprise platforms |
| `recon-bakeries` | Bakeries | ~18% CORS | Wildcard CORS, 28+ leaked files observed |
| `recon-breweries` | Breweries | ~15% | Age gate patterns, Untappd API |
| `recon-cafes` | Cafes | ~20% | Toast POS, Square Online |
| `recon-carwashes` | Car washes | ~20% source leaks | .env, Dockerfile, actuator |
| `recon-churches` | Churches | ~30% | Highest unpatched WP rate |
| `recon-daycare` | Daycare | ~20% | Child PII, contact forms |
| `recon-dentists` | Dentists | ~35% | Patient portals, insurance forms |
| `recon-fire-restoration` | Fire restoration | ~10% | Servpro franchise pattern |
| `recon-gyms` | Gyms | ~40% | Mindbody/ClubReady integration |
| `recon-hvac` | HVAC | ~35% | Emergency forms, booking |
| `recon-landscaping` | Landscaping | ~50% | CORS + WP users (Tier 1) |
| `recon-laundromats` | Laundromats | ~20% | Cents/LaundryLocker |
| `recon-mattress-stores` | Mattress | ~25% | Financing APIs, Affirm/Klarna |
| `recon-moving-companies` | Moving | ~6% | Fewer WP, more SaaS |
| `recon-pet-grooming` | Pet grooming | ~20% | Gingr/PetExec portals |
| `recon-plumbing` | Plumbing | ~35% | Emergency booking (Tier 1) |
| `recon-pools` | Pool services | ~45% | CORS + WP users (Tier 1) |
| `recon-property-management` | Property | ~30% | Tenant portals, PII |
| `recon-roofing` | Roofing | ~45% | CORS + source leaks (Tier 1) |
| `recon-salons` | Salons | ~30% | Booksy/Vagaro integration |
| `recon-smb-services` | General SMB | ~30% | Contact form PII leakage |
| `recon-tree-services` | Tree service | ~30% | Free estimate forms |
| `recon-sector-expansion` | Any sector | Variable | Multi-sector batch expansion |

### Methodology (6) — Hunting workflow and OSINT

| Skill | Description |
|-------|-------------|
| `bb-methodology` | 5-phase hunting workflow + critical thinking framework |
| `bb-local-toolkit` | Complete bug bounty toolkit: recon → hunt → report |
| `bug-bounty` | Master orchestrator: 30+ vuln classes, AI testing |
| `web2-recon` | Full asset discovery pipeline: subfinder → httpx → katana → ffuf |
| `osint-methodology` | 5-stage OSINT: seed → asset → enrich → expose → report |
| `offensive-osint` | Operational arsenal: probes, wordlists, regexes, dorks |

### Operations (9) — Reporting, OPSEC, finding validation

| Skill | Description |
|-------|-------------|
| `parallel-recon-triad` | **Orchestrator**: 3 parallel agents every 20min, self-improving |
| `ops-proxyns` | Kernel-level proxy via network namespaces |
| `evidence-hygiene` | PoC redaction, HAR sanitization, screenshot discipline |
| `triage-validation` | 7-question gate before writing any report |
| `report-writing` | Bug bounty report templates, CVSS 3.1, tone |
| `redteam-report-template` | Client-facing red-team deliverable format |
| `bugcrowd-reporting` | Bugcrowd-specific: VRT fallback, severity request, OOS rebuttal |
| `security-arsenal` | Payloads, bypass tables, gf patterns, always-rejected list |
| `redteam-mindset` | Operator discipline: mindset corrections for red vs WAPT |

### Infrastructure (13) — Platform-specific attacks

| Skill | Description |
|-------|-------------|
| `cloud-iam-deep` | AWS/Azure/GCP: IAM enum, escalation, Cognito |
| `enterprise-vpn-attack` | Cisco/Fortinet/Citrix/Pulse/PaloAlto: CVE matrix, fingerprint |
| `m365-entra-attack` | M365/Entra ID: ROPC, spray, CA bypass |
| `okta-attack` | Okta: tenant discovery, user enum, MFA fatigue |
| `vmware-vcenter-attack` | vCenter: CVE chain, SSO, LDAP enum |
| `supply-chain-attack-recon` | Package squatting, dependency confusion, SBOM |
| `meme-coin-audit` | Solana SPL token audit, rug pull detection |
| `mid-engagement-ir-detection` | Client SOC detection during active engagements |
| `cors-chain-automation` | Multi-endpoint CORS batch probe |
| `wp-plugin-automation` | Batch WP plugin CVE testing |
| `wp-plugin-cve-hunt` | Systematic plugin CVE discovery and matching |
| `wordpress-cors-xmlrpc-rce-chain` | Proven WP CORS→XMLRPC→RCE chain automation |
| `apk-redteam-pipeline` | Android APK: decompile, secret grep, intent probes |
| `web3-audit` | Smart contract: 10 DeFi bug classes, Foundry PoC |

---

## 3. Built-in Skills (~70)

### Creative (17)
architecture-diagram, ascii-art, ascii-video, baoyu-infographic, claude-design, comfyui, design-md, excalidraw, humanizer, manim-video, p5js, popular-web-designs, pretext, sketch, songwriting-and-ai-music, touchdesigner-mcp

### GitHub (6)
github-auth, github-code-review, github-issues, github-pr-workflow, github-repo-management, codebase-inspection

### Software Development (10)
plan, spike, systematic-debugging, test-driven-development, python-debugpy, node-inspect-debugger, requesting-code-review, simplify-code, hermes-agent-skill-authoring, skill-library-maintenance

### MLOps (6)
huggingface-hub, llama-cpp, serving-llms-vllm, evaluating-llms-harness, weights-and-biases, segment-anything-model, audiocraft-audio-generation

### Productivity (8)
airtable, google-workspace, notion, nano-pdf, ocr-and-documents, powerpoint, maps, teams-meeting-pipeline

### Media (4)
youtube-content, gif-search, heartmula, songsee

### Research (4)
arxiv, blogwatcher, llm-wiki, polymarket

### Autonomous AI (4)
claude-code, codex, opencode, hermes-agent

### Other
email/himalaya, data-science/jupyter-live-kernel, note-taking/obsidian, smart-home/openhue, social-media/xurl, computer-use, dogfood, yuanbao

---

## Skill Index by Category Path

When loading skills via `skill_view()` or referencing in cron jobs, use the skill's registered name (not the filesystem path). The Hermes skill index resolves these automatically. To browse: use `skills_list()` with optional category filter.

For skills in the redteam/ directory, the name alone works (e.g., `hunt-xss`, `web2-recon`). For agentiko skills, use the name as listed in the agentiko custom section above.
