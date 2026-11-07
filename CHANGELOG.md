# Changelog

## 2026-11-07 — Catalog quality sweep

- Repaired broken snippets catalog-wide (unclosed heredocs and quotes,
  unfinished payloads, unquoted placeholders, `grep -E` on PCRE patterns).
- Replaced cosmetic self-test Verification blocks with evidence checklists.
- Normalized section order (Pitfalls before Verification), removed duplicated
  trigger sections, and sharpened generic When-to-Use text.
- Defined `TARGET`/`OUTPUT_DIR` in How-to-Run blocks, expanded portable
  platform declarations, and consolidated duplicate skills into owners.

## 2026-07-29 — Methodology and portability review

- Reframed the catalog around external web, API, authentication, and focused
  vulnerability validation.
- Rebuilt the central recon, WordPress, API no-auth, attack-pattern, and
  WordPress chain guidance around bounded tests and negative controls.
- Removed engagement-derived result sections, campaign statistics, orphaned
  field notes, private output paths, and runtime-specific workarounds.
- Moved `llm-prompt-injection` to the vulnerability-class catalog.
- Added repository validation for campaign artifacts and private output paths.
- Added a lightweight GitHub Actions validation workflow.

## 2026-07-25 — v1 Release

### Initial release with 144 skills
- **recon/** (41): Subdomain enumeration, CORS credential reflection, XMLRPC exploitation, WordPress plugin hunting, JS secrets extraction, API no-auth hunting, email security, source leak hunting, port scanning, ASN infrastructure mapping, web enumeration, GitHub secret hunting, CMS detection, browser evasion, origin IP discovery, subdomain takeover, vhost enumeration, visual recon, and more.
- **redteam/** (93): Per-class vulnerability hunting (XSS, SQLi, SSRF, RCE, IDOR, ATO, CSRF, LFI, SSTI, XXE, JWT, SAML, OAuth, GraphQL, WebSocket, cache poison, deserialization, race condition, host header, HTTP smuggling, mass assignment, prototype pollution, broken function-level auth, information disclosure, CORS, Firebase, Supabase, MCP security, LLM attacks, cloud IAM, Docker, K8s, and more). Plus methodology and reporting skills.
- **meta/** (6): Recon playbook, sector methodology, attack patterns reference, cross-wave delta analysis, Google dorks catalog, pentest playbook.
- **chains/** (2): Cross-attack chaining, WordPress full compromise.
- **auth/** (1): SAML SSO attacks.
- **infra/** (1): Docker privilege escalation.

### Quality baseline
- Added `STYLE.md` as the baseline for new and substantially revised skills.
- Standardized core YAML frontmatter and unique skill names.
- Added structural validation for metadata, links, related-skill names, and
  runtime-specific coupling.
- Kept incomplete legacy migrations visible as validator warnings.

### Research integration
- AI Agent Framework Audit (correctover, 2026): 56+ vulns, CVE-2026-2287 (CrewAI RCE CVSS 9.8)
- HuntBook Methodology (su6osec, 2026): XSS, SQLi, SSRF techniques
- PortSwigger Research (2025): SAML bypass, WebSocket, HTTP anomaly detection
- Tool benchmarks: dnsx (2x), httpx (5.6x), naabu (8x), ffuf vs curl rate-limit testing

### License
MIT — see LICENSE file.
