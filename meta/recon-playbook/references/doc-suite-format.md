# Target Documentation Suite — Standard Format

When generating the 3-doc suite for a target after Deep Invade (Phase 3 → Phase 3.5), follow this structure.

## Language

- Hiago context: PT-BR (Brazilian Portuguese)
- All section headings, table labels, descriptions in PT-BR
- PoC commands and code blocks in English (kept as-is)

## File 1: MASTER_REPORT.md

**Target: ~1,200-1,600 lines** | **Content-driven, not padding**

### Required Sections (in order)

1. **Sumário Executivo** — 1 paragraph overview + severity table (CRÍTICO/ALTO/MÉDIO/BAIXO) + top risks bullet list + caminho mais curto para RCE
2. **Stack Tecnológico** — CMS, CDN, server, TLS version, all identified plugins with versions
3. **Portas e Serviços** — open ports, services, banners
4. **XMLRPC — Análise Completa** — endpoint, Content-Type, table of all methods (name, description, auth required, risk), PoC curl for each key method (listMethods, multicall, wp.getUsersBlogs, wp.uploadFile, pingback.ping)
5. **system.multicall — BF Massivo** — impact analysis, batch size, speed, wordlist coverage, Python BF script (complete, runnable), curl PoC
6. **Usuários** — table (ID, username, display name, role), enum PoC
7. **WP REST API** — public vs authed endpoints, tables
8. **WooCommerce API** — version, Store API public table, admin API table, PoC curl for data extraction
9. **Gravity Forms API** (if present) — endpoints, impact analysis, extraction PoC
10. **SolidWP Mail API** (if present) — endpoints, SMTP config risk, PoC
11. **Application Passwords** — endpoint, impact, token generation PoC
12. **CORS Matrix** — table of all endpoints tested (ACAO, ACAC, risk), PoC HTML for exfiltration
13. **Análise de Rate Limiting** — test results table (method, requests, blocked?)
14. **Subdomínios** — table of discovered subdomains
15. **Arquivos Sensíveis** — paths checked, status codes, content if found
16. **Plugins Instalados** — table (plugin, version, risk, description)
17. **Attack Chains Completas** — 7+ chains (A-I), each with steps and PoC
18. **Timeline das Descobertas** — wave by wave what was found
19. **Remediação** — P0/P1/P2 tables with specific actions

### PoC Requirements

- Every curl command must be functional (copy-paste ready)
- Every Python script must be complete (imports, error handling, output)
- HTML PoCs must include script tags and CSS
- All PoCs must be in code blocks with language tags

## File 2: ATTACK_SURFACE.md

**Target: ~300-600 lines** | **Catalog, not narrative**

### Structure

- **Índice** — numbered TOC
- **Portas Abertas** — table (#, port, protocol, service, banner)
- **XMLRPC** — numbered endpoint table (method, description, auth required, risk)
- **WP REST API (wp/v2)** — public endpoints table + authed endpoints table
- **WooCommerce (wc/v3)** — numbered endpoint table
- **WooCommerce Store API (wc/store/v1)** — public endpoints table
- **Gravity Forms API (gf/v2)** — endpoints table
- **SolidWP Mail API** — endpoints table
- **Application Passwords** — endpoint
- **Arquivos/Diretórios Sensíveis** — paths with HTTP status
- **Páginas Administrativas** — paths
- **Usuários** — table (ID, username, role)
- **CORS Matrix** — all endpoints tested with ACAO/ACAC status
- **Plugins Identificados** — table
- **Subdomínios** — table
- **Resumo por Categoria** — count table (total, requires auth, public, criticals)

### Style

- Number all endpoints sequentially across categories for easy reference
- Use compact tables — no prose paragraphs
- One row per endpoint

## File 3: EXPLOIT_CHAINS.md

**Target: ~300-500 lines** | **Actionable, step-by-step**

### Structure

- **Matriz de Risco** — table (#, cadeia, impacto, probabilidade, esforço, prioridade P0-P2)
- **Chain A: BF → RCE** (always P0 if multicall + admins available) — steps, Python script, curl PoC
- **Chain B: Application Password → API Total** — token generation, curl examples for each API
- **Chain C: WooCommerce Mining** — data extraction curl commands
- **Chain D: Gravity Forms PII Theft** — form/entry extraction
- **Chain E: SolidWP Mail Exploit** — SMTP cred extraction, log export
- **Chain F: CORS Data Exfiltration** — full PoC HTML, attack flow
- **Chain G: SSRF via Pingback** — scan ports/IPs curl script
- **Chain H: Registro → RCE** (if registration open) — register, login, upload
- **Chain I: Multi-Plugin Chain** — combined attack flow
- **Scripts Utilitários** — scanner rápido, rate limit test, data dump completo
- **Checklist de Exploração** — pre/active/post sections with checkbox format

### Style

- Each chain: one sentence summary → numbered steps → script/code → curl PoC
- Python scripts: complete with imports, error handling
- Bash scripts: complete with shebang, comments
- Mark `[x]` for confirmed items in checklist, `[ ]` for pending

## File Sizes (Empirical)

| File | wines.com | biglots.com | restonic.com |
|------|-----------|-------------|--------------|
| MASTER_REPORT.md | 1,312 | 1,602 | 1,841 |
| ATTACK_SURFACE.md | 647 | 301 | 985 |
| EXPLOIT_CHAINS.md | 511 | 577 | 319 |
| **Total/target** | **2,470** | **2,723** | **3,145** |

## Writing Rules

1. No marketing language ("powerful", "comprehensive", "seamless", "advanced")
2. Every claim backed by a reproducible PoC
3. Tables over prose for structured data
4. Code blocks always have language tag
5. PT-BR unless code/command output
6. Include remediation section (P0/P1/P2) in MASTER_REPORT
7. Severity: CRÍTICO/ALTO/MÉDIO/BAIXO (Portuguese caps)
