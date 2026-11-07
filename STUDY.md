# Estudo do catálogo `uphiago/recon-skills`

Estudo read-only do repositório clonado em 2026-11-06, commit `1260244`
(`fix: restore attribute-context payloads and trim policy prose in hunt-xss`).
Nenhum teste ativo foi executado contra alvos; os defeitos marcados como
"verificado" foram reproduzidos localmente com `bash -n`, `grep`, `sort -V` e
leitura direta do código.

Fontes de governança lidas antes do catálogo: `README.md`, `AGENTS.md`,
`SOUL.md`, `STYLE.md`, `CHANGELOG.md`, `scripts/validate_skills.py` e o workflow
de CI.

## Resumo executivo

O repositório é uma biblioteca de 146 playbooks ofensivos portáveis, com forte
concentração em web externo, reconhecimento, WordPress, identidade e classes de
vulnerabilidade. Há conteúdo de campo valioso, sobretudo em:

- disciplina de evidência e validação (`cross-attack-chains`, `triage-validation`,
  `redteam-mindset`, `evidence-hygiene`, `wordpress-cors-xmlrpc-rce-chain`);
- protocolos e superfícies específicas (`hunt-ntlm-info`, `hunt-ldap`,
  `hunt-race-condition`, `m365-entra-attack`, `hunt-aspnet`, `hunt-k8s`);
- reconhecimento operacional (`recon-playbook`, `port-mass-scan`,
  `humanize-automation`, `web2-recon`, `recon-sector`).

Ao mesmo tempo, o catálogo tem dois padrões de qualidade incompatíveis. As
skills v2/v3 (9 arquivos) seguem o contrato; as 133 skills v1.1.0 são, em grande
parte, catálogos de payload com estrutura incompleta. O validador oficial não
detecta os defeitos mais graves: ele só emite avisos de seção e valida
`related_skills` quando o campo está indentado, mas 57 skills usam YAML plano e
87 não têm o campo; apenas 2 arquivos são parseáveis.

Números do estudo:

| Métrica | Valor |
|---|---|
| Skills | 146 |
| Avisos do validador | 449 |
| Skills com ao menos uma seção obrigatória ausente | 113 |
| Skills sem `platforms` | 86 |
| Skills sem `related_skills` | 87 (só 2 em formato que o validador lê) |
| Seções obrigatórias ausentes (soma) | 363 |
| Descrições acima de 100 caracteres (alvo do STYLE: <=60) | 89 |
| Skills carimbadas com a mesma versão `1.1.0` | 133 |
| Skills que usam `${OUTPUT_DIR:-./output}` corretamente | minoria; a maioria usa `/tmp`, `~/tools` ou `recon/$TARGET` |
| Erros estruturais do validador | 0 |

O problema central não é falta de conhecimento: é falta de manutenção
estrutural, referências quebradas, comandos não executáveis e verificação
cosmética. A maior parte das "Verification" apenas faz `grep` no próprio arquivo
para confirmar que ele contém `name:`, `category:` e `Pitfalls`; isso não prova
que o procedimento funciona.

## Como ler este documento

Cada skill tem três campos:

- **Objetivo**: quando ela se aplica.
- **Técnica/veredito**: o que ela agrega e qual é a qualidade real.
- **Overlap**: skills vizinhas, quando relevante.

Classificação usada:

- **Forte**: conteúdo original, disciplina de evidência e estrutura utilizável.
- **Sólida**: boa ideia ou bom conteúdo, com defeitos corrigíveis.
- **Fraca**: conteúdo raso, estrutura quebrada ou verificação sem valor.
- **Quebrada**: há comando que não executa, lógica invertida ou artefato ausente.

## Mapa do catálogo

| Categoria | Skills | Papel |
|---|---:|---|
| `auth/` | 1 | SSO/SAML |
| `chains/` | 2 | Caminhos de ataque compostos |
| `infra/` | 1 | Escape de container |
| `meta/` | 6 | Planejamento e metodologia |
| `recon/` | 41 | Descoberta, enumeração e validação inicial |
| `redteam/` | 95 | Classes de vulnerabilidade, plataformas, OSINT e relatório |

O catálogo do site lista 176 entradas; o repositório contém 146 `SKILL.md`. A
diferença parece vir de variantes de setor e referências indexadas pelo site.

---

## auth, chains e infra

### 1. `saml-sso-attack`

- **Objetivo:** atacar SSO SAML: metadados de IdP, XSW, stripping, comment
  injection em NameID, enumeração por timing e Golden SAML.
- **Técnica/veredito:** a decodificação de `SAMLRequest` e a extração de
  metadados são práticas; a tabela de CVEs não tem detecção de versão e o XSW é
  descrito em seis `echo`, sem template forjado. A enumeração por timing usa uma
  única amostra. **Sólida, fraca em execução.**
- **Overlap:** `hunt-saml` (quase total), `hunt-auth-bypass`, `jwt-attack`.

### 2. `cross-attack-chains`

- **Objetivo:** portão para compor dois ou mais achados verificados em um
  caminho de ataque demonstrável.
- **Técnica/veredito:** vocabulário Observed/Confirmed/Inferred/Not tested e a
  regra "a severidade não pode exceder a evidência" são a melhor disciplina
  epistêmica do repositório. **Forte.** O template local existe, mas não é
  citado no SKILL.md.
- **Overlap:** `wordpress-full-compromise`, `triage-validation`,
  `attack-patterns-reference`.

### 3. `wordpress-full-compromise`

- **Objetivo:** decidir se primitivas WordPress verificadas compõem controle
  administrativo ou apenas execução benigna.
- **Técnica/veredito:** a separação upload versus execução (cinco checagens) e a
  exigência de ação administrativa descartável são excelentes. Puramente
  conceitual, sem comandos. **Forte como gate, fraca como procedimento.**
- **Overlap:** `wordpress-cors-xmlrpc-rce-chain`, `hunt-wordpress`,
  `xmlrpc-exploitation`.

### 4. `docker-privesc`

- **Objetivo:** escape de container para root do host via grupo/socket Docker,
  `--privileged`, capabilities e forense de privesc anterior.
- **Técnica/veredito:** o fallback REST via `curl --unix-socket` é útil quando
  não há binário Docker. O método de cgroup é prometido e não entregue; mudanças
  de estado não são autorizadas antes dos comandos. **Sólida.**
- **Overlap:** `hunt-k8s` no nível de container.

---

## meta

### 5. `attack-patterns-reference`

- **Objetivo:** mapear comportamentos observados para a skill que valida cada
  um; é navegação, não scanner.
- **Técnica/veredito:** a tabela de variantes CORS e os pré-requisitos por caminho
  candidato são boas. Duplica CORS de `hunt-cors`/`cors-credential-wordpress`.
  **Sólida.**
- **Overlap:** `cross-attack-chains`, `recon-playbook`, `hunt-cors`.

### 6. `cross-wave-delta-analysis`

- **Objetivo:** comparar ondas de recon e rotular NEW, REGRESSION, PERSISTENT,
  CHANGE e REVERSED.
- **Técnica/veredito:** a categoria REVERSED (proteção aplicada e removida) é
  boa. O procedimento não traz comandos de `diff`/`jq`; é uma metodologia sem
  mecanismo. **Fraca.**
- **Overlap:** `recon-playbook`, `wp-mass-recon`.

### 7. `google-dorks-catalog`

- **Objetivo:** dorks passivos para configs, segredos, `.env`, chaves de serviço
  e busca de código no GitHub.
- **Técnica/veredito:** o corpus de dorks é útil, inclusive filtros de ruído.
  Faltam `Prerequisites`, `How to Run` e `Procedure`; a sintaxe `ext:a | ext:b`
  é inválida e a verificação usa um `result.json` que nunca é criado.
  **Fraca como skill, útil como referência.**
- **Overlap:** `offensive-osint`, `github-secret-hunting`, `source-leak-hunt`.

### 8. `pentest-playbook`

- **Objetivo:** pipeline de sete fases, do recon passivo ao relatório.
- **Técnica/veredito:** a tabela de gatilhos de pivot e a "3-Attempt Rule" são
  julgamento de campo real. Faltam três seções obrigatórias e há grande
  divergência com `recon-playbook` sobre fases e artefatos. **Sólida, obsoleta.**
- **Overlap:** `recon-playbook` (muito alta), `web2-recon`.

### 9. `recon-playbook`

- **Objetivo:** recon externo autorizado: escopo, ativos, DNS/serviços, rotas,
  APIs/identidades, hipóteses, validação e evidência.
- **Técnica/veredito:** escopo como artefato, limites de taxa, `OUTPUT_DIR` e o
  template de hipótese com controle negativo fazem dela a skill de referência
  do repositório. **Forte.** Menor: `dnsx -aaaa` dobra a carga DNS.
- **Overlap:** `web2-recon`, `pentest-playbook`, `subdomain-enumeration`.

### 10. `sector-recon-methodology`

- **Objetivo:** escolher setores, compilar domínios e fazer probing em lote de
  WordPress/CORS/XML-RPC/leaks.
- **Técnica/veredito:** o script `scripts/parallel_sector_probe.py` existe e é
  citado; a distinção entre franquias e matrizes é boa. As tabelas têm `\n`
  literais, as taxas de vulnerabilidade têm precisão falsa e `$OUTDIR` não tem
  default. **Sólida, mal acabada.**
- **Overlap:** `recon-playbook`, `wp-mass-recon`, `recon-sector`.

---

## recon

### 11. `401-403-bypass-techniques`

- **Objetivo:** contornar 401/403 em rotas conhecidas explorando normalização
  divergente entre CDN, proxy, servidor e framework.
- **Técnica/veredito:** modelo de normalização em camadas, baseline e
  `--path-as-is`; melhor higiene de curl e melhor verificação do lote. Os `✓`
  das tabelas não estão amarrados a um stack testado. Diretório
  `401-403-bypass` versus nome `401-403-bypass-techniques`. **Forte.**
- **Overlap:** `hunt-auth-bypass`, `hunt-http-smuggling`, `hunt-host-header`.

### 12. `api-noauth-hunt`

- **Objetivo:** achar APIs sem autenticação/autorização, validar leitura e fazer
  CRUD sintético só com autorização explícita.
- **Técnica/veredito:** o gate `I_HAVE_EXPLICIT_WRITE_AUTHORIZATION` é o melhor
  controle de escrita do lote. `$OUTDIR` sem default resolve para a raiz do
  filesystem; alguns curls não têm `--connect-timeout`. **Sólida.**
- **Overlap:** `hunt-api-misconfig`, `hunt-idor`, `firebase-supabase-attack`.

### 13. `asn-infrastructure-mapping`

- **Objetivo:** domínio, IP, ASN, CIDR, hosts e serviços, com reverse DNS e
  expansão de TLD.
- **Técnica/veredito:** a consulta de route-object no RADB e o pivot de reverse
  DNS são o valor. Falta `How to Run` e há forte dependência de ferramentas.
  **Sólida, mal empacotada.**
- **Overlap:** `port-mass-scan`, `origin-ip-discovery`, `vhost-enumeration`.

### 14. `cache-attack`

- **Objetivo:** cache poisoning e cache deception em CloudFront, Cloudflare,
  Fastly, Varnish e Nginx.
- **Técnica/veredito:** insiste corretamente em provar armazenamento, não
  reflexo. Usa `/tmp`, não usa `OUTPUT_DIR` e tem quatro curls sem `--max-time`.
  **Sólida.**
- **Overlap:** `hunt-cache-poison` (quase total), `hunt-host-header`.

### 15. `cms-detection`

- **Objetivo:** fingerprint de CMS/framework/servidor e mapeamento de versão
  para CVE.
- **Técnica/veredito:** caminhos canônicos de vazamento de versão por CMS e
  checagem de namespace `wp-json`; o alerta de generator spoofado é correto.
  Falta `How to Run`; alvos hardcoded. **Sólida.**
- **Overlap:** `wordpress-plugin-hunt`, `wp-mass-recon`, `visual-recon`.

### 16. `cors-credential-wordpress`

- **Objetivo:** detectar, confirmar e explorar reflexão de credenciais CORS no
  REST do WordPress.
- **Técnica/veredito:** a PoC em navegador é a forma correta de confirmação, mas
  o texto superestima "roubo de cookie" quando o cookie é `HttpOnly`.
  **Sólida.**
- **Overlap:** `hunt-cors`, `attack-patterns-reference`.

### 17. `deep-invade`

- **Objetivo:** aprofundar alvos WordPress bem pontuados: SSRF XML-RPC, mineração
  de log, CVE de plugin, segredos em JS, staging, portas e APIs.
- **Técnica/veredito:** o cruzamento namespace de plugin com `readme.txt` é
  rápido e de alto sinal. Usa `192.0.2.1` como IP de metadata (errado), tem
  fases 6 e 7 duplicadas e dispersa `/tmp`. **Sólida, remendada.**
- **Overlap:** `wp-mass-recon`, `xmlrpc-exploitation`, `error-log-mining`.

### 18. `email-security`

- **Objetivo:** inspecionar SPF/DMARC/DKIM/MX, interpretar spoofing e testar
  SMTP/SES.
- **Técnica/veredito:** a tabela de políticas e o caso `include:amazonses.com`
  são bons. Faltam três seções e a afirmação "`p=none` confirma spoofável" é
  forte demais: `p=none` só remove enforcement de DMARC; a prova é entrega real.
  **Fraca.**
- **Overlap:** `exchange-owa-attack`, `hunt-tls-network`.

### 19. `error-log-mining`

- **Objetivo:** achar logs de erro PHP expostos, baixar amostra limitada e
  extrair caminhos, e-mails, credenciais, SQL e chaves.
- **Técnica/veredito:** `Content-Length` + `curl -r 0-5000000` e a checagem de
  conteúdo antes de confiar em 200 são boa higiene. Usa `grep -Eo` com `\K`, que
  falha em GNU grep ERE; `OUTDIR` sem default. **Sólida.**
- **Overlap:** `deep-invade`, `source-leak-hunt`, `hunt-information-disclosure`.

### 20. `exchange-owa-attack`

- **Objetivo:** fingerprint de Exchange/OWA, metadata NTLM Type-2, mapeamento de
  endpoints e recon de ADFS/O365/autodiscover.
- **Técnica/veredito:** o parser de AV_PAIR é a técnica de baixo nível mais
  original do lote. A verificação de spray com cinco tentativas não prova
  ausência de rate limit e o `\K` também está presente. **Sólida.**
- **Overlap:** `password-spray-methodology`, `hunt-ntlm-info`,
  `m365-entra-attack`.

### 21. `firebase-supabase-attack`

- **Objetivo:** explorar Firebase e Supabase públicos quando a config vaza em JS.
- **Técnica/veredito:** a contagem via cabeçalho do Supabase e a cadeia
  signup-then-read do Firebase são úteis. O filtro CRUD procura
  `test=eq.RLS_BYPASS`, mas o insert grava `rls_bypass_probe_<ts>`; a
  confirmação nunca casa. **Sólida, com bug central.**
- **Overlap:** `hunt-firebase`, `hunt-supabase`, `js-secrets-extraction`.

### 22. `flask-werkzeug-attack`

- **Objetivo:** detectar e explorar o debugger Werkzeug exposto.
- **Técnica/veredito:** o discriminador `/console` 400 versus 404 é bom, mas o
  arquivo tem `PORT` literal em todos os comandos, três seções ausentes,
  `FAIL/FAIL` na verificação e cita a skill inexistente `hunt-python`.
  **Quebrada.**
- **Overlap:** `hunt-rce`, `hardcoded-credential-hunt`, `source-leak-hunt`.

### 23. `github-secret-hunting`

- **Objetivo:** achar chaves e tokens vazados em organizações públicas do GitHub.
- **Técnica/veredito:** padrões por extensão e filtro `--only-verified` do
  TruffleHog são o valor; falta `How to Run` e há comandos quebrados.
  **Sólida.**
- **Overlap:** `offensive-osint`, `js-secrets-extraction`, `gitlab-public-recon`.

### 24. `gitlab-public-recon`

- **Objetivo:** enumerar projetos GitLab públicos, baixar configs sensíveis e
  inspecionar CI/variáveis.
- **Técnica/veredito:** enumeração `visibility=public` e API de raw file estão
  corretas. Afirma que variáveis de CI são legíveis sem token de admin; não são.
  `SENSITIVE_PATTERNS` fica morto. **Sólida.**
- **Overlap:** `hunt-cicd`, `source-leak-hunt`, `github-secret-hunting`.

### 25. `hardcoded-credential-hunt`

- **Objetivo:** achar credenciais em `value=`, JS inline, JSON de config e
  páginas de debug.
- **Técnica/veredito:** o extrator de hidden/password inputs é concreto; porém
  tratar 200/302 como sucesso de login garante falso positivo sem baseline.
  Falta `How to Run`. **Fraca.**
- **Overlap:** `js-secrets-extraction`, `source-leak-hunt`, `flask-werkzeug-attack`.

### 26. `http2-header-impersonation`

- **Objetivo:** imitar SETTINGS, ordem de pseudo-headers e headers de Chrome,
  Firefox, Safari iOS e OkHttp para vencer anti-bot.
- **Técnica/veredito:** a tabela de ordem de pseudo-headers e SETTINGS é
  conteúdo raro e específico. `[REDACTED_IP]` aparece onde deveria estar a
  versão do Chrome, gerando UAs inválidos. Falta `How to Run`. **Sólida.**
- **Overlap:** `tls-fingerprint-impersonation`, `stealth-browser-launch`.

### 27. `humanize-automation`

- **Objetivo:** substituir interações instantâneas do Playwright por curvas de
  Bézier, erros de digitação e scroll acelerado/desacelerado.
- **Técnica/veredito:** as tabelas de parâmetros são excepcionalmente concretas
  (pontos de controle, 2% de erro, eventos CDP confiáveis). Depende do binário
  externo `cloakbrowser`. **Forte.**
- **Overlap:** `stealth-browser-launch`, `tls-fingerprint-impersonation`.

### 28. `iot-camera-recon`

- **Objetivo:** avaliar câmeras IP expostas via RTSP 554, snapshots, ONVIF e
  credenciais padrão.
- **Técnica/veredito:** a matriz por fabricante (Axis, Hikvision, Dahua,
  Intelbras, ONVIF) e a exigência de JPEG válido como prova são boas. Algumas
  credenciais padrão não são testadas de forma segura (podem contar lockout).
  **Sólida.**
- **Overlap:** `scada-hikvision-isapi`, `port-mass-scan`, `hunt-ssrf`.

### 29. `js-secrets-extraction`

- **Objetivo:** minerar bundles e source maps por chaves, JWTs, APIs internas e
  config Firebase/Supabase.
- **Técnica/veredito:** os padrões de backend por plataforma e a distinção
  "`dpl_*` não é segredo" são boas. Faltam `Prerequisites`, `How to Run` e
  `Procedure`; o código Node usa `print()`, que não existe em Node. **Fraca.**
- **Overlap:** `hardcoded-credential-hunt`, `source-leak-hunt`, `hunt-source-leak`.

### 30. `jwt-attack`

- **Objetivo:** decodificar e atacar JWTs: `alg:none`, confusão RS256→HS256,
  segredo fraco, injeção em `kid`, reuso de token expirado.
- **Técnica/veredito:** tabela compacta de ataque/impacto e cracker real em
  Python. A verificação ainda é status/header em vários pontos. **Sólida.**
- **Overlap:** `hunt-oauth`, `hunt-auth-bypass`, `hunt-session`.

### 31. `origin-ip-discovery`

- **Objetivo:** achar o servidor real atrás de Cloudflare/Akamai/Fastly via
  favicon, DNS passivo, SANs e IDs de analytics.
- **Técnica/veredito:** validar por MD5 de favicon e título com Host header é
  mais forte que apenas encontrar um IP. Exclusão de CIDR Cloudflare é concreta.
  **Sólida.**
- **Overlap:** `subdomain-enumeration`, `vhost-enumeration`,
  `asn-infrastructure-mapping`.

### 32. `phpinfo-to-rce`

- **Objetivo:** triar um `phpinfo()` exposto e encadear para webshell se houver
  caminho de upload.
- **Técnica/veredito:** a tabela de diretivas e a distinção LD_PRELOAD/FFI são
  boas; upload de webshell não é precedido de gate. **Sólida.**
- **Overlap:** `source-leak-hunt`, `xmlrpc-exploitation`,
  `wordpress-full-compromise`.

### 33. `port-mass-scan`

- **Objetivo:** RustScan/Masscan em alta velocidade e Nmap para detecção.
- **Técnica/veredito:** tabela de desempenho realista, sharding e o alerta de que
  banner grabbing precisa de IP de origem separado. **Forte.**
- **Overlap:** `port-service-discovery`, `iot-camera-recon`.

### 34. `port-service-discovery`

- **Objetivo:** follow-up Nmap limitado para MySQL, Mongo, Redis, PostgreSQL,
  MSSQL, FTP, SSH e APIs em portas não padrão.
- **Técnica/veredito:** checagens específicas (PING no Redis, FTP anônimo) e a
  lista de paths de API são úteis; a verificação de conexão real ao MySQL é
  prometida e não executada. **Sólida.**
- **Overlap:** `port-mass-scan`, `deep-invade`, `hunt-ntlm-info`.

### 35. `s3-minio-content-type-xss`

- **Objetivo:** transformar objeto público S3/MinIO em XSS same-origin via
  `response-content-type=text/html`.
- **Técnica/veredito:** o bypass é realmente útil e vence validação de
  magic-byte/extensão no momento da entrega. A verificação tem curl sem
  `--max-time`; upload não é gated. **Sólida.**
- **Overlap:** `hunt-xss`, `hunt-cloud-misconfig`, `hunt-file-upload`.

### 36. `scada-hikvision-isapi`

- **Objetivo:** enumerar rotas ISAPI/Bumblebee do Hikvision a partir de bundles JS
  e sondar interfaces industriais.
- **Técnica/veredito:** o mapa de rotas e a interpretação `ErrorCode 216` são
  conhecimento de fornecedor concreto. Depende de exposição de JS e não cobre
  autenticação além do login CAS. **Sólida.**
- **Overlap:** `iot-camera-recon`, `port-service-discovery`, `hunt-ssrf`.

### 37. `source-leak-hunt`

- **Objetivo:** varrer URLs vivas por `.env`, `.git/config`, backups de
  `wp-config`, logs, dumps e phpinfo.
- **Técnica/veredito:** filtro por conteúdo e heurística de domínio parkeado são
  excelentes. A verificação imprime literalmente `FAIL`/`FAIL`; arrays de shell
  são exportados para `bash -c` e o scan paralelo não roda. **Sólida, com falhas
  de execução.**
- **Overlap:** `web-enumeration` (quase duplicata), `hunt-source-leak`.

### 38. `staging-subdomain-hunt`

- **Objetivo:** achar staging/dev via crt.sh quando produção está endurecida.
- **Técnica/veredito:** a comparação de headers prod versus staging e as
  checagens de install page são boas. O CORS checa `ACAC: true` sem provar
  reflexão de origem. Duplica grande parte de `subdomain-enumeration`.
  **Sólida.**
- **Overlap:** `subdomain-enumeration`, `subdomain-takeover-hunt`, `wp-mass-recon`.

### 39. `stealth-browser-launch`

- **Objetivo:** lançar Chromium corrigido com spoof de fingerprint em nível de
  binário para passar Turnstile/reCAPTCHA v3/FingerprintJS.
- **Técnica/veredito:** a tabela de flags (GPU, memória, timezone, WebRTC, noise,
  font metrics) é referência valiosa; o multiplexador CDP por seed também.
  Depende de um binário externo e cita skill inexistente
  `proxy-geoip-automation`. **Forte como referência.**
- **Overlap:** `humanize-automation`, `tls-fingerprint-impersonation`.

### 40. `subdomain-enumeration`

- **Objetivo:** kickoff de descoberta via crt.sh, subfinder, resolução DNS,
  probing, takeover, permutações e TLDs.
- **Técnica/veredito:** cobertura ampla, retry no crt.sh e avisos de wildcard/CDN
  são corretos. Bug central: `dnsx -resp-only` emite só IPs, mas o código lê
  `cut -f1` como subdomínio e `cut -f2` como IP, produzindo pares errados.
  **Sólida, com bug de parsing.**
- **Overlap:** `staging-subdomain-hunt`, `subdomain-takeover-hunt`, `hunt-subdomain`.

### 41. `subdomain-takeover-hunt`

- **Objetivo:** detectar CNAMEs pendentes para Heroku/S3/Azure/GitHub Pages/etc.
- **Técnica/veredito:** a tabela de mensagens de erro por provedor evita confiar
  cegamente em scanner. O pipeline S3 é concreto; a exploração/claim não é
  gated. **Sólida.**
- **Overlap:** `subdomain-enumeration`, `hunt-subdomain`.

### 42. `tls-fingerprint-impersonation`

- **Objetivo:** igualar JA3/JA4 e SETTINGS HTTP/2 de navegador com `impit`.
- **Técnica/veredito:** a matriz por navegador (GREASE, MLKEM768, FFDHE, ECH,
  compressão de certificado) é referência densa. Depende de biblioteca externa
  não pinada. **Sólida.**
- **Overlap:** `http2-header-impersonation`, `stealth-browser-launch`.

### 43. `unauth-api-flow-hijack`

- **Objetivo:** abusar de workflows multi-etapa sem autenticação (entrevista,
  onboarding, checkout), incluindo upload/export e replay de sessão.
- **Técnica/veredito:** o enquadramento do state machine inteiro é correto, mas
  `$FLOW_ID` é usado sem definição e as rotas são adivinhadas genericamente.
  **Fraca.**
- **Overlap:** `api-noauth-hunt`, `hunt-write-gap`, `hunt-idor`.

### 44. `vhost-enumeration`

- **Objetivo:** achar virtual hosts ocultos em um IP via Host fuzzing, SANs, PTR e
  diferença de conteúdo.
- **Técnica/veredito:** a calibração manual e o uso de `-ac` no ffuf são
  corretos. Falta `How to Run`; duplica a seção de vhost de `web-enumeration`.
  **Sólida.**
- **Overlap:** `web-enumeration`, `origin-ip-discovery`, `hunt-host-header`.

### 45. `visual-recon`

- **Objetivo:** tirar screenshots de muitos hosts e triar visualmente install
  pages, painéis, servidores default e infra compartilhada.
- **Técnica/veredito:** a tabela "o que a screenshot significa" é boa, mas a
  ferramenta é frágil por versão e a sequência de banco/relatório está quebrada.
  Falta `How to Run`. **Fraca.**
- **Overlap:** `cms-detection`, `web-enumeration`, `web2-recon`.

### 46. `web-enumeration`

- **Objetivo:** varredura de arquivos sensíveis, bypass de path traversal,
  `.env` via Host, extração de credenciais, log Laravel e categorização de URLs.
- **Técnica/veredito:** o conjunto de regex de `.env` e o ponteiro para a
  referência local são valiosos. Faltam três seções; o teste de catch-all nunca
  casa porque o body é lowercased e os marcadores incluem `<!DOCTYPE` maiúsculo.
  **Fraca.**
- **Overlap:** `source-leak-hunt` (quase duplicata), `401-403-bypass`,
  `error-log-mining`.

### 47. `wordpress-plugin-hunt`

- **Objetivo:** enumerar plugins via namespace REST, `readme.txt` e HTML, e mapear
  versões para CVE.
- **Técnica/veredito:** os catálogos de namespace/slug e a matriz por provedor
  são práticos; a tabela de CVE está parcialmente obsoleta. Usa `\K` com
  `grep -E`. **Sólida.**
- **Overlap:** `wp-plugin-cve-hunt`, `wp-plugin-automation`, `wp-mass-recon`.

### 48. `wp-mass-recon`

- **Objetivo:** triagem WordPress em lote: detecção, users, CORS, XMLRPC,
  registro aberto, leaks e pontuação.
- **Técnica/veredito:** o modelo de score e a checagem de três strings para
  registro são bons; o `ThreadPoolExecutor` é razoável. Invoca
  `parallel_batch.py`, mas o arquivo empacotado é `scripts/scanner.py`.
  **Sólida, com referência quebrada.**
- **Overlap:** `wp-plugin-automation`, `wordpress-full-compromise`,
  `xmlrpc-exploitation`.

### 49. `wp-plugin-rest-auth-bypass`

- **Objetivo:** enumerar rotas REST de plugins e achar operações sem autenticação.
- **Técnica/veredito:** a classificação de resposta (`Missing parameter` =
  vivo, `rest_forbidden` = auth aplicada) é o melhor conteúdo. Variáveis de loop
  perdem escopo e o endpoint hardcoded não está na própria lista. **Fraca.**
- **Overlap:** `wp-plugin-automation`, `hunt-api-misconfig`, `hunt-write-gap`.

### 50. `xmlrpc-exploitation`

- **Objetivo:** detectar XMLRPC, enumerar métodos, usar `pingback.ping` para
  SSRF/IMDS e `system.multicall` para força bruta amplificada.
- **Técnica/veredito:** oráculo de timing, interpretação de `faultCode` e regra
  de papel para upload são boas; `faultCode 0` não é prova de SSRF. Usa
  `192.0.2.1` como IMDS e `tr -d '%0A%0D'` em base64 (remove caracteres que não
  estão lá e pode corromper). **Sólida, com bugs.**
- **Overlap:** `wordpress-cors-xmlrpc-rce-chain`, `wordpress-full-compromise`,
  `hunt-ssrf`.

### 51. `zimbra-attack`

- **Objetivo:** fingerprint do Zimbra, enumeração SOAP, UploadServlet,
  CVE-2022-37042 e SSRF em `/service/proxy`.
- **Técnica/veredito:** o oráculo de enumeração é simples e eficaz quando
  funciona; `$TARGET_DOMAIN` é indefinido e o branch de credenciais default é
  inalcançável. **Sólida.**
- **Overlap:** `exchange-owa-attack`, `hunt-ntlm-info`.

### 52. `apk-redteam-pipeline`

- **Objetivo:** pipeline Android: aquisição de APK, decompilação, segredos,
  certificado pinado, componentes exportados, Frida e captura de tráfego.
- **Técnica/veredito:** extração de SANs de certificado pinado pode revelar APIs
  internas que o recon passivo não vê; a verificação é funcional. **Forte.**
- **Overlap:** `bug-bounty`, `hunt-api-misconfig`, `cloud-iam-deep`.

---

## redteam: metodologia, OSINT, plataformas e relatório

### 53. `bug-bounty`

- **Objetivo:** orquestrador mestre de bug bounty com 30+ classes e cadeias.
- **Técnica/veredito:** o capítulo de CI/CD no formato "pergunta-gate →
  profundidade → kill signal" é excelente, com tabela GHSA. A descrição promete
  gatilhos em chinês que não existem no corpo. **Forte como referência.**
- **Overlap:** `bb-local-toolkit` (extrema), `bb-methodology`, `hunt-cicd`.

### 54. `bb-local-toolkit`

- **Objetivo:** apresentado como "workflow completo de bug bounty"; na prática é
  quase cópia de `bug-bounty` com instalação de ferramentas.
- **Técnica/veredito:** o aprofundamento de CI/CD (36 relatórios pagos citados)
  é o material original. Fora isso, 1.530 linhas com apenas ~30 linhas de
  diferença para `bug-bounty`. **Duplicata forte.**
- **Overlap:** `bug-bounty`, `bb-methodology`, `web2-recon`.

### 55. `bb-methodology`

- **Objetivo:** orquestrador de início de sessão: modo de engajamento, objetivo,
  uma ou duas classes e workflow não linear de 5 fases.
- **Técnica/veredito:** o PART 0 (bounty versus red team versus pentest versus
  audit) é a melhor ideia do lote; a lição quantificada sobre confundir formatos
  é campo real. Marker Discipline e Body-Diff Rule são concretos. **Forte.**
- **Overlap:** `bug-bounty`, `bb-local-toolkit`, `triage-validation`.

### 56. `bugcrowd-reporting`

- **Objetivo:** táticas específicas de submissão no Bugcrowd: VRT, override,
  parágrafo de severidade, réplica a OOS e escolha de ambiente.
- **Técnica/veredito:** a réplica OOS citando a cláusula e o argumento de que
  verificador de senha/token/OTP é endpoint de autenticação são específicos e
  úteis. **Sólida.**
- **Overlap:** `report-writing`, `triage-validation`, `bug-bounty`.

### 57. `cloud-iam-deep`

- **Objetivo:** exploração pós-descoberta em Cloud Functions, Firestore, Cloud
  Run, S3, MinIO, Blob e chaves de service account.
- **Técnica/veredito:** a construção de access token a partir de SA key e a
  enumeração IAM são valiosas; o código chama `load_pem_private_key` sem import e
  usa `project_id` indefinido. AWS é muito mais raso que o título sugere.
  **Fraca.**
- **Overlap:** `hunt-cloud-misconfig`, `hunt-firebase`, `hunt-supabase`.

### 58. `cors-chain-automation`

- **Objetivo:** triagem CORS em lote separando reflexão com credenciais,
  null-origin e bypass de regex.
- **Técnica/veredito:** a matriz de classificação e a lição "teste todos os
  endpoints" são boas; há contradição bash/zsh e variável não vinculada.
  **Sólida.**
- **Overlap:** `hunt-cors`, `cors-credential-wordpress`, `hunt-subdomain`.

### 59. `enterprise-vpn-attack`

- **Objetivo:** matriz de ataque a SSL-VPN/perímetro: Cisco ASA, Fortinet,
  Citrix, Palo Alto, Pulse/Ivanti, SonicWall e F5.
- **Técnica/veredito:** snippets de CVE compactos e de alto sinal; é a skill mais
  disciplinada em mudanças de estado. **Forte.**
- **Overlap:** `vmware-vcenter-attack`, `hunt-rce`, `m365-entra-attack`.

### 60. `evidence-hygiene`

- **Objetivo:** redaction antes de screenshot/HAR, mascaramento de cookie, tarja
  de PII, sanitização de HAR e ordem de PoC.
- **Técnica/veredito:** a função jq `sanitize_har` é pronta para uso e cobre
  headers e cookies de request/response. **Forte.**
- **Overlap:** `bugcrowd-reporting`, `report-writing`, `triage-validation`.

### 61. `hunt-api-misconfig`

- **Objetivo:** mass assignment, JWT, prototype pollution, verb tampering, OData,
  Swagger exposto, shadow APIs e aliases de rate limit.
- **Técnica/veredito:** a seção OData é o material mais distinto (extração
  booleana de hash, bypass de ACL por `$orderby`, evasão WAF com `$batch`).
  Começa no "## 12", contradiz a posse de CORS e tem quote faltando em curl
  (linha 265). **Sólida, mal montada.**
- **Overlap:** `hunt-cors`, `hunt-graphql`, `hunt-schema-enumeration`.

### 62. `hunt-aspnet`

- **Objetivo:** superfície ASP.NET/WebForms/WCF/SharePoint/Telerik, ViewState,
  machineKey, diferenciais de parser, `trace.axd`/`elmah.axd` e WCF.
- **Técnica/veredito:** o diferencial de duplo parser (XML versus LosFormatter)
  produzindo mensagens distintas é a melhor técnica do lote. O sinal
  `__VIEWSTATEENCRYPTED=""` e o rubric de severidade primitive-vs-chain são
  fortes. **Forte.**
- **Overlap:** `hunt-sharepoint`, `hunt-rce`, `hunt-file-upload`.

### 63. `hunt-ato`

- **Objetivo:** taxonomia e cadeias de ATO: reset poisoning, leak por Referer,
  token fraco, reuso, troca de e-mail, JWT, password change sem step-up, SSO,
  device flow e PKCE.
- **Técnica/veredito:** exige prova contra uma segunda conta e confirmação por
  leitura do e-mail real, não do header refletido. Diz 9 caminhos e documenta 12.
  **Forte.**
- **Overlap:** `hunt-mfa-bypass`, `hunt-oauth`, `hunt-host-header`.

### 64. `hunt-auth-bypass`

- **Objetivo:** bypass de autenticação em SAML, caracteres de controle em
  domain-binding, reuso cross-IdP, XMLRPC de WordPress, JWT, Duende BFF e
  function-level auth.
- **Técnica/veredito:** a Legacy-Protocol Matrix (Uber XMLRPC → SharePoint
  `Authentication.asmx`, EWS, Jira, Tomcat) é o artefato mais reutilizável do
  lote. O arquivo tem um byte NUL (byte 22588), então `grep` o trata como
  binário, e um code fence aberto engole o "Related Skills" até o EOF.
  **Forte, com corrupção de arquivo.**
- **Overlap:** `hunt-broken-function-level-auth` (duplicata), `hunt-ato`,
  `hunt-saml`.

### 65. `hunt-broken-function-level-auth`

- **Objetivo:** falhas de autorização em nível de ação: verb drift, rota legada,
  feature flag, batch/job e paridade de transporte.
- **Técnica/veredito:** a "sibling-function rule" é compacta e acionável, mas a
  skill é uma reafirmação de uma seção de `hunt-auth-bypass`; a verificação é
  prosa. **Fraca.**
- **Overlap:** `hunt-auth-bypass`, `hunt-api-misconfig`, `hunt-idor`.

### 66. `hunt-brute-force`

- **Objetivo:** rate limit ausente/fraco em login, OTP, reset, stuffing,
  enumeração, política fraca, CAPTCHA e ReDoS.
- **Técnica/veredito:** a classificação em quatro estados e o seed de
  shadow-throttle são a melhor defesa contra falso negativo do lote; a matemática
  de keyspace está correta. **Forte.**
- **Overlap:** `password-spray-methodology`, `hunt-mfa-bypass`, `hunt-ato`.

### 67. `hunt-business-logic`

- **Objetivo:** lógica financeira: cupom/gift card, quantidade negativa, overflow
  decimal, preço confiado do cliente, TOCTOU de preço arquivado.
- **Técnica/veredito:** o padrão de detectar e provar "servidor confia no preço
  do cliente" é conciso e focado em impacto. **Sólida.**
- **Overlap:** `hunt-race-condition`, `hunt-idor`, `hunt-write-gap`.

### 68. `hunt-cache-poison`

- **Objetivo:** cache poisoning e deception em apps com CDN: headers não
  chaveados, extensão de path, cache de erro, redirect envenenado.
- **Técnica/veredito:** a disciplina de cache-buster é a melhor lição; a
  verificação exige hit consistente, não apenas reflexo. **Sólida.**
- **Overlap:** `cache-attack`, `hunt-host-header`, `hunt-xss`.

### 69. `hunt-cicd`

- **Objetivo:** ataques a pipeline: Jenkins console/CVE-2024-23897, GitHub
  Actions `${{ }}`/Pwnrequest, runner self-hosted, OIDC trust policy, GitLab
  runner token, Terraform state, artefatos e logs.
- **Técnica/veredito:** o gate "It-Didn't-Happen-Without-Proof" é a melhor seção
  individual do lote, com a distinção precisa entre expressão `${{ }}` e env var.
  **Forte.**
- **Overlap:** `bug-bounty`, `supply-chain-attack-recon`, `cloud-iam-deep`.

### 70. `hunt-cloud-misconfig`

- **Objetivo:** storage/compute público, IMDS via SSRF, Firebase, painéis admin,
  LocalStack e CloudWatch RUM.
- **Técnica/veredito:** a cadeia RUM (`guestRoleArn` + `identityPoolId` →
  credenciais STS) é o conteúdo original. A linha 198 testa
  `echo 192.0.2.1 | grep 169.254`, que sempre falha; GCS/Azure/Lambda/RDS
  prometidos não aparecem. **Fraca.**
- **Overlap:** `cloud-iam-deep`, `hunt-firebase`, `hunt-ssrf`.

### 71. `hunt-cors`

- **Objetivo:** CORS com credenciais, null-origin, bypass de regex, preflight e
  postMessage.
- **Técnica/veredito:** tabela de classes regex e prova em navegador; usa
  evidência específica de alvos reais (`gocarwash.com` etc.). **Forte.**
- **Overlap:** `cors-chain-automation`, `cors-credential-wordpress`, `hunt-csrf`.

### 72. `hunt-csrf`

- **Objetivo:** CSRF moderno com ênfase em cadeia para ATO: troca de conta,
  e-mail, vínculo social, OAuth, API e upload.
- **Técnica/veredito:** a tabela de pré-condições e a cadeia de login CSRF são
  boas; a descrição tem ~800 caracteres e o loop de token usa `\K` com
  `grep -E`. **Sólida.**
- **Overlap:** `hunt-dom`, `hunt-xss`, `hunt-session`.

### 73. `hunt-deserialization`

- **Objetivo:** deserialização insegura em Java, PHP, Python pickle, .NET,
  Ruby Marshal e JNDI/Log4Shell.
- **Técnica/veredito:** cobre seis ecossistemas em 205 linhas; instalação não é
  reproduzível (`shiro_exploit.py` nunca é baixado, jar vai para CWD e a
  verificação procura em `/opt`). **Fraca.**
- **Overlap:** `hunt-rce`, `hunt-aspnet`, `hunt-ssti`.

### 74. `hunt-dispatch`

- **Objetivo:** loader de um orquestrador `/hunt`: fingerprint, seleção de skill,
  limite de 8, taxonomia.
- **Técnica/veredito:** não tem as seis seções e depende de `/hunt`, "Skill CLI" e
  `commands/hunt.md`, que não existem no repositório. **Fraca.**
- **Overlap:** `bug-bounty`, `recon-playbook`.

### 75. `hunt-django`

- **Objetivo:** falhas de permissão em Django/DRF, ORM raw, admin, template
  injection e paridade de auth no Channels.
- **Técnica/veredito:** o decode de `sessionid` é enganoso (não é JSON
  comprimido genérico); o loop de CSRF usa `TOKEN` literal. **Fraca.**
- **Overlap:** `hunt-fastapi`, `hunt-laravel`, `hunt-idor`.

### 76. `hunt-dom`

- **Objetivo:** DOM clobbering, postMessage, service worker, CSS exfiltration,
  `dangerouslySetInnerHTML` e client-side template injection.
- **Técnica/veredito:** a tabela de vetores e a persistência via SW são boas;
  `Pitfalls` vem depois de `Verification` e usa `recon/$TARGET/**/*.js` sem criar
  os arquivos. **Sólida.**
- **Overlap:** `hunt-xss`, `hunt-csrf`, `hunt-cors`.

### 77. `hunt-fastapi`

- **Objetivo:** mineração de OpenAPI, falhas de dependency injection, coerção
  Pydantic, trust em proxy ASGI, paridade de auth em WebSocket e GraphQL montado.
- **Técnica/veredito:** contradiz o default real do Pydantic v2
  (`extra=ignore`, não erro) e o exemplo de coerção não prova autorização.
  **Fraca.**
- **Overlap:** `hunt-django`, `hunt-api-misconfig`, `hunt-graphql`.

### 78. `hunt-file-upload`

- **Objetivo:** upload para RCE/XSS/XXE, traversal de nome, ZIP slip, SSRF via
  ImageMagick/ffmpeg e HTML→PDF.
- **Técnica/veredito:** a matriz de formatos e sinks é boa, mas há `Phase X`
  depois de "Related Skills", `/tmp` em 10 pontos e `[REDACTED_IP]` em 6.
  **Sólida.**
- **Overlap:** `hunt-rce`, `hunt-xxe`, `s3-minio-content-type-xss`.

### 79. `hunt-firebase`

- **Objetivo:** exploração Firebase/Firestore/GCP: descoberta de API key, auth
  anônima, enumeração, leitura/escrita RTDB, storage e service account.
- **Técnica/veredito:** cobre o ciclo completo, mas `cat /tmp/*.map | python3`
  quebra com múltiplos maps (JSON concatenado) e a extração de project ID é
  frouxa. **Sólida.**
- **Overlap:** `hunt-supabase`, `firebase-supabase-attack`,
  `hunt-cloud-misconfig`.

### 80. `hunt-graphql`

- **Objetivo:** IDOR via GID/node/mutation, cross-tenant, SSRF por argumento,
  batching, bypass de custo e authz por campo.
- **Técnica/veredito:** a tabela de alias batching e a escada de cadeias IDOR são
  análises fortes; cita documento de verificação inexistente e
  `clairvoyance.py` sem instalação. **Sólida.**
- **Overlap:** `hunt-idor`, `hunt-api-misconfig`, `hunt-schema-enumeration`.

### 81. `hunt-grpc`

- **Objetivo:** enumeração por reflection, auth ausente ou só na borda, h2c,
  leak de proto, transcoding gRPC-Web e Rapid Reset.
- **Técnica/veredito:** a correção `/run` versus `/exec` no kubelet e o spoof de
  metadata são precisos; há duas seções "related" e `brew` como padrão.
  **Forte.**
- **Overlap:** `hunt-k8s`, `hunt-api-misconfig`, `hunt-auth-bypass`.

### 82. `hunt-host-header`

- **Objetivo:** injeção de Host: reset poisoning, cache poisoning, SSRF de
  roteamento, bypass de ACL por `X-Original-URL` e envenenamento de issuer
  OAuth/OIDC.
- **Técnica/veredito:** a distinção entre roteamento e sobrescrita de path é
  valiosa. Usa `[REDACTED_IP]` 7 vezes e não formaliza gate de estado.
  **Forte.**
- **Overlap:** `hunt-ato`, `hunt-cache-poison`, `hunt-ssrf`.

### 83. `hunt-http-smuggling`

- **Objetivo:** CL.TE, TE.CL, H2.CL, H2.TE, CL.0, TE.TE e desync client-side.
- **Técnica/veredito:** cobre variantes e ranking HA, mas começa com "## 17",
  tem `nc` contra 443 sem TLS, flags conflitantes e instruções de instalação
  contraditórias. **Sólida.**
- **Overlap:** `hunt-cache-poison`, `hunt-host-header`, `hunt-auth-bypass`.

### 84. `hunt-idor`

- **Objetivo:** IDOR em IDs de recursos, IDs GraphQL, downloads e SaaS multi-tenant.
- **Técnica/veredito:** a escada de cadeias e a distinção leitura/escrita são
  boas; citações erradas e `Phase X` após "Related Skills". **Sólida.**
- **Overlap:** `hunt-graphql`, `hunt-write-gap`, `hunt-api-misconfig`.

### 85. `hunt-information-disclosure`

- **Objetivo:** vazamento por erro, DVCS/config, source maps, oráculos
  diferenciais e versão.
- **Técnica/veredito:** usa `target.com` hardcoded, grava no CWD e tem só 176
  linhas; duplica três skills de recon. **Fraca.**
- **Overlap:** `source-leak-hunt`, `error-log-mining`, `hunt-source-leak`.

### 86. `hunt-k8s`

- **Objetivo:** API anônima, kubelet `/run`/`/exec`, etcd, dashboard, tokens
  RBAC/SA, docker.sock, runc, `nodes/proxy` e EphemeralContainers.
- **Técnica/veredito:** a distinção `/run` versus `/exec` e a prova por artefato
  são boas; `H=` é definido e não usado, e `[REDACTED_IP]` aparece 4 vezes.
  **Forte.**
- **Overlap:** `hunt-grpc`, `docker-privesc`, `cloud-iam-deep`.

### 87. `hunt-laravel`

- **Objetivo:** debug/Ignition RCE, Telescope/Horizon, `.env`/APP_KEY, URLs
  assinadas, mass assignment e cookie deserialization.
- **Técnica/veredito:** `cut -d= -f2` trunca o padding base64 do `APP_KEY`;
  `laravel_cookie_forge.py` nunca é baixado; o curl do Ignition não completa o
  RCE. **Fraca.**
- **Overlap:** `hunt-django`, `hunt-fastapi`, `hunt-deserialization`.

### 88. `hunt-ldap`

- **Objetivo:** bypass de auth LDAP, exfiltração cega de atributos, enumeração AD
  e XPath injection.
- **Técnica/veredito:** a correção AD-versus-LDAP genérico e o oráculo cego
  controlado são excelentes. `E=` no XPath é morto e o endpoint wildcard do AD é
  frágil. **Forte.**
- **Overlap:** `hunt-auth-bypass`, `hunt-ntlm-info`, `password-spray-methodology`.

### 89. `hunt-lfi`

- **Objetivo:** LFI/RFI/path traversal, log poisoning, filter-chain RCE,
  wrappers e confirmação cega.
- **Técnica/veredito:** a cadeia de filtros PHP e o gate OOB são fortes; a tabela
  de cadeias não tem linha separadora e depende de `~/wordlists`/`/usr/share/wfuzz`.
  **Forte.**
- **Overlap:** `hunt-rce`, `error-log-mining`, `hunt-file-upload`.

### 90. `hunt-llm-ai`

- **Objetivo:** prompt injection direta/indireta, exfiltração por markdown/tool,
  smuggling ASCII/Unicode, leak de system prompt, IDOR via IA, RAG/poisoning e
  agentes (OWASP ASI).
- **Técnica/veredito:** o False-Positive Gate com encoder Tags-block e a regra
  "rodar duas vezes" são os melhores controles anti-confabulação do lote.
  **Forte.**
- **Overlap:** `hunt-mcp-security`, `llm-prompt-injection`, `hunt-ssrf`.

### 91. `hunt-mass-assignment`

- **Objetivo:** injeção de campos como `isAdmin`, `role`, `ownerId`, `plan` e
  `balance` em endpoints que fazem bind genérico.
- **Técnica/veredito:** o dicionário de campos e as variantes de shape (dot-path,
  bracket, chave duplicada, batch) são compactos; requer `requests` sem declarar.
  **Sólida.**
- **Overlap:** `hunt-api-misconfig`, `hunt-idor`, `hunt-write-gap`.

### 92. `hunt-mcp-security`

- **Objetivo:** testar integrações MCP: tool access sem auth, injeção em
  parâmetros, poisoning de output, registro inseguro, agência excessiva e leak
  cross-tool.
- **Técnica/veredito:** "tool output é input do atacante" é o modelo mental
  correto, mas os caminhos REST são inventados para um protocolo JSON-RPC; quem
  seguir os curls recebe 404 na maioria dos servidores. **Fraca.**
- **Overlap:** `hunt-llm-ai`, `llm-prompt-injection`, `hunt-api-misconfig`.

### 93. `hunt-metrics-exposure`

- **Objetivo:** achar `/metrics`, `/health`, `/status`, Actuator e Telescope
  esquecidos.
- **Técnica/veredito:** a tabela métrica→inteligência é útil (modelo de IA, pool
  de DB), mas não tem `Procedure`, tem duas `Verification` e trata
  `/actuator/env` como CRITICAL sem checar redaction. **Fraca.**
- **Overlap:** `hunt-springboot`, `hunt-information-disclosure`.

### 94. `hunt-mfa-bypass`

- **Objetivo:** MFA ausente em endpoints sensíveis, skip de etapa, replay de OTP,
  brute force, race, backup code, device trust e replay biométrico.
- **Técnica/veredito:** a tabela de transição de estado e o aviso de que dois
  requests paralelos não bastam são marcadores de qualidade. Duplica a race de
  OTP de `hunt-race-condition`. **Sólida.**
- **Overlap:** `hunt-race-condition`, `hunt-ato`, `hunt-session`.

### 95. `hunt-misc`

- **Objetivo:** catch-all para access control, information disclosure, lógica de
  convite/auth, SSRF em config, dependency confusion e higiene de DNS.
- **Técnica/veredito:** a Body-Diff Rule com marcador único é a melhor regra
  anti-falso-positivo do lote; Gate 0 é forte. Ainda assim, é muito moldada por
  GitHub/GitLab/Shopify. **Sólida.**
- **Overlap:** `hunt-auth-bypass`, `hunt-ato`, `hunt-subdomain`.

### 96. `hunt-nestjs`

- **Objetivo:** gaps de guard/decorator, mismatch de metadata no Reflector,
  coerção do ValidationPipe, leak de serializer e drift de auth em transporte de
  microserviço.
- **Técnica/veredito:** o foco em internals de framework é real, mas os comandos
  de transporte são ruins (`nc` contra JsonSocket, `redis-cli PUBLISH`) e a
  verificação é só status. **Fraca.**
- **Overlap:** `hunt-nodejs`, `hunt-api-misconfig`, `hunt-mass-assignment`.

### 97. `hunt-nextjs`

- **Objetivo:** Server Actions, bypass de middleware, SSRF em `/_next/image`,
  poisoning de ISR, IDOR em `/_next/data`, leak de RSC e source maps.
- **Técnica/veredito:** o gate de FP do `/_next/image` (400 de allowlist não é
  bypass; 200 é imagem otimizada, não o body upstream) é excelente, assim como a
  correção da CVE-2024-34351. **Forte.**
- **Overlap:** `hunt-ssrf`, `hunt-idor`, `hunt-nodejs`.

### 98. `hunt-nodejs`

- **Objetivo:** prototype pollution até RCE, `trust proxy`, SSTI EJS/Pug/Handlebars,
  injeção em `child_process` e `/proc/self/environ`.
- **Técnica/veredito:** o sink `NODE_OPTIONS --require /proc/self/fd/0` e o loop
  de rotação de IP por `trust proxy` são práticos. Duplica pesadamente
  `hunt-prototype-pollution` e tem payloads não verificados. **Sólida.**
- **Overlap:** `hunt-prototype-pollution`, `hunt-ssti`, `hunt-nextjs`.

### 99. `hunt-nosqli`

- **Objetivo:** NoSQLi em MongoDB/Mongoose, CouchDB, Redis e Elasticsearch.
- **Técnica/veredito:** a tabela de posição/encoding de operador e o dump por
  prefixo de regex são reutilizáveis; Redis via `gopher://` é corretamente
  tratado como caminho de alto impacto. **Sólida.**
- **Overlap:** `hunt-sqli`, `hunt-auth-bypass`, `hunt-ssrf`.

### 100. `hunt-ntlm-info`

- **Objetivo:** capturar challenge NTLM Type-2 anônimo em IIS/SharePoint/
  Exchange/Citrix e decodificar AV_PAIRs.
- **Técnica/veredito:** o decoder raw-socket completo é o artefato executável
  mais forte do lote; o tell `WIN-XXXXXXXXXXX` e a causa raiz em
  `applicationHost.config` mostram profundidade real. **Forte.**
- **Overlap:** `hunt-sharepoint`, `hunt-aspnet`, `m365-entra-attack`.

### 101. `hunt-oauth`

- **Objetivo:** redirect_uri, state CSRF, nonce replay, bypass de ordem, leak por
  Referer, deep links móveis e client secrets.
- **Técnica/veredito:** a tabela browser-parse versus server-parse é a melhor
  análise original do lote, com a explicação correta do parsing WHATWG de
  userinfo. **Forte.**
- **Overlap:** `hunt-open-redirect`, `hunt-subdomain`, `hunt-ato`.

### 102. `hunt-open-redirect`

- **Objetivo:** achar redirects abertos e encadear para roubo de código OAuth,
  phishing ou SSRF.
- **Técnica/veredito:** a tabela de bypass e a cadeia `redirect_uri =
  target/redirect?url=evil` são corretas; a severidade honesta (Low isolado,
  Critical na cadeia) é boa. Verificação duplicada. **Sólida.**
- **Overlap:** `hunt-oauth`, `hunt-ssrf`, `hunt-ato`.

### 103. `hunt-prototype-pollution`

- **Objetivo:** prototype pollution client/server via merge/clone/`$.extend`/
  lodash, com gadgets para XSS e RCE.
- **Técnica/veredito:** reúne quatro famílias de gadget e distingue corretamente
  poluição client (XSS) de server (RCE). Duplica `hunt-nodejs`. **Sólida.**
- **Overlap:** `hunt-nodejs`, `hunt-xss`, `hunt-rce`.

### 104. `hunt-race-condition`

- **Objetivo:** races/TOCTOU em cupom, carteira, OTP, voto, convite, quota e
  reset, incluindo single-packet HTTP/2.
- **Técnica/veredito:** a referência de single-packet (TLS/HTTP2, last-byte sync,
  Wireshark, h2.0 versus h2.cl) é a melhor técnica do lote; os templates 2/3/5
  quebram a própria sincronização que prometem. **Forte.**
- **Overlap:** `hunt-mfa-bypass`, `hunt-business-logic`, `hunt-http-smuggling`.

### 105. `hunt-rce`

- **Objetivo:** RCE amplo em template engines, shell, YAML/XML, caminhos,
  resolução de dependência e superfícies cloud-native.
- **Técnica/veredito:** as correções `/icons/` versus `/cgi-bin/` para
  CVE-2021-41773 e o args4j `@file` do Jenkins são precisas; Gate 0 é forte.
  **Forte.**
- **Overlap:** `hunt-ssti`, `hunt-deserialization`, `hunt-file-upload`.

### 106. `hunt-saml`

- **Objetivo:** XSW, comment injection em NameID, stripping, XXE em assertions,
  manipulação de NameID e confusão de chave.
- **Técnica/veredito:** a explicação de comment injection distingue corretamente
  forma canônica assinada de extração de text-node; a nota de DEFLATE no binding
  Redirect é precisa. A tabela XSW usa descrições não canônicas. **Sólida.**
- **Overlap:** `saml-sso-attack`, `hunt-auth-bypass`, `hunt-xxe`.

### 107. `hunt-schema-enumeration`

- **Objetivo:** transformar erros de validação em descoberta de schema em
  PostgREST/Supabase, FastAPI, Zod, GraphQL e REST.
- **Técnica/veredito:** a extração de `hint` do PostgREST é um truque preto de
  alto rendimento. Erro factual: chama FastAPI de ".NET/Go"; skill fina e com
  verificação duplicada. **Fraca.**
- **Overlap:** `hunt-supabase`, `hunt-graphql`, `api-noauth-hunt`.

### 108. `hunt-session`

- **Objetivo:** fixation, invalidação em logout/senha/e-mail, IDs de baixa
  entropia, JWT como sessão, refresh reuse, SSO/DBSC e atributos de cookie.
- **Técnica/veredito:** a regra de duas sessões + body-diff + cookie lixo como
  controle negativo é a melhor disciplina de FP do lote; a regra static-vs-state
  é correta. **Forte.**
- **Overlap:** `hunt-ato`, `hunt-auth-bypass`, `hunt-mfa-bypass`.

### 109. `hunt-sharepoint`

- **Objetivo:** SharePoint on-prem: endpoints anônimos, versão, bypass SOAP
  legado, pré-condições do ToolShell (CVE-2025-53770), Picker.aspx e NTLM.
- **Técnica/veredito:** a cadeia de pré-condições do ToolShell é forte e corrige
  que machineKey é loot, não gate. Estrutura não conforme e `target.example`.
  **Forte.**
- **Overlap:** `hunt-aspnet`, `hunt-auth-bypass`, `hunt-ntlm-info`.

### 110. `hunt-source-leak`

- **Objetivo:** artefatos de fonte/build no início do recon: `.js.map`, Swagger,
  `.env`, `.git`, `.DS_Store` e chunks webpack.
- **Técnica/veredito:** o detector de faux-map e o fallback de bundle bruto são
  práticos; a verificação imprime `FAIL/FAIL`, a seção Pitfalls tem sufixo que
  quebra o contrato e há colisão de arquivos em `/tmp`. **Sólida.**
- **Overlap:** `js-secrets-extraction`, `source-leak-hunt`, `hunt-nextjs`.

### 111. `hunt-springboot`

- **Objetivo:** Actuator (heapdump, env, loggers, mappings, shutdown), SpEL, H2
  console, Jolokia e Spring4Shell.
- **Técnica/veredito:** o enumerador recusa `200 + Whitelabel` como exposição e
  o texto de SpEL nota corretamente que `exec()` retorna `Process`, exigindo OOB.
  É um cheat sheet sem prerequisites/related. **Sólida.**
- **Overlap:** `hunt-cloud-misconfig`, `hunt-rce`, `hunt-metrics-exposure`.

### 112. `hunt-sqli`

- **Objetivo:** SQL/NoSQL injection em GET/POST/JSON/header/cookie.
- **Técnica/veredito:** a classe de byte NUL (truncamento em drivers PHP
  quote-then-prepare) é o material mais original. Duas seções "Related Skills"
  idênticas e `Phase X` no lugar errado. **Sólida.**
- **Overlap:** `hunt-nosqli`, `hunt-ldap`, `security-arsenal`.

### 113. `hunt-ssrf`

- **Objetivo:** SSRF em fetchers, previews, imports, webhooks e renderizadores.
- **Técnica/veredito:** o gate "OOB ou não aconteceu" é o modelo do repositório,
  com 38 payloads e zero callbacks documentados como controle negativo. Porém
  `[REDACTED_IP]` substitui `169.254.169.254` e a skill chama `192.0.2.1` de
  "holy grail" do metadata. **Forte, com redaction quebrada.**
- **Overlap:** `hunt-xxe`, `hunt-cloud-misconfig`, `hunt-rce`.

### 114. `hunt-ssti`

- **Objetivo:** SSTI em Jinja2, Twig, Freemarker, ERB, Velocity, Thymeleaf,
  Smarty e Mako.
- **Técnica/veredito:** fingerprint por matemática diferencial e payload Jinja2
  OOB cego são bons; não há um curl sequer, só payloads, e diz que
  `{% import os %}` é Jinja2 (não é). **Sólida.**
- **Overlap:** `hunt-rce`, `hunt-xss`, `security-arsenal`.

### 115. `hunt-subdomain`

- **Objetivo:** takeover por CNAME/NS/A pendente, com foco em primitivas de ATO.
- **Técnica/veredito:** a tabela de cinco cadeias (OAuth redirect, cookie pai,
  CSP, CORS regex, DKIM/SPF) é excelente; usa `~/nuclei-templates` e `$GOPATH`.
  **Forte.**
- **Overlap:** `subdomain-enumeration`, `subdomain-takeover-hunt`, `hunt-oauth`.

### 116. `hunt-supabase`

- **Objetivo:** exploração Supabase após leak de URL/anon key: tabelas, RLS, RPC,
  signup, storage e org-ID.
- **Técnica/veredito:** a troca de org-ID contra RLS é a cadeia multi-tenant
  canônica. Falha grave: nunca menciona `service_role`, o segredo mais crítico;
  `ACCESS_TOKEN=*** "$SIGNUP"` é bash inválido. **Fraca.**
- **Overlap:** `hunt-firebase`, `firebase-supabase-attack`, `hunt-idor`.

### 117. `hunt-tls-network`

- **Objetivo:** HSTS, ciphers, certificados, AXFR, SPF/DKIM/DMARC, CT logs,
  CNAMEs pendentes, CAA e bypass de mTLS.
- **Técnica/veredito:** a calibração "o que realmente paga" é a mais honesta do
  repositório. O bloco SPF/DMARC tem erro de sintaxe real: `$(dig +short  #`
  comenta o `)` de fechamento e o script não parseia. **Forte, com shell
  quebrado.**
- **Overlap:** `email-security`, `hunt-subdomain`, `offensive-osint`.

### 118. `hunt-websocket`

- **Objetivo:** CSWSH, Origin/auth fracos no handshake, authz por mensagem,
  tampering e authz de namespace/room no socket.io.
- **Técnica/veredito:** a explicação packet-level (`40/admin,` versus `?nsp=`) é
  precisa e o gate "101 não é CSWSH" é correto. **Forte.**
- **Overlap:** `hunt-csrf`, `hunt-http-smuggling`, `hunt-session`.

### 119. `hunt-wordpress`

- **Objetivo:** mapeamento WordPress limitado antes de escolher o teste de
  vulnerabilidade.
- **Técnica/veredito:** é a única skill totalmente conforme ao STYLE: seis
  seções, `OUTPUT_DIR`, `sleep`, gate de mudança de estado e verificação por
  conteúdo. **Forte.**
- **Overlap:** `wordpress-plugin-hunt`, `xmlrpc-exploitation`,
  `wordpress-full-compromise`.

### 120. `hunt-write-gap`

- **Objetivo:** achar endpoints em que GET é protegido mas PATCH/POST/DELETE não.
- **Técnica/veredito:** a distinção exists/own/other user é boa, mas a skill tem
  148 linhas, `Verification` duplicada, Pitfalls copiados de memória-corruption e
  verificação errada (`204` em vez de `200` no PostgREST). **Fraca.**
- **Overlap:** `hunt-supabase`, `hunt-idor`, `hunt-mass-assignment`.

### 121. `hunt-xss`

- **Objetivo:** XSS refletido, armazenado, DOM, SVG/upload, markdown e cache
  poisoning.
- **Técnica/veredito:** a tabela de sinks por framework e a disciplina de marker
  atacam as duas maiores fontes de FP. Setup operacional fino e
  `/tmp/target_js` assumido. **Forte.**
- **Overlap:** `hunt-dom`, `hunt-cache-poison`, `s3-minio-content-type-xss`.

### 122. `hunt-xxe`

- **Objetivo:** XXE em SVG/Office, SOAP, SAML, troca JSON→XML, OOB cego, SSRF e
  RCE.
- **Técnica/veredito:** o pré-gate de entidade inline (se `hello` não expande,
  file read não funciona) é o melhor controle moderno; cita documento
  inexistente e usa en-dash no payload de bypass de WAF. **Forte.**
- **Overlap:** `hunt-ssrf`, `hunt-file-upload`, `hunt-saml`.

### 123. `llm-prompt-injection`

- **Objetivo:** teste autorizado de prompt injection, exposição de system prompt,
  tool use insegura e falha de fronteira RAG.
- **Técnica/veredito:** extração booleana e análise de context length são as
  técnicas que funcionam contra modelos endurecidos; falta triagem de alvo e
  rubric de impacto. Verificação duplicada. **Sólida.**
- **Overlap:** `hunt-llm-ai`, `hunt-mcp-security`.

### 124. `m365-entra-attack`

- **Objetivo:** descoberta de tenant, enumeração de usuários, Smart Lockout,
  bypass de CA, validação ROPC, prova SAML e detecção de atacante ativo.
- **Técnica/veredito:** a tabela AADSTS e a armadilha de substring em
  `"access_token"` são excepcionais; é uma das skills mais críveis do lote.
  `engagement_log/` hardcoded e `pip --break-system-packages`. **Forte.**
- **Overlap:** `password-spray-methodology`, `hunt-mfa-bypass`, `okta-attack`.

### 125. `meme-coin-audit`

- **Objetivo:** rug detection em meme coins: mint oculto, honeypot, fee
  manipulação, drenagem de LP, bonding curve e Token-2022.
- **Técnica/veredito:** "autoridade retida É o vetor de rug" é o modelo correto,
  mas `solana account ... | check mint_authority` não devolve autoridades
  parseadas e não há prerequisites. **Sólida.**
- **Overlap:** `web3-audit`, `triage-validation`.

### 126. `mid-engagement-ir-detection`

- **Objetivo:** detectar patch do SOC, atividade concorrente e mudança de estado
  durante o engajamento, convertendo em entregáveis.
- **Técnica/veredito:** a tese "falha de reprodução é mudança de estado, não falso
  positivo" é original e valiosa; a execução tem `$ENGAGEMENT_DIR` indefinido e
  depende de `bc`. **Forte como ideia.**
- **Overlap:** `m365-entra-attack`, `evidence-hygiene`,
  `cross-wave-delta-analysis`.

### 127. `offensive-osint`

- **Objetivo:** índice operacional de recon externo: subdomínios, APIs, Swagger,
  identidade, buckets, origem, fingerprints, CI/CD, padrões de segredo, breach.
- **Técnica/veredito:** o score de interesse e a biblioteca de hints viram recon
  em leads priorizados. O refactor deixou a navegação quebrada: o corpo só tem
  headings §0–6, §20, §21, §39, §49, §50, mas o self-test aponta dezenas de
  seções ausentes. **Sólida.**
- **Overlap:** `osint-methodology`, `web2-recon`, `github-secret-hunting`.

### 128. `okta-attack`

- **Objetivo:** cadeia de ataque com Okta como IdP: descoberta, enumeração,
  fatores, spray, redirect_uri OIDC, metadata SAML e API admin.
- **Técnica/veredito:** a tabela de interpretação de fatores é útil e o loop de
  redirect_uri é compacto. Verificação cosmética e descrição muito longa.
  **Sólida.**
- **Overlap:** `password-spray-methodology`, `osint-methodology`,
  `m365-entra-attack`.

### 129. `ops-proxyns`

- **Objetivo:** roteamento Tor em nível de kernel via network namespaces
  (`proxy-ns`), cobrindo TCP/UDP/DNS.
- **Técnica/veredito:** a abordagem por namespace é melhor que `LD_PRELOAD` para
  binários Go/Rust. A verificação não testa Tor nem proxy-ns (usa porta 8080 em
  vez de 9050) e sobrescreve `/etc/tor/torrc` sem backup. **Fraca.**
- **Overlap:** `osint-methodology`, `web2-recon`.

### 130. `osint-methodology`

- **Objetivo:** metodologia de recon externo em 1.731 linhas: pipeline de 5
  estágios, 29 tipos de ativo, rubric de confiança/severidade, identidade, API/JS/
  mobile/cloud, cripto, imagem/vídeo, atribuição e phishing.
- **Técnica/veredito:** o modelo de confiança, a "rule of three" e os probes de
  identidade (`getuserrealm.srf`) são fortes. Estruturalmente não conforme,
  referências internas dependem de outra skill e há contradição com
  `okta-attack` sobre enumeração. **Forte como referência.**
- **Overlap:** `web2-recon`, `offensive-osint`, `recon-playbook`.

### 131. `password-spray-methodology`

- **Objetivo:** pipeline universal de spray: enumerar, classificar lockout,
  gerar padrões, executar por protocolo, interpretar erros e detectar terceiro.
- **Técnica/veredito:** a garantia matemática do Smart Lockout (≤1 tentativa/
  usuário não causa lockout de 10) e o trap de shadow-throttle são bons. O loop
  de shadow-throttle lê `/tmp/bf_body`, que nunca é escrito. **Sólida.**
- **Overlap:** `m365-entra-attack`, `okta-attack`, `hunt-brute-force`.

### 132. `recon-sector`

- **Objetivo:** recon setorial SMB parametrizado por `references/sectors.yaml`.
- **Técnica/veredito:** é a melhor estrutura do lote e as regras de verificação
  (CORS ACAC, `methodResponse`, PII em log, `Index of`) seguem o STYLE. Não roda
  como escrito: `references/probe_sector.py` não existe. **Forte, artefato
  ausente.**
- **Overlap:** `recon-sector-expansion`, `wp-mass-recon`,
  `cors-credential-wordpress`.

### 133. `recon-sector-expansion`

- **Objetivo:** achar novos setores/domínios em vez de aprofundar um alvo.
- **Técnica/veredito:** o padrão de HTML do crt.sh contorna a API JSON instável.
  O texto está preso ao modelo antigo de "skills por setor" (25 skills que não
  existem) e usa placeholders `[SECTOR_EXAMPLE]`. **Fraca.**
- **Overlap:** `recon-sector`, `web2-recon`, `wp-mass-recon`.

### 134. `redteam-mindset`

- **Objetivo:** disciplina de operador: não se autolimitar, não retratar por uma
  falha, varrer apps irmãs, tratar WAF/SOC como dado e registrar tudo.
- **Técnica/veredito:** as árvores de decisão de bloqueio (CAPTCHA/WAF) e a
  disciplina de retratação são o melhor conteúdo; é prosa quase sem comandos.
  **Forte como pensamento.**
- **Overlap:** `triage-validation`, `mid-engagement-ir-detection`,
  `redteam-report-template`.

### 135. `redteam-report-template`

- **Objetivo:** estrutura de relatório red team voltado ao cliente, com seis
  seções por achado, status, DOCX, tom e QA pré-entrega.
- **Técnica/veredito:** o campo de status ("confirmado; corrigido durante o
  engajamento") e a tradução por audiência são diferenciadores. Aponta para
  `templates/` inexistente e para `~/.claude/...`; exige python-docx não
  declarado. **Fraca na execução, boa no conteúdo.**
- **Overlap:** `report-writing`, `bugcrowd-reporting`, `evidence-hygiene`.

### 136. `report-writing`

- **Objetivo:** escrita de relatório de bug bounty para H1/Bugcrowd/Intigriti/
  Immunefi, com fórmula de título, CVSS e contra-argumentos de downgrade.
- **Técnica/veredito:** a fórmula de título e a ordem "título → impacto → curl →
  passos" são corretas; a verificação faz grep de palavras que o arquivo
  necessariamente contém. **Sólida.**
- **Overlap:** `triage-validation`, `bugcrowd-reporting`, `security-arsenal`.

### 137. `security-arsenal`

- **Objetivo:** biblioteca de payloads e bypass: XSS, SSRF, SQLi, XXE, traversal,
  IDOR/auth, JWT/OAuth, NoSQLi, command injection, SSTI, smuggling, WebSocket,
  MFA e SAML.
- **Técnica/veredito:** amplitude e as notas de 2026 (CL.TE morto em
  Nginx/Caddy/Envoy; XXE morto em lxml ≥5) são honestas. É referência, não skill
  executável; conflita com `osint-methodology` sobre severidade de headers.
  **Sólida como arsenal.**
- **Overlap:** `triage-validation`, praticamente todas as `hunt-*`.

### 138. `supply-chain-attack-recon`

- **Objetivo:** dependency confusion, typosquat, injeção em GitHub Actions,
  imagens expostas, SBOM e registry interno.
- **Técnica/veredito:** o grep de workflow injection (tags mutáveis) é preciso e
  atual; cita `feedback_skill_boundaries` como skill, mas não existe. Placeholders
  executáveis. **Sólida.**
- **Overlap:** `hunt-rce`, `cloud-iam-deep`, `hunt-cicd`.

### 139. `triage-validation`

- **Objetivo:** matar achados ruins antes do relatório: sete perguntas, quatro
  gates, lista never-submit, CVSS, retração.
- **Técnica/veredito:** o template de request da Q1 e os quatro casos de retração
  codificam modos reais de falha. O smoke test procura "Question N", mas os
  headings são "QN". **Forte.**
- **Overlap:** `security-arsenal`, `report-writing`, `redteam-mindset`.

### 140. `vmware-vcenter-attack`

- **Objetivo:** matriz externa para vCenter exposto, Workspace ONE, Aria e ESXi.
- **Técnica/veredito:** a confirmação por canário no Workspace ONE evita o falso
  positivo clássico de "uid= apareceu"; pesquisa e CVEs são boas. Diz que vCenter
  interno está fora de escopo e depois usa âncoras internas. **Forte.**
- **Overlap:** `enterprise-vpn-attack`, `hunt-saml`, `hunt-rce`.

### 141. `web2-recon`

- **Objetivo:** pipeline de descoberta web2: subfinder/Chaos, dnsx/httpx,
  katana/wayback/gau, ffuf, SecretFinder/LinkFinder, monitoramento e Swagger.
- **Técnica/veredito:** o fallback para SIGSEGV em macOS e a lista Swagger são
  práticos; muita dependência de `~/tools`, `~/wordlists` e binários ProjectDiscovery.
  A regra de 5 minutos conflita com `redteam-mindset`. **Sólida.**
- **Overlap:** `osint-methodology`, `offensive-osint`, `recon-playbook`.

### 142. `web3-audit`

- **Objetivo:** auditoria de contrato Solidity/DeFi: dez classes de bug, greps,
  kill signals, template Foundry e exemplos pagos.
- **Técnica/veredito:** o catálogo de variáveis de estado e as variantes de
  accounting desync são fortes. A verificação checa ferramentas Solana para um
  corpo Solidity/EVM. **Sólida, verificação errada.**
- **Overlap:** `meme-coin-audit`, `report-writing`, `triage-validation`.

### 143. `wordpress-cors-xmlrpc-rce-chain`

- **Objetivo:** avaliar se CORS, XML-RPC, papel e upload compõem execução não
  autorizada de arquivo.
- **Técnica/veredito:** é a melhor skill de estado de evidência do lote: separa
  observado de inferido e upload de execução. Como procedimento, é
  subespecificada. **Forte.**
- **Overlap:** `wordpress-full-compromise`, `cors-credential-wordpress`,
  `xmlrpc-exploitation`.

### 144. `wp-plugin-automation`

- **Objetivo:** detectar plugins, extrair versão e casar CVE em lote.
- **Técnica/veredito:** o mapa slug→diretório (`revslider` →
  `slider-revolution`) é detalhe de campo. O comparador de versão está invertido
  (linhas 76–93): `sort -V | head -1` pega a menor e a condição sinaliza a maior
  como vulnerável. **Quebrada no núcleo.**
- **Overlap:** `wp-plugin-cve-hunt` (quase cópia), `hunt-wordpress`.

### 145. `wp-plugin-cve-hunt`

- **Objetivo:** pesquisa guiada de CVE de plugin com múltiplas fontes de versão,
  WPScan/NVD/Patchstack, comparação e eliminação de FP.
- **Técnica/veredito:** a extração multi-fonte e o checklist "patchado mas readme
  velho" são melhores que a automação; o lookup NVD fixa `cvssMetricV31[0]` e
  retorna N/A em CVE só v2/v4. **Sólida.**
- **Overlap:** `wp-plugin-automation`, `hunt-wordpress`.

### 146. `wstg-web-pentest`

- **Objetivo:** metodologia completa de 12 fases alinhada ao OWASP WSTG, com
  comandos, saída esperada, pitfalls e remediação.
- **Técnica/veredito:** é a melhor estrutura de skill grande: ladder
  Signal→Exposed→Vulnerable→Exploitable e folha final de cinco perguntas. Bug:
  trata `cpanel:2082` como path (`https://alvo/cpanel:2082`) e `index.html.~`
  como extensão. **Forte.**
- **Overlap:** praticamente todo o catálogo `hunt-*` e `web2-recon`.

---

## Análise transversal

### Distribuição de conformidade

- 33/146 skills têm as seis seções obrigatórias (22,6%).
- 113/146 falham ao menos uma seção.
- 86/146 não declaram `platforms`.
- 87/146 não têm `related_skills`; só 2 usam o formato indentado que o
  validador reconhece.
- 89/146 têm descrição acima de 100 caracteres; o STYLE pede uma frase de até
  60 caracteres.
- 133/146 estão em `1.1.0`; as nove exceções são justamente as versões 2.x/3.x
  migradas. O carimbo uniforme sugere edição em massa, não revisão por skill.

A única skill totalmente conforme entre as `hunt-*` de redteam é
`hunt-wordpress`. Isso é significativo: o arquivo que serve de modelo está no
lugar certo, mas não foi usado como template.

### Defeitos verificados localmente

| Arquivo:linha | Defeito | Prova |
|---|---|---|
| `recon/deep-invade/SKILL.md:96`, `recon/xmlrpc-exploitation/SKILL.md:137`, `redteam/hunt-ssrf/SKILL.md:483`, `redteam/hunt-host-header/SKILL.md` | Usa `192.0.2.1` como endpoint de metadata; o correto é `169.254.169.254` (AWS/Azure/GCP variam) | `192.0.2.0/24` é TEST-NET-1, não link-local |
| `recon/error-log-mining`, `recon/exchange-owa-attack`, `redteam/hunt-csrf:180`, `redteam/wp-plugin-cve-hunt:63`, `redteam/hunt-source-leak:102`, `redteam/hunt-springboot:73`, `redteam/hunt-ato:252`, `redteam/hunt-tls-network:196,207`, `redteam/hunt-nextjs:48`, `recon/wordpress-plugin-hunt:224` | `grep -Eo` com `\K` | reproduzido: `echo 'a="x"' \| grep -Eo 'a="\K[^"]+'` retorna vazio; com `grep -P` funciona |
| `recon/firebase-supabase-attack/SKILL.md:262` vs `:268,277` | Insere `test=rls_bypass_probe_<ts>`, mas PATCH/DELETE filtram `test=eq.RLS_BYPASS` | leitura direta |
| `redteam/hunt-auth-bypass/SKILL.md` (byte 22588; EOF) | Byte NUL faz `grep` tratar o arquivo como binário; code fence aberto antes de "Related Skills" nunca fecha | `file` = `data`, `grep -c $'\x00'`; `tail` mostra fence aberto |
| `redteam/hunt-cloud-misconfig/SKILL.md:198` | `echo 192.0.2.1 \| grep -q 169.254` sempre falha | leitura direta |
| `redteam/hunt-tls-network/SKILL.md:133-134` | `SPF=$(dig +short  # ...)` e `DMARC=$(...)`: o `#` comenta o `)` de fechamento | `bash -n` falha com "unexpected EOF while looking for matching `)`" |
| `redteam/hunt-supabase/SKILL.md:253` | `ACCESS_TOKEN=*** "$SIGNUP" \| python3 ...` | atribuição inválida; deveria ser `ACCESS_TOKEN=$(... \| python3 ...)` |
| `recon/subdomain-enumeration/SKILL.md:171-180` | `dnsx -a -resp-only` emite só IPs; o código lê `cut -f1` como subdomínio e `cut -f2` como IP | leitura direta |
| `recon/web-enumeration/SKILL.md:65-69` | Body é lowercased, mas os marcadores incluem `<!DOCTYPE`/`<!DOCTYPE`; o teste de catch-all nunca casa | leitura direta |
| `redteam/wp-plugin-automation/SKILL.md:76-93` | Comparador de versão invertido: `sort -V \| head -1` pega a menor e a condição marca a maior como vulnerável | leitura direta e teste com `sort -V` |
| `redteam/hunt-api-misconfig/SKILL.md:265` | `-H "X-API-Key: *** "https://..."` — quote de fechamento ausente | leitura direta |
| `recon/flask-werkzeug-attack/SKILL.md` (todo) | `PORT`literal nos comandos e `FAIL/FAIL` na verificação | leitura direta |
| `recon/unauth-api-flow-hijack/SKILL.md:109,157` | `$FLOW_ID` usado sem definição | leitura direta |
| `recon/wp-mass-recon/SKILL.md:48` | Invoca `parallel_batch.py`, mas o arquivo é `scripts/scanner.py` | `ls recon/wp-mass-recon/scripts/` |
| `redteam/hunt-schema-enumeration/SKILL.md:15,61` | Chama FastAPI de ".NET/Go"; FastAPI é Python | leitura direta |
| `redteam/hunt-mcp-security/SKILL.md:30-55` | Inventa caminhos REST (`/mcp/tools/execute`, `/mcp/schema`) para um protocolo JSON-RPC | leitura direta |
| `redteam/hunt-write-gap/SKILL.md` | `Verification` duplicada e Pitfalls sobre memória-corrupção | leitura direta |
| `redteam/wstg-web-pentest/SKILL.md:272,306` | Trata `cpanel:2082` como path e cria `index.html.~` | leitura direta |
| `redteam/password-spray-methodology/SKILL.md:106` | Lê `/tmp/bf_body`, que o curl do loop nunca escreve (`-o /dev/null`) | leitura direta |
| `redteam/hunt-source-leak/SKILL.md:415-416` | Verificação imprime `FAIL`/`FAIL` | leitura direta |

### Artefatos e referências quebradas

- `redteam/recon-sector/SKILL.md:43` chama `references/probe_sector.py`; só
  `references/sectors.yaml` existe.
- `redteam/redteam-report-template/SKILL.md:177,278` aponta para
  `templates/reference.docx`; o diretório `templates/` não existe.
- Cinco skills citam `docs/verification/*.md` inexistentes
  (`hunt-oauth`, `web2-recon`, `hunt-xxe`, `hunt-graphql`,
  `hunt-cloud-misconfig`).
- Referências a skills inexistentes: `hunt-cache-poisoning`
  (`bug-bounty:1624`), `feedback_skill_boundaries` (`supply-chain:381`,
  `vmware:236`), `hunt-python` (`flask-werkzeug:171`) e
  `proxy-geoip-automation` (`stealth-browser-launch:15`).
- `redteam/hunt-sqli` tem duas seções `Related Skills & Chains` idênticas
  (linhas 432 e 456).
- `redteam/hunt-supabase` e `redteam/hunt-file-upload` têm seções depois de
  "Related Skills", quebrando a ordem do contrato.
- `llm-prompt-injection`, `hunt-metrics-exposure`, `hunt-open-redirect`,
  `hunt-schema-enumeration` e `hunt-nextjs` têm `Verification` duplicada.
- `hunt-source-leak` usa `## Pitfalls (Read Before Probes)`; o validador só
  reconhece `## Pitfalls` exato.

### Duplicação

A duplicação não é incidental; há blocos copiados inteiros:

| Par | Evidência |
|---|---|
| `bug-bounty` × `bb-local-toolkit` | 1.530 linhas com ~30 linhas de diferença; ambos com 1.600+ linhas |
| `wp-plugin-automation` × `wp-plugin-cve-hunt` | Mesma tabela de CVE, mesma extração de versão; a primeira tem comparador errado, a segunda corrige |
| `hunt-prototype-pollution` × `hunt-nodejs` | Fases 2–3 são o mesmo conteúdo, com payloads ligeiramente divergentes |
| `hunt-auth-bypass` × `hunt-broken-function-level-auth` | BFLA é uma seção reescrita da primeira |
| `cache-attack` × `hunt-cache-poison` | Mesma superfície e mesmas técnicas |
| `firebase-supabase-attack` × `hunt-firebase`/`hunt-supabase` | Cobertura idêntica em duas gerações |
| `source-leak-hunt` × `web-enumeration` | Mesma varredura de arquivos sensíveis |
| `subdomain-enumeration` × `staging-subdomain-hunt` | Mesmo bloco de crt.sh e mesma descoberta |
| `saml-sso-attack` × `hunt-saml` | Mesmo domínio, duas profundidades |
| `stealth-browser-launch` × `humanize-automation` × `tls-fingerprint-impersonation` × `http2-header-impersonation` | Quatro camadas de uma pilha de evasão sem guia único |

O repositório tem clusters de WordPress (10 skills), CORS (4), identidade (6) e
recon DNS (3). O STYLE manda colapsar skills que diferem só por nome de setor;
`recon-sector` faz isso corretamente com YAML, mas as 25 skills de setor que ela
diz substituir não existem mais — e `recon-sector-expansion` ainda se refere a
elas.

### Portabilidade

O contrato pede `${OUTPUT_DIR:-./output}`, ferramentas declaradas e fallback
quando possível. Na prática:

- A maioria das skills v1 usa `~/tools`, `~/wordlists`, `/usr/share/seclists`,
  `/tmp`, `~/nuclei-templates`, `$GOPATH` e `brew` sem declarar sistema.
- `hunt-firebase` usa `/tmp` 12 vezes; `hunt-file-upload`, 10; `hunt-supabase`
  e `password-spray` compartilham arquivos fixos em `/tmp`.
- `ops-proxyns` sobrescreve `/etc/tor/torrc` sem backup.
- `hunt-http-smuggling` exige escrita em `/tools`.
- `redteam-report-template` e `hunt-dispatch` assumem `~/.claude/skills` e um
  runtime `/hunt` que não está no repositório.
- `[REDACTED_IP]` aparece em sete skills como se fosse um valor colável; em
  `hunt-ssrf` ele substitui justamente o IP de metadata.

### Verificação

Há dois estilos:

1. **Semântico** — baseline, body-diff, controle negativo, callback OOB,
   artefato. Exemplos: `hunt-session`, `hunt-ssrf`, `hunt-websocket`,
   `hunt-tls-network`, `hunt-ldap`, `hunt-k8s`, `hunt-cicd`, `hunt-xss`.
2. **Cosmético** — `grep -q "^## Pitfalls" SKILL.md` e verificar se o arquivo
   contém `name:`. Esse bloco é anexado no fim de dezenas de skills e testa a
   forma do documento, não o procedimento.

O próprio STYLE define o critério semântico (CORS com ACAO refletido **e**
ACAC; XML-RPC com `methodResponse`; log com PII; listing com `Index of`), mas
só uma minoria implementa os controles que o documento exige. `email-security`,
`hardcoded-credential-hunt`, `hunt-cloud-misconfig` e `hunt-write-gap` são
exemplos de verificação que passa fácil por um resultado falso.

### Mudanças de estado

Cadastro, upload de webshell, PATCH/DELETE, criação de PR/issue, poisoning de
cache, sprays, alteração de senha, `actuator/shutdown`, execução em container e
claims de domínio são mudanças de estado. A maioria não tem um gate explícito
antes do comando. Exceções positivas: `api-noauth-hunt`
(`I_HAVE_EXPLICIT_WRITE_AUTHORIZATION`), `hunt-wordpress`,
`enterprise-vpn-attack`, `wordpress-cors-xmlrpc-rce-chain` e
`vmware-vcenter-attack`. Cleanup raramente é documentado.

### Frontmatter, validador e CI

- O schema do STYLE usa `metadata:` aninhado; quase todo o catálogo usa YAML
  plano. O validador só reconhece `related_skills` indentado, então 87 skills
  com o campo plano escapam da checagem de referências.
- `platforms` é exigido pelo AGENTS.md, mas o validador trata como aviso; 86
  skills não o têm.
- O validador não detecta `\K`, IP errado, comparador invertido, fence aberto,
  NUL, shell inválido, CRUD que não casa, artefato ausente citado em prosa ou
  `[REDACTED_IP]`. O CI fica verde com 0 erros e 449 avisos.
- O workflow `.github/workflows/validate.yml` apenas executa o validador; não há
  lint de shell, link checker de prosa, parser de YAML real nem teste de
  comandos.

### Contradições entre skills

- `osint-methodology` diz que Okta authn 400 versus 401 revela usuário;
  `okta-attack` diz que a superfície é unificada/endurecida.
- `security-arsenal`/`triage-validation` listam headers ausentes como
  "never submit"; `osint-methodology` os pontua como MEDIUM/HIGH.
- `web2-recon` manda desistir em 5 minutos; `redteam-mindset` manda não parar.
- Severidade de usuários públicos de WordPress e CORS em dados públicos diverge
  entre `recon-sector`, `wp-plugin-automation` e `triage-validation`.
- `hunt-ato` diz 9 caminhos e documenta 12.
- `hunt-fastapi` afirma que Pydantic v2 lança erro para campos extras por
  padrão; o default real é `ignore`.

## Recomendações priorizadas

### P0 — corrigir o que não executa

1. Trocar `192.0.2.1` por `169.254.169.254` nos payloads de metadata e remover
   `[REDACTED_IP]` dos valores coláveis (ou documentar a constante).
2. Trocar `grep -Eo '...\K...'` por `grep -Po` ou reescrever com `sed`.
3. Corrigir o fence e o byte NUL de `hunt-auth-bypass`.
4. Corrigir o comparador de `wp-plugin-automation` para `sort -V | tail -1` e
   comparar com a versão corrigida.
5. Corrigir `ACCESS_TOKEN` no `hunt-supabase`, o filtro CRUD do Firebase, o bloco
   SPF/DMARC do `hunt-tls-network` e o parsing do `dnsx` no
   `subdomain-enumeration`.
6. Corrigir o teste de catch-all de `web-enumeration` e o `/tmp/bf_body` do
   `password-spray-methodology`.
7. Recriar `recon-sector/references/probe_sector.py` e
   `redteam-report-template/templates/`, ou remover as referências.
8. Resolver as quatro referências a skills inexistentes.

### P1 — cumprir o contrato

1. Adicionar as seis seções às 113 skills que falham, começando pelas 95 sem
   `Prerequisites` e pelas 113 sem `How to Run`.
2. Padronizar o frontmatter no formato do STYLE e fazer o validador parsear YAML
   de verdade, incluindo `metadata.related_skills` plano.
3. Substituir o self-test de três greps por ao menos uma verificação viva ou de
   fixture por skill.
4. Declarar `platforms`, ferramentas, privilégios e dependências; trocar
   `/tmp`/`~/tools` por `${OUTPUT_DIR:-./output}`.
5. Adicionar gate de autorização antes de toda mudança de estado e uma seção de
   cleanup.

### P2 — reduzir e consolidar

1. Fundir `bug-bounty` e `bb-local-toolkit` em um documento canônico.
2. Fundir `wp-plugin-automation` em `wp-plugin-cve-hunt`.
3. Fundir `source-leak-hunt` e `web-enumeration`.
4. Fundir `cache-attack` em `hunt-cache-poison`.
5. Fundir `hunt-broken-function-level-auth` em `hunt-auth-bypass`.
6. Escolher uma geração para Firebase/Supabase e uma para SAML.
7. Criar um guia único para a pilha de evasão TLS/HTTP2/browser.
8. Unificar Django/FastAPI/Laravel/Node em uma skill parametrizada por
   framework.
9. Remover `hunt-dispatch` se o runtime `/hunt` não for parte do escopo.

## Apêndice A — skills mais fortes

`recon-playbook`, `cross-attack-chains`, `wordpress-full-compromise`,
`triage-validation`, `redteam-mindset`, `evidence-hygiene`,
`wordpress-cors-xmlrpc-rce-chain`, `wstg-web-pentest`, `hunt-wordpress`,
`hunt-session`, `hunt-race-condition`, `hunt-ssrf`, `hunt-websocket`,
`hunt-ntlm-info`, `hunt-oauth`, `hunt-ldap`, `hunt-k8s`,
`hunt-aspnet`, `hunt-cicd`, `m365-entra-attack`, `enterprise-vpn-attack`,
`apk-redteam-pipeline`, `supply-chain-attack-recon`, `humanize-automation`,
`port-mass-scan`, `recon-sector`.

## Apêndice B — skills que precisam de reescrita

`flask-werkzeug-attack`, `email-security`, `web-enumeration`,
`js-secrets-extraction`, `wp-plugin-rest-auth-bypass`, `unauth-api-flow-hijack`,
`wp-plugin-automation` (núcleo quebrado), `hunt-supabase` (lacuna de
`service_role`), `hunt-mcp-security`, `hunt-schema-enumeration`,
`hunt-django`, `hunt-fastapi`, `hunt-cloud-misconfig`, `cloud-iam-deep`,
`ops-proxyns`, `web3-audit` (verificação de outro ecossistema),
`recon-sector-expansion`, `redteam-report-template`, `hunt-dispatch`.

## Apêndice C — limites do estudo

- Revisão read-only; nenhuma skill foi executada contra alvo real.
- Os defeitos marcados como verificados foram reproduzidos no shell local, não
  validados contra as versões de ferramenta dos autores.
- Contagens de linhas, seções e frontmatter foram extraídas por script do
  estado atual do commit.
- O estudo não julgou a correção técnica de cada payload contra o comportamento
  real de cada produto; apontou inconsistências internas e riscos de execução.
- Evidência privada de engajamento não faz parte do repositório por desenho.
