# Attack Surface Catalog Reference

Estrutura padrao para documentar a superficie de ataque de um alvo apos todas as fases de recon. Gere este arquivo por alvo em `/root/output/recon_us/<domain>/ATTACK_SURFACE.md`.

Este documento é parte de um **suite de 3 documentos** gerados após deep invade:

| Documento | Propósito | Localização |
|-----------|-----------|-------------|
| `MASTER_REPORT.md` | Relatório completo com todas as descobertas, CVEs, attack chains, PoCs, waves | `/root/output/recon_us/<domain>/MASTER_REPORT.md` |
| `ATTACK_SURFACE.md` | (este) Catálogo de endpoints, portas, serviços, CORS, tecnologia | `/root/output/recon_us/<domain>/ATTACK_SURFACE.md` |
| `EXPLOIT_CHAINS.md` | Cadeias de exploração com PoCs curl passo a passo | `/root/output/recon_us/<domain>/EXPLOIT_CHAINS.md` |

Gere ATTACK_SURFACE.md e EXPLOIT_CHAINS.md em paralelo via delegate_task (Flash), enquanto Pro escreve MASTER_REPORT.md diretamente. Consulte o skill `recon-playbook` seção Phase 3.5 para o fluxo completo.

## Quando usar

- Apos concluir as fases de recon (subdominios, portas, web enum, plugins, CORS, XMLRPC)
- ANTES de iniciar explotacao ou escrever relatorios de bug bounty
- Para consolidar todos os achados em um unico documento de referencia

## Estrutura Padrao (16 secoes)

### 1. Resumo Executivo
Visao geral do alvo, tech stack, riscos imediatos. 1-2 paragrafos.

### 2. Catalogo de Portas
Tabela: Porta | Servico | Status | Observacao
Incluir: 21(FTP), 22(SSH), 53(DNS), 80(HTTP), 143(IMAP), 443(HTTPS), 587(SMTP), 993(IMAPS), 3306(MySQL), 8443, 8080, 27017(MongoDB), 6379(Redis)

### 3. Subdominios
Tabela: # | Subdominio | Resolve | Notas
Agrupar por funcao: admin/api/dev/staging destacados como ALERTA

### 4. Tecnologias e Stack
Tabela: Componente | Tecnologia | Versao | Detalhes
Secao de Versoes Criticas para versoes EoL ou com CVEs conhecidos

### 5. Caminhos HTTP Descobertos
Separar por instalacao:
- 5.1 Instalacao moderna (raiz)
- 5.2 Instalacao legada (/magical/, /old/, /blog/, etc.)
- 5.3 Foruns e CMS secundarios (/forum/, /wineboard/, /bbpress/)
- 5.4 CGI e Scripts legados

### 6. Matriz de Endpoints HTTP
Tabela completa: # | Caminho | Status | Tam. | CORS | Categoria
39+ endpoints com codigos de status HTTP e flag CORS

### 7. WordPress REST API
- 7.1 Tabela de endpoints REST com status e CORS
- 7.2 CORS Misconfiguration detail (ACAO + ACAC values)

### 8. XMLRPC
- 8.1 Informacoes gerais (URL, status, metodo count)
- 8.2 Resumo por categoria com quantidades
- Destacar system.multicall e pingback.ping

### 9. MyBB / Foruns Secundarios
- 9.1 Endpoints do forum
- 9.2 Riscos associados (admin exposto, config exposto)

### 10. CGI e Scripts Legados
Scripts CGI, servlets, binarios legados

### 11. Plugins e Componentes
- 11.1 WordPress Plugins (com versoes)
- 11.2 Temas
- 11.3 Componentes de CMS secundarios

### 12. IDs de Tracking e Publicidade
- Google AdSense (ca-pub-*)
- Google Analytics (G-*, UA-*)
- Facebook Pixel, Hotjar, etc.

### 13. Caminhos de Servidor
- 13.1 phpinfo: Document Root, paths de config
- 13.2 error_log expostos (tamanho, localizacao)
- 13.3 Estrutura de diretorios inferida

### 14. CORS -- Status por Endpoint
Tabela: Endpoint | ACAO | ACAC | Risco
Separar endpoints COM CORS vs SEM CORS

### 15. Usuarios WordPress Enumerados
Total de usuarios, IDs, tecnicas de ataque via enumeracao

### 16. Anexo: Metodos XMLRPC (Completo)
Listar todos os 76+ metodos com tabelas por prefixo:
- system.* (4)
- wp.* (22) + wp.edit.* (6) + wp.new.* (6) + wp.delete.* (5)
- mt.* (8)
- pingback.* (1)
- demo.* (2)
- taxonomy.* (4)
- media.* (2)
- comment.* (6)
- option.* (4)
- post.* (7)

### Checklist de Exploracao Prioritaria
Tabela final com 8-12 itens priorizados (Critico -> Alta -> Media -> Baixa)

## Dados a incluir (verificar de cada fase)

| Fase de Recon | Dados para o catalogo |
|---------------|----------------------|
| Subdominios | 23 subdominios com status de resolucao |
| Portas | 8+ portas abertas com servico |
| Web enum | 39+ caminhos HTTP com status codes |
| CORS teste | ACAO + ACAC por endpoint WP REST |
| XMLRPC | 76 metodos completos, SSRF, multicall |
| Plugins | Versoes do Elementor, ElementsKit, etc. |
| Source leaks | phpinfo, error_log, .env expostos |
| Tech detect | Apache, PHP, WP, MyBB, cPanel |

## Formato

- Idioma: PT-BR (Portugues Brasileiro) ou EN conforme solicitado
- Tabelas Markdown com cabecalhos alinhados
- Destaques em **negrito** para achados criticos
- Codigo inline com `backticks` para paths e comandos
- Blocos ``` para codigo e dados brutos
- Nao usar Unicode/emoji se o security scanner bloquear -- usar equivalentes ASCII
