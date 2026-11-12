---
name: bfla-account-controls
description: Bug bounty methodology for hunting and validating Broken Function-Level Authorization (BFLA) on account-level security controls of multi-tenant SaaS - IP allowlists, SSO/SAML settings, session policies, audit exports. Use when testing RBAC/role matrices, probing admin endpoints with non-admin accounts, confirming authorization flaws, falsifying bypass vectors (XFF spoofing), or writing VRT reports for access control bugs. Worked example LaunchDarkly writer-role IP allowlist BFLA.
---

# BFLA hunting on account-level security controls

## Core thesis

Authorization drift concentrates in **account/organization settings surfaces** ("Account settings → Security", "Org settings"): the UI gates them to admins, public role docs say Admin-only, but backend policies are maintained separately from docs and UI. The bug class is not injection — it is a missing `acct`-resource statement check for one specific role. Find it by systematic write-probing with a real non-admin identity, never by reading code.

## Phase 0 — Setup and safety

1. Provision at least 2 accounts in a DISPOSABLE test org: Owner + target role (e.g., Writer) + optionally Reader. Capture cookies per account into separate files (Netscape format works with `requests`).
2. Fix a consistent User-Agent across all requests; capture API tokens for each role when possible (tokens exercise `Authorization` path; cookies exercise browser path — test BOTH).
3. Safety rules (non-negotiable):
   - NEVER enable IP restrictions / lockout-class flags unless your current egress IP is already on the list (vendors often return an anti-lockout 409 otherwise — that message is itself evidence).
   - Every mutating probe must have a scripted revert; verify final state (`totalCount=0`, toggles false) before ending.
   - Single egress IP = you CANNOT live-prove blocking of other IPs. Do not brick your only org trying. Use vendor guard messages as enforcement evidence instead.

## Phase 1 — Map the API surface before touching it

1. Fetch the OpenAPI spec if exposed (e.g., `/api/v2/openapi.json`, may require beta header like `LD-API-Version: beta`). Extract exact request body schemas — sending guessed bodies produces false 400s that mask authz behavior.
2. Enumerate endpoints by blast-radius class:
   - Account-level security controls (highest value): IP allowlist, SSO/SAML config, domain verification, session/MFA policy, member invites, custom roles, token policy.
   - Org-wide integrations: relay/proxy configs, webhooks, OAuth clients/apps.
3. Cross-check each endpoint against the PUBLIC role/policy documentation. Note which resources are documented as admin-scoped (LaunchDarkly example: `acct` resource statements exist ONLY in the Admin role template).

## Phase 2 — Read sweep (baseline)

Run an identical list of GETs under every role. Diff status codes AND bodies byte-level.
- Zero diff between low and high roles ⇒ broad read is by design (document as negative finding, move on).
- Diffs reveal what the platform DOES consider sensitive — those are your high-value write targets.

## Phase 3 — Write-probe matrix (the money phase)

For each sensitive endpoint × each role, attempt the least-destructive write (POST minimal object / PATCH single field). Classify:

| Response | Meaning |
|---|---|
| 403 naming the action (`createIpAllowlistEntry`) | Authz check EXISTS for this role — negative control |
| 401 | Auth problem, retry with fresh creds |
| **400/404/409 business/validation errors** | **Passed authorization!** The request reached business logic — investigate |
| 2xx | BINGO — confirmed BFLA |

Key insight: validation errors AFTER authz prove authorization succeeded. A `409 "Calling IP would be blocked by allowlist change"` fired for a Writer means Writer writes were authorized end-to-end.

Probe both channels per role: cookies+session headers AND raw API tokens. Some platforms enforce differently per auth kind.

## Phase 4 — Confirm with controls (make it undeniable)

A finding needs this exact set:
1. **Negative control**: lower role (Reader) denied on same endpoint with named action.
2. **Positive exploit**: target role (Writer) succeeds on POST, PATCH (state change), and DELETE — full CRUD where possible.
3. **Contrast set**: same session denied on OTHER admin functions (`createMember`, `createRole`) — proves it's a specific gap, not broken tenancy or a shared secret.
4. **Policy cross-reference**: quote public docs showing resource belongs to Admin template only.
5. **State verification**: GET after each mutation showing persisted state.

## Phase 5 — Escalate impact safely

1. **Admin-artifact tampering**: create entry/object as Owner, then modify/delete it as the low-priv role (proves no ownership concept — silent destruction of protections).
2. **Bypass falsification**: while enforcement is ON with YOUR IP listed (safe state), send spoofed headers: `X-Forwarded-For` (fake, `fake,real`, `real,fake`), `X-Real-IP`, `Forwarded`, `Client-IP`, `True-Client-IP`, `CF-Connecting-IP`. If any changes the decision ⇒ NEW higher-severity finding (control bypass). If none do ⇒ document the negative result; it preempts triager objections.
3. **Validation probing** of entry formats: `/0`, IPv6, octal/integer forms, reserved ranges — document rejections (shows vendor rigor elsewhere, isolates the pure-authz nature of the flaw).
4. **Attack chain narrative**: foothold (role compromise) → durable credential (personal API token within role's rights) → control capture via the BFLA → deny/disrupt (lockout admins, kill CI/CD REST access) → persistence (pre-minted tokens/OAuth refresh). Write it out explicitly in the report.

## Evidence discipline

- JSON transcript, one object per step: `{step, title, method, url, body, status, response_excerpt, cleanup}`.
- Always end with final-state verification step.
- Save reports in both submission language and working language.

## Reporting (Bugcrowd VRT)

- Title pattern: `<Role> can <privileged action> on <account-wide control>` (+ "(Broken Function-Level Authorization)").
- VRT: Broken Access Control > Privilege Escalation; request P3 manually with impact justification (lockout of admins + org-wide integration outage + sabotage of admin-configured controls).
- Impact section MUST include: why it's not intended behavior (docs/UI/backend-policy triple mismatch), blast radius beyond dashboard (CI/CD/Terraform), persistence angle, and the negative-results section (bypass vectors tested and failed).

## Adapting to other vendors (control-class map)

Account-level security controls exist in every enterprise SaaS — probe their equivalents:

| Control class | Examples by platform |
|---|---|
| IP allowlist / network policy | LaunchDarkly ip-allowlist, Snowflake network policies, MongoDB Atlas project IP access list, GitHub allowed IPs |
| Identity/SSO settings | Okta admin API, Entra ID org policies, Atlassian admin SAML |
| Session/auth policy | Slack session duration, Google Workspace password policy |
| Org secrets/policies | GitLab instance/group settings, Vercel/Netlify team settings |

Vendor-neutral tells that an endpoint is account-scoped: path contains `org|account|team|instance` without resource id; response embeds `_createdByMemberId`-style ownership fields with no enforcement; UI hides it for non-admins while the OpenAPI spec exposes it.

## Worked example — LaunchDarkly (Aug 2026)

- Target: `https://app.launchdarkly.com/api/v2/account/ip-allowlist` (POST/PATCH collection toggles `apiTokenAllowlistEnabled`/`sessionAllowlistEnabled`; PATCH/DELETE `/{id}`).
- Headers: `LD-API-Version: beta`, `LD-Account-ID: <org id>` (cookies path), plain JSON bodies (NOT JSON-patch arrays).
- Result: Reader → 403 `createIpAllowlistEntry`; Writer → full CRUD 200/201/204 incl. deleting Admin-created entries; enabling without caller IP listed → 409 anti-lockout message (fires post-authz); XFF-family spoofing all ignored (enforcement uses TCP source IP); entry validation tight (min CIDR /8, IPv6/reserved rejected).
- Docs basis: Writer base role has no `acct` statement; Admin has `{"effect":"allow","actions":["*"],"resources":["acct"]}`.
- Full evidence: `FINDING_ipallowlist_bfla_evidence.json` next to this project's reports.
