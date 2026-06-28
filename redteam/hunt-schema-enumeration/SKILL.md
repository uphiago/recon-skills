---
name: hunt-schema-enumeration
description: "Enumerate hidden tables, fields, and endpoints via API error hints. Agnostic across PostgREST, Zod, FastAPI, GraphQL, and REST."
sources: field_recon, offensive_research
report_count: 10
author: uphiago
---

## When to Use

The target API returns structured error messages (JSON) that hint at valid table names, field names, or endpoint paths. This is the single most productive black-box recon technique for REST/GraphQL APIs — one fuzz request reveals the entire database schema.

Most common on: PostgREST (Supabase), FastAPI (.NET), Zod (Next.js/Node), tRPC, GraphQL, and any framework with validation error details enabled in production.

---

## Phase 1 — PostgREST Error Hint Enumeration

PostgREST is the REST API layer for Supabase/PostgreSQL. When you query a non-existent table, it returns a hint with the real table name.

```bash
SUPABASE_URL="https://PROJECT.supabase.co"
ANON_KEY="eyJ..."

# Fuzz with common table names — read the hints
for table in users profiles posts products orders data config settings; do
  echo "=== $table ==="
  curl -sk "${SUPABASE_URL}/rest/v1/${table}?select=*&limit=1" \
    -H "apikey: ${ANON_KEY}" \
    -H "Authorization: Bearer ${ANON_KEY}" 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
hint=d.get('hint','')
if hint: print(f'  -> {hint}')
"
done

# The response pattern:
# {"hint":"Perhaps you meant the table 'public.real_table_name'"}
# {"hint":"Perhaps you meant the table 'public.user_sessions'"}
```

**Build a wordlist for targeted fuzzing:**
```bash
# Common patterns found in field:
# - Game apps: hands, scores, sessions, players, items, inventory
# - SaaS: subscriptions, subscribers, billing, invoices, teams, api_keys  
# - Health: patients, appointments, assessments, prescriptions
# - Gov: citizens, certificates, documents, protocols
# - Finance: transactions, accounts, wallets, withdrawals, deposits
```

---

## Phase 2 — Zod/FastAPI Validation Error Mining

Modern frameworks return detailed validation errors exposing all expected fields.

### FastAPI (.NET/Go)
```bash
# POST with empty body or wrong fields
curl -sk -X POST "https://api.target.com/endpoint" \
  -H "Content-Type: application/json" -d '{}' 2>/dev/null
# Response reveals ALL required fields:
# {"errors":{"usuario":["required"],"senha":["required"]}}
```

### Zod (Next.js/Node)
```bash
curl -sk -X POST "https://target.com/api/workspaces" \
  -H "Content-Type: application/json" -d '{}' 2>/dev/null
# Response: {"error":{"name":"ZodError","message":"[\n  {\"expected\":\"string\",\"path\":[\"name\"]}\n]"}}
```

---

## Phase 3 — GraphQL Introspection

```bash
# Standard introspection query
curl -sk -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name type{name}}}}}"}' 2>/dev/null

# Even if introspection is disabled, error messages reveal type names:
# "Cannot query field 'x' on type 'User'. Did you mean 'users'?"
```

---

## Phase 4 — Aggressive Table Fuzzing

Generate a comprehensive wordlist combining:

```bash
# 1. From JS bundle analysis
grep -oP 'from\(["\x60][a-zA-Z_]+["\x60]\)' /tmp/target.js | sort -u

# 2. From common patterns
# Singular/plural: user/users, post/posts, product/products
# Snake/camel: user_sessions, userSessions, UserSessions
# Domain-specific: appointments, patients, assessments, certificates

# 3. Systematic fuzz
for table in $(cat /tmp/wordlist.txt); do
  curl -sk -w "%{http_code}" "${BASE}/rest/v1/${table}?select=count" \
    -H "apikey: ${KEY}" 2>/dev/null | tee -a /tmp/fuzz_results.txt
done
```

---

## Verification

- **PostgREST hit confirmed**: Response is `[]` (empty array = table exists, RLS blocks read) or data returned
- **Zod hit confirmed**: Error lists exact field names and types expected
- **FastAPI hit confirmed**: 422 with `detail` array listing missing fields
- **False positive**: Generic 404 HTML page (not a JSON error)

---

## What Next

- If PostgREST hints reveal tables → proceed to `hunt-write-gap` (test PATCH/POST/DELETE)
- If Zod errors reveal fields → test `hunt-business-logic` (mass assignment, price tampering)
- If FastAPI reveals auth schema → test `jwt-attack` or `api-noauth-hunt`
- Schema enumeration always leads to the next attack — never the final step
