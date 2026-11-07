---
name: api-noauth-hunt
description: Use when an API may expose data or privileged operations without authentication.
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  tags: [recon, API, no-auth, data-breach, CRUD]
  category: recon
  related_skills:
    - firebase-supabase-attack
    - js-secrets-extraction
    - port-service-discovery
    - source-leak-hunt
---

# API No-Authentication Validation

Identify API operations that may be reachable without the authentication or
authorization required by their data and business function. Discovery is
read-only by default. Write validation uses synthetic records and requires
explicit authorization immediately before execution.

## When to Use

- Port scan reveals HTTP services on non-standard ports (3000, 5000, 8080-8085, 9000).
- Target has an API subdomain (api.target.com, backend.target.com).
- JavaScript bundles reference internal API endpoints.
- After `port-service-discovery` finds HTTP on unexpected ports.
- After `firebase-supabase-attack` identifies backend APIs.

## Prerequisites

- curl, python3, jq installed.
- Target URL or IP:port of the suspected API.
- List of common API paths for fuzzing.

## How to Run

```bash
# Quick API test — try common paths without auth
TARGET="https://api.target.com"
for path in "/" "/api" "/api/v1" "/api/users" "/api/health" "/docs" "/swagger.json"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "$TARGET$path")
  echo "HTTP $code: $TARGET$path"
done
```

## Quick Reference

| Signal | What It Means | Action |
|--------|---------------|--------|
| HTTP 200 on `/api/users` or `/api/clients` | Possible unauthenticated data access | Validate one bounded sample |
| HTTP 2xx on POST without auth | Possible unauthenticated write | Stop and obtain write authorization |
| OpenAPI/Swagger at `/docs`, `/swagger.json` | Full API map exposed | Enumerate all endpoints |
| Stack trace on error | Internal paths, framework version | Map infrastructure |
| State change via an unexpected method | Possible method-level authorization gap | Reproduce with a synthetic record |
| Login without password validation | Possible authentication bypass | Verify with an approved test account |

## Procedure

### Phase 1 — API Discovery

```bash
TARGET="$1"      # URL or IP:port
OUTDIR="$OUTDIR/api_recon"
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
  code=$(curl -sk -o /tmp/api_probe_$$.tmp -w "%{http_code}" --max-time 5 --connect-timeout 5 "$TARGET$path" 2>/dev/null)

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
  schema=$(curl -sk --max-time 10 --connect-timeout 10 "$TARGET$sw_path" 2>/dev/null)

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

### Phase 3 — Authorized Synthetic CRUD Validation

This phase changes server state. Run it only when the scope explicitly permits
write testing and the endpoint stores disposable synthetic records. The guard
below is deliberate: do not remove it or substitute an existing object ID.

```bash
TARGET="$1"
ENDPOINT="$2"  # approved test collection
OUTPUT_DIR="${OUTPUT_DIR:-./output}"
PROBE_ID="noauth-test-$(date +%s)"

if [[ "${I_HAVE_EXPLICIT_WRITE_AUTHORIZATION:-no}" != "yes" ]]; then
  echo "Refusing state-changing validation without explicit authorization." >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR/api-validation"

create_body=$(curl -sk --max-time 10 --connect-timeout 5 \
  -X POST "$TARGET$ENDPOINT" \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"$PROBE_ID\",\"test_record\":true}")
printf '%s\n' "$create_body" \
  > "$OUTPUT_DIR/api-validation/create-response.json"

created_id=$(printf '%s' "$create_body" | jq -r '.id // .uuid // empty')
if [[ -z "$created_id" ]]; then
  echo "Create response did not expose a disposable object ID; stop here." >&2
  exit 1
fi

curl -sk --max-time 10 --connect-timeout 5 \
  "$TARGET$ENDPOINT/$created_id" \
  -o "$OUTPUT_DIR/api-validation/read-response.json"

curl -sk --max-time 10 --connect-timeout 5 \
  -X PATCH "$TARGET$ENDPOINT/$created_id" \
  -H "Content-Type: application/json" \
  -d '{"validation_state":"updated"}' \
  -o "$OUTPUT_DIR/api-validation/update-response.json"

curl -sk --max-time 10 --connect-timeout 5 \
  -X DELETE "$TARGET$ENDPOINT/$created_id" \
  -o "$OUTPUT_DIR/api-validation/delete-response.txt"
```

### Phase 4 — Bounded Read Validation

```bash
TARGET="$1"
ENDPOINT="$2"  # confirmed no-auth endpoint
OUTPUT_DIR="${OUTPUT_DIR:-./output}"

mkdir -p "$OUTPUT_DIR/api-validation"
curl --max-time 15 --connect-timeout 5 -sk \
  "$TARGET$ENDPOINT?page=1&limit=2" \
  -o "$OUTPUT_DIR/api-validation/bounded-sample.json"

jq 'if type == "array" then .[:2] else . end' \
  "$OUTPUT_DIR/api-validation/bounded-sample.json"
```


## Pitfalls

- **HTTP 200 ≠ API.** Some services return HTML on unexpected paths. Verify JSON content type.
- **Pagination can turn validation into collection.** Request the smallest page
  that proves the access-control failure. Do not enumerate the dataset.
- **POST, PATCH, PUT, and DELETE change state.** Require explicit authorization
  and operate only on a synthetic object created for the test.
- **Authentication tests can lock accounts or trigger alerts.** Use approved
  test identities and the agreed request rate.

## Verification

- Confirm that the same operation succeeds without authentication and is
  rejected by the expected negative control.
- For reads, retain only the minimum sanitized sample needed to demonstrate the
  protected data class.
- For writes, record creation, retrieval, update, deletion, and cleanup of the
  same synthetic object.
- Document the URL, method, expected policy, observed behavior, identity,
  timestamp, control result, and testing limit.
