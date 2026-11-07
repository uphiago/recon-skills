---
name: saml-sso-attack
description: Attack SAML SSO via XSW, signature strip, metadata extract.
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
compatibility: Requires curl, python3, bash
metadata:
  tags: [auth, SAML, SSO, XML-signature, identity]
  category: auth
  related_skills:
    - jwt-attack
    - exchange-owa-attack
    - api-noauth-hunt
---

# SAML SSO Attack Skill

SAML Single Sign-On attack methodology — IdP metadata analysis, XML Signature Wrapping (XSW), signature stripping, comment injection in NameID, and SSO timing-based user enumeration. Confirmed on TARGET_ORG_A (SimpleSAMLphp IdP, 79 XMLRPC methods on WordPress SP), TARGET_ORG_B (Ory Kratos + OIDC), and TARGET_ORG_C (ADFS WS-Trust exposed).

## When to Use

- Target uses SSO (redirects to `idp.`, `sso.`, `login.`, `auth.` subdomains).
- URL contains `SAMLRequest=` or `SAMLResponse=` parameter.
- Metadata endpoint accessible at `/saml2/idp/metadata.php` or `/FederationMetadata/2007-06/FederationMetadata.xml`.
- After `exchange-owa-attack` discovers ADFS.

## Prerequisites

- curl, python3.
- Target SAML endpoint URLs (from recon or metadata).
- SAML Raider Burp extension for interactive testing (optional).

## How to Run

```bash
# Discover SAML IdP metadata
curl --max-time 30 --connect-timeout 10 -sk "https://TARGET/saml2/idp/metadata.php" | python3 -c "
import sys, base64, zlib
from xml.etree import ElementTree as ET
content = sys.stdin.read()
if 'EntityDescriptor' in content:
    root = ET.fromstring(content)
    for el in root.iter():
        if 'entityID' in el.attrib:
            print(f'entityID: {el.attrib[\"entityID\"]}')
"

# Decode SAMLRequest from URL
echo "SAMLREQUEST_BASE64" | python3 -c "
import sys, base64, zlib
raw = base64.b64decode(sys.stdin.read().strip())
decompressed = zlib.decompress(raw, -15)
print(decompressed.decode())
"
```

## Quick Reference

| Attack | Prerequisites | Impact |
|--------|------------|--------|
| XML Signature Wrapping (XSW) | Valid signed assertion from any user | Impersonate any user |
| Signature stripping | Server doesn't validate signature presence | Full identity forgery |
| Comment injection in NameID | NameID format allows comments | User impersonation |
| SAML Response replay | No `InResponseTo` validation | Session hijacking |
| Key confusion | Multiple signing certs in metadata | Sign assertions with different key |
| Audience restriction bypass | No `Audience` validation | Cross-SP token reuse |
| Metadata extraction | Public IdP metadata | Discover certs, endpoints, bindings |
| Golden SAML (post-exploit) | Stolen ADFS token-signing cert | Forge tokens, impersonate any user |

## Procedure

### Phase 1 — Discover SAML Endpoints

```bash
TARGET="$1"

echo "[*] SAML endpoint discovery on $TARGET"

# Common SAML paths
declare -A SAML_PATHS
SAML_PATHS["/saml2/idp/metadata.php"]="SimpleSAMLphp IdP"
SAML_PATHS["/saml2/sp/metadata.php"]="SimpleSAMLphp SP"
SAML_PATHS["/FederationMetadata/2007-06/FederationMetadata.xml"]="ADFS"
SAML_PATHS["/adfs/ls/IdpInitiatedSignOn.aspx"]="ADFS Login"
SAML_PATHS["/adfs/services/trust"]="ADFS WS-Trust"
SAML_PATHS["/auth/realms/master/protocol/saml"]="Keycloak SAML"
SAML_PATHS["/.well-known/openid-configuration"]="OIDC"
SAML_PATHS["/sso/saml"]="Generic SAML"
SAML_PATHS["/idp/shibboleth"]="Shibboleth"
SAML_PATHS["/simplesamlphp"]="SimpleSAMLphp root"

for path in "${!SAML_PATHS[@]}"; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 --connect-timeout 5 "https://$TARGET$path")
  [[ "$code" == "200" || "$code" == "302" ]] && echo "  [FOUND] $path — ${SAML_PATHS[$path]} (HTTP $code)"
  sleep 1
done
```

### Phase 2 — Extract IdP Metadata

```bash
METADATA_URL="$1"  # e.g., https://idp.target.com/saml2/idp/metadata.php

echo "[*] Extracting SAML metadata from $METADATA_URL"

METADATA=$(curl -sk --max-time 10 --connect-timeout 10 "$METADATA_URL" 2>/dev/null)

if [[ -z "$METADATA" ]]; then
  echo "[-] No metadata accessible"
  exit 1
fi

# Parse with Python
echo "$METADATA" | python3 -c "
import sys
from xml.etree import ElementTree as ET

content = sys.stdin.read()
root = ET.fromstring(content)

# Namespaces
ns = {'md': 'urn:oasis:names:tc:SAML:2.0:metadata',
      'ds': 'http://www.w3.org/2000/09/xmldsig#'}

# Entity ID
entity_id = root.get('entityID', 'unknown')
print(f'Entity ID: {entity_id}')

# Signing certificates
for cert_el in root.iter('{http://www.w3.org/2000/09/xmldsig#}X509Certificate'):
    cert = cert_el.text.strip()
    print(f'Signing Cert ({len(cert)} chars): {cert[:60]}...')

# SSO endpoints
for el in root.iter():
    if 'Binding' in el.attrib:
        binding = el.attrib['Binding']
        location = el.attrib.get('Location', '')
        if 'HTTP-Redirect' in binding or 'HTTP-POST' in binding:
            print(f'Endpoint: {location} [{binding.split(\":\")[-1]}]')

# NameID formats
for el in root.iter('{urn:oasis:names:tc:SAML:2.0:metadata}NameIDFormat'):
    print(f'NameID Format: {el.text}')
" 2>/dev/null
```

### Phase 3 — Decode & Analyze SAMLRequest

```bash
SAML_B64="$1"  # from URL parameter or Burp

echo "[*] Decoding SAMLRequest"

echo "$SAML_B64" | python3 -c "
import sys, base64, zlib
from xml.etree import ElementTree as ET

raw = sys.stdin.read().strip()
decoded = base64.b64decode(raw)
try:
    decompressed = zlib.decompress(decoded, -15)
except:
    decompressed = decoded

xml = decompressed.decode('utf-8', errors='replace')
print(xml[:3000])

root = ET.fromstring(xml)
print()
print('=== Analysis ===')

# Request ID
req_id = root.get('ID', 'none')
print(f'Request ID: {req_id}')

# Issuer
issuer_el = root.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
if issuer_el is not None:
    print(f'Issuer: {issuer_el.text}')

# ForceAuthn
force = root.get('ForceAuthn', 'false')
print(f'ForceAuthn: {force}')

# NameIDPolicy
policy_el = root.find('.//{urn:oasis:names:tc:SAML:2.0:protocol}NameIDPolicy')
if policy_el is not None:
    allow_create = policy_el.get('AllowCreate', 'false')
    fmt = policy_el.get('Format', 'unspecified')
    print(f'NameIDPolicy: AllowCreate={allow_create}, Format={fmt}')
" 2>/dev/null
```

### Phase 4 — SSO Timing-Based User Enumeration

```bash
TARGET="$1"  # SSO login endpoint
USERS_FILE="$2"  # List of usernames/emails to test

echo "[*] SSO timing-based user enumeration"

# The technique: valid users produce a different response time than invalid users
# because the server checks LDAP/AD before returning the SAML response

while read -r user; do
  START=$(date +%s%N)
  curl -sk -o /dev/null --max-time 15 --connect-timeout 10 \
    "https://$TARGET/sso/login?username=$user&password=WRONG_PASS" 2>/dev/null
  END=$(date +%s%N)
  ELAPSED=$(( (END - START) / 1000000 ))

  echo "  $user: ${ELAPSED}ms"
  sleep 1
done < "$USERS_FILE" | sort -t: -k2 -rn | head -20

echo "[*] Users with significantly higher response times likely exist"
```

### Phase 5 — XML Signature Wrapping (XSW) Test

```bash
TARGET="$1"

echo "[*] XSW vulnerability analysis"

# Check if IdP signs only the Assertion (good) or the entire Response (better)
# If only the Assertion is signed, XSW is possible:
# 1. Capture a valid SAML Response with signed Assertion
# 2. Create a new Response containing the original signed Assertion + a forged Assertion
# 3. If the SP validates the forged Assertion instead of the signed one → impersonation

echo "[*] Manual XSW test steps:"
echo "  1. Capture SAML Response from browser (Burp/DevTools)"
echo "  2. Decode SAMLResponse (base64 + inflate)"
echo "  3. Check: is Signature on Response or Assertion level?"
echo "  4. If Assertion-level: wrap original Assertion + forged Assertion in new Response"
echo "  5. Submit forged SAMLResponse to SP ACS endpoint"
echo "  6. If SP accepts → XSW confirmed"
```

## Pitfalls

- **XSW is complex.** Requires understanding of XML namespaces, canonicalization, and SAML response structure.
- **SAML message is large.** SAMLResponse in URL can be 4000+ characters. POST binding is more common for responses.
- **SP may validate InResponseTo.** If it does, replay attacks fail. Check by sending the same SAMLResponse twice.
- **Signature stripping only works on broken SPs.** Most modern SPs reject unsigned assertions.
- **Rate limiting.** SSO timing enumeration and endpoint discovery can trigger account lockouts or IP bans. Always add `sleep` between requests (≥1s) and use a pool of source IPs for production engagements.

## Verification

- Metadata MUST reveal at minimum: entity ID, signing certificates, SSO endpoints, and NameID formats.
- SAMLRequest MUST decode to valid XML with Issuer, ID, and NameIDPolicy elements.
- SSO timing enum MUST show a statistically significant difference (>200ms) between valid and invalid users.
- XSW: Forged SAMLResponse MUST be accepted by the SP and create a valid session.
- All SAML endpoints must be documented: IdP metadata URL, SP ACS URL, binding types, certificate details.


## Modern SAML CVEs & Techniques

| CVE | Affected | Impact | Year |
|-----|----------|--------|------|
| CVE-2025-25291 | ruby-saml ≤ 1.17.0 | Auth bypass via XSW / signature confusion | 2025 |
| CVE-2025-25292 | ruby-saml ≤ 1.17.0 | Auth bypass via parser differential | 2025 |
| CVE-2024-45428 | GitLab (ruby-saml) | SAML auth bypass — full account takeover | 2024 |
| CVE-2024-45409 | ruby-saml ≤ 1.16.0 | Signature wrapping (XSW) auth bypass | 2024 |
| CVE-2023-2813 | GitLab CE/EE | SAML group claim misvalidation | 2023 |

### Golden SAML Attack (Post-Exploitation)

After gaining access to an ADFS server or extracting the token-signing certificate:
1. Extract the ADFS token-signing certificate (.pfx or private key).
2. Use tools like **AADInternals** or a custom Python script to forge SAML tokens.
3. Impersonate any user (including cloud-only identities) without requiring password or MFA.
4. Relevant for Azure AD / Entra ID federated domains — forged tokens are trusted indefinitely.

### SAML Tools

- **SAML Raider** (Burp extension) — encode/decode, XSW, certificate manipulation
- **SAMLReQuest** (Burp extension) — lightweight SAML request editor
- **saml2aws** — CLI for AWS SSO via SAML
- **AADInternals** — PowerShell toolkit for Azure AD / Entra ID (Golden SAML)
- **ESPOOR** — SAML message manipulation tool
