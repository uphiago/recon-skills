---
name: recon-playbook
description: Use when starting or restructuring an authorized external web and API assessment.
version: 2.0.0
license: MIT
platforms: [linux, macos]
compatibility: Requires curl, jq, subfinder, dnsx, httpx, katana, and optional nmap
metadata:
  tags: [meta, recon, web, api, workflow]
  category: meta
  related_skills:
    - attack-patterns-reference
    - evidence-hygiene
    - offensive-osint
    - port-service-discovery
    - report-writing
    - subdomain-enumeration
    - triage-validation
    - source-leak-hunt
    - web2-recon
---

# External Web Recon Playbook

Use this playbook to turn an authorized root domain or asset list into a
prioritized map of web applications, APIs, authentication boundaries, and
testable security hypotheses.

```text
scope
  -> assets
  -> DNS and services
  -> routes and client code
  -> APIs and identities
  -> hypotheses
  -> focused validation
  -> evidence and reporting
```

## When to Use

- Beginning an external web, API, or bug bounty assessment.
- Recon output exists but lacks normalization, provenance, or prioritization.
- The target spans multiple applications, subdomains, or identity boundaries.
- A broad scan needs to be converted into focused manual validation.

Do not use this playbook to justify activity outside the agreed scope or to run
every available tool against every asset.

## Prerequisites

- Explicit authorization, target boundaries, exclusions, rate limits, and stop
  conditions.
- `curl`, `jq`, `subfinder`, `dnsx`, `httpx`, and `katana`.
- `nmap` only when IP or port discovery is in scope.
- Approved test identities for authorization and session testing.
- A writable evidence directory.

## How to Run

```bash
export TARGET="example.test"
export OUTPUT_DIR="${OUTPUT_DIR:-./output/$TARGET}"

mkdir -p \
  "$OUTPUT_DIR/assets" \
  "$OUTPUT_DIR/http" \
  "$OUTPUT_DIR/urls" \
  "$OUTPUT_DIR/evidence"
```

Run each phase only after reviewing the preceding output. Keep raw source files
so every hostname, URL, and hypothesis has provenance.

## Procedure

### 1. Record Scope

Keep a short operator-readable scope record beside the output:

```text
allowed: *.example.test
excluded: status.example.test
identities: anonymous, test-user-a, test-user-b
request rate: 2 requests/second/host
state changes: synthetic records only
```

The scope must answer what may be tested, which identities may be used, how
much traffic is acceptable, and whether a state-changing test is allowed.

### 2. Discover and Normalize Assets

```bash
subfinder -d "$TARGET" -silent \
  > "$OUTPUT_DIR/assets/subfinder.txt"

curl -sS --max-time 30 \
  "https://crt.sh/?q=%25.${TARGET}&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/^\*\.//' \
  > "$OUTPUT_DIR/assets/crtsh.txt"

cat "$OUTPUT_DIR/assets/subfinder.txt" \
    "$OUTPUT_DIR/assets/crtsh.txt" \
  | tr '[:upper:]' '[:lower:]' \
  | grep -E '^[a-z0-9.-]+\.[a-z]{2,}$' \
  | sort -u \
  > "$OUTPUT_DIR/assets/hostnames.txt"
```

Review wildcard results, certificate SANs, third-party CNAMEs, and excluded
assets before active probing.

### 3. Resolve and Identify HTTP Services

```bash
dnsx \
  -l "$OUTPUT_DIR/assets/hostnames.txt" \
  -silent -a -aaaa -cname -json \
  -o "$OUTPUT_DIR/assets/dns.jsonl"

httpx \
  -l "$OUTPUT_DIR/assets/hostnames.txt" \
  -threads 10 \
  -rate-limit 2 \
  -status-code -title -tech-detect -server -ip -cname \
  -json \
  -o "$OUTPUT_DIR/http/services.jsonl"

jq -r '.url // empty' "$OUTPUT_DIR/http/services.jsonl" \
  | sort -u \
  > "$OUTPUT_DIR/http/live-urls.txt"
```

Treat technology labels and banners as routing signals. Confirm important
components from more than one source before associating a vulnerability.

### 4. Map Routes, Parameters, and Client Code

```bash
katana \
  -list "$OUTPUT_DIR/http/live-urls.txt" \
  -silent -jc -kf all \
  -c 2 -p 2 -rl 2 \
  -o "$OUTPUT_DIR/urls/katana.txt"

grep -Ei '/api/|/graphql|swagger|openapi|/rest/' \
  "$OUTPUT_DIR/urls/katana.txt" \
  > "$OUTPUT_DIR/urls/api-candidates.txt"

grep -Ei 'login|logout|register|reset|oauth|saml|callback|session|token' \
  "$OUTPUT_DIR/urls/katana.txt" \
  > "$OUTPUT_DIR/urls/auth-candidates.txt"

grep -Ei '\.js([?#].*)?$' "$OUTPUT_DIR/urls/katana.txt" \
  > "$OUTPUT_DIR/urls/javascript.txt"
```

Map current routes before adding archive sources. Historical URLs are useful
for discovery, but they do not prove that an endpoint remains reachable.

### 5. Map APIs and Identity Boundaries

For each application, record:

- API base URLs, descriptions, versions, operations, and object identifiers;
- anonymous, user, tenant, manager, and administrator boundaries;
- login, logout, refresh, password reset, MFA, OAuth, and SAML flows;
- cookie, token, CORS, CSRF, and WebSocket behavior;
- state-changing methods and the synthetic objects approved for testing.

Authorization testing needs at least two approved identities when the claim
depends on cross-user or cross-tenant access.

### 6. Select Focused Skills

Use `attack-patterns-reference` to classify observations, then open only the
skills supported by current evidence. Common routes include:

| Observation | Follow-up skill |
|---|---|
| JavaScript bundles or source maps | `js-secrets-extraction`, `source-leak-hunt` |
| REST objects and identifiers | `hunt-api-misconfig`, `hunt-idor` |
| GraphQL endpoint | `hunt-graphql` |
| OAuth or SAML flow | `hunt-oauth`, `hunt-saml` |
| WordPress surface | `hunt-wordpress`, `wordpress-plugin-hunt` |
| Public service port | `port-service-discovery` |
| Candidate multi-step path | `cross-attack-chains` |

### 7. Validate One Hypothesis at a Time

Write the hypothesis before the probe:

```text
Expected: user A cannot read user B's synthetic object.
Test: repeat the same object request with both approved sessions.
Positive evidence: user A receives user B's object and its non-public fields.
Negative control: an unknown object returns the documented not-found response.
Stop condition: any access to non-synthetic or out-of-scope data.
```

Use `triage-validation` before reporting. A status code, scanner label, version
string, or permissive-looking header is not sufficient by itself.

### 8. Preserve Evidence

For every material result, retain:

- target, identity, UTC timestamp, and scope context;
- sanitized request and response;
- expected and observed behavior;
- negative control;
- side effects, cleanup, and testing limits;
- tool and relevant version.

Use `evidence-hygiene` while testing and `report-writing` after validation.

## Pitfalls

- Catch-all applications return `200` for nonexistent sensitive paths.
- CDN IPs and headers do not identify an origin or application version alone.
- Archived endpoints may be dead, redirected, or reassigned.
- Public client identifiers are not automatically secrets.
- Broad crawling can cross into third-party or excluded domains.
- Pagination can turn a bounded proof into unnecessary data collection.
- State-changing validation requires explicit authorization immediately before
  the command and must use synthetic records.

## Verification

- Every active asset traces back to an allowed scope entry and discovery source.
- Live services have normalized URLs and DNS context.
- Application maps include routes, APIs, authentication, and identity roles.
- Every promoted finding includes semantic evidence and a negative control.
- Candidate attack paths label unverified steps as inferred or not tested.
- Evidence is sanitized, reproducible, and stored beneath `OUTPUT_DIR`.
