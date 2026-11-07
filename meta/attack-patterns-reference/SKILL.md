---
name: attack-patterns-reference
description: Use when classifying a verified web or WordPress behavior and selecting a related validation skill.
version: 1.2.0
license: MIT
platforms: [linux]
compatibility: N/A (reference catalog)
metadata:
  tags: [meta, reference, patterns, validation]
  category: meta
  related_skills:
    - cors-credential-wordpress
    - cross-attack-chains
    - error-log-mining
    - js-secrets-extraction
    - phpinfo-to-rce
    - port-service-discovery
    - source-leak-hunt
    - staging-subdomain-hunt
    - wordpress-plugin-hunt
    - wp-mass-recon
    - xmlrpc-exploitation
---

# Attack Patterns Reference

This catalog maps observed web and WordPress behavior to the skill that owns
its validation. Pattern IDs are navigation labels. They do not establish
exploitability, severity, prevalence, or a confirmed attack path.

## When to Use

- A recon result needs to be classified before focused testing.
- Several verified behaviors may form a candidate attack path.
- A WordPress, CORS, XML-RPC, source-leak, or exposed-service signal needs an
  owning validation procedure.

Do not use the catalog as a scanner finding list or a substitute for the
verification section of the owning skill.

## Prerequisites

- An authorized target and current scope constraints.
- Captured evidence for the observation being classified.
- The tools and identities required by the selected follow-up skill.

## How to Run

1. Match the observed behavior to the closest pattern.
2. Open the owning skill listed in the table.
3. Check its prerequisites and side effects.
4. Run the smallest validation and negative control that can falsify the
   hypothesis.
5. Record the result as observed, inferred, confirmed, or not tested.

## Procedure

### General Web Patterns

| Pattern | Initial signal | Owning skill |
|---|---|---|
| WordPress user exposure | REST or author route returns user metadata | `wp-mass-recon` |
| Credentialed CORS | Untrusted origin reflected with credentials | `cors-credential-wordpress` |
| XML-RPC methods | Protocol-valid `system.listMethods` response | `xmlrpc-exploitation` |
| XML-RPC SSRF | `pingback.ping` reaches a controlled callback | `xmlrpc-exploitation` |
| Public registration | Registration is enabled | `wp-mass-recon` |
| Plugin surface | REST namespace, asset, or version marker | `wordpress-plugin-hunt` |
| Staging difference | Non-production host has weaker controls | `staging-subdomain-hunt` |
| Exposed error log | Response contains real application errors | `error-log-mining` |
| PHPInfo exposure | PHP configuration page is reachable | `phpinfo-to-rce` |
| Source or backup leak | Response contains repository, configuration, or database content | `source-leak-hunt` |
| JavaScript secret candidate | Bundle contains a credential-shaped value | `js-secrets-extraction` |
| Public service | Non-HTTP or administrative service is internet reachable | `port-service-discovery` |

See [`references/p-patterns.md`](references/p-patterns.md) for the extended
pattern notes.

### CORS Variants

| Variant | Initial signal | Required validation |
|---|---|---|
| Origin reflection with credentials | Untrusted origin plus `ACAC: true` | Credentialed browser reads non-public data |
| Null-origin trust | `ACAO: null` plus `ACAC: true` | Sandboxed browser reads non-public data |
| Wildcard without credentials | `ACAO: *` | Determine whether the response is already public |
| Credentialed preflight | OPTIONS accepts origin, method, and headers | Actual request succeeds and browser exposes response |
| Auth-route CORS | CORS headers appear on a protected route | Approved session returns readable protected data |
| Plugin-specific CORS | Only one plugin namespace accepts the origin | Response contains protected data or performs an authorized test action |
| Environment-specific CORS | Staging and production policies differ | Demonstrate impact in the authorized environment |
| Third-party allowlist | One external service origin is trusted | Establish control of that origin and protected-data access |

### Candidate Attack Paths

These are composition templates, not confirmed findings:

| Path | Preconditions that must be verified |
|---|---|
| CORS to protected-data read | Approved session, untrusted origin, browser-readable non-public response |
| XML-RPC SSRF to cloud metadata | Controlled callback, reachable metadata service, usable secondary impact |
| Open registration to upload | Approved synthetic account, upload-capable role, executable file path |
| Exposed log to account access | Current credential material, approved identity, valid authentication control |
| Staging exposure to production impact | Shared trust boundary, reusable secret or deployment path, explicit scope |

Use `cross-attack-chains` only after every prerequisite is independently
verified.

## Pitfalls

- Historical frequency is not evidence about the current target.
- A product name, version, status code, or header does not prove impact.
- A catch-all route can make sensitive paths appear reachable.
- Public client identifiers and intentionally public APIs are not automatically
  credentials or authorization failures.
- Pattern prerequisites change across product and plugin versions.
- An attack path inherits the uncertainty of its weakest step.

## Verification

- Match every pattern to captured request and response evidence.
- Run a negative control that distinguishes the result from public or generic
  behavior.
- Use a browser for CORS impact; headers alone are insufficient.
- Use a controlled callback for blind SSRF; a protocol status alone is
  insufficient.
- Use exact component and prerequisite checks before associating a CVE.
- Report only the impact reproduced within scope.
