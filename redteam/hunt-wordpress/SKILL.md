---
name: hunt-wordpress
description: Use when an authorized target exposes WordPress core, plugin, theme, REST, or XML-RPC behavior.
version: 3.0.0
license: MIT
platforms: [linux, macos]
compatibility: Requires curl, jq, and optional wpscan
metadata:
  tags: [redteam, wordpress, web, api, plugins]
  category: redteam
  related_skills:
    - cors-credential-wordpress
    - error-log-mining
    - source-leak-hunt
    - staging-subdomain-hunt
    - wordpress-plugin-hunt
    - wp-plugin-rest-auth-bypass
    - xmlrpc-exploitation
---

# WordPress Security Assessment

Map WordPress core, REST, XML-RPC, plugins, themes, authentication boundaries,
and adjacent installations before selecting a vulnerability-specific test.
WordPress presence, a public route, or a version match is not a finding by
itself.

## When to Use

- HTML, headers, assets, cookies, or routes identify WordPress.
- `/wp-json/`, `/wp-login.php`, `/xmlrpc.php`, or `/wp-content/` is reachable.
- JavaScript or source code references a WordPress backend.
- A staging or subdirectory installation may differ from the main site.

## Prerequisites

- Explicit authorization and current target boundaries.
- `curl` and `jq`; `wpscan` is optional.
- Approved test identities for role or authorization checks.
- A controlled callback service only when blind SSRF testing is authorized.
- Explicit approval immediately before registration, upload, password, plugin,
  or other state-changing tests.

## How to Run

Begin with a bounded, read-only map:

```bash
TARGET="https://www.example.test"
OUTPUT_DIR="${OUTPUT_DIR:-./output/wordpress}"
mkdir -p "$OUTPUT_DIR"

for path in \
  / \
  /wp-json/ \
  /wp-login.php \
  /xmlrpc.php \
  /readme.html \
  /author-sitemap.xml; do
  curl -sS --max-time 10 \
    -o /dev/null \
    -w '%{http_code} %{content_type} %{size_download} %{url_effective}\n' \
    "$TARGET$path"
  sleep 1
done
```

## Procedure

### 1. Confirm WordPress

Use multiple signals:

```bash
curl -sS --max-time 10 "$TARGET/" \
  | grep -Eio 'wp-content|wp-includes|wp-json|wordpress' \
  | sort -u

curl -sS --max-time 10 "$TARGET/wp-json/" \
  -o "$OUTPUT_DIR/rest-index.json"

jq -r '.namespaces[]? // empty' "$OUTPUT_DIR/rest-index.json" \
  | sort -u \
  > "$OUTPUT_DIR/rest-namespaces.txt"
```

A generic `200` response is insufficient. Compare suspicious paths with a
random nonexistent path to detect catch-all routing.

### 2. Map Core, Theme, and Plugin Assets

```bash
curl -sS --max-time 10 "$TARGET/" \
  | grep -Eo "wp-content/(plugins|themes)/[^/?\"']+" \
  | sort -u \
  > "$OUTPUT_DIR/components.txt"
```

Confirm a component with at least two signals when practical: an asset path,
REST namespace, readme or changelog, HTML marker, or versioned file. Match CVEs
only after establishing the exact affected version and prerequisite.

Use `wordpress-plugin-hunt` for plugin discovery and version validation.

### 3. Map REST Data and Authorization

```bash
for path in \
  /wp-json/ \
  /wp-json/wp/v2/types \
  /wp-json/wp/v2/posts?per_page=2 \
  /wp-json/wp/v2/pages?per_page=2 \
  /wp-json/wp/v2/users?per_page=2; do
  curl -sS --max-time 10 \
    -D "$OUTPUT_DIR/headers.tmp" \
    -o "$OUTPUT_DIR/body.tmp" \
    "$TARGET$path"
  printf '%s %s\n' "$path" "$(wc -c < "$OUTPUT_DIR/body.tmp")"
  sleep 1
done
```

Classify the response before assigning impact:

- published posts and pages are usually public by design;
- usernames may increase phishing or authentication risk but are not account
  takeover;
- email addresses, roles, drafts, settings, form entries, orders, and logs need
  separate access-control review;
- a plugin namespace may exist while every operation remains protected.

For authorization claims, compare anonymous, user A, user B, and an approved
privileged identity against the same synthetic object.

### 4. Validate CORS in a Browser

```bash
curl -sS --max-time 10 \
  -D "$OUTPUT_DIR/cors-headers.txt" \
  -o "$OUTPUT_DIR/cors-body.txt" \
  -H 'Origin: https://attacker.example' \
  "$TARGET/wp-json/wp/v2/users?per_page=2"
```

Header reflection is only a lead. Credentialed CORS impact requires:

1. an untrusted origin accepted by the response;
2. `Access-Control-Allow-Credentials: true` when cookies are required;
3. an approved authenticated browser session;
4. browser JavaScript that can read non-public data;
5. an anonymous or public-data negative control.

Use `cors-credential-wordpress` for the complete browser workflow.

### 5. Classify XML-RPC

```bash
curl -sS --max-time 15 \
  -X POST "$TARGET/xmlrpc.php" \
  -H 'Content-Type: text/xml' \
  --data-binary \
  '<methodCall><methodName>system.listMethods</methodName></methodCall>' \
  -o "$OUTPUT_DIR/xmlrpc-methods.xml"

grep -Eo '<string>[^<]+</string>' "$OUTPUT_DIR/xmlrpc-methods.xml" \
  | sed -E 's#</?string>##g' \
  | sort -u
```

Do not follow redirects during protocol classification. A valid
`methodResponse` proves XML-RPC behavior; a status code alone does not.
Credential testing, multicall amplification, uploads, and SSRF bypasses require
their own authorization and safety limits. Use `xmlrpc-exploitation` only when
the relevant method and prerequisites have been confirmed.

### 6. Check Staging and Secondary Installations

Certificate transparency, archives, and asset paths may reveal staging hosts or
subdirectory installations. Compare:

- WordPress and plugin versions;
- authentication and WAF behavior;
- REST and XML-RPC exposure;
- debug configuration and source files;
- shared cookies, credentials, storage, and deployment paths.

A weaker staging control matters only when the environment is in scope and its
impact is demonstrated. Use `staging-subdomain-hunt` for a bounded comparison.

### 7. Check Source and Error Exposure

Probe only the paths justified by the observed stack. Validate content rather
than status:

| Candidate | Required content |
|---|---|
| `.git/HEAD` | Git ref such as `ref: refs/heads/...` |
| `.env` | Configuration assignments, not generic HTML |
| `debug.log` or `error_log` | Real application errors or sensitive runtime data |
| backup archive | Correct file signature and meaningful contents |
| directory listing | Directory index markers and actual entries |

Use `source-leak-hunt` and `error-log-mining`; retain only the minimum sanitized
sample needed to demonstrate exposure.

### 8. Build a Candidate Attack Path

Connect only verified prerequisites:

```text
observed component
  -> exact version and configuration
  -> reachable vulnerable operation
  -> approved identity or synthetic object
  -> reproduced security impact
```

Registration, XML-RPC, an upload route, and an executable PHP configuration do
not automatically form an RCE chain. Confirm the role capability, upload
validation, storage path, and execution behavior independently.

## Pitfalls

- WordPress routes frequently sit behind CDN, cache, or catch-all behavior.
- `GET /xmlrpc.php` returning `405` does not classify a valid POST method call.
- A REST namespace does not prove that a plugin operation is unauthenticated.
- Public author metadata is not automatically sensitive.
- Plugin versions can be hidden, backported, or reported by stale assets.
- Large logs, sitemaps, and REST collections can cause unnecessary data
  collection; request bounded samples.
- Default credential attempts, password spraying, registration, uploads, and
  writes require explicit authorization and agreed lockout limits.

## Verification

- WordPress is confirmed from content, not only a status code.
- Every component finding includes a second signal or explains why one is not
  available.
- Every CVE association includes exact version and prerequisite evidence.
- REST authorization uses approved identities and a negative control.
- CORS impact is reproduced in a browser with non-public data.
- XML-RPC behavior uses a protocol-valid response or controlled callback.
- State-changing tests use synthetic records, preserve cleanup evidence, and
  remain within scope.
