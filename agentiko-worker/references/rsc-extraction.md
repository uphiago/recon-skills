# RSC Content Extraction (Vercel Next.js Bypass)

When a target runs on Vercel with Next.js and the WAF/Security Checkpoint blocks automated requests, the content may still be embedded in the initial RSC (React Server Components) streaming payload. This is a server-rendered HTML blob that ships with the first HTTP response before the JS bundle even loads.

## When it works

- **First request to a fresh IP** often succeeds before Vercel's rate-based checkpoint triggers
- **App Router** (Next.js 13+) ships content in `self.__next_f.push([1, "...encoded..."])` chunks
- The content is in the page HTML, just encoded with React's internal serialization

## Extraction method

```bash
# Step 1: Fetch the page (first request is critical)
curl -sL "https://target.com" -m 30 > /tmp/page.html
```

```python
# Step 2: Python extraction
import re

with open('/tmp/page.html') as f:
    html = f.read()

# Find content by marker (e.g., 'PLAYBOOK', article title, etc.)
idx = html.find('PLAYBOOK')  # replace with your content marker
if idx >= 0:
    chunk = html[idx:idx+150000]
    
    # Decode Next.js RSC escaping
    decoded = chunk
    for escape, replacement in [
        ('\\n', '\n'),
        ('\\u003c', '<'), ('\\u003e', '>'),
        ('\\u0026', '&'), ('\\u0027', "'"),
        ('\\u0022', '"'), ('\\/', '/'),
        ('\\&#39;', "'"), ('&#39;', "'"),
        ('\\&quot;', '"'), ('&quot;', '"'),
        ('\\&amp;', '&'), ('&amp;', '&'),
    ]:
        decoded = decoded.replace(escape, replacement)
    
    # Strip HTML tags
    decoded = re.sub(r'<[^>]+>', '', decoded)
    
    # Filter out RSC noise
    lines = []
    for line in decoded.split('\n'):
        line = line.strip()
        if not line or len(line) < 2:
            continue
        if re.match(r'^[\d,:\[\]{}"\' ]+$', line):
            continue
        if line.startswith('$') and len(line) < 30:
            continue
        if line.startswith(('I:', 'n:', 'S:')):
            continue
        lines.append(line)
    
    content = '\n'.join(lines)
```

## Common escape patterns

| Raw in HTML | Decoded | Context |
|-------------|---------|---------|
| `\\n` | `\n` | Newlines in RSC stream |
| `\\u003c` | `<` | HTML tag open |
| `\\u003e` | `>` | HTML tag close |
| `\\u0026` | `&` | Ampersand |
| `\\u0027` | `'` | Single quote |
| `\\u0022` | `"` | Double quote |
| `\\&#39;` | `'` | HTML entity single quote |
| `\\&quot;` | `"` | HTML entity double quote |
| `\\&amp;` | `&` | HTML entity ampersand |

## Pitfalls

- **First request matters** — Vercel Security Checkpoint blocks after detecting automation patterns. Subsequent requests from the same IP get a 403 challenge page. Wait 5-10 minutes before retrying.
- **RSC format varies** by Next.js version. App Router uses the push-chunk format above; Pages Router uses different encoding.
- **Not all content appears as plaintext** — images and binary assets are base64-encoded in the RSC stream.
- **Large payloads** get split across multiple `push()` calls — search for all chunks, not just the first one.
- **Some sites use server-only streaming** where content is never embedded in the initial HTML — in those cases the extraction won't work.

## Key verification before extraction

Before spending time on decoding, verify the content is actually there:

```python
import re
# Search for known keywords in the raw HTML
for keyword in ['pentest', 'playbook', 'recon', 'methodology']:
    matches = re.findall(r'(?i)' + re.escape(keyword), html)
    print(f"'{keyword}' -> {len(matches)} matches")
```

If matches are 0 despite the page loading, the content is fetched client-side via JS and the RSC extraction won't work — try a headless browser instead.
