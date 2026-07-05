---
name: origin-ip-discovery
description: Discover origin IPs behind CDN/WAF via favicon hash, DNS history, and SSL certs.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, python3, shodan CLI
metadata:
  tags: [recon, origin-ip, CDN, WAF, bypass, Cloudflare, favicon, DNS]
  category: recon
  related_skills:
    - subdomain-enumeration
    - vhost-enumeration
    - port-mass-scan
---

# Origin IP Discovery

Discover the real server IP behind CDN/WAF protections (Cloudflare, Akamai, Fastly). When the origin IP is found, the raw server is exposed without firewall rules, rate limiting, or application-layer filtering. Techniques include favicon hash fingerprinting across Shodan, historical DNS records from passive sources, SSL certificate SAN field matching, and Google Analytics ID cross-referencing.

## When to Use

- Target is behind Cloudflare/Akamai and returns 403 or CAPTCHA challenges on all requests.
- You need direct access to the origin to bypass WAF rules.
- Subdomain enumeration reveals internal/staging hosts on non-CDN IPs.
- The target uses a single favicon across all infrastructure.
- SSL certificates share the same organization name across IPs.

## Prerequisites

- `terminal` tool with curl, python3, and shodan CLI.
- Shodan API key: `shodan init <KEY>`.
- Target favicon file or URL.

## Quick Detection

```bash
# Check Cloudflare presence
curl -sI "https://target.com" | grep -i "cf-ray\|server: cloudflare"

# If Cloudflare detected, check for common origin leaks
curl -sk "https://target.com/cdn-cgi/trace" | grep -E "ip=|colo="
```

## Procedure

### Phase 1 — Favicon Hash Fingerprinting

```bash
# Get favicon hash
FAVICON_URL="https://target.com/favicon.ico"
curl -sk "$FAVICON_URL" -o favicon_target.ico

# Calculate hash
python3 -c "
import hashlib, base64
with open('favicon_target.ico', 'rb') as f:
    hash_bytes = base64.b64encode(hashlib.md5(f.read()).digest())
    print(f'favicon hash: {hash_bytes.decode()}')
"

# Search Shodan for IPs serving this favicon
HASH=$(python3 -c "
import hashlib, base64
with open('favicon_target.ico','rb') as f:
    print(base64.b64encode(hashlib.md5(f.read()).digest()).decode())
")
shodan search "http.favicon.hash:$HASH" --fields ip_str,port,org,hostnames

# Automated tools
python3 favUp.py -ff favicon_target.ico --shodan-cli
python3 favUp.py --web target.com -sc
```

### Phase 2 — Historical DNS Records

```bash
# SecurityTrails — DNS history
curl -s "https://securitytrails.com/domain/target.com/history/a" \
  -H "APIKEY: $SECURITYTRAILS_KEY" \
  | jq '.records[].values[].ip' | sort -u

# AlienVault OTX — passive DNS
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/target.com/passive_dns" \
  | jq '.passive_dns[].address' | sort -u

# Automated tools
echo "target.com" | originiphunter
cat domains.txt | originiphunter
```

### Phase 3 — SSL Certificate Search

```bash
# crt.sh — find all certs for the domain, extract unique IPs from SAN fields
curl -s "https://crt.sh/?q=%25.target.com&output=json" \
  | jq -r '.[].name_value' | tr ',' '\n' | sort -u > cert_domains.txt

# Censys — search by parsed names
# Web: https://search.censys.io — query: parsed.names: target.com

# Shodan — search by SSL subject CN
shodan search "ssl.cert.subject.cn:target.com" --fields ip_str,port,org

# Netlas — deep infrastructure search
# Web: https://netlas.io — query: domain:*.target.com
```

### Phase 4 — Google Analytics ID Cross-Referencing

```bash
# Extract Analytics ID from target pages
curl -s "https://target.com" | grep -oP '(?:UA-|G-|GTM-)[A-Z0-9]+'

# Find all domains sharing the same GA ID
curl -s "https://api.hackertarget.com/analyticslookup/?q=UA-XXXXXXXX-X"
curl -s "https://builtwith.com/relationships/target.com"

# Automated
cat subdomains.txt | analyticsrelationships
```

### Phase 5 — Common Origin Leak Vectors

```bash
# Direct IP in page source
curl -sk "https://target.com" | grep -oP '\b(?:\d{1,3}\.){3}\d{1,3}\b' | sort -u

# DNS CNAME chain — may expose origin
dig target.com ANY +noall +answer
dig www.target.com CNAME +short

# MX records — mail server often shares infrastructure
dig target.com MX +short

# SPF records — may contain non-CDN IPs
dig target.com TXT +short | grep -oP '\b(?:\d{1,3}\.){3}\d{1,3}\b'

# Subdomain with different IP pattern
subfinder -d target.com -silent | dnsx -silent -a -resp-only | sort -u > all_ips.txt
# Filter out Cloudflare IPs (104.x, 172.64-71.x)
grep -vE '^104\.(1[6-9]|2[0-9]|3[0-1])\.|^172\.(6[4-9]|7[0-1])\.' all_ips.txt > non_cf_ips.txt
# Probe each for the target's content
for ip in $(cat non_cf_ips.txt); do
  curl -sk --connect-timeout 5 "https://$ip" -H "Host: target.com" -o /dev/null -w "%{http_code} $ip\n"
done | grep -v "^403\|^000"
```

### Phase 6 — Validate Origin

```bash
# Check if IP serves the target's content
curl -sk "https://ORIGIN_IP" -H "Host: target.com" | grep -o '<title>[^<]*</title>'

# Verify favicon matches
curl -sk "https://ORIGIN_IP/favicon.ico" -H "Host: target.com" -o favicon_origin.ico
md5sum favicon_target.ico favicon_origin.ico  # should match

# Probe ports directly on origin
naabu -host ORIGIN_IP -p - -rate 2000
```

## Pitfalls

- **Cloudflare may block your IP on repeated scans.** Rotate user-agents and proxies.
- **Shodan queries require an API key.** Free tier is rate-limited.
- **The origin may also be behind firewall rules.** Even if you find the IP, it may only accept traffic from Cloudflare's IP ranges.
- **Google Analytics IDs are shared across unrelated sites.** Verify by favicon or content match before claiming a finding.
- **Non-CDN IPs from subdomains may be load balancers,** not the actual web server origin. Probe with Host header to confirm.

## Verification

1. Favicon hash matches between CDN-cached site and direct origin IP.
2. HTTPS request to origin IP with `Host: target.com` returns the same page content.
3. Open ports on origin differ from CDN-proxied ports (origin exposes SSH, MySQL, etc.).
4. SSL certificate on the origin IP lists the target domain in SAN.

## Related Skills

- **`subdomain-enumeration`** — Generate the subdomain list needed for IP deduplication.
- **`vhost-enumeration`** — Once origin IP is found, enumerate virtual hosts.
- **`port-mass-scan`** — Scan origin IP for exposed services.
