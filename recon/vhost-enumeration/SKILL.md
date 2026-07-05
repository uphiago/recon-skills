---
name: vhost-enumeration
description: Discover hidden virtual hosts via Host header fuzzing and SSL certificate parsing.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, ffuf, dnsx
metadata:
  tags: [recon, vhost, virtual-host, Host-header, fuzzing, SSL, PTR]
  category: recon
  related_skills:
    - subdomain-enumeration
    - origin-ip-discovery
    - web-enumeration
---

# Virtual Host Enumeration

Discover hidden virtual hosts on IP addresses by fuzzing the `Host` header. Many servers only respond to specific domain names and remain invisible to standard subdomain enumeration. VHOST fuzzing exposes internal services, development environments, and admin panels that share the same IP but answer to different hostnames.

## When to Use

- You have a list of target IPs from `origin-ip-discovery` or `port-service-discovery`.
- A server returns default/blank pages for unknown Host headers.
- Subdomain enumeration may have missed internal-only hostnames.
- SSL certificates on an IP list multiple domain names in the SAN field.
- You need to map internal services behind a reverse proxy.

## Prerequisites

- `terminal` tool with curl, ffuf, dnsx, and httpx.
- A DNS wordlist for hostname fuzzing.
- A list of target IP addresses.

## Quick Detection

```bash
# Basic VHOST fuzz on a single IP
ffuf -u http://TARGET_IP \
  -w /path/to/wordlist.txt \
  -H "Host: FUZZ.target.com" \
  -fs 0 -mc 200,301,302,401,403
```

## Procedure

### Phase 1 — Host Header Fuzzing

```bash
# Fuzz for virtual hosts matching the target domain pattern
ffuf -u http://TARGET_IP \
  -w $DNS_WORDLIST \
  -H "Host: FUZZ.target.com" \
  -fs DEFAULT_RESPONSE_SIZE \
  -mc 200,301,302,401,403 \
  -o vhost_ffuf.json

# HTTPS variant
ffuf -u https://target.com \
  -w $DNS_WORDLIST \
  -H "Host: FUZZ.target.com" \
  -mc 200,301,302,401,403

# Fuzz multiple IPs with a wordlist
cat unique_ips.txt | while read ip; do
  ffuf -u "http://$ip" \
    -w $DNS_WORDLIST \
    -H "Host: FUZZ.target.com" \
    -fs 0 -mc 200,301,302 -o "vhost_$ip.json"
done
```

### Phase 2 — Response Filtering

```bash
# Auto-calibrate: ffuf detects default response size and filters it out
ffuf -u http://TARGET_IP \
  -w $DNS_WORDLIST \
  -H "Host: FUZZ.target.com" \
  -ac -sf -s \
  -mc 200

# Manual calibration: find the default response size first
curl -s http://TARGET_IP -H "Host: nonexistentxxxxx12345.target.com" | wc -c
# Use that size as -fs filter
```

### Phase 3 — Accessing VHOST Targets

```bash
# Method 1 — direct curl with Host header
curl -H "Host: dev.target.com" http://TARGET_IP

# Method 2 — /etc/hosts injection for browser access
echo "TARGET_IP  dev.target.com internal.target.com admin.target.com" | sudo tee -a /etc/hosts
# Then open http://dev.target.com in browser

# Method 3 — httpx with custom host resolution
echo "http://dev.target.com" | httpx -silent
```

### Phase 4 — SSL Certificate SAN Enumeration

```bash
# Extract hostnames from SSL certificate
echo | openssl s_client -connect TARGET_IP:443 -servername target.com 2>/dev/null \
  | openssl x509 -noout -text \
  | grep -oP 'DNS:[^,\s]+' | cut -d: -f2 | sort -u

# Batch: extract hostnames from all discovered IPs
cat unique_ips.txt | while read ip; do
  echo | timeout 5 openssl s_client -connect $ip:443 2>/dev/null \
    | openssl x509 -noout -text 2>/dev/null \
    | grep -oP 'DNS:[^,\s]+' | cut -d: -f2 | sort -u >> ssl_hostnames.txt
done

# Check which of those hostnames resolve to the target
cat ssl_hostnames.txt | dnsx -silent -a -resp-only | sort -u
```

### Phase 5 — PTR Reverse DNS on IP Ranges

```bash
# If you have IP ranges, resolve PTR records to find hostnames
echo "66.211.170.0/23" | dnsx -silent -resp-only -ptr

# Batch on multiple CIDR ranges
cat cidr_ranges.txt | mapcidr -silent | dnsx -ptr -resp-only -silent > ptr_domains.txt
```

### Phase 6 — Content Differencing

```bash
# For each found VHOST, take a screenshot for visual triage
cat found_vhosts.txt | gowitness file -f - --no-http -P ./vhost_screenshots/

# Compare content across hosts — different content = different service
for host in $(cat found_vhosts.txt); do
  curl -sk "http://TARGET_IP" -H "Host: $host" | md5sum
done | sort
```

## Pitfalls

- **Wildcard DNS returns valid HTTP for any Host header.** Use auto-calibration (`-ac`) and verify manually.
- **The default virtual host may return a generic page for unknown names.** Calibrate `-fs` with a known-nonexistent hostname.
- **SSL/TLS prevents content comparison without SNI.** Use `openssl s_client -servername` for each hostname.
- **Some servers accept any Host header.** This produces false positives — verify each finding with manual curl.
- **Internal-only services may not be accessible from your IP.** They may require internal network access.

## Verification

1. ffuf returns a status code and response size different from the calibrated default.
2. Manual curl with the discovered Host header returns meaningful content (not the default page).
3. The discovered hostname is not in the public subdomain list (previously unknown).
4. SSL certificate SAN field confirms the hostname belongs on this server.
5. Take a screenshot and confirm it's a distinct application or service.

## Related Skills

- **`subdomain-enumeration`** — Generate the DNS wordlist and existing subdomains.
- **`origin-ip-discovery`** — Find the origin IPs that need VHOST scanning.
- **`web-enumeration`** — Once VHOSTs are found, fuzz directories and endpoints.
