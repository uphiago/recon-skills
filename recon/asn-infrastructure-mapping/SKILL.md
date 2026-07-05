---
name: asn-infrastructure-mapping
description: Map organization IP infrastructure via ASN, CIDR, TLD expansion, and reverse DNS.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, whois, dnsx, mapcidr
metadata:
  tags: [recon, ASN, CIDR, IP-range, TLD, reverse-DNS, infrastructure]
  category: recon
  related_skills:
    - subdomain-enumeration
    - origin-ip-discovery
    - vhost-enumeration
    - port-mass-scan
---

# ASN Infrastructure Mapping

Map an organization's entire IP infrastructure by pivoting from domain to ASN (Autonomous System Number), extracting CIDR ranges, and discovering every hostname and service across all owned IP blocks. Includes TLD expansion to find sibling domains on different top-level domains with separate infrastructure.

## When to Use

- You have a target domain and want to discover EVERY IP owned by the organization.
- Passive subdomain enumeration found only a few hosts — the rest may be on sibling TLDs or different IP ranges.
- The target has a known ASN that can be expanded to full CIDR blocks.
- Services on non-standard ports are invisible to web-only recon.
- Acquired subsidiaries or international domains may sit on different ASNs with weaker security.

## Prerequisites

- `terminal` tool with whois, dnsx, mapcidr, httpx, and asnmap.
- The target domain and/or a known IP belonging to the organization.
- Shodan API key (optional, for deeper OSINT).

## Quick Detection

```bash
# Start: domain → IP → ASN → CIDR ranges
IP=$(dig target.com +short | head -1)
ASN=$(whois $IP | grep -i "origin\|OriginAS" | awk '{print $NF}' | head -1)
echo "ASN: $ASN"
whois -h whois.radb.net -- "-i origin $ASN" | grep -Eo "([0-9.]+){4}/[0-9]+" | sort -u
```

## Procedure

### Phase 1 — Domain to ASN Discovery

```bash
# asnmap — automated domain → ASN
asnmap -d target.com

# Manual whois approach
IP=$(dig target.com +short | head -1)
whois $IP | grep -iE "origin|OriginAS|route:|descr:" | head -10

# spk — finds all ASNs for a company by name (including subsidiaries)
spk -json -s "Company Name"

# Web tools
# https://bgp.he.net — search by company name
# https://asnlookup.com — search by org name, ASN, or CIDR
# https://bgp.tools — modern BGP explorer
```

### Phase 2 — ASN to CIDR Ranges

```bash
# asnmap — direct CIDR extraction
asnmap -a AS33905 -silent > cidr_ranges.txt

# RADB whois — full route objects
whois -h whois.radb.net -- "-i origin AS33905" \
  | grep -Eo "([0-9.]+){4}/[0-9]+" \
  | sort -u >> cidr_ranges.txt

# metabigor — multi-source IP intelligence
echo "Company Name" | metabigor net --org -o cidr_ranges.txt
echo "ASN33905" | metabigor net --asn -o cidr_ranges.txt
```

### Phase 3 — CIDR to Individual IPs

```bash
# mapcidr — split CIDR into flat IP list
cat cidr_ranges.txt | mapcidr -silent > all_ips.txt
wc -l all_ips.txt

# prips — alternative IP generator
while read cidr; do prips "$cidr"; done < cidr_ranges.txt >> all_ips.txt

# Scan discovered IPs for live web services
cat all_ips.txt | httpx \
  -ports 80,443,8080,8443,3000,5000,8000,8888,9090,9443 \
  -status-code -title -web-server -silent \
  -o live_ip_services.txt
```

### Phase 4 — Reverse DNS on IP Ranges

```bash
# dnsx PTR — resolve hostnames from IP blocks
cat cidr_ranges.txt | dnsx -silent -resp-only -ptr > ptr_domains.txt

# Filter for target-related hosts
grep -i "target" ptr_domains.txt > ptr_target.txt

# hakrevdns — reverse DNS at scale
hakrevdns -d target.com -R resolvers.txt

# resolveDomains — check which IPs serve target content
resolveDomains -d all_subs.txt > resolved.txt
awk '{print $3}' resolved.txt | sort -u > unique_ips.txt
```

### Phase 5 — TLD Expansion

```bash
# tldbrute — discover all registered TLD variants
tldbrute -d target.com

# Manual IANA TLD list approach
wget -q https://data.iana.org/TLD/tlds-alpha-by-domain.txt
ROOT=$(echo "target.com" | cut -d. -f1)
cat tlds-alpha-by-domain.txt | tr '[:upper:]' '[:lower:]' \
  | while read tld; do echo "$ROOT.$tld"; done \
  | httpx -silent -mc 200 > tlds_alive.txt

# Apply to all known subdomains
cat all_subs.txt | while read sub; do
  cat tlds-alpha-by-domain.txt | tr '[:upper:]' '[:lower:]' \
    | sed "s/^/$sub./"
done | dnsx -silent > subs_tld_expanded.txt
```

### Phase 6 — Architecture Visualization

```bash
# Map which domains belong to which IP
cat unique_ips.txt | while read ip; do
  echo -n "$ip: "
  grep -l "$ip" resolved.txt 2>/dev/null | tr '\n' ' '
  echo
done > ip_to_domain_map.txt

# Identify shared infrastructure (one IP serving multiple domains — CDN or reverse proxy)
awk '{if (NF > 2) print}' ip_to_domain_map.txt > shared_infra.txt

# Scan non-web ports on ALL discovered IPs  
naabu -l all_ips.txt -p - -rate 1000 -c 50 -exclude-ports 80,443 -o all_services.txt
```

### Phase 7 — Sub-organization Discovery

```bash
# Extract all company/organization names from whois
cat all_ips.txt | while read ip; do
  whois $ip 2>/dev/null | grep -iE "OrgName|org-name|descr:" | head -1
done | sort -u > subsidiary_names.txt

# For each subsidiary, repeat the ASN → CIDR pipeline
cat subsidiary_names.txt | while read org; do
  metabigor net --org "$org" >> expanded_cidr.txt
done
```

## Pitfalls

- **CIDR ranges can be massive (e.g., AWS).** Only scan IP ranges confirmed to belong to the target, not the entire hosting provider.
- **RADB whois data may be stale.** Cross-reference with multiple sources (bgp.he.net, Censys, Shodan).
- **TLD expansion is noisy.** Only .com/.org/.net/.io/.dev usually produce useful results.
- **Reverse DNS may reveal internal hostnames.** Handle with care in external recon — these leaks are findings themselves.
- **Sub-organization discovery can lead to out-of-scope targets.** Always verify the relationship before scanning.

## Verification

1. CIDR ranges were confirmed via at least two sources (whois + bgp.he.net or asnmap).
2. Reverse DNS on discovered IPs returned target-related hostnames.
3. TLD expansion found live domains on sibling TLDs.
4. Web service scan identified unique applications on non-standard ports.
5. Map the full infrastructure: domains → IPs → services → vulnerabilities.

## Related Skills

- **`subdomain-enumeration`** — Generate the initial subdomain list before expanding to IP infrastructure.
- **`origin-ip-discovery`** — Once CIDR ranges are known, identify which IPs are origins behind CDN.
- **`vhost-enumeration`** — Scan discovered IPs for hidden virtual hosts.
- **`port-mass-scan`** — Scan all discovered IPs for exposed services.
