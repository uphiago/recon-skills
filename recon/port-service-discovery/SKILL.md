---
name: port-service-discovery
description: Nmap scan for MySQL, Redis, FTP, SSH, internal API services.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires agentiko worker (curl, nmap, python3, masscan, subfinder, httpx, nuclei)
metadata:
  hermes:
    tags: [recon, port-scan, mysql, FTP, SSH, internal-api]
    category: recon
    related_skills:
      - deep-invade
      - wp-mass-recon
      - cross-attack-chains
      - staging-subdomain-hunt
      - xmlrpc-exploitation
---

# Port & Service Discovery Skill

Fast port scanning with nmap to discover exposed services (MySQL, FTP, SSH, SMTP, internal APIs, Redis, MongoDB) on WordPress and web targets. MySQL on port 3306 open to the internet is one of the rarest but most critical findings — confirmed on patientportal.com (healthcare SaaS). Port scanning reveals the infrastructure layer that HTTP-based recon misses.

## When to Use

- Running `deep-invade` Phase 6 on a high-value target.
- After surface recon shows no exploitable web vulnerabilities — pivot to infrastructure.
- When the target is a SaaS with backend APIs on non-standard ports.
- After discovering a staging subdomain — check for database/admin ports.

## Prerequisites

- `terminal` tool with nmap (available on worker container).
- Target domain or IP address.
- For full port scan: patience (can take 10-60 minutes for all 65535 ports).

## How to Run

```bash
# Fast top-100 port scan (30 seconds)
nmap -F --open -T4 TARGET -oN nmap_fast.txt

# Top 1000 ports (2-3 minutes)
nmap --top-ports 1000 --open -T4 TARGET -oN nmap_1000.txt

# Service version detection on open ports
nmap -sV -p $(grep 'open' nmap_fast.txt | cut -d/ -f1 | tr '\n' ',') TARGET

# Firewall bypass: fragment packets
nmap -f -F TARGET
```

## Quick Reference

| Port | Service | Finding Severity |
|------|---------|-----------------|
| 3306 | MySQL | Critical (if open to internet) |
| 27017 | MongoDB | Critical (if no auth) |
| 6379 | Redis | Critical (if no auth) |
| 5432 | PostgreSQL | High |
| 1433 | MS SQL Server | High |
| 21 | FTP | High (anonymous login?) |
| 22 | SSH | Info (check for weak auth) |
| 8080/8081/8082/8084 | Internal APIs | High (backend services exposed) |
| 9200 | Elasticsearch | High (data exposure) |
| 25/587 | SMTP | Medium (open relay?) |
| 110/143/993 | POP3/IMAP | Info |
| 8443 | HTTPS alt (admin panels) | Medium |
| 9090 | Prometheus/Cockpit | Medium |
| 3000 | Grafana/Node.js dev | Medium |

## Procedure

### Step 1 — Fast Top-100 Scan

```bash
TARGET="$1"
OUTDIR="/root/output/ports"
mkdir -p "$OUTDIR"

echo "[*] Fast scan (top 100 ports) on $TARGET..."
nmap -F --open -T4 --max-retries 1 --host-timeout 60s "$TARGET" -oN "$OUTDIR/${TARGET}_fast.nmap" 2>/dev/null

echo "[*] Open ports:"
grep 'open' "$OUTDIR/${TARGET}_fast.nmap" || echo "  None found"
```

### Step 2 — Service Version Detection

```bash
TARGET="$1"
OUTDIR="/root/output/ports"

# Get comma-separated list of open ports
OPEN_PORTS=$(grep '^[0-9]' "$OUTDIR/${TARGET}_fast.nmap" | awk -F/ '{print $1}' | tr '\n' ',' | sed 's/,$//')

if [[ -n "$OPEN_PORTS" ]]; then
  echo "[*] Service detection on ports: $OPEN_PORTS"
  nmap -sV --version-intensity 5 -p "$OPEN_PORTS" "$TARGET" -oN "$OUTDIR/${TARGET}_services.nmap" 2>/dev/null

  echo "[*] Services:"
  grep 'open' "$OUTDIR/${TARGET}_services.nmap"
else
  echo "[-] No open ports found"
fi
```

### Step 3 — Critical Exposure Check

```bash
TARGET="$1"
OUTDIR="/root/output/ports"

echo "[*] Critical exposure assessment:"

# MySQL (3306)
if grep -q '3306.*open' "$OUTDIR/${TARGET}_fast.nmap" 2>/dev/null; then
  echo ""
  echo "[CRITICAL] MySQL 3306 OPEN — attempting banner grab..."
  # Try to get MySQL version
  mysql_info=$(timeout 5 nc -w 3 "$TARGET" 3306 </dev/null 2>/dev/null | head -1)
  [[ -n "$mysql_info" ]] && echo "  Banner: $mysql_info"

  # Test for no-auth MySQL
  echo "  Testing anonymous access..."
  # This typically requires mysql client; note methodology
  echo "  Manual check: mysql -h $TARGET -u root --skip-ssl"
  echo "  Manual check: mysql -h $TARGET -u admin --skip-ssl"
fi

# MongoDB (27017)
if grep -q '27017.*open' "$OUTDIR/${TARGET}_fast.nmap" 2>/dev/null; then
  echo ""
  echo "[CRITICAL] MongoDB 27017 OPEN"
  echo "  Manual check: mongosh mongodb://$TARGET:27017"
fi

# Redis (6379)
if grep -q '6379.*open' "$OUTDIR/${TARGET}_fast.nmap" 2>/dev/null; then
  echo ""
  echo "[HIGH] Redis 6379 OPEN — testing no-auth access..."
  redis_test=$(timeout 5 bash -c "echo -e 'PING\r\nINFO\r\n' | nc -w 3 '$TARGET' 6379 2>/dev/null")
  if echo "$redis_test" | grep -q "PONG"; then
    echo "  [CRITICAL] Redis NO AUTH — full access!"
    echo "  Response: $(echo "$redis_test" | head -5)"
  else
    echo "  Redis requires auth (or connection failed)"
  fi
fi

# Internal API ports (8080-8089)
for port in 8080 8081 8082 8084 8088 8443 3000 5000 9000 9090; do
  if grep -q "${port}.*open" "$OUTDIR/${TARGET}_fast.nmap" 2>/dev/null; then
    echo ""
    echo "[HIGH] Port $port OPEN — probing HTTP..."
    http_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "http://$TARGET:$port/" 2>/dev/null)

    if [[ "$http_code" != "000" ]]; then
      echo "  HTTP $http_code on port $port"
      title=$(curl -sk --max-time 5 "http://$TARGET:$port/" 2>/dev/null | grep -oP '<title>\K[^<]+')
      [[ -n "$title" ]] && echo "  Title: $title"

      # Check for Swagger/API docs
      for api_path in "swagger.json" "api-docs" "swagger-ui.html" "graphql" "actuator/health"; do
        api_code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 "http://$TARGET:$port/$api_path")
        [[ "$api_code" == "200" ]] && echo "  [API] http://$TARGET:$port/$api_path (HTTP 200)"
      done
    fi
  fi
done

# FTP (21) — check for anonymous login
if grep -q '21.*open' "$OUTDIR/${TARGET}_fast.nmap" 2>/dev/null; then
  echo ""
  echo "[HIGH] FTP 21 OPEN — testing anonymous login..."
  anon_test=$(timeout 10 bash -c "echo -e 'anonymous\nanonymous\n' | nc -w 3 '$TARGET' 21 2>/dev/null")
  if echo "$anon_test" | grep -qi "230"; then
    echo "  [CRITICAL] Anonymous FTP login successful!"
  elif echo "$anon_test" | grep -qi "530\|331"; then
    echo "  Anonymous FTP: requires auth"
  fi
fi

# SSH (22) — check for weak ciphers
if grep -q '22.*open' "$OUTDIR/${TARGET}_fast.nmap" 2>/dev/null; then
  echo ""
  echo "[INFO] SSH 22 OPEN"
  ssh_banner=$(timeout 5 nc -w 3 "$TARGET" 22 </dev/null 2>/dev/null | head -1)
  [[ -n "$ssh_banner" ]] && echo "  Banner: $ssh_banner"
fi
```

### Step 4 — Extended Port Range (when fast scan finds nothing)

```bash
TARGET="$1"
OUTDIR="/root/output/ports"

# If no ports found in top-100, expand to top-1000
if ! grep -q 'open' "$OUTDIR/${TARGET}_fast.nmap" 2>/dev/null; then
  echo "[*] No ports in top-100, scanning top-1000..."
  nmap --top-ports 1000 --open -T4 --max-retries 1 --host-timeout 120s "$TARGET" -oN "$OUTDIR/${TARGET}_1000.nmap" 2>/dev/null

  OPEN=$(grep 'open' "$OUTDIR/${TARGET}_1000.nmap")
  if [[ -z "$OPEN" ]]; then
    # Try SYN scan with fragmentation for firewall evasion
    echo "[*] Still nothing — trying fragmented SYN scan..."
    nmap -f -sS -F --open -T4 "$TARGET" -oN "$OUTDIR/${TARGET}_frag.nmap" 2>/dev/null
  fi
fi
```

### Step 5 — Firewall/WAF Fingerprinting

```bash
TARGET="$1"

echo "[*] WAF/CDN detection:"

# Check for Cloudflare
cf_header=$(curl -skI --max-time 5 "https://$TARGET/" 2>/dev/null | grep -i "cf-ray\|cloudflare")
[[ -n "$cf_header" ]] && echo "  Cloudflare detected"

# Check for AWS CloudFront
cf_header=$(curl -skI --max-time 5 "https://$TARGET/" 2>/dev/null | grep -i "x-amz-cf\|cloudfront")
[[ -n "$cf_header" ]] && echo "  AWS CloudFront detected"

# Check origin IP (bypass CDN)
echo "[*] Historical DNS records for origin IP discovery:"
# SecurityTrails, DNSDumpster, etc. — use web_extract for these
echo "  Manual: securitytrails.com/domain/$TARGET/dns/a"
echo "  Manual: dnsdumpster.com"

# Try direct IP connection (if known)
# curl -sk --resolve "$TARGET:443:ORIGIN_IP" "https://$TARGET/"
```

## Pitfalls

- **nmap SYN scan requires root.** The worker container runs as root, so `-sS` (SYN scan) is available. If running from a non-root context, use `-sT` (TCP connect).
- **Rate limiting on port scans.** Some providers (AWS, Cloudflare) rate-limit or block port scans. Use `-T2` (polite timing) and `--max-retries 1` on sensitive targets.
- **MySQL/MongoDB banner grab may not work.** Some DBs require TLS negotiation (MySQL 8.0+ defaults to `caching_sha2_password`). Banner may be empty.
- **Internal API ports may time out.** Some services only respond to specific Host headers or valid HTTP requests. Use `curl` with various Host headers.

## Verification

- Every open port MUST be confirmed with service version detection (`nmap -sV`).
- MySQL access MUST be tested with actual connection attempt (not just port open).
- Redis no-auth MUST return `PONG` to `PING` command.
- FTP anonymous MUST return code 230 (login successful).
- All findings MUST be documented with exact port, service, version, and access level.
