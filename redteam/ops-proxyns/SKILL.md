---
name: ops-proxyns
description: "Kernel-level proxy protection via proxy-ns — forces ALL traffic (TCP/UDP/DNS) through Tor using Linux network namespaces. Unlike proxychains, this works with Go/Rust/static binaries, prevents DNS leaks, and is impossible for applications to bypass. Includes Tor circuit rotation, IPv6 leak prevention, stealth headers, and jitter configuration. Use AT THE START of any pentest or recon engagement — before any probes that could leak your source IP. Setup once at the beginning of a session and run the entire toolchain inside the proxy-ns shell."
sources: field_ops, linux_kernel
report_count: 3
---

# OPS-PROXYNS — Kernel-Level Proxy / OPSEC Protection

## Why proxy-ns Over proxychains

| Feature | proxychains | proxy-ns |
|---------|-------------|----------|
| Covers Go/Rust static binaries | NO (LD_PRELOAD fails) | YES (kernel namespace) |
| DNS leak protection | Partial | Complete |
| UDP isolation | NO | YES |
| Bypassable by app | YES (direct socket) | NO |
| IPv6 leak | Common | Blocked |
| All traffic types | TCP only | TCP+UDP+DNS+ICMP |

proxy-ns uses Linux **network namespaces** to route ALL traffic from a process through a Tor proxy. The application has no way to detect or bypass it — it sees only the Tor exit node's IP.

---

## Installation

```bash
# Prerequisites
sudo apt update && sudo apt install -y tor proxychains4 git make gcc curl

# Clone and build proxy-ns
git clone https://github.com/OkamiW/proxy-ns.git /tmp/proxy-ns
cd /tmp/proxy-ns
CGO_ENABLED=0 make
sudo cp proxy-ns /usr/local/bin/

# Configure Tor
sudo tee /etc/tor/torrc << 'EOF'
SOCKSPort 9050
ControlPort 9051
CookieAuthentication 0
DataDirectory /var/lib/tor
EOF

# Restart Tor
sudo systemctl restart tor 2>/dev/null || sudo tor &
sleep 3
```

---

## Basic Usage

```bash
# Run a single command through Tor
sudo proxy-ns curl -s ifconfig.me
# Output: [Tor exit node IP]

# Run a full shell through Tor (ALL commands go through Tor)
sudo proxy-ns $SHELL

# Inside the proxy-ns shell:
curl -s ifconfig.me   # Tor IP
nmap -sT target.com   # Works (Go binary)
masscan 10.0.0.0/24 -p80 --rate 100  # Works
python3 -c "import requests; print(requests.get('https://ifconfig.me').text)"  # Works
whois target.com      # Works (DNS queries also routed through Tor)
```

---

## Tor Circuit Rotation

```bash
# Rotate to a new exit node IP
echo -e "AUTHENTICATE\r\nSIGNAL NEWNYM\r" | nc -w1 127.0.0.1 9051
sleep 2

# Verify new IP
sudo proxy-ns curl -s ifconfig.me
```

### Automated Rotation Script
```bash
#!/bin/bash
# rotate-tor.sh — Rotate Tor circuit and wait for new IP
rotate() {
    echo -e "AUTHENTICATE\r\nSIGNAL NEWNYM\r" | nc -w1 127.0.0.1 9051
    sleep $(awk -v min=3 -v max=8 'BEGIN{srand(); print int(min+rand()*(max-min+1))}')
}
NEW_IP=$(sudo proxy-ns curl -s ifconfig.me 2>/dev/null)
echo "[+] New Tor IP: $NEW_IP"

# Usage: rotate between every N requests
```

---

## IPv6 Leak Prevention

proxy-ns automatically blocks IPv6. Verify:

```bash
# Inside proxy-ns shell, test for leaks:
sudo proxy-ns bash -c '
  echo "=== IPv4 check ==="
  curl -s ifconfig.me
  echo ""
  echo "=== IPv6 check (should fail) ==="
  curl -6 -s ifconfig.me 2>&1 || echo "[OK] No IPv6"
  echo "=== DNS leak check ==="
  dig +short myip.opendns.com @resolver1.opendns.com
'
```

---

## Stealth Headers and Jitter

Always use rotating User-Agent and jitter between requests:

```python
# stealth_headers.py — Use inside proxy-ns shell
import requests, random, time

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
]

ACCEPT_LANGS = ["en-US,en;q=0.9", "en-GB,en;q=0.8", "en-CA,en;q=0.7"]

def stealth_session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(ACCEPT_LANGS),
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    })
    return s

def stealth_get(url, session=None, min_delay=2, max_delay=6):
    """Make a stealth GET with jitter"""
    s = session or stealth_session()
    time.sleep(random.uniform(min_delay, max_delay))
    return s.get(url, timeout=30)

# Usage:
# session = stealth_session()
# r = stealth_get("https://target.com/.env", session=session)
```

---

## Real Exposure Risks

| Risk | How It Happens | Consequence |
|------|---------------|-------------|
| **Leaked IP** | Server logs, WebRTC, DNS leaks | Blocking, tracking |
| **Fingerprinting** | User-Agent, TLS fingerprint (JA3), headers | Identified as bot |
| **Rate Limit** | Too many requests in a short period | IP permanently blocked |
| **Honeypot** | Fake endpoint that alerts the security team | Legal action |
| **SIEM/Splunk** | Centralized logs detect patterns | Security team alerted |
| **Cloudflare WAF** | Many sequential 403/503 | IP added to blacklist |
| **Tracked SA Key** | Excessive service account usage | Key revoked |
| **GitHub API** | Too many queries on the search API | Rate limit, token revoked |

## Pre-Test OPSEC Checklist

Before making ANY request to a target:

```
[ ] VPN/Tor active and verified (ifconfig.me shows non-originating IP)
[ ] IP not leaking? (check https://ipleak.net)
[ ] DNS not leaking (dig myip.opendns.com @resolver1.opendns.com)
[ ] WebRTC disabled?
[ ] IPv6 disabled/blocked (curl -6 ifconfig.me should fail)
[ ] Generic and rotating User-Agent?
[ ] Random delay (2-6s jitter between requests)?
[ ] GitHub credentials NOT logged in (or use dedicated burner account)
[ ] Nmap using -sT (SYN scan -sS is unsupported via proxy)
[ ] proxy-ns shell active for ALL commands (not just curl)
[ ] GitHub credentials logged in only when needed?
```

---

## Rate Limiting Protection

```bash
# Rotate IP between every N requests automatically
for i in $(seq 1 10); do
  echo "Request $i"
  sudo proxy-ns curl -s "https://target.com/.env" > /dev/null
  sleep 3
done

# After 10 requests, rotate Tor circuit
echo -e "AUTHENTICATE\r\nSIGNAL NEWNYM\r" | nc -w1 127.0.0.1 9051
sleep 3
NEW_IP=$(sudo proxy-ns curl -s ifconfig.me)
echo "[+] Rotated to IP: $NEW_IP"
```

---

## Recon Under proxy-ns

Run the entire recon toolchain inside proxy-ns:

```bash
# Start proxy-ns shell
sudo proxy-ns $SHELL

# Inside the protected shell:
TARGET="target.com"

# subfinder works (Go binary)
subfinder -d "$TARGET" -silent > subs.txt

# httpx works
cat subs.txt | httpx -silent -status-code > live.txt

# curl works
curl -sk "https://$TARGET/.env" | grep -i "DB_PASSWORD"

# nuclei works
nuclei -l live.txt -t ~/nuclei-templates/ -severity critical,high

# Python requests work
python3 -c "
import requests
r = requests.get('https://target.com/wp-json/wp/v2/users')
print(r.status_code, len(r.text))
"
```

---

## Common Pitfalls

| Issue | Solution |
|-------|----------|
| `sudo: proxy-ns: command not found` | Rebuild: `cd /tmp/proxy-ns && sudo make install` |
| Tor not running | `sudo systemctl start tor` or `sudo tor &` |
| `Connection refused` on port 9050 | Check `sudo netstat -tlnp | grep 9050` |
| Nmap SYN scan fails | Use `nmap -sT` (TCP connect scan) instead of `-sS` |
| Masscan banner grabbing | Use `--source-ip` with an interface IP on the host |
| Go binaries still show real IP | Ensure proxy-ns is installed correctly: `CGO_ENABLED=0 make` |
| Too slow (Tor latency) | Tor is naturally slow. Increase jitter or use a premium VPN as alternative. |

---

## Alternatives

If proxy-ns doesn't work on your kernel:

```bash
# Level 1: proxychains (works for Python/curl, NOT for Go/static binaries)
sudo apt install proxychains4
proxychains4 curl ifconfig.me

# Level 2: Full VPN (best performance, worst OPSEC — VPN logs)
# Level 3: Tails OS / Whonix (entire OS is Tor-routed)
# Level 4: Dedicated pentest VPS (separate jurisdiction)
```
