# Proxy Setup on Alpine Worker (proxychains + Tor)

Validated setup for Alpine Linux 3.21 worker containers.

## Install
```bash
apk add tor proxychains-ng
```

## Configure Tor
```bash
tor --DataDirectory /tmp/tordata \
    --SOCKSPort 9050 \
    --ControlPort 9051 \
    --CookieAuthentication 0 &
sleep 5  # wait for bootstrap
```

Wait for "Bootstrapped 100% (done)" in logs.

## Configure proxychains
Config file: `/etc/proxychains/proxychains.conf`

```ini
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 9050
```

## Verify
```bash
# Direct IP (ISP)
curl -s https://httpbin.org/ip

# Through Tor
proxychains4 curl -s https://httpbin.org/ip
# Should show different IP
```

## Tor Circuit Rotation
```bash
echo -e "AUTHENTICATE\r\nSIGNAL NEWNYM\r" | nc -w1 127.0.0.1 9051
sleep 2
```

## Known Issues
- **ifconfig.me blocks Tor** — use httpbin.org/ip instead
- **Nmap SYN scan (-sS) doesn't work** — use -sT (TCP connect)
- **Alpine uses BusyBox** — grep -P unsupported, use python3
- **Go binaries need proxy-ns** (not installed by default)
