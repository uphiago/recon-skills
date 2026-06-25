# Wave 2 Sector Expansion — 25 US Company Domains (2026-06-24)

## Summary

Batch expansion into 10 fresh sectors: 25 domains tested via Python script with full 6-step pipeline (httpx → WP REST → CORS → XMLRPC → port scan → severity). Five vulnerable: 2 HIGH (credentialled CORS) + 3 MEDIUM (WP users exposed / CORS).

## Sector Coverage

| Sector | Domains Tested | High | Med | Low | None |
|--------|---------------|------|-----|-----|------|
| Dental | 5 | 0 | 1 | 0 | 4 |
| Auto Body | 4 | 1 | 0 | 1 | 2 |
| Bakery | 4 | 0 | 0 | 1 | 3 |
| Gym/Fitness | 3 | 0 | 1 | 0 | 2 |
| Carpet Cleaning | 3 | 0 | 0 | 1 | 2 |
| Laundry | 2 | 0 | 0 | 1 | 1 |
| Tree Services | 1 | 0 | 0 | 0 | 1 |
| Pest Control | 1 | 0 | 0 | 0 | 1 |
| Moving | 1 | 1 | 0 | 0 | 0 |
| Daycare | 1 | 0 | 1 | 0 | 0 |

## HIGH Findings

### greekmoving.com (Moving)
**Credentialled CORS** — `Access-Control-Allow-Origin: https://evil.com` + `Access-Control-Allow-Credentials: true` on `/wp-json/wp/v2/users`. WordPress 7.0 with 5 users exposed (Corey Schuchman, Good Greek Moving & Storage, stggreekmoving, tcrivari@peakactivity.com, Will Lam). XMLRPC open. Ports 21/53/80/110/143/443 open.

### leonsautobody.com (Auto Body)
**Credentialled CORS** — Same pattern. WordPress with 1 user (Gilmedia). Behind WP Engine + CloudFlare. Ports 80/443.

## MEDIUM Findings

### coastdental.com (Dental)
WordPress with **9 users** exposed via REST API (Debbie Nicholson, Devin Gilliam, Howie Taylor, Malic Vann, Office FL/GA/TX, Press Release, Rafael Rondon RDH BS). CORS reflects origin but no credentials. Port 8080 open.

### f45training.com (Gym/Fitness)
WordPress 6.9 with **8 users** exposed including **'administrator'** account. XMLRPC open. Yoast SEO Premium 27.2, WPML 4.8.6. Behind CloudFlare but REST API fully open.

### brighthorizons.com (Daycare)
**Wildcard CORS** — `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Headers: *` and `Access-Control-Allow-Methods: *`. No credentials flag, but broad wildcard policy.

## Notes

- Dental was the largest new sector tested (5 domains) and previously had zero coverage
- Many chain domains (24hourfitness.com, petsmart.com, montessori.com) timed out or were unreachable at time of testing
- CloudFlare was the most common CDN among tested domains (blocking deeper probes on some)
- CORS with credentials was the most severe finding pattern (2 out of 25 domains)
- All PHP/WordPress sites — no React SPAs or JAMStack sites found among these chains
