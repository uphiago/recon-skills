# Wave 9 Deep Invade — 7 US Targets (2026-06-24)

## Summary

7 targets deep-probed in under 15 minutes via parallel batching:
httpx → WP REST API enumeration → CORS testing → XMLRPC → port scan → sensitive files → JS bundle analysis.

## Target Ranking

### CRITICAL
1. **wines.com** — PHPInfo at /info.php AND /test.php (839 config entries), MySQL/FTP/SMTP/IMAP/DNS all open, CORS with credentials, XMLRPC 80 methods + multicall, WP registration open, directory listing on wp-content
2. **patientportal.com** — MySQL 3306 OPEN, CORS wildcard *, Port 8081 API backend (apiUrl leaked in JS bundle), React Admin Chatbot Portal, NOT WordPress

### HIGH
3. **realpro.com** — 3 super admins with PII, 33 REST namespaces (Elementor Pro, Forminator, MailPoet, WP Mail SMTP, Bit Integrations), CORS on user-specific endpoints
4. **restonic.com** — WooCommerce + Gravity Forms + solidwp-mail logs, 3 WP users, CORS with credentials
5. **toolking.com** — Slider Revolution 6.7.34 (known CVEs), 46 REST namespaces (most), Jetpack backup-helper-script

### MEDIUM
6. **defy.com** — 9 WP users with business emails (@circustrix.com, @skyzone.com), WP Store Locator API
7. **biglots.com** — wp/v2/users blocked (hardened) but author IDs leaked via posts/media

## Techniques Proven

- **Parallel batching**: httpx → WP REST → CORS → XMLRPC → ports — all 7 targets simultaneously, results in <15min
- **JS bundle apiUrl extraction**: Found https://patientportal.com:8081 by scanning React bundle with python3 regex
- **CORS matrix testing**: 3 origins × 6 endpoints per target = 18 CORS probes per target
- **PHPInfo discovery**: Both /info.php AND /test.php existed on wines.com — check both
- **Cross-WordPress subdirectory**: wines.com had /magical/ subdirectory with different install
- **BusyBox-safe regex**: python3 instead of grep -P for JS bundle analysis on Alpine

## Key Commands Reference

See SKILL.md sections: "Parallel Multi-Target Batch Probing", "WordPress REST API Deep Enumeration", "CORS Testing on Multiple Endpoints", "Sensitive File Enumeration", "JS bundle API key extraction (BusyBox-safe)".
