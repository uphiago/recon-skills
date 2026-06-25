# Target Attack Prioritization

How to pick the top 3 targets from a batch of recon findings. Based on evaluating 58 vulnerable companies across 28 sectors.

## Evaluation Criteria (weighted)

| Criterion | Weight | What to Look For |
|-----------|--------|------------------|
| **RCE path** | 10 | PHPInfo with exec/shell_exec NOT disabled + registration open OR upload accessible |
| **SSRF to IMDS** | 9 | XMLRPC pingback.ping returning faultCode 0 to 169.254.169.254 |
| **No auth needed** | 8 | Open registration, CORS without auth, XMLRPC without auth |
| **Brute force surface** | 7 | system.multicall (1000x amplification), no rate limit, known usernames |
| **Data value** | 6 | WooCommerce orders, Gravity Forms entries, patient data, employee PII |
| **Attack chain length** | 5 | Fewer steps = better. 1 step >> 4 steps |
| **Corporate email leak** | 4 | Spear-phishable contacts → credential theft |
| **Super admin exposure** | 3 | is_super_admin:true, ID=1 exposed |

## Quick Assessment Flow

```
Start with all findings
  ├─ Has PHPInfo + exec NOT disabled + registration open? → #1 priority (immediate RCE)
  ├─ Has XMLRPC pingback to 169.254.169.254 (faultCode 0)? → #2 (instant AWS account)
  ├─ Has system.multicall + known users + no rate limit? → #3 (brute force chain)
  └─ Has CORS credential + corporate emails? → Phishing chain (supplemental)
```

## Real Examples

| Target | RCE Path | SSRF→IMDS | No Auth | Brute | Score | Rank |
|--------|----------|-----------|---------|-------|-------|------|
| wines.com | ✅ (register → upload → exec) | ❌ | ✅ | ✅ | 10+8+7=25 | #1 |
| biglots staging | ❌ | ✅ (15 endpoints) | ✅ | ❌ | 9+8=17 | #2 |
| restonic.com | 🔄 (needs brute 1st) | ❌ | ✅ | ✅ (multicall) | 8+7=15 | #3 |

## Key Insight

**Single-vector exploitation > multi-step chain.** A target with a 1-step RCE path (wines.com: register → upload → exec) is always higher priority than a target requiring a 4-step chain (phish → steal creds → login → upload → RCE), even if the latter has more total findings.
