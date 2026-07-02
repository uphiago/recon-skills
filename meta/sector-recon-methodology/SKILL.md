---
name: sector-recon-methodology
description: Pick sectors, compile targets, batch recon for campaigns.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
compatibility: Requires curl, nmap, python3, masscan, subfinder, httpx, nuclei
metadata:
  hermes:
    tags: [meta, sector, methodology, target-selection, us-companies]
    category: meta
    related_skills:
      - recon-playbook
      - wp-mass-recon
      - attack-patterns-reference
      - subdomain-enumeration
      - cross-wave-delta-analysis
      - web-enumeration
---

# Sector Recon Methodology Skill

Methodology for selecting non-regulated industry sectors with the highest WordPress vulnerability rates, compiling company domain lists, and running batch reconnaissance. Distilled from surveying 600+ US companies across 28 sectors. Identifies which sectors to target, which to skip, and what patterns dominate each sector.

## When to Use

- Planning a new recon campaign and need to choose sectors.
- Expanding from tested sectors into new ones.
- Building target lists from sector keywords via crt.sh.
- After `recon-playbook` Phase 0 — this skill provides the sector intelligence.
- Comparing your findings against baseline vulnerability rates per sector.

## Prerequisites

- `terminal` tool with curl, jq, httpx, subfinder.
- Understanding of the US regulatory landscape (HIPAA, GLBA, PCI-DSS) — regulated sectors have near-zero vulnerability rates.
- Worker container for batch scanning.

## How to Run

```bash
# Generate targets for a sector
SECTOR="landscaping"
curl -sk "https://crt.sh/?q=%25.${SECTOR}%25&output=json" | jq -r '.[].name_value' | \
  sed 's/\*\.//g' | sed 's/^www\.//' | sort -u > ${SECTOR}_targets.txt
```

**Script**: `scripts/parallel_sector_probe.py` — OPSEC-controlled batch probe with random delays, generates per-domain findings files. Run `python3 scripts/parallel_sector_probe.py targets.txt output_dir/` for a full WP/CORS/XMLRPC/leak scan.

## Quick Reference

| Tier | Sectors | Typical WP Rate | Best Pattern | Notes |
|------|---------|----------------|--------------|-------|
| 1 | Law, Landscaping, Pools, Pest, Roofing, Dental, Gyms, Real Estate, HVAC, Property, Auto Repair, Photography | 30-50% | CORS + WP users | Minimal WAF, GoDaddy/Bluehost |
| 2 | Cleaning, Moving, Accounting, Septic, Window, Car Wash, Bakery, Locksmith, Solar, Chimney, Fire, Pet Grooming | 20-40% | Source leaks, CORS | Mixed hosting, some WAF |
| 3 | Car Dealers, Insurance, Travel, Banks, Healthcare | 0-5% | N/A | Enterprise WAF, regulated, no WP |

## Sector Vulnerability Rankings

### Tier 1 — High Yield (15-25% vulnerability rate)

| Sector | Vuln Rate | Top Pattern | WordPress Rate | WAF Protection | Best Targets |
|--------|-----------|-------------|----------------|----------------|-------------|
| Law Firms | 25% | P-06 (CORS auth) | ~30% | Minimal | Solo/small firm, GoDaddy-hosted |
| Landscaping | 20% | WP-01 (user enum) | ~50% | Minimal | Local SMB, franchise model |
| Pool Services | 20% | WP-01 (user enum) | ~45% | Minimal | Summer-seasonal businesses |
| Pest Control | 20% | P-02 (CORS) | ~40% | Minimal | Franchise-heavy |
| Roofing | 15% | WP-01, P-17 | ~45% | Minimal | Local contractors |
| Dental Clinics | 15% | WP-01 (user enum) | ~35% | Some | Single-dentist practices |
| Gyms/Fitness | 15% | WP-01 (user enum) | ~40% | Some | CrossFit, yoga, martial arts |
| Real Estate | 15% | P-02 (CORS) | ~40% | Some | Independent brokerages |
| HVAC/Plumbing | 14% | WP-01, P-02 | ~35% | Some | Franchise-heavy, staging common |
| Property Management | 15% | P-02 (CORS) | ~30% | Some | PII-heavy sector |\n| Auto Repair | 11% | WP-01 | ~30% | Some | Independent shops |
| Photography | 10% | WP-01 (user enum) | ~50% | Some | Portfolio sites, often WP |
| Funeral Homes | 10% | WP-01 (user enum) | ~33% | Minimal | WordPress + user enum found on 2 targets (funeralwise.com, memorialplanning.com) |
| Senior Living | 17% | P-02 (CORS) + XMLRPC | ~33% | Cloudflare | SeniorLifestyle.com (80 XMLRPC methods + CORS + multicall), SonataSeniorLiving.com (CORS) — 2/12 tested = CRITICAL findings |\n\n**Target these first.** Small to medium businesses, mostly self-managed WordPress, minimal security budget, no compliance requirements.

### Tier 2 — Medium Yield (5-14% vulnerability rate)

| Sector | Vuln Rate | Notes |
|--------|-----------|-------|
| Cleaning Services | 13% | Carpet, window, mold remediation |
| Moving Companies | 6% | Fewer WP, more SaaS platforms |
| Accounting/CPA | 5% | Some regulated, some not — financial data at risk |
| Septic Services | 25% source leaks | Massive source leak rate (.env, .git, wp-config) |
| Window Cleaning | 25% CORS | Small operations, DIY WP |
| Car Washes | 20% source leaks | Dockerfile, swagger, actuator endpoints common |
| Bakeries | 18% CORS wildcard | 28 leaked files on one target |
| Locksmiths | 20% WP users + XMLRPC | 38 subdomains on one target |
| Solar Installers | Minimal | Major brands use enterprise platforms |
| Chimney Sweeps | ~10% CORS + XMLRPC | Small family businesses, WP common |
| Fire Restoration | ~10% | Franchise model (Servpro, Belfor) |
| Pet Grooming | 20% WP users | Dogtopia, Camp Bow Wow — WP detected |

### Critical Finding Example (from 248-target new sector expansion)

**russellpools.com — Critical (Score 9):**
- 3 users exposed via REST API (wpadmin ID=1 — default admin account)
- CORS credential reflection confirmed
- XMLRPC system.multicall active
- **Attack chain:** CORS phishing → exfiltrate user data → brute force wpadmin via XMLRPC multicall → full site takeover

### Tier 3 — Zero/Low Yield (0-3% vulnerability rate)

| Sector | Vuln Rate | Why |
|--------|-----------|-----|
| Car Dealerships | 0% | Enterprise CDK/Dealertrack platforms, not WordPress |\n| Furniture Retail | 0% | Major brands (Ashley, Wayfair, Crate&Barrel, Pottery Barn) behind Cloudflare/WAF — 11/15 returned 403/429 |\n| Insurance | 0% | Enterprise portals, heavily WAF'd |
| Travel Agencies | 0% | SaaS (Sabre, Amadeus), not self-hosted |
| Banks/Credit Unions | 0% | GLBA regulated, mandatory security |
| Major Healthcare | 0% | HIPAA regulated, HITRUST certified |
| Home Services | 0% | Angi/Thumbtack platforms, not self-hosted |

**Skip these sectors** unless you have specific intelligence suggesting WordPress usage.

## Procedure

### Step 1 — Sector Selection

```bash
OUTDIR="/root/output/sectors"
mkdir -p "$OUTDIR"

echo "[*] Sector vulnerability potential assessment:"
echo ""

# Run quick sector probe: crt.sh → httpx → WP detection → user count
probe_sector() {
  local sector="$1"
  local file="$OUTDIR/${sector}_probe.txt"

  echo "[*] Probing sector: $sector"

  # Get domains from crt.sh
  curl -sk --max-time 20 "https://crt.sh/?q=%25.${sector}%25&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sed 's/^www\.//' | \
    grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' | sort -u | head -50 > "$OUTDIR/${sector}_domains.txt"

  # Option C: Manual known-company list (when crt.sh/subfinder time out)
  if [[ ! -s "$OUTDIR/${sector}_domains.txt" ]]; then
    echo "  crt.sh empty — using manual known-company list"
    # Generate known US companies in this sector
    # Example: for "vet" or "pet_care" sector, known chains include:
    cat > "$OUTDIR/${sector}_domains.txt" << 'EOF'
banfield.com
vca.com
petco.com
medvet.com
bluepearlvet.com
petcureoncology.com
animalclinic.com
petvets.com
veterinarypracticenews.com
EOF
  fi

  local total=$(wc -l < "$OUTDIR/${sector}_domains.txt")
  echo "  Domains: $total"

  # Probe with httpx
  httpx -silent -l "$OUTDIR/${sector}_domains.txt" -threads 30 -status-code -tech-detect \
    -o "$OUTDIR/${sector}_alive.txt" 2>/dev/null

  local alive=$(wc -l < "$OUTDIR/${sector}_alive.txt")
  echo "  Live: $alive"

  # WordPress count
  local wp=$(grep -ci 'wordpress' "$OUTDIR/${sector}_alive.txt" 2>/dev/null || echo 0)
  echo "  WordPress: $wp"

  # Quick user enumeration on WP targets
  local users=0
  grep -i 'wordpress' "$OUTDIR/${sector}_alive.txt" 2>/dev/null | awk '{print $1}' | head -10 | while read -r url; do
    ucount=$(curl -sk --max-time 5 "$url/wp-json/wp/v2/users" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 0)" 2>/dev/null || echo 0)
    [[ "$ucount" -gt 0 ]] && echo "    $url: $ucount users" >> "$OUTDIR/${sector}_users.txt"
  done

  local user_targets=$(wc -l < "$OUTDIR/${sector}_users.txt" 2>/dev/null || echo 0)
  echo "  User leaks: $user_targets"

  # Score the sector
  echo "$sector | domains=$total | alive=$alive | wp=$wp | user_leaks=$user_targets" >> "$OUTDIR/sector_scores.txt"
}

# Probe top candidate sectors
for sector in "landscaping" "roofing" "hvac" "pools" "plumbing" "lawn-care" \
  "pest-control" "law-firm" "dentist" "gym" "real-estate" "auto-repair" \
  "moving-company" "photography" "cleaning-service" "church"; do
  probe_sector "$sector"
  sleep 3  # Rate limit
done

echo ""
echo "[*] Sector scores:"
sort -t'|' -k5 -rn "$OUTDIR/sector_scores.txt" 2>/dev/null | head -15
```

### Step 2 — Target List Compilation

```bash
OUTDIR="/root/output/sectors"

# For selected high-yield sectors, compile full target lists
SELECTED_SECTORS=("landscaping" "roofing" "pools" "plumbing" "pest-control" "law-firm")

echo "[*] Compiling target lists for selected sectors..."

> "$OUTDIR/all_targets.txt"

for sector in "${SELECTED_SECTORS[@]}"; do
  echo "  Sector: $sector"

  # crt.sh wildcard search
  curl -sk --max-time 20 "https://crt.sh/?q=%25.${sector}%25&output=json" 2>/dev/null | \
    jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | sed 's/^www\.//' | \
    grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' | sort -u > "$OUTDIR/${sector}_all.txt"

  # Also try subfinder
  subfinder -d "${sector}.com" -silent 2>/dev/null >> "$OUTDIR/${sector}_all.txt"

  # Add to master list with sector label
  while read -r domain; do
    echo "$domain|$sector" >> "$OUTDIR/all_targets.txt"
  done < "$OUTDIR/${sector}_all.txt"

  sleep 2
done

# Clean: remove CDN domains, parking pages, known false positives
echo "[*] Cleaning target list..."

# Remove common false positives
grep -viE 'cloudflare|akamai|fastly|awsdns|googleusercontent|azurewebsites' "$OUTDIR/all_targets.txt" | \
  sort -u > "$OUTDIR/all_targets_clean.txt"

total=$(wc -l < "$OUTDIR/all_targets_clean.txt")
echo "[+] $total clean targets across ${#SELECTED_SECTORS[@]} sectors"
```

### Step 3 — Sector Baseline Statistics

After batch recon (using `recon-playbook`), compute per-sector stats:

```bash
OUTDIR="/root/output/sectors"
FINDINGS_DIR="/root/output/playbook/phase2_findings"

echo "[*] Computing sector statistics..."

# Extract sector from target list
declare -A SECTOR_WP
declare -A SECTOR_CORS
declare -A SECTOR_XMLRPC
declare -A SECTOR_LEAKS
declare -A SECTOR_TOTAL

# Read target list
while IFS='|' read -r domain sector; do
  [[ -z "$sector" ]] && continue
  ((SECTOR_TOTAL[$sector]++))

  findings_file="$FINDINGS_DIR/${domain}_p2.md"
  if [[ -f "$findings_file" ]]; then
    grep -q "WordPress:" "$findings_file" && ((SECTOR_WP[$sector]++))
    grep -q "CORS:" "$findings_file" && ((SECTOR_CORS[$sector]++))
    grep -q "XMLRPC:" "$findings_file" && ((SECTOR_XMLRPC[$sector]++))
    grep -q "Source leak:" "$findings_file" && ((SECTOR_LEAKS[$sector]++))
  fi
done < "$OUTDIR/all_targets_clean.txt"

# Print sector report
echo ""
echo "## Sector Vulnerability Report"
echo ""
echo "| Sector | Targets | WP | CORS | XMLRPC | Leaks | Rate |"
echo "|--------|---------|-----|------|--------|-------|------|"

for sector in "${!SECTOR_TOTAL[@]}"; do
  total=${SECTOR_TOTAL[$sector]}
  wp=${SECTOR_WP[$sector]:-0}
  cors=${SECTOR_CORS[$sector]:-0}
  xmlrpc=${SECTOR_XMLRPC[$sector]:-0}
  leaks=${SECTOR_LEAKS[$sector]:-0}
  vulns=$((cors + xmlrpc + leaks))
  rate=$(python3 -c "print(f'{$vulns/$total*100:.1f}%')" 2>/dev/null || echo "0%")

  echo "| $sector | $total | $wp | $cors | $xmlrpc | $leaks | $rate |"
done
```

### Step 4 — Sector Recon Skill Template

When creating a new sector-specific recon skill, use this template:

```markdown
---
name: recon-SECTORNAME
description: Reconnaissance workflow for SECTOR NAME companies.
version: 1.0.0
author: uphiago
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [recon, sector, SECTORNAME]
    category: recon
---

# SECTOR NAME Recon Skill

[2-3 sentence description of sector-specific attack surface]

## When to Use

- Targeting SECTOR NAME companies for recon.
- [Sector-specific trigger]

## Quick Reference

| Attack Surface | Expected Prevalence | Top Pattern |
|----------------|---------------------|-------------|
| WordPress | XX% | WP-01 |
| CORS | XX% | V1 |
| XMLRPC | XX% | WP-05 |
| Source leaks | XX% | P-17 |

## Attack Surface Signals

- [Sector-specific CMS/platform signals]
- [Common third-party integrations]
- [Typical infrastructure patterns]
- [PII/regulated data vectors]

## Sector-Specific Bypasses

- [WAF/CDN patterns for this sector]
- [Rate limiting characteristics]
- [Common security gaps]

## Real Examples

- [Target name]: [finding] (severity)
- [Target name]: [finding] (severity)

## Related Skills

- wp-mass-recon
- cors-credential-wordpress
- xmlrpc-exploitation
- source-leak-hunt
```

## Pitfalls

- **Sector keyword overlap.** `pest control` may return `pestcontrol.com` (the SaaS, not pest control companies). Filter by domain patterns typical of SMBs.
- **crt.sh noise from CDN/cloud.** Domains like `*.cloudfront.net` or `*.awsdns-*.org` appear in sector crt.sh queries. Filter aggressively.
- **crt.sh / subfinder timeouts.** Both tools frequently hang or return empty for low-traffic sectors or during high-demand windows. When they fail, fall back to manually compiling known US companies in the sector: use top-ranked national chains, franchise directories, and industry association member lists. Known-company lists are often more productive than sparse API results for long-tail sectors.
- **Sector saturation.** After scanning 50+ targets per sector, you'll see the same patterns. Move to new sectors once the baseline is established.
- **Corporate vs. franchise.** Some sectors (HVAC, pest control) have both corporate parent domains and individual franchise domains. The franchise domains are softer targets.

## Verification

- Sector vulnerability rates should be based on at least 20 scanned targets.
- Every sector should have at least one WordPress detection, CORS finding, or source leak to be considered "productive."
- Zero-yield sectors should be re-verified with a different methodology before being fully written off.
- Sector reports should include: total targets, alive hosts, WP detected, vulnerabilities found, top patterns, and representative examples.
