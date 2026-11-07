---
name: email-security
description: "DMARC/SPF/DKIM check, email spoofing, SMTP test, and security header analysis"
version: 1.1.0
revision_date: 2026-07-25
license: MIT
platforms: [linux]
metadata:
  tags: [email, SPF, DKIM, DMARC, spoofing, SMTP, recon]
  category: recon
---

# Email Security -- DMARC, SPF, DKIM

## When to Use

- During passive reconnaissance (Phase 1)
- After initial DNS enumeration
- DMARC p=none means DMARC enforcement is off; actual spoofability still depends on SPF/DKIM and the receiver's local policy
- Critical for identifying phishing/business email compromise risks

## Prerequisites

- Explicit authorization, target boundaries, and rate limits for the target.
- Tooling: `dig`, `swaks`.
- A writable evidence directory: `export OUTPUT_DIR="${OUTPUT_DIR:-./output}" && mkdir -p "$OUTPUT_DIR"`.
- For any state-changing step (writes, uploads, credential attempts), obtain explicit confirmation immediately before the command.

## How to Run

```bash
# SPF
dig +short TXT $target | grep "v=spf1"

# DMARC
dig +short TXT _dmarc.$target

# DKIM (common selector: google)
dig +short TXT google._domainkey.$target

# MX
dig +short MX $target
```

## Procedure

The phases below are the procedure. Keep each probe bounded (`--max-time`), record evidence beneath `OUTPUT_DIR`, and stop at the stop-conditions listed in Pitfalls.

## DMARC/SPF/DKIM Check Commands

```bash
# SPF
dig +short TXT $target | grep "v=spf1"

# DMARC
dig +short TXT _dmarc.$target

# DKIM (common selector: google)
dig +short TXT google._domainkey.$target

# MX
dig +short MX $target
```

## Interpreting Results

| Config | Meaning | Risk |
|--------|---------|------|
| v=spf1 ~all (softfail) | SPF suggests blocking but doesnt enforce | Spoofed emails may pass |
| v=spf1 ?all (neutral) | SPF does nothing | Totally permissive |
| v=spf1 include:amazonses.com ~all | SES can send as domain | Any AWS SES account can spoof |
| v=DMARC1; p=none | DMARC disabled | Zero spoofing protection |
| v=DMARC1; p=quarantine | Failed emails go to spam | Partial protection |
| v=DMARC1; p=reject | Failed emails rejected | Full protection |
| DKIM missing | No cryptographic signature | Email can be forged |

## Email Spoofing via SMTP

```bash
# Test SMTP relay
timeout 3 bash -c 'exec 3<>/dev/tcp/TARGET/25; head -1 <&3'

# Send spoofed email via open relay (swaks)
swaks --to victim@target.com --from admin@target.com   --server TARGET --body "Spoofed email"
```

## Headers That Indicate Security Level

| Header | Value | Meaning |
|--------|-------|---------|
| Authentication-Results | spf=pass | SPF passed |
| Authentication-Results | spf=fail | SPF failed |
| Authentication-Results | dmarc=pass | DMARC passed |
| Authentication-Results | dmarc=fail | DMARC failed |
| Authentication-Results | dkim=pass | DKIM passed |
| Received-SPF | Pass | Sender authorized |
| Received-SPF | Softfail | Sender not fully authorized |
| Received-SPF | Fail | Sender not authorized |
| ARC-Authentication-Results | | Authentication chain |

## AWS SES Spoofing (When SPF includes amazonses.com)

With `v=spf1 include:amazonses.com ~all`:
1. Create AWS account
2. Configure SES with your own domain (verified)
3. Send email with From: admin@target.com
4. SPF PASSES (because of include:amazonses.com)
5. DMARC p=none -- the receiver applies no DMARC policy; delivery then depends on SPF/DKIM and local filters

## Real-World Cases

**Field observation (reported as CRITICAL after delivery proof)**: an organization with DMARC p=none on both domains and SPF `include:amazonses.com`, where a message spoofed via a separate SES account was delivered to a controlled inbox. The inbox-delivery evidence, not the p=none record alone, justified the severity.

## Pitfalls

| Issue | Solution |
|-------|----------|
| SPF lookup limit | DNS has 10 lookup limit for SPF includes |
| DKIM selector unknown | Try common selectors: google, selector1, selector2, 2022, 2023 |
| DMARC reporting | rua=mailto: may leak authentication results to third party |

## Verification

```bash
# Check the DMARC policy first
dig +short TXT _dmarc.target.com
# p=none means no DMARC enforcement — it does NOT by itself prove spoofing.
# Proof = a spoofed message actually delivered to an inbox you control:
swaks --to you@your-inbox.example --from ceo@target.com \
  --server <an-smtp-relay-you-control-or-localhost> --header-From "ceo@target.com"
# Then inspect the delivered message's Authentication-Results header:
# dmarc=none or dmarc=pass with an attacker-controlled source = confirmed.
# Reject/quarantine or spam-folder delivery = not demonstrated.
```
