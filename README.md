# Recon Skills — agentiko

Offensive reconnaissance skill library for the agentiko Hermes Agent.

**Focus:** Recon, pentest, red team, vulnerability hunting, attack chains.

## Structure

| Directory | Purpose |
|-----------|---------|
| recon/ | Reconnaissance skills (subdomain enum, port scan, WP mass recon, CORS, XMLRPC) |
| redteam/ | Per-class vulnerability hunting (51 hunt-* skills), sector recon (27 sectors), ops |
| chains/ | Multi-step attack chains (cross-attack, WordPress full compromise) |
| meta/ | Orchestration playbooks, methodology references, sector selection |
| auth/ | Authentication attacks (SAML SSO) |
| infra/ | Infrastructure attacks (Docker privesc) |
| agentiko-* | Agentiko environment skills (Hermes + Worker) |

## Usage

Skills are loaded by the Hermes Agent via skill_view(name). Each SKILL.md is a self-contained operational package.

## Data Hygiene

All skills are fully agnostic — no company names, domains, emails, or identifiable target data.
