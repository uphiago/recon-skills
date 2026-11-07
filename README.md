# Recon Skills

<p align="center">
  <img src="banner.png" alt="Recon and pentest skills" width="800">
</p>

A curated pack of security skills for external reconnaissance, web
applications, APIs, authentication, vulnerability validation, attack-path
analysis, and reporting.

> These skills are for authorized security testing only. Only test targets you
> own or have explicit written permission to test.

> **Blog & research**: [hiago.sh](https://hiago.sh) - Pentest Playbook, field
> notes, and tooling.

## What Is Included

The catalog is primarily focused on external web security:

- subdomain, DNS, port, HTTP, and technology discovery;
- route, parameter, JavaScript, source-map, and API mapping;
- authentication, authorization, session, OAuth, SAML, and MFA testing;
- web vulnerability and framework-specific validation;
- cloud, identity, container, and exposed-infrastructure pivots;
- evidence review, attack-path analysis, and reporting.

Each skill owns a focused objective and documents the prerequisites, procedure,
pitfalls, verification criteria, and related techniques needed for that
objective. Older skills are being migrated incrementally to the complete
[quality baseline](STYLE.md).

## Catalog

```text
recon-skills/
|-- chains/     Multi-step attack-path analysis
|-- infra/      Infrastructure-focused techniques
|-- meta/       Engagement planning and cross-skill workflows
|-- recon/      Discovery, enumeration, and focused validation
`-- redteam/    Vulnerability-class and platform playbooks
```

## Using the Pack

Clone the repository and locate the skills that match the observed surface:

```bash
git clone https://github.com/uphiago/recon-skills.git
cd recon-skills

find . -name SKILL.md -print | sort
rg -n "SSRF|OAuth|GraphQL|Kubernetes" --glob 'SKILL.md'
```

For a broad external web assessment, useful entry points are
`redteam/web2-recon`, `recon/subdomain-enumeration`,
`recon/web-enumeration`, and `redteam/bb-methodology`. Add vulnerability or
platform skills only when discovery produces a relevant signal.

Set a writable output location before running examples:

```bash
export OUTPUT_DIR="${OUTPUT_DIR:-./output}"
mkdir -p "$OUTPUT_DIR"
```

Commands assume standard Linux tooling unless a skill states otherwise. Tool
availability, scope, network policy, concurrency, credentials, and isolation
remain the operator's responsibility.

## High-Signal Entry Points

| Skill | Purpose |
|---|---|
| `meta/recon-playbook` | End-to-end recon workflow and escalation gates |
| `redteam/bb-methodology` | Bug bounty methodology and prioritization |
| `redteam/web2-recon` | Broad web attack-surface discovery |
| `redteam/offensive-osint` | External intelligence and asset pivots |
| `recon/subdomain-enumeration` | Passive and active subdomain discovery |
| `recon/port-service-discovery` | Port and service classification |
| `recon/web-enumeration` | Web paths, files, and technology enumeration |
| `recon/js-secrets-extraction` | Client-side bundle and secret analysis |
| `chains/cross-attack-chains` | Evidence-based attack-path construction |
| `redteam/triage-validation` | Finding validation before reporting |
| `redteam/evidence-hygiene` | Reproducible and redacted evidence capture |
| `redteam/report-writing` | Client and bug bounty reporting |

The `hunt-*` skills cover individual vulnerability classes and platform
surfaces. Skills can be followed manually or loaded as task context by an
automation system. Commands use standard tools and write persistent artifacts
beneath `${OUTPUT_DIR:-./output}` unless a skill documents another input.

## Quality and Safety

The quality baseline lives in [STYLE.md](STYLE.md). Contributor guidance lives
in [AGENTS.md](AGENTS.md). The operating principles live in [SOUL.md](SOUL.md).

Run the catalog validator before reviewing a change:

```bash
python3 scripts/validate_skills.py
```

Structural errors fail the command. Existing style debt is reported separately
as warnings so it can be improved incrementally.

## License

MIT. See [LICENSE](LICENSE).
