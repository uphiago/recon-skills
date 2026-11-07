# Skill Library Contributor Guide

This repository contains portable offensive-security playbooks. It does not
configure or document the runtime that consumes them.

> These skills are for authorized security testing only. Only test targets you
> own or have explicit written permission to test.

## Scope

Add or maintain skills for:

- external asset discovery and OSINT;
- web, API, cloud, identity, and infrastructure testing;
- platform-specific vulnerability validation;
- attack-path analysis;
- evidence handling, triage, and reporting.

Do not add:

- agent framework configuration;
- model or provider selection;
- chat, dashboard, cron, or scheduler instructions;
- private container, host, SSH, or network topology;
- deployment-specific workarounds;
- target-specific evidence or credentials;
- unrelated productivity or creative automation.

Docker, SSH, controllers, workers, and similar terms are valid when they are
the subject of a security technique. They are not valid as assumptions about
where this repository is running.

## Repository Layout

| Directory | Ownership |
|---|---|
| `chains/` | Evidence-backed attack paths |
| `infra/` | Infrastructure exploitation and validation |
| `meta/` | Cross-skill workflows and engagement methodology |
| `recon/` | Discovery and focused enumeration |
| `redteam/` | Vulnerability-class, platform, and reporting skills |

Place supporting material next to its skill:

```text
category/skill-name/
|-- SKILL.md
|-- references/
|-- scripts/
`-- templates/
```

## Skill Contract

Every new or substantially revised `SKILL.md` must follow [STYLE.md](STYLE.md)
and include:

1. `When to Use`
2. `Prerequisites`
3. `How to Run`
4. `Procedure`
5. `Pitfalls`
6. `Verification`

Frontmatter must provide a unique kebab-case `name`, a concise description,
semantic version, license, supported platforms, category, tags, and valid
related-skill names.

Commands must be runnable, bounded, and explicit about side effects. Include
timeouts and conservative concurrency. Distinguish discovery from validation,
and require operator confirmation before any state-changing request.

## Portability

Assume only an authorized execution environment with the prerequisites listed
by the skill.

- Use normal command names such as `curl`, `nmap`, or `python3`.
- Use `${OUTPUT_DIR:-./output}` for generated artifacts.
- State when root, raw sockets, browser automation, Tor, a proxy, or credentials
  are required.
- Provide a portable fallback when practical.
- Do not assume a specific Linux distribution or package manager.
- Do not reference private IPs, container names, mounted secrets, or runtime
  control APIs.

Runtime-specific behavior belongs in the runtime repository, not in a security
methodology skill.

## Evidence and Claims

A response code alone rarely proves a vulnerability. Verification must describe
the semantic evidence required for the claim.

- CORS with credentials requires both a trusted or reflected origin and
  `Access-Control-Allow-Credentials: true`, plus a credentialed data-access
  scenario.
- An exposed path requires meaningful content, not only `200 OK`.
- XML-RPC requires a protocol-valid response, not only an HTTP status.
- A service banner or old version does not establish exploitability.
- A public client identifier is not automatically a secret.
- Configuration weaknesses must be separated from demonstrated impact.

Record requests, responses, timestamps, scope, tool versions, and redaction
decisions. Keep raw engagement evidence outside this repository.

## Cross-References

Use a skill's frontmatter `name`, not its filesystem path, in
`related_skills`. References must resolve to a current skill. Avoid duplicating
large payload catalogs or procedures; link to their owning skill or local
reference file.

## Validation

Run:

```bash
python3 scripts/validate_skills.py
```

Errors cover malformed metadata, duplicate names, broken skill references, and
forbidden runtime coupling. Warnings identify older skills that have not yet
reached the full section baseline.

Before presenting a change, also inspect:

```bash
git diff --check
git diff --stat
git diff
```

Do not commit, push, publish, or deploy unless the operator explicitly asks.
