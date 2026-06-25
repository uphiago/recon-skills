---
name: hiago-blog
description: Extract blog posts from hiago.sh via RSC payload.
version: 1.0.0
author: agentiko
---

# Hiago Blog Extractor Skill

Extracts blog post content from hiago.sh using Next.js RSC payload parsing.

## When to Use
- Need to read a blog post from hiago.sh
- Research referenced in the Pentest Playbook

## How to Run
```bash
python3 scripts/hiago_blog.py                          # List posts
python3 scripts/hiago_blog.py pentest-playbook          # Read post
python3 scripts/hiago_blog.py --search recon            # Search
python3 scripts/hiago_blog.py --json                    # JSON output
```

## Available Posts
- pentest-playbook — The Practical Pentest Playbook
- agentic-engineering — Skills Stack, MCP, and Project Context
- linux-graphics — DE, WM, X11 and Wayland
- secure-boot — Signing Modules in UEFI Environments
