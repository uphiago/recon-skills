#!/usr/bin/env python3
"""probe_sector.py — parameterized SMB-sector recon driver for recon-sector.

Implements the probe suite documented in SKILL.md:
WordPress detection, REST user enum, CORS credential reflection, XMLRPC
exposure, debug log mining, directory listing, source leaks and
sector-specific paths from references/sectors.yaml.

Usage:
    python3 probe_sector.py SECTOR TARGETS_FILE [OUTDIR]

Writes one findings markdown per target under OUTDIR (default ./output).
Read-only HTTP GET/POST probes only; bounded by --max-time and per-target
sleeps. Authorization and scope are the operator's responsibility.
"""

import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("PyYAML is required: pip install pyyaml")

TIMEOUT = 10
SLEEP = 1
UA = {"User-Agent": "recon-sector/2.0"}
EVIL_ORIGIN = "https://evil.example"

SRC_LEAK_PATHS = ["/.env", "/.git/config", "/info.php"]
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
PII_RE = re.compile(r"(address|phone|street|zip|SSN|card|CC|credit).{0,80}")


def http(url, method="GET", data=None, headers=None, timeout=TIMEOUT):
    """Return (status, headers-dict, body-text) or (0, {}, '') on failure."""
    req = urllib.request.Request(url, method=method, data=data, headers=headers or UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return e.code, dict(e.headers or {}), body
    except Exception:
        return 0, {}, ""


def probe_target(target, sector_paths):
    findings = []

    code, _, _ = http(f"https://{target}/wp-login.php")
    if code and code != 404:
        findings.append(("WP", f"/wp-login.php returned HTTP {code}"))

    headers = {"Origin": EVIL_ORIGIN, **UA}
    code, resp_headers, _ = http(
        f"https://{target}/wp-json/wp/v2/users", headers=headers
    )
    acao = resp_headers.get("Access-Control-Allow-Origin", "")
    acac = resp_headers.get("Access-Control-Allow-Credentials", "")
    if acao == EVIL_ORIGIN and acac.lower() == "true":
        findings.append(
            ("CORS", f"ACAO reflects {EVIL_ORIGIN} with ACAC: true on wp/v2/users")
        )

    xmlrpc_body = (
        b'<?xml version="1.0"?>'
        b"<methodCall><methodName>system.listMethods</methodName></methodCall>"
    )
    code, _, body = http(
        f"https://{target}/xmlrpc.php",
        method="POST",
        data=xmlrpc_body,
        headers={"Content-Type": "text/xml", **UA},
    )
    if "methodResponse" in body:
        multicall = "YES" if "system.multicall" in body else "no"
        findings.append(("XMLRPC", f"active (system.multicall: {multicall})"))

    code, _, body = http(f"https://{target}/wp-content/debug.log", timeout=15)
    if body and len(body) > 200:
        emails = sorted(set(EMAIL_RE.findall(body)))[:10]
        pii_lines = len(PII_RE.findall(body))
        if emails or pii_lines:
            findings.append(
                (
                    "DEBUGLOG",
                    f"{len(body)} bytes, {len(emails)} emails, {pii_lines} PII hint lines",
                )
            )

    code, _, body = http(f"https://{target}/wp-content/uploads/")
    if code == 200 and "Index of" in body:
        findings.append(("DIRLIST", "/wp-content/uploads/ shows 'Index of'"))

    for path in SRC_LEAK_PATHS:
        code, _, body = http(f"https://{target}{path}")
        if code == 200 and body:
            leak_markers = ("DB_", "APP_", "_KEY", "_SECRET", "[core]", "PHP Version")
            if any(m in body for m in leak_markers):
                findings.append(("SRCLEAK", f"{path} returns sensitive content"))

    for path in sector_paths:
        code, _, _ = http(f"https://{target}{path}")
        if code and code != 404:
            findings.append(("SECTOR", f"{path} returned HTTP {code}"))
        time.sleep(SLEEP)

    return findings


def main():
    if len(sys.argv) < 3:
        sys.exit("usage: probe_sector.py SECTOR TARGETS_FILE [OUTDIR]")
    sector, targets_file = sys.argv[1], sys.argv[2]
    outdir = Path(sys.argv[3] if len(sys.argv) > 3 else "output")
    outdir.mkdir(parents=True, exist_ok=True)

    yaml_path = Path(__file__).parent / "sectors.yaml"
    data = yaml.safe_load(yaml_path.read_text())
    sector_info = data["sectors"].get(sector)
    if sector_info is None:
        known = ", ".join(sorted(data["sectors"]))
        sys.exit(f"unknown sector {sector!r}; known: {known}")
    sector_paths = sector_info.get("high_value_paths", [])

    for line in Path(targets_file).read_text().splitlines():
        target = line.strip()
        if not target:
            continue
        findings = probe_target(target, sector_paths)
        time.sleep(SLEEP)
        if not findings:
            continue
        report = outdir / f"{target.replace('/', '_')}.md"
        lines = [f"# recon-sector findings — {target} (sector: {sector})", ""]
        for kind, detail in findings:
            lines.append(f"- [{kind}] {detail}")
        report.write_text("\n".join(lines) + "\n")
        for kind, detail in findings:
            print(f"[{kind}] {target} — {detail}")


if __name__ == "__main__":
    main()
