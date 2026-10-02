#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import time
import urllib.request
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config" / "sources.json"
CUSTOM_BLOCK = ROOT / "custom" / "block.txt"
CUSTOM_ALLOW = ROOT / "custom" / "allow.txt"
DIST = ROOT / "dist"

ADBLOCK_RE = re.compile(r"^\|\|([A-Za-z0-9._*-]+)\^")
DNSMASQ_RE = re.compile(r"^(?:address|server)=/([^/]+)/")
HOST_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+(\S+)")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?$"
)

USER_AGENT = "dns-master-blocklist/1.0 (+github-actions)"


def canonicalize(raw: str) -> str | None:
    s = raw.strip().lower()
    if not s or s.startswith(("#", "!", ";")):
        return None

    # Strip inline comments where safe.
    if " #" in s:
        s = s.split(" #", 1)[0].strip()

    m = ADBLOCK_RE.match(s)
    if m:
        s = m.group(1)
    else:
        m = DNSMASQ_RE.match(s)
        if m:
            s = m.group(1)
        else:
            m = HOST_RE.match(s)
            if m:
                s = m.group(1)
            else:
                # Plain list / wildcard forms.
                s = s.removeprefix("*.").removeprefix("||")
                s = s.removesuffix("^").rstrip(".")

    if not s or "/" in s or " " in s or "\t" in s:
        return None

    # Ignore IP literals.
    try:
        ipaddress.ip_address(s)
        return None
    except ValueError:
        pass

    # Convert Unicode hostnames to ASCII IDNA.
    try:
        s = s.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    s = s.rstrip(".")
    if s in {"localhost", "localhost.localdomain", "broadcasthost", "ip6-localhost"}:
        return None
    if "_" in s:  # DNS service records are not block targets here.
        return None
    if not DOMAIN_RE.match(s):
        return None
    return s


def parse_lines(lines: Iterable[str]) -> set[str]:
    out: set[str] = set()
    for line in lines:
        d = canonicalize(line)
        if d:
            out.add(d)
    return out


def fetch_text(url: str, timeout: int = 45, retries: int = 3) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read()
            return data.decode("utf-8", errors="replace")
        except Exception as e:
            last = e
            if attempt + 1 < retries:
                time.sleep(2 ** attempt)
    raise RuntimeError(f"fetch failed: {url}: {last}")


def is_allowed(domain: str, allow: set[str]) -> bool:
    # If allow contains example.com, exempt example.com + all subdomains.
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        if ".".join(parts[i:]) in allow:
            return True
    return domain in allow


def load_local(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return parse_lines(path.read_text(encoding="utf-8").splitlines())


def validate_source_selection(sources: list[dict]) -> None:
    enabled = [s for s in sources if s.get("enabled")]
    base = [s["name"] for s in enabled if s.get("role") in {"base", "alternate-base"}]
    if len(base) > 1:
        raise SystemExit(
            "ERROR: enable exactly one base tier. Enabled base tiers: "
            + ", ".join(base)
        )


def write_outputs(blocked: set[str], allow: set[str], report: dict) -> None:
    DIST.mkdir(parents=True, exist_ok=True)
    domains = sorted(blocked)

    (DIST / "blocklist.txt").write_text(
        "\n".join(domains) + ("\n" if domains else ""), encoding="utf-8"
    )
    (DIST / "allowlist.txt").write_text(
        "\n".join(sorted(allow)) + ("\n" if allow else ""), encoding="utf-8"
    )
    (DIST / "dnsmasq.conf").write_text(
        "".join(f"address=/{d}/#\n" for d in domains), encoding="utf-8"
    )
    (DIST / "adblock.txt").write_text(
        "".join(f"||{d}^\n" for d in domains), encoding="utf-8"
    )
    (DIST / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(CONFIG))
    ap.add_argument("--no-network", action="store_true",
                    help="Build only custom files; skip remote sources.")
    args = ap.parse_args()

    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    sources = cfg["sources"]
    validate_source_selection(sources)

    allow = load_local(CUSTOM_ALLOW)
    blocked = load_local(CUSTOM_BLOCK)

    report = {
        "enabled_sources": [],
        "source_stats": {},
        "custom_block": len(blocked),
        "custom_allow": len(allow),
        "removed_by_allow": 0,
        "final_domains": 0,
        "errors": [],
    }

    if not args.no_network:
        for src in sources:
            if not src.get("enabled"):
                continue
            name = src["name"]
            report["enabled_sources"].append(name)
            try:
                text = fetch_text(src["url"])
                parsed = parse_lines(text.splitlines())
                before = len(blocked)
                blocked.update(parsed)
                report["source_stats"][name] = {
                    "parsed_domains": len(parsed),
                    "new_unique_domains": len(blocked) - before,
                }
            except Exception as e:
                report["errors"].append({"source": name, "error": str(e)})
                print(f"WARNING: {name}: {e}", file=sys.stderr)

    before_allow = len(blocked)
    blocked = {d for d in blocked if not is_allowed(d, allow)}
    report["removed_by_allow"] = before_allow - len(blocked)
    report["final_domains"] = len(blocked)

    write_outputs(blocked, allow, report)

    print(f"Final domains: {len(blocked):,}")
    if report["errors"]:
        print(f"Source errors: {len(report['errors'])}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
