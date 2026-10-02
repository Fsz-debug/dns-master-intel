#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import ipaddress
import json
import re
import sqlite3
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CFG = ROOT / "config" / "firebog_sources.json"
UA = "dns-master-intel-v5/1.0"

CAT_BITS = {
    "suspicious": 1,
    "advertising": 2,
    "tracking": 4,
    "malicious": 8,
    "other": 16,
}
CAT_NAMES = {
    1: "S",
    2: "A",
    4: "T",
    8: "M",
    16: "O",
}

HOSTS_RE = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+(\S+)")
ADBLOCK_RE = re.compile(r"^\|\|([A-Za-z0-9._*-]+)\^")
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$"
)

def normalize(line: str) -> str | None:
    s = line.strip().lower()
    if not s or s.startswith(("#", "!", ";")):
        return None
    if " #" in s:
        s = s.split(" #", 1)[0].strip()

    m = HOSTS_RE.match(s)
    if m:
        s = m.group(1)
    else:
        m = ADBLOCK_RE.match(s)
        if m:
            s = m.group(1)
        else:
            # common plain/wildcard formats
            s = s.removeprefix("*.").removeprefix("||").removesuffix("^").rstrip(".")

    # Reject URL/path forms; this project is DNS-domain only.
    if "://" in s or "/" in s or " " in s or "\t" in s:
        return None

    try:
        ipaddress.ip_address(s)
        return None
    except ValueError:
        pass

    try:
        s = s.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if "_" in s or not DOMAIN_RE.match(s):
        return None
    return s

def fetch(url: str, timeout: int = 60, retries: int = 3) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    err = None
    for n in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read().decode("utf-8", errors="replace")
        except Exception as e:
            err = e
            if n + 1 < retries:
                time.sleep(2 ** n)
    raise RuntimeError(f"{url}: {err}")

def cat_flags(mask: int) -> str:
    return "".join(name for bit, name in CAT_NAMES.items() if mask & bit) or "-"

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=str(DEFAULT_CFG))
    ap.add_argument("--out", default=str(ROOT / "build" / "intel"))
    ap.add_argument("--db", default=str(ROOT / "build" / "intel.sqlite3"))
    args = ap.parse_args()

    cfg = json.loads(Path(args.config).read_text(encoding="utf-8"))
    sources = cfg["sources"]
    if len(sources) > 62:
        raise SystemExit("v5 source bitmask supports at most 62 sources.")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    shard_dir = out / "shards"
    shard_dir.mkdir(parents=True, exist_ok=True)

    db_path = Path(args.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        db_path.unlink()

    con = sqlite3.connect(db_path)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("PRAGMA temp_store=FILE")
    con.execute("""
        CREATE TABLE domains (
            domain TEXT PRIMARY KEY,
            catmask INTEGER NOT NULL,
            srcmask INTEGER NOT NULL,
            source_count INTEGER NOT NULL
        ) WITHOUT ROWID
    """)
    con.execute("CREATE TEMP TABLE source_seen(domain TEXT PRIMARY KEY) WITHOUT ROWID")

    source_report = []
    errors = []

    for idx, src in enumerate(sources):
        name = src.get("name") or f"source-{idx}"
        url = src["url"]
        category = src["category"]
        catbit = CAT_BITS[category]
        srcbit = 1 << idx

        con.execute("DELETE FROM source_seen")
        parsed_lines = 0
        unique_in_source = 0

        try:
            txt = fetch(url)
            batch = []
            for line in txt.splitlines():
                d = normalize(line)
                if not d:
                    continue
                parsed_lines += 1
                batch.append((d,))
                if len(batch) >= 10000:
                    con.executemany("INSERT OR IGNORE INTO source_seen(domain) VALUES (?)", batch)
                    batch.clear()
            if batch:
                con.executemany("INSERT OR IGNORE INTO source_seen(domain) VALUES (?)", batch)

            unique_in_source = con.execute("SELECT COUNT(*) FROM source_seen").fetchone()[0]

            # WHERE 1 avoids SQLite UPSERT ambiguity with INSERT ... SELECT.
            con.execute("""
                INSERT INTO domains(domain, catmask, srcmask, source_count)
                SELECT domain, ?, ?, 1 FROM source_seen WHERE 1
                ON CONFLICT(domain) DO UPDATE SET
                    catmask = domains.catmask | excluded.catmask,
                    srcmask = domains.srcmask | excluded.srcmask,
                    source_count = domains.source_count + 1
            """, (catbit, srcbit))
            con.commit()

            source_report.append({
                "id": idx,
                "name": name,
                "category": category,
                "url": url,
                "parsed_lines": parsed_lines,
                "unique_domains_in_source": unique_in_source,
                "ok": True,
            })
            print(f"[{idx+1}/{len(sources)}] {category}: {unique_in_source:,} unique - {url}")
        except Exception as e:
            con.rollback()
            errors.append({"id": idx, "url": url, "error": str(e)})
            source_report.append({
                "id": idx,
                "name": name,
                "category": category,
                "url": url,
                "parsed_lines": parsed_lines,
                "unique_domains_in_source": 0,
                "ok": False,
                "error": str(e),
            })
            print(f"ERROR {url}: {e}", file=sys.stderr)

    total_unique = con.execute("SELECT COUNT(*) FROM domains").fetchone()[0]

    # 256 hash-prefix shards. Each row:
    # domain<TAB>category flags<TAB>source count<TAB>source bitmask hex
    handles = {}
    plain_paths = []
    for i in range(256):
        p = shard_dir / f"{i:02x}.tsv"
        plain_paths.append(p)
        handles[i] = p.open("w", encoding="utf-8")

    try:
        cur = con.execute("SELECT domain, catmask, srcmask, source_count FROM domains ORDER BY domain")
        for domain, cmask, smask, count in cur:
            shard = int(hashlib.sha256(domain.encode("utf-8")).hexdigest()[:2], 16)
            handles[shard].write(f"{domain}\t{cat_flags(cmask)}\t{count}\t{smask:x}\n")
    finally:
        for h in handles.values():
            h.close()

    shard_manifest = {}
    for i, p in enumerate(plain_paths):
        lines = 0
        gz = p.with_suffix(".tsv.gz")
        with p.open("rb") as fin, gzip.open(gz, "wb", compresslevel=9) as fout:
            for line in fin:
                fout.write(line)
                lines += 1
        p.unlink()
        shard_manifest[f"{i:02x}"] = {
            "file": gz.name,
            "entries": lines,
            "bytes": gz.stat().st_size,
        }

    manifest = {
        "version": 5,
        "mode": "full-intelligence-reference-not-auto-block",
        "total_sources": len(sources),
        "successful_sources": sum(1 for s in source_report if s["ok"]),
        "failed_sources": len(errors),
        "total_unique_domains": total_unique,
        "category_bits": CAT_BITS,
        "category_flags": {
            "S": "suspicious",
            "A": "advertising",
            "T": "tracking",
            "M": "malicious",
            "O": "other",
        },
        "shard_rule": "sha256(domain) first byte -> 00..ff",
        "row_format": "domain<TAB>category_flags<TAB>source_count<TAB>source_bitmask_hex",
        "sources": source_report,
        "shards": shard_manifest,
        "errors": errors,
    }
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print(f"TOTAL UNIQUE DOMAINS: {total_unique:,}")
    print(f"SHARDS: 256")
    print(f"SOURCE ERRORS: {len(errors)}")
    con.close()
    # Fail-soft: source outages are recorded in manifest.json but do not block publishing.
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
