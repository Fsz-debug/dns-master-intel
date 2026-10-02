#!/usr/bin/env python3
from __future__ import annotations
import json, re, urllib.request, ipaddress
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[1]
CFG = ROOT / "config" / "firebog_sources.json"
DIST = ROOT / "dist"
UA = "dns-master-blocklist-firebog-intel/1.0"

ADBLOCK = re.compile(r"^\|\|([A-Za-z0-9._*-]+)\^")
HOSTS = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1|::1)\s+(\S+)")
DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$")

def norm(line:str):
    s=line.strip().lower()
    if not s or s.startswith(("#","!",";")):
        return None
    if " #" in s:
        s=s.split(" #",1)[0].strip()
    m=HOSTS.match(s)
    if m: s=m.group(1)
    else:
        m=ADBLOCK.match(s)
        if m: s=m.group(1)
        else:
            s=s.removeprefix("*.").removeprefix("||").removesuffix("^").rstrip(".")
    if "/" in s or " " in s or "\t" in s:
        return None
    try:
        ipaddress.ip_address(s)
        return None
    except ValueError:
        pass
    try:
        s=s.encode("idna").decode("ascii")
    except Exception:
        return None
    if not DOMAIN.match(s):
        return None
    return s

def fetch(url):
    req=urllib.request.Request(url,headers={"User-Agent":UA})
    with urllib.request.urlopen(req,timeout=45) as r:
        return r.read().decode("utf-8","replace")

cfg=json.loads(CFG.read_text(encoding="utf-8"))
domains=set()
cats=defaultdict(set)
stats=[]
errors=[]

for src in cfg["sources"]:
    url=src["url"]; cat=src["category"]
    try:
        txt=fetch(url)
        parsed=set()
        for line in txt.splitlines():
            d=norm(line)
            if d:
                parsed.add(d)
        before=len(domains)
        domains.update(parsed)
        cats[cat].update(parsed)
        stats.append({
            "category":cat,
            "url":url,
            "parsed":len(parsed),
            "new_unique":len(domains)-before
        })
    except Exception as e:
        errors.append({"url":url,"error":str(e)})

DIST.mkdir(parents=True,exist_ok=True)
(DIST/"firebog-intel.txt").write_text("\n".join(sorted(domains))+("\n" if domains else ""),encoding="utf-8")
for cat, ds in cats.items():
    (DIST/f"firebog-{cat}.txt").write_text("\n".join(sorted(ds))+("\n" if ds else ""),encoding="utf-8")

report={
    "mode":"intel_only",
    "total_unique_domains":len(domains),
    "categories":{k:len(v) for k,v in sorted(cats.items())},
    "sources":stats,
    "errors":errors
}
(DIST/"firebog-report.json").write_text(json.dumps(report,indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
print(json.dumps({"total_unique_domains":len(domains),"errors":len(errors)},ensure_ascii=False))
