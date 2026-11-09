#!/usr/bin/env python3
"""eggs.py — the incubator: regenerate data/eggs.json for 2shell.lol.

Egg shells are brand-shaped domains (nextjs2shell.com, quic2shell.com …)
registered in the last 10 days but with no confirmed vulnerability behind
them yet: squatters, or a researcher sitting very quietly on a disclosure.
When one hatches (a real *2Shell disclosure lands), it moves to data/vulns.json
via PR and stops being an egg.

Scoring MUST MATCH the canonical rater — crucix apis/sources/nrd-watch.mjs
(NIXNAS fork) — *2Shell/*4Shell SLD=90, ssh<word>=50, tech+genre-suffix=40,
+15 tech prefix, +10 brand TLD, +5 short SLD, cap 100. Board names and the
site's own domain are excluded (hatched eggs).

Status classification (from the site's title, top-24 only):
  quiet    — no site / no title yet
  parking  — title == domain (the squatter holding-pen tell)
  stirring — a site that says something, but not vuln language
  cracking — vuln language in the title; about to hatch (the tracker also
             sees this via crucix NRDWatch and opens a PR)

Run daily by .github/workflows/eggs.yml; also fine by hand.
Stdlib only. Writes data/eggs.json; exits 0 even on feed failure (the
previous file stays — an incubator that misses a day is not an incident).
"""
from __future__ import annotations

import json
import re
import ssl
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NRD_URL = "https://raw.githubusercontent.com/cenk/nrd/HEAD/nrd-last-10-days.txt"
MAX_EGGS = 24
TITLE_TIMEOUT = 6

# --- MUST MATCH crucix apis/sources/nrd-watch.mjs scoring -------------------
P_SHELL = re.compile(r"^[a-z0-9-]+[24]shell$")
P_SSH = re.compile(r"^ssh[a-z0-9-]{2,12}$")
P_GENRE = re.compile(r"^[a-z0-9-]+(bleed|hole|pipe|leak|pwn|ageddon|pocalypse)$")
TECH_WORDS = set(("php,wp,wordpress,node,bun,curl,git,go,rust,java,spring,tomcat,"
                  "kafka,docker,k8s,nginx,apache,python,django,flask,fastapi,rails,"
                  "mysql,postgres,redis,mongodb,elastic,ssh,openssh,linux,alpine,"
                  "musl,aws,azure,gcp,dotnet,log4,log4j,log,http,api").split(","))
BRAND_TLDS = {"com", "net", "org", "io", "dev", "lol", "app"}
GENRE_SUFFIXES = ("2shell", "4shell", "bleed", "hole", "pipe", "leak", "pwn",
                  "ageddon", "pocalypse")


def tech_of(sld: str):
    """A brand SLD decomposes as <tech>[digits] + <genre suffix> — php2shell,
    log4shell, sshhole. The tech word must BE the remainder after stripping
    the suffix, never a mere prefix: goldcoastdrainandpipe starts with 'go',
    but the head after 'pipe' is not a tech word, so it is not Golang."""
    for suf in sorted(GENRE_SUFFIXES, key=len, reverse=True):
        if sld.endswith(suf):
            head = sld[:-len(suf)].rstrip("0123456789")
            return head if head in TECH_WORDS else None
    return None
VULN_TITLE = re.compile(r"(?i)cve|rce|exploit|vulnerab|unauthenticated|0-?day|"
                        r"bypass|pre-auth|memory|advisory|disclos")

SELF_DOMAINS = {"2shell.lol", "www.2shell.lol"}

# Canonical tier-2 is OpenJev (crucix NRDWatch judges every non-shell-pattern
# candidate vuln-brand vs generic-brand via the litellm /jev shim). This
# Action-side display copy cannot reach the LAN judge, so it tightens
# deterministically instead: ssh-genus needs a curated vuln suffix
# (sshhole-style — sshockey.com is a hockey blog), and genre-suffix needs a
# tech prefix (goldcoastdrainandpipe.com is a plumbing company).
SSH_GENUS_SUFFIXES = {"hole", "pwn", "fail", "trap", "gap"}


def score(domain: str):
    dot = domain.find(".")
    if dot < 1:
        return None
    sld, tld = domain[:dot], domain[dot + 1:].split(".")[0]
    if P_SHELL.match(sld):
        base, why = 90, "shell-pattern"
    elif P_SSH.match(sld):
        if sld[3:] not in SSH_GENUS_SUFFIXES:
            return None
        base, why = 50, "ssh-genus"
    elif P_GENRE.match(sld):
        if not tech_of(sld):
            return None
        base, why = 40, "genre-suffix"
    else:
        return None
    tech = tech_of(sld)
    score_v = min(100, base
                  + (15 if tech else 0)
                  + (10 if tld in BRAND_TLDS else 0)
                  + (5 if len(sld) <= 14 else 0))
    return score_v, why, tech


def fetch(url: str, timeout: int) -> bytes:
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "2shell-eggkeeper/1.0"})
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
        return r.read()


def grab_title(domain: str) -> str:
    for scheme in ("https", "http"):
        try:
            html = fetch(f"{scheme}://{domain}/", TITLE_TIMEOUT).decode("utf-8", "replace")[:20000]
            m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
            if m:
                return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", m.group(1))).strip()[:120]
        except Exception:
            continue
    return ""


def classify(domain: str, title: str) -> str:
    if not title:
        return "quiet"
    if title.lower() == domain:
        return "parking"
    if VULN_TITLE.search(title):
        return "cracking"
    return "stirring"


def main() -> int:
    # hatched eggs (the board) and the site itself are excluded
    try:
        board = json.loads((ROOT / "data" / "vulns.json").read_text())
        board_names = {str(v.get("name", "")).lower() for v in board.get("vulns", [])}
        board_names |= {str(a).lower() for v in board.get("vulns", []) for a in (v.get("aka") or [])}
    except Exception:
        board_names = set()

    try:
        raw = fetch(NRD_URL, 60).decode("utf-8", "replace")
    except Exception as e:
        print(f"NRD feed unreachable ({e}) — keeping the previous eggs.json")
        return 0

    scored = []
    for line in raw.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        domain = line.strip().lower()
        s = score(domain)
        if not s:
            continue
        label = domain.split(".")[0]
        if domain in SELF_DOMAINS or any(bn and bn in label for bn in board_names):
            continue
        scored.append((domain, s[0], s[1], s[2]))

    scored.sort(key=lambda x: (-x[1], x[0]))
    eggs = []
    for domain, sc, why, tech in scored[:MAX_EGGS]:
        title = grab_title(domain)
        eggs.append({
            "domain": domain,
            "score": sc,
            "why": why,
            "tech": tech,
            "title": title,
            "status": classify(domain, title),
        })
        time.sleep(0.4)  # polite: at most ~2.5 title fetches/sec

    out = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "window": "last 10 days of public new-domain registrations",
        "count": len(scored),
        "eggs": eggs,
        "note": "Egg shells: brand-shaped domains, registered but not yet hatched. "
                "Squatters or researchers — the incubator does not judge. Statuses: "
                "quiet (no site), parking (squatter holding pen), stirring (site says "
                "something), cracking (vuln language — about to hatch).",
    }
    path = ROOT / "data" / "eggs.json"
    path.write_text(json.dumps(out, indent=2) + "\n")
    print(f"wrote {path}: {len(scored)} brand-shaped total, top {len(eggs)} kept")
    return 0


if __name__ == "__main__":
    sys.exit(main())
