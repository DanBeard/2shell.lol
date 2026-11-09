#!/usr/bin/env python3
"""Validate data/vulns.json — the contract between the site, the bot, and PRs.

Every entry:
  name     — ends in "Shell" with the mandatory digit (Log4Shell, wp2shell, ...)
  date     — YYYY-MM-DD, real calendar day (public disclosure day)
  cves     — list of well-formed CVE ids (may be empty while researched)
  summary  — non-empty, sane length
  era      — "classic" (2021-22 genre-founding era) | "wave" (the 2026 2Shell wave)
  added / added_by — provenance
Extra keys (evidence, cvss, url, tech, aka) are allowed and pass through.
Names are unique case-insensitively.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import date
from pathlib import Path

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+#.\-]{0,20}?[24][Ss]hell$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MOOD_ID_RE = re.compile(r"^[a-z][a-z0-9-]{0,30}$")
MOOD_CLASSES = {"mood-zero", "mood-fresh", "mood-year", "mood-due", "mood-record"}
MOOD_KEYS = {"id", "class", "line", "min_days", "max_days", "record", "overdue"}

def main() -> int:
    path = Path(__file__).resolve().parent.parent / "data" / "vulns.json"
    try:
        data = json.loads(path.read_text())
    except Exception as e:
        print(f"FAIL: data/vulns.json is not valid JSON: {e}")
        return 1

    vulns = data.get("vulns")
    if not isinstance(vulns, list) or not vulns:
        print("FAIL: top-level 'vulns' must be a non-empty list")
        return 1

    errors: list[str] = []
    seen: set[str] = set()
    for i, v in enumerate(vulns):
        tag = f"vulns[{i}]"
        name = v.get("name")
        if not name or not NAME_RE.match(name):
            errors.append(f"{tag}: name {name!r} doesn't match the *2Shell/*4Shell pattern")
        if name and name.lower() in {"2shell", "4shell"}:
            errors.append(f"{tag}: {name!r} is the family name, not a member")
        if name and name.lower() in seen:
            errors.append(f"{tag}: duplicate name {name!r}")
        if name:
            seen.add(name.lower())

        d = v.get("date")
        if not d or not DATE_RE.match(str(d)):
            errors.append(f"{tag}: date {d!r} must be YYYY-MM-DD")
        else:
            try:
                date.fromisoformat(str(d))
            except ValueError:
                errors.append(f"{tag}: date {d!r} is not a real calendar day")

        cves = v.get("cves", [])
        if not isinstance(cves, list):
            errors.append(f"{tag}: 'cves' must be a list")
        else:
            for c in cves:
                if not CVE_RE.match(str(c)):
                    errors.append(f"{tag}: malformed CVE {c!r}")

        s = v.get("summary")
        if not s or len(str(s)) < 10:
            errors.append(f"{tag}: summary missing or too short")
        if len(str(s)) > 280:
            errors.append(f"{tag}: summary over 280 chars — take it to the blog post")
        if v.get("era") not in {"classic", "wave"}:
            errors.append(f"{tag}: era must be 'classic' or 'wave'")
        if not v.get("added") or not DATE_RE.match(str(v.get("added"))):
            errors.append(f"{tag}: 'added' must be a YYYY-MM-DD provenance date")
        if not v.get("added_by"):
            errors.append(f"{tag}: 'added_by' provenance missing")

    # moods block (optional, but shape-checked when present: the JSON stands
    # on its own, so the copy has to survive the same gate as the data)
    moods = data.get("moods")
    if moods is not None:
        if not isinstance(moods, list) or not moods:
            errors.append("moods: must be a non-empty list (or absent entirely)")
        else:
            seen_ids: set[str] = set()
            for i, m in enumerate(moods):
                tag = f"moods[{i}]"
                if not isinstance(m, dict):
                    errors.append(f"{tag}: must be an object")
                    continue
                unknown = set(m) - MOOD_KEYS
                if unknown:
                    errors.append(f"{tag}: unknown key(s) {sorted(unknown)} "
                                  f"(vocabulary: id, class, line, min_days, max_days, record, overdue)")
                mid = m.get("id")
                if not mid or not MOOD_ID_RE.match(str(mid)):
                    errors.append(f"{tag}: 'id' must be a kebab slug (zero, due-in-a-week, ...)")
                elif mid in seen_ids:
                    errors.append(f"{tag}: duplicate mood id {mid!r}")
                else:
                    seen_ids.add(mid)
                if m.get("class") not in MOOD_CLASSES:
                    errors.append(f"{tag}: 'class' must be one of "
                                  f"{', '.join(sorted(MOOD_CLASSES))} "
                                  f"(new looks need a one-line CSS PR first)")
                line = m.get("line")
                if not line or len(str(line)) > 140:
                    errors.append(f"{tag}: 'line' must be 1-140 chars (it's a sticker chip)")
                mn, mx = m.get("min_days"), m.get("max_days")
                if mn is not None and (not isinstance(mn, int) or mn < 0):
                    errors.append(f"{tag}: 'min_days' must be a non-negative int")
                if mx is not None and (not isinstance(mx, int) or mx < 0):
                    errors.append(f"{tag}: 'max_days' must be a non-negative int")
                if isinstance(mn, int) and isinstance(mx, int) and mn > mx:
                    errors.append(f"{tag}: min_days > max_days — unreachable mood")
                if not any(m.get(k) is not None for k in ("min_days", "max_days", "record", "overdue")):
                    errors.append(f"{tag}: no constraint — this mood always wins. "
                                  f"Give it a min_days/max_days/record/overdue")
                for k in ("record", "overdue"):
                    if k in m and not isinstance(m[k], bool):
                        errors.append(f"{tag}: '{k}' must be true/false")

    if errors:
        print("FAIL: data/vulns.json has problems:")
        for e in errors:
            print(f"  - {e}")
        return 1
    n_moods = len(moods) if isinstance(moods, list) else 0
    print(f"OK: {len(vulns)} shell(s), {n_moods} mood line(s), all valid. "
          f"It has been a while. For now.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
