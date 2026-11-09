#!/usr/bin/env python3
"""2shell-tracker — keep the 2shell.lol arrivals board fed.

Every 6h, this job reads the crucix dashboard's SocialSignal synthesis
(``/api/data`` → ``social.clusters``) and looks for chatter about
vulnerabilities whose branded name ends in "Shell" with the mandatory digit
(Log4Shell, Spring4Shell, wp2shell, PHP2Shell, …). For a candidate the
board doesn't already list, it opens a GitHub pull request against
``data/vulns.json`` with the social evidence attached — humans review,
correct the disclosure date, and merge. If no GitHub token is configured it
falls back to an ntfy ping so candidates are never silently dropped.

Design mirrors k8s/crucix-monitor (stdlib only, PVC state, ntfy alerts,
fail-open on every optional dependency):

  1. Pull crucix /api/data; extract social clusters (reliability-ranked
     story clusters: corroborated / multi-report / unverified, samples with
     author+network+url, OpenJev verdicts where they landed).
  2. Regex sample text for *2Shell / *4Shell names; exclude the family
     words ("2shell" itself) and everything already on the board.
  3. Strength gate: >= 2 distinct authors, or any trusted author, or a
     corroborated cluster. Weak mentions are logged, never PR'd.
  4. Open one PR per candidate (branch + contents update + PR, via GitHub
     API), idempotent against both the PVC seen-set and already-open PRs.
  5. ntfy ping on every PR, and on candidates that can't be PR'd
     (no token / GitHub down), suppressed to one ping per 24h per key.

Stdlib only (offline-resilience rules). Canonical copy: the 2shell.lol
repository, tracker/ — the nixnas k8s/2shell-tracker manifest builds this.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------------------- #
# Config (env)                                                                 #
# --------------------------------------------------------------------------- #

CRUCIX_URL = os.environ.get("CRUCIX_URL", "http://crucix:3117").rstrip("/")
CRUCIX_TIMEOUT = float(os.environ.get("CRUCIX_TIMEOUT", "30"))

# GitHub — repo is "<owner>/<name>"; token is a fine-grained PAT scoped to
# that repo with Contents: RW + Pull requests: RW. Without a token the job
# degrades to read-only board checks + ntfy pings.
GITHUB_REPO = os.environ.get("GITHUB_REPO", "").strip()          # e.g. "dbeard/2shell.lol"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "").strip()
GITHUB_BRANCH = os.environ.get("GITHUB_BRANCH", "main")
GITHUB_TIMEOUT = float(os.environ.get("GITHUB_TIMEOUT", "30"))
GITHUB_API = os.environ.get("GITHUB_API", "https://api.github.com")
GITHUB_RAW = os.environ.get("GITHUB_RAW_BASE", "https://raw.githubusercontent.com").rstrip("/")

# ntfy — one ping per PR, and per candidate that couldn't be PR'd.
NTFY_URL = os.environ.get("NTFY_SERVER_URL", "http://ntfy:8280").rstrip("/")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "household-alerts")
NTFY_TOKEN = os.environ.get("NTFY_TOKEN", "")

STATE_DIR = os.environ.get("STATE_DIR", "/data")
SEEN_PATH = os.path.join(STATE_DIR, "seen.json")
HISTORY_PATH = os.path.join(STATE_DIR, "history.jsonl")
PUSHES_PATH = os.path.join(STATE_DIR, "push_history.json")
PUSH_SUPPRESS_HOURS = float(os.environ.get("PUSH_SUPPRESS_HOURS", "24"))
SEEN_MAX_AGE_DAYS = int(os.environ.get("SEEN_MAX_AGE_DAYS", "60"))

# The meme family: a branded name ending in 2Shell/4Shell. Case-insensitive;
# leading part is the tech (php2shell, Node2Shell, curl2shell…). The family
# words themselves ("2shell" / "4shell") are excluded — they name the genre.
NAME_RE = re.compile(r"(?i)([A-Za-z0-9][A-Za-z0-9+#.\-]{0,20}?[24][Ss]hell)")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")
FAMILY_WORDS = {"2shell", "4shell"}
# NRDWatch gate: a domain alone isn't a disclosure — its site must say
# something beyond the domain itself (parking pages title themselves with
# the domain) or carry strict vuln language.
VULN_TITLE = re.compile(r"(?i)cve|rce|exploit|vulnerab|unauthenticated|0-?day|"
                        r"bypass|pre-auth|memory|advisory|disclos")

UA = "2shell-tracker/1.0 (+2shell.lol)"


def log(msg: str) -> None:
    print(f"[2shell-tracker] {msg}", flush=True)


def today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


# --------------------------------------------------------------------------- #
# HTTP helpers                                                                 #
# --------------------------------------------------------------------------- #

def _request(method: str, url: str, *, timeout: float, headers: dict | None = None,
             body: bytes | None = None) -> tuple[int, bytes]:
    hdrs = {"User-Agent": UA, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, r.read()


def _get_json(url: str, timeout: float, headers: dict | None = None) -> dict:
    status, raw = _request("GET", url, timeout=timeout, headers=headers)
    return json.loads(raw)


def gh(method: str, path: str, payload: dict | None = None) -> dict:
    """GitHub API call. Raises on HTTP error (caller decides what's fatal)."""
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    body = json.dumps(payload).encode() if payload is not None else None
    status, raw = _request(method, f"{GITHUB_API}{path}", timeout=GITHUB_TIMEOUT,
                           headers=headers, body=body)
    return json.loads(raw) if raw else {}


def ntfy(title: str, message: str, priority: int = 3, tags: str = "shell") -> bool:
    if not NTFY_TOPIC:
        return False
    payload = {"topic": NTFY_TOPIC, "title": title, "message": message,
               "priority": priority, "tags": tags}
    headers = {"Content-Type": "application/json"}
    if NTFY_TOKEN:
        headers["Authorization"] = f"Bearer {NTFY_TOKEN}"
    try:
        _request("POST", f"{NTFY_URL}", timeout=15, headers=headers,
                 body=json.dumps(payload).encode())
        return True
    except Exception as e:
        log(f"ntfy push failed: {e}")
        return False


# --------------------------------------------------------------------------- #
# State (PVC)                                                                  #
# --------------------------------------------------------------------------- #

def load_state() -> tuple[dict, list]:
    os.makedirs(STATE_DIR, exist_ok=True)
    seen: dict = {}
    if os.path.exists(SEEN_PATH):
        try:
            seen = json.load(open(SEEN_PATH))
        except Exception:
            log("seen.json unreadable — starting a fresh seen-set")
    pushes: list = []
    if os.path.exists(PUSHES_PATH):
        try:
            pushes = json.load(open(PUSHES_PATH))
        except Exception:
            pushes = []
    return seen, pushes


def save_state(seen: dict, pushes: list) -> None:
    # Prune old entries: a candidate still chattering after this window gets
    # one fresh chance (maybe the PR was closed as a false positive and the
    # story developed; re-PRing is then correct).
    cutoff = time.time() - SEEN_MAX_AGE_DAYS * 86400
    seen = {k: v for k, v in seen.items() if v.get("ts", 0) >= cutoff}
    tmp = SEEN_PATH + ".tmp"
    json.dump(seen, open(tmp, "w"), indent=2)
    os.replace(tmp, SEEN_PATH)
    cutoff = time.time() - PUSH_SUPPRESS_HOURS * 3600
    pushes = [p for p in pushes if p.get("ts", 0) >= cutoff][-500:]
    tmp = PUSHES_PATH + ".tmp"
    json.dump(pushes, open(tmp, "w"), indent=2)
    os.replace(tmp, PUSHES_PATH)


def push_suppressed(pushes: list, key: str) -> bool:
    cutoff = time.time() - PUSH_SUPPRESS_HOURS * 3600
    return any(p.get("key") == key and p.get("ts", 0) >= cutoff for p in pushes)


def append_history(run: dict) -> None:
    with open(HISTORY_PATH, "a") as f:
        f.write(json.dumps(run, default=str) + "\n")


def nrd_candidates(data: dict, board_names: set) -> dict:
    """crucix NRDWatch: shell-pattern domains with live, non-parking sites.

    A registered *2Shell domain whose site says something (a title beyond
    the domain itself, or strict vuln language) becomes a PR candidate —
    the domain watch flows downstream like any other crucix signal.
    Parking pages (title == domain) and title-less sites are watched, not PR'd.
    """
    nrd = data.get("nrd") or {}
    cands: dict = {}
    for d in nrd.get("domains") or []:
        if not d.get("isNew") or d.get("score", 0) < 70:
            continue
        domain = (d.get("domain") or "").lower()
        label = domain.split(".")[0]
        if not label or label in board_names:
            continue
        # crucix's OpenJev verdict is authoritative: judge says generic → out
        jev = d.get("jev") or {}
        if jev.get("vulnBrand") is False:
            log(f"nrd: {domain} — OpenJev says generic-brand, skipping")
            continue
        grab = d.get("grab") or {}
        title = (grab.get("title") or "").strip()
        if not title:
            log(f"nrd: {domain} (score {d.get('score')}) — no site title yet, watching")
            continue
        parking = title.lower() == domain
        strict = bool(VULN_TITLE.search(title))
        if d.get("score", 0) >= 90 and not parking:
            verdict = "shell-pattern + live site"
        elif strict:
            verdict = "vuln-language title"
        else:
            log(f"nrd: {domain} (score {d.get('score')}) — title looks like "
                f"{'parking' if parking else 'noise'}, watching: {title[:60]}")
            continue
        log(f"nrd: {domain} — CANDIDATE ({verdict}): {title[:60]}")
        cands[label] = {
            "display": label,
            "authors": {"nrd-watch"},
            "trusted": True,
            "corroborated": True,
            "cves": set(),
            "evidence": [{
                "author": "nrd-watch (crucix NRDWatch)",
                "network": "nrd",
                "url": f"https://{domain}",
                "text": f"domain registered, brand-score {d.get('score')} "
                        f"({d.get('why')}); site title: {title}",
                "level": "nrd",
            }],
        }
    return cands

def social_clusters(data: dict) -> list:
    """crucix /api/data serves the inject-transformed view (.social), with
    the raw sources view (.sources.SocialSignal) as a fallback."""
    for path in (
        lambda: data["social"]["clusters"],
        lambda: data["sources"]["SocialSignal"]["clusters"],
    ):
        try:
            val = path()
            if isinstance(val, list):
                return val
        except (KeyError, TypeError):
            continue
    return []


def extract_candidates(clusters: list) -> dict:
    """name_key -> {display, evidence[], authors, trusted, corroborated, cves}"""
    cands: dict = {}
    for c in clusters:
        level = c.get("level", "unverified")
        trusted_authors = set(c.get("trustedAuthors") or [])
        llm = c.get("llm") or {}
        for s in c.get("samples") or []:
            text = s.get("text") or ""
            for m in NAME_RE.finditer(text):
                raw = m.group(1)
                key = raw.lower()
                if key in FAMILY_WORDS:
                    continue
                cve_list = CVE_RE.findall(text)
                cand = cands.setdefault(key, {
                    "display": raw, "evidence": [], "authors": set(),
                    "trusted": False, "corroborated": False, "cves": set(),
                })
                # Prefer the properly-capitalized display form seen most often
                # (e.g. "PHP2Shell" over a lowercase URL fragment).
                if raw[:1].isupper() or (raw.lower() == raw and "." not in raw):
                    cand["display"] = raw
                cand["authors"].add(s.get("author"))
                cand["trusted"] = cand["trusted"] or s.get("author") in trusted_authors
                cand["corroborated"] = cand["corroborated"] or level == "corroborated"
                cand["cves"].update(cve_list)
                cand["evidence"].append({
                    "author": s.get("author"), "network": s.get("network"),
                    "url": s.get("url"), "text": text[:200], "level": level,
                    "llm_relevant": llm.get("relevance"),
                })
    return cands


# --------------------------------------------------------------------------- #
# Board (GitHub)                                                               #
# --------------------------------------------------------------------------- #

def fetch_board() -> dict | None:
    """Current data/vulns.json from GitHub (API with token if private, raw
    otherwise). Returns None if the board can't be read at all."""
    if GITHUB_TOKEN and GITHUB_REPO:
        try:
            f = gh("GET", f"/repos/{GITHUB_REPO}/contents/data/vulns.json"
                          f"?ref={GITHUB_BRANCH}")
            return json.loads(base64.b64decode(f["content"]))
        except Exception as e:
            log(f"board read via API failed ({e}); trying raw")
    if GITHUB_REPO:
        try:
            url = f"{GITHUB_RAW}/{GITHUB_REPO}/{GITHUB_BRANCH}/data/vulns.json"
            return _get_json(url, GITHUB_TIMEOUT)
        except Exception as e:
            log(f"board read via raw failed: {e}")
    return None


def known_names(board: dict | None) -> set:
    names = set()
    for v in (board or {}).get("vulns", []):
        names.add(str(v.get("name", "")).lower())
        for aka in v.get("aka") or []:
            names.add(str(aka).lower())
    return names


def open_pr_for(cand: dict, key: str) -> str:
    """Open a PR adding one candidate entry. Returns the PR HTML url."""
    assert GITHUB_REPO, "GITHUB_REPO unset"
    display = cand["display"]
    date = today()
    entry = {
        "name": display,
        "date": date,
        "cves": sorted(cand["cves"]),
        "tech": "",
        "summary": "Detected by the 2shell.lol tracker — pending human review.",
        "url": (cand["evidence"][0] or {}).get("url") or "",
        "era": "wave",
        "added_by": "2shell-tracker",
        "added": date,
        "evidence": cand["evidence"][:6],
    }

    repo = gh("GET", f"/repos/{GITHUB_REPO}")
    base_branch = repo.get("default_branch", GITHUB_BRANCH)
    file = gh("GET", f"/repos/{GITHUB_REPO}/contents/data/vulns.json"
                     f"?ref={base_branch}")
    board = json.loads(base64.b64decode(file["content"]))
    if key in known_names(board):
        log(f"{display}: already on the board (raced a human?) — skipping")
        return ""

    board["vulns"] = sorted(board.get("vulns", []),
                            key=lambda v: str(v.get("date", "")))
    board["vulns"].append(entry)
    content = json.dumps(board, indent=2, ensure_ascii=False) + "\n"

    branch = f"tracker/{key.replace('#', '').replace('.', '')}-{date.replace('-', '')}"
    base_sha = gh("GET", f"/repos/{GITHUB_REPO}/git/ref/heads/{base_branch}")["object"]["sha"]
    gh("POST", f"/repos/{GITHUB_REPO}/git/refs", {
        "ref": f"refs/heads/{branch}", "sha": base_sha})
    gh("PUT", f"/repos/{GITHUB_REPO}/contents/data/vulns.json", {
        "message": f"tracker: add {display} (candidate)",
        "content": base64.b64encode(content.encode()).decode(),
        "branch": branch,
        "sha": file["sha"],
    })

    ev_lines = "\n".join(
        f"- **{e.get('author')}** ({e.get('network')}, cluster: {e.get('level')})"
        + (f" [jev: {e['llm_relevant']}]" if e.get("llm_relevant") else "")
        + f": {e.get('text')}\n  {e.get('url')}"
        for e in cand["evidence"][:6])
    body = (
        f"The [2shell.lol tracker](https://2shell.lol) detected `{display}` in "
        f"the crucix signal (social chatter and/or the NRD domain watch).\n\n"
        f"**Evidence** (last 5 days of Mastodon/Bluesky chatter):\n{ev_lines}\n\n"
        f"**Before merging, please:**\n"
        f"1. Verify it is a real, publicly disclosed vulnerability — not a "
        f"joke, a rumor, or a mention of an existing shell under another name.\n"
        f"2. Fix `date` to the actual disclosure day (the tracker stamps the "
        f"detection day, which is wrong for anything older).\n"
        f"3. Fill in `tech` and a real `summary` (one line — snark welcome, "
        f"facts mandatory), replace `url` with a primary source, and set "
        f"`era` (`classic` if pre-2026, else `wave`).\n"
        f"4. Remove the `evidence` block (it stays in this PR for the record).\n\n"
        f"CVEs seen in the chatter: {', '.join(entry['cves']) or 'none'}.\n"
        f"Board rules and the JSON schema: `README.md`."
    )
    pr = gh("POST", f"/repos/{GITHUB_REPO}/pulls", {
        "title": f"tracker: add {display}",
        "head": branch, "base": base_branch,
        "body": body,
    })
    return pr.get("html_url", "")


def pr_already_open(key: str) -> bool:
    if not GITHUB_REPO:
        return False
    try:
        prs = gh("GET", f"/repos/{GITHUB_REPO}/pulls?state=open&per_page=100")
        return any(key in (p.get("title", "") + p.get("body", "")).lower()
                   for p in prs)
    except Exception as e:
        log(f"open-PR check failed ({e}) — assuming none")
        return False


# --------------------------------------------------------------------------- #
# Main                                                                         #
# --------------------------------------------------------------------------- #

def main() -> int:
    ap = argparse.ArgumentParser(description="2shell.lol candidate tracker")
    ap.add_argument("--dry-run", action="store_true",
                    help="log candidates, touch nothing (no PRs, no pushes)")
    args = ap.parse_args()

    run = {"started": datetime.now(timezone.utc).isoformat(),
           "dry_run": args.dry_run, "candidates": []}

    # 1. crucix signal (social clusters + NRD domain watch)
    try:
        data = _get_json(f"{CRUCIX_URL}/api/data", CRUCIX_TIMEOUT)
    except Exception as e:
        log(f"crucix unreachable ({e}) — nothing to do, failing loudly")
        run["error"] = f"crucix: {e}"
        append_history(run)
        return 1
    clusters = social_clusters(data)
    log(f"crucix ok: {len(clusters)} social cluster(s)")

    board = fetch_board()
    board_names = known_names(board)
    if GITHUB_REPO and board is None:
        log("WARNING: board unreadable — cannot dedupe, proceeding anyway")
    seen, pushes = load_state()

    # 2. candidates — social chatter + NRD domain watch
    cands = extract_candidates(clusters)
    cands.update(nrd_candidates(data, board_names))

    new, weak = [], []
    for key, cand in sorted(cands.items()):
        if key in board_names or key in seen:
            continue
        strong = (len(cand["authors"]) >= 2 or cand["trusted"]
                  or cand["corroborated"])
        (new if strong else weak).append(cand)

    for cand in weak:
        log(f"weak mention (log-only): {cand['display']} "
            f"authors={len(cand['authors'])} trusted={cand['trusted']}")
    for cand in new:
        log(f"CANDIDATE: {cand['display']} authors={len(cand['authors'])} "
            f"trusted={cand['trusted']} corroborated={cand['corroborated']} "
            f"cves={sorted(cand['cves'])}")
    run["candidates"] = [{"name": c["display"], "authors": len(c["authors"]),
                          "trusted": c["trusted"]} for c in new]

    notified: list[str] = []
    if not args.dry_run:
        for cand in new:
            key = cand["display"].lower()
            # already-PR'd or already-known: belt (PVC) and braces (GitHub)
            if pr_already_open(key):
                log(f"{cand['display']}: open PR exists — marking seen")
                seen[key] = {"ts": time.time(), "action": "pr"}
                continue
            if not GITHUB_REPO or not GITHUB_TOKEN:
                pkey = f"nopr-{key}"
                if not push_suppressed(pushes, pkey):
                    ok = ntfy(
                        "2shell.lol: candidate (PR disabled)",
                        f"{cand['display']} chatter detected "
                        f"({len(cand['authors'])} author(s), "
                        f"trusted={cand['trusted']}). No GITHUB_TOKEN — "
                        f"add it manually: https://2shell.lol README.",
                        priority=3, tags="shell")
                    if ok:
                        pushes.append({"key": pkey, "ts": time.time()})
                        seen[key] = {"ts": time.time(), "action": "notified"}
                        notified.append(cand["display"])
                continue
            try:
                url = open_pr_for(cand, key)
                if url:
                    log(f"PR opened: {url}")
                    seen[key] = {"ts": time.time(), "action": "pr", "url": url}
                    if not push_suppressed(pushes, f"pr-{key}"):
                        if ntfy("2shell.lol: tracker PR",
                                f"New candidate {cand['display']} — PR open "
                                f"for review: {url}", priority=3, tags="shell"):
                            pushes.append({"key": f"pr-{key}", "ts": time.time()})
            except urllib.error.HTTPError as e:
                detail = ""
                try:
                    detail = e.read(300).decode(errors="replace")
                except Exception:
                    pass
                log(f"PR for {cand['display']} failed: HTTP {e.code} {detail}")
                pkey = f"prfail-{key}"
                if not push_suppressed(pushes, pkey):
                    if ntfy("2shell.lol: PR FAILED",
                            f"Could not open PR for {cand['display']} "
                            f"(HTTP {e.code}); will retry next run.",
                            priority=4, tags="warning"):
                        pushes.append({"key": pkey, "ts": time.time()})
            except Exception as e:
                log(f"PR for {cand['display']} failed: {e}")

        save_state(seen, pushes)

    run["finished"] = datetime.now(timezone.utc).isoformat()
    run["new"] = len(new) if not args.dry_run else 0
    run["handled"] = notified
    append_history(run)
    log(f"done: {len(new)} candidate(s), {len(weak)} weak mention(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
