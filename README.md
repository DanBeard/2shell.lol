# 2shell.lol

**It has been a countable number of days since the last 2Shell-named
vulnerability.** This is the scoreboard.

The internet spent 2026 inventing a new branded vulnerability roughly every
time the meme budget allowed — `wp2shell`, `PHP2Shell`, and friends, each
with its own website, its own logo, its own Wikipedia page. The naming wave
that [Log4Shell](https://en.wikipedia.org/wiki/Log4Shell) started in 2021
became a genre. This page keeps the box score: the counter, the complete
arrivals list, the gaps between them, and an over/under on the next one that
has no right to be as accurate as it occasionally is.

The whole site is one static page + one JSON file, hosted on GitHub Pages.
No framework, no build, no tracking. Fork away.

## Membership rule

A shell gets on the board if it is a **real, publicly disclosed
vulnerability whose branded name ends in "Shell"** (Log4Shell, Spring4Shell,
Text4Shell, wp2shell, PHP2Shell…). Parody names, rumors, and things that
turned out to be marketing are not shells. The digit is whatever the
branders chose; the genre accepts both 2s and 4s.

**Honorary members**: the board really counts the *naming circus*, so a
genuinely-branded genus member that doesn't end in Shell can still board
with `"family": "honorary"` — it needs the same real-vulnerability proof
plus its own branded site/link. `sshhole` (sshhole.com) is the first. No
site, no slot. The two eras are framing
only: `classic` (the 2021–22 genre-founding era) and `wave` (the 2026
2Shell wave).

## Add one (PR guide)

1. Fork and edit **[`data/vulns.json`](data/vulns.json)**. Shells are entries in
   `vulns`; the whole site's content lives in this one file:

   ```json
   {
     "name": "Your2Shell",
     "date": "2026-11-01",
     "cves": ["CVE-2026-000000"],
     "tech": "what it breaks",
     "summary": "one line, ideally funny",
     "url": "a primary source",
     "era": "wave",
     "added_by": "your-handle",
     "added": "2026-11-09"
   }
   ```

   - `date` = the day it went public (disclosure day), not the day you heard
     about it. The counter is computed from this, client-side, in UTC —
     nobody redeploys to make the number tick.
   - `summary` = one line, max 280 chars. Snark welcome; facts mandatory.
   - `era` = `classic` (pre-2026, sepia chips) or `wave` (2026, rainbow chips).
   - `family` = omit for Shell-family names; `"honorary"` for branded genre
     members that don't end in Shell (`sshhole`) — they require a `url`.
   - `cves` may be `[]` if you're still researching — the board shows a dash.

2. Open a PR. CI validates the shape (`scripts/validate.py`) and a human
   merges.
3. The counter resets the moment you merge. Yes. That's on you.

## Mood lines (also just JSON)

The sticker chip under the counter ("A NEW SHELL HAS ARRIVED. WELCOME TO
THE FUTURE.") is data, not code — the `moods` array in the same file.
First match wins, top to bottom, so order is priority:

```json
"moods": [
  { "id": "zero", "class": "mood-zero", "max_days": 0,
    "line": "A NEW SHELL HAS ARRIVED. WELCOME TO THE FUTURE." },
  { "id": "fresh", "class": "mood-fresh", "min_days": 1, "max_days": 1,
    "line": "ONE DAY OF CALM. SAVOR IT." }
]
```

- Constraints are declarative: `min_days` / `max_days` (inclusive bounds on
  the count), `"record": true` (calmer than any gap ever), `"overdue": true`
  (past the median over/under). At least one required.
- `class` picks the chip look: `mood-zero` (rainbow), `mood-fresh` (mint),
  `mood-record` (lavender), `mood-year` (sky), `mood-due` (yellow).
  New looks need a one-line CSS PR first.
- `line` max 140 chars. No mood matched → no chip; silence is also copy.

## There is also a bot

A tracker (a plain-stdlib Python CronJob on the maintainer's cluster, this
repo's [`tracker/`](tracker/) directory) reads an OSINT dashboard's outputs
every six hours — the security social-signal synthesis **and** a
newly-registered-domains watch that scans ~700k fresh domains a day for
vuln-brand-shaped names, scores them, and peeks at their site titles — and
opens PRs by itself, one per candidate, with the evidence attached. Bot PRs
are drafts with a review checklist: a human verifies it's real, fixes the
disclosure date, and merges. The bot proposes; humans dispose.

If a bot PR beat you to your favorite shell, add your name in `added_by`
when you clean it up. The board belongs to whoever shows up.

## Egg shells

The board also shows its **incubator**: brand-shaped domains from the last
10 days of public new-domain registrations that haven't hatched yet —
`nextjs2shell.com` is in there right now, parked. Could be a squatter,
could be a researcher sitting on a disclosure; the incubator does not judge.
Statuses say what the site's own title says:

- **QUIET** — no site / no title yet
- **PARKING** — the title is just the domain: squatter holding pen
- **STIRRING** — a real site that says something
- **CRACKING** — vuln language in the title; about to hatch

`data/eggs.json` is machine-maintained — a daily GitHub Action
(`.github/workflows/eggs.yml`) regenerates it from the public NRD lists
with the same scoring crucix's NRDWatch uses (the canonical rater lives in
the maintainer's crucix fork). When an egg hatches — a real shell lands on
the board via PR — it stops being an egg. PRs still gate the board itself;
the incubator is display-only.

## Repo layout

| Path | Purpose |
|------|---------|
| `index.html` | the board (countdown, arrivals, egg shells, next-service panel) |
| `data/vulns.json` | **the product** — every shell, open data |
| `data/eggs.json` | the incubator (machine-written daily, no PRs needed) |
| `scripts/validate.py` | JSON contract checks, run by CI on every PR |
| `scripts/eggs.py` | the incubator generator (must match crucix NRDWatch scoring) |
| `.github/workflows/validate.yml` | the CI gate |
| `.github/workflows/eggs.yml` | daily egg refresh |
| `tracker/track.py` | the bot (stdlib Python; deploy notes in its docstring) |
| `DESIGN.md` | the visual world of the board |

## Data license

The compiled `data/vulns.json` is released under
[CC0](https://creativecommons.org/publicdomain/zero/1.0/). Take it, mirror
it, build a better board. The page design likewise — though if you build a
better board, PR the improvements back instead, cowards.

## Fine print

Not affiliated with any shell, any vendor, or any naming consultant. The
"estimated days to next service" is a median of historical gaps with a
sample size smaller than a SOC's sense of humor; it has a confidence of
NONE and should not be used for patch planning, investing, or emotional
preparation. Patch your PHP.
