# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Stack

Static HTML/CSS/JS on GitHub Pages, custom domain 2shell.lol. Explicitly chosen
by the owner ("github pages as the frontend only host"). No framework, no
build step: `index.html` + `data/vulns.json`, curl-able.

## Users

- Security-community readers (researchers, practitioners, infosec social
  media) who watched the 2026 "X2Shell" named-vulnerability wave and want the
  running joke quantified. *(inferred from brief)*
- General internet passersby who keep hearing about "the shell thing".
  *(inferred)*
- The owner + contributors who maintain the list via PRs. *(explicit)*

## Product Purpose

The canonical scoreboard of the 2Shell meme wave: "It has been X days since
the last 2Shell-named vulnerability" — a big countdown plus a complete,
fact-checked list (name, CVE, disclosure date, what broke), gap statistics,
and a deadpan-doom prediction of the next one. Success = the community treats
it as the reference for the joke, PRs arrive when a new shell drops, and the
counter is always right.

## Positioning

A neighbor could copy the HTML in an afternoon, but not the combination:
the live bot (crucix SocialSignal) proposing entries via PRs, the open
JSON data contract, CI validation, and being first. The data IS the product;
the page is its face.

## Operating Context

- `data/vulns.json` is the single source of truth; everything (page, bot,
  PRs) reads it. Schema + PR guide in README.
- CI (`.github/workflows/validate.yml`) validates the JSON on every PR/push
  via `scripts/validate.py`.
- The tracker bot (cluster CronJob, `~/nixnas/k8s/2shell-tracker/`) mines
  the crucix social-signal clusters every 6h and opens draft PRs for new
  candidate names; humans merge. *(explicit in brief)*
- GitHub Pages, HTTPS, apex domain `2shell.lol`. *(explicit)*

## Capabilities and Constraints

- Fully static: countdown computed client-side (never goes stale between
  pushes), data fetched at render time. No backend, no cookies, no tracking.
- Tongue-in-cheek voice, but every vulnerability entry must carry real,
  verifiable facts (CVE id, disclosure date, affected tech). Snark lives in
  the copy, never in the data.
- Vulnerability "membership" rule: the branded name must end in "Shell"
  (Log4Shell, Spring4Shell, wp2shell, PHP2Shell …) and be a real,
  publicly-disclosed vulnerability, not a parody. *(inferred; matches owner's
  "X2Shell where x = some technology")*
- Two eras for framing: "classic" (2021-22 genre-founding: Log4Shell,
  Spring4Shell, Text4Shell) and "wave" (the 2026 2Shell era). *(inferred)*

## Brand Commitments

- Domain: `2shell.lol` (owned by dbeard). *(binding)*
- Tone: "tongue-in-cheek but also kinda useful". *(binding, verbatim brief)*
- Community maintenance: "people could even issue PRs if I missed one".
  *(binding, verbatim brief)*
- Visual voice (2026-11-09, binding until the owner says otherwise): **rainbow,
  fun, meme-y.** The first shipped world (dark split-flap station board)
  read to the owner as "too black and corpo" and was replaced with a
  candy-sticker world: cream ground, ink outlines, hard block shadows, a
  fixed seven-hue candy palette doing semantic work (wave era = rainbow,
  genesis era = sepia). Deadpan copy stays; the chrome gets loud.
- A `console.log("hey look. It's js2shell lol")` easter egg ships on every
  page. *(binding, owner request 2026-11-09)*

## Evidence on Hand

`data/vulns.json` seeded 2026-11-09 with five verified entries (Log4Shell
CVE-2021-44228, Spring4Shell CVE-2022-22965, Text4Shell CVE-2022-42889,
wp2shell CVE-2026-63030/60137, PHP2Shell CVE-2026-109618/109619 — sources:
Wikipedia, Wordfence, Sophos/CISA advisories). No logo, no art assets, no
photography — the page ships none of its own imagery. *(owner provided none)*

## Product Principles

1. The counter is the product — everything else is a footnote to it.
2. Snark in the copy, never in the facts.
3. The data is open; every change merges through a PR (bot and human alike).
4. Zero build, zero framework, zero tracking — the page is a file anyone can
   curl and anyone can fork.
5. The bot proposes, humans dispose.

## Accessibility & Inclusion

Public scoreboard: WCAG-ish contrast, `prefers-reduced-motion` respected,
semantic HTML, works without JS for the core facts (list is rendered
server-side... static — meaning: content must be readable from the JSON and
the page must degrade gracefully). *(inferred, standard for public web)*

---

*Init interview not conducted (single-turn build). Facts above inferred from
the owner's brief are labeled; product-truth corrections are cheap — say the
word and PRODUCT.md gets updated.*
