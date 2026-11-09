# Design — 2shell.lol

The page is a **Solari split-flap departure board** for the internet's
shellpocalypse. Roll-assigned direction (impeccable concept-seed 790bd77a,
assigned index 3); raises carried from the dealt challengers: numbered
arrivals (card-run), two-ink lamp states (cabaret bill), full-width ruled
rows with tabular gap numerals (power-hammer ledger), one-line summaries
(zine explainer), states printed as board states (phosphor terminal).

## Palette

Dark physical scene: a reader checks the number between advisories, at
night, on a phone — the board is lit in a dark room.

| Role | Token | Notes |
|------|-------|-------|
| ground | `#141417` | flap-plastic near-black, never pure #000 |
| flap tile lit half | `#202027` | top half, light from the room |
| flap tile shadow half | `#16161c` | bottom half |
| seam | `#0b0b0e` | the horizontal split line |
| letters | `#f2ede4` | ivory flap letters |
| signal amber | `#ffb000` | the ONE saturated ink: wave-era lamps, live numbers, links |
| secondary | `#9b968b` | tinted from the ivory, never flat gray |
| tertiary | `#8a8478` | ≥4.5:1 on ground |
| rules | `#2a2a31` | hairline row/panel dividers |

Two-ink lamp discipline: lamps resolve crisp lit/unlit — wave = amber fill,
classic = cold ivory fill, never midtones.

## Type

One face does everything: **Departure Mono** (Helena Zhang, OFL, self-hosted
in `assets/fonts/` with its license) — a pixel-terminal face designed for
airport signage, the exact artifact. Hierarchy is made of size, case, rules,
and lamps, never a second typeface. Scale: counter up to 11rem → section h2
1.32rem → names 1.28rem → body 1rem → micro-labels .72–.8rem (tracked caps).
Body measure ≤72ch.

## Components

- **Flap tile**: `.flap` — two absolutely-positioned halves (`.fh-t`,
  `.fh-b`), same glyph at 1.8em clipped 50/50, bottom half shifted up half a
  tile; sizes in em so tiles scale by font-size only (never rem inside a flap).
- **Counter**: 3+ digit pad, tiles settle from random chars staggered
  (≈350ms + 180ms/digit), exponential ease via tick timing; instant under
  `prefers-reduced-motion`. `role="img"` with a live aria-label carrying the
  number.
- **NEXT SERVICE panel**: bordered instrument — ETA from the median gap of
  wave-to-wave arrivals (falls back to all-time), "CONFIDENCE: NONE" state
  line, amber `.overdue` when the quiet period passes the median.
- **Stats strip**: one ruled row of four cells (shells, median gap, longest
  calm, current quiet percentile) — a table, never cards.
- **Arrival row**: full-width ruled grid — lamp / №0000 (padded, numbered as a
  fixed run) / name+tech / CVE chips (NVD links) / ARR date / gap (tabular
  numerals) / SRC↗ provenance ticket / one-line summary. Newest first; top
  row is why the counter reads what it reads.
- **Era dividers**: centered tracked-caps labels between ruled lines;
  `THE 2026 WAVE` in amber, `THE GENESIS ERA` in secondary.
- **Board states print as board states**: `PANEL SWEEP IN PROGRESS` (loading),
  `DEPARTURES UNAVAILABLE` (fetch error), `THE BOARD IS EMPTY` (no data),
  `A NEW SHELL HAS ARRIVED` (day-zero amber flood).
- **Ticker**: aria-hidden marquee loop of current stats; hover pauses;
  static under reduced-motion. World-native (station tickers exist); the
  only intentionally accepted detector warning.

## Motion

One authored moment: the flap settle on load. One acknowledgment: the row №
tile's top half tilts back 38° on hover (flap responding to a touch).
Nothing else animates.

## Fallbacks & a11y

`prefers-reduced-motion` renders every final state instantly. The board
degrades without JS to a note + link to the raw JSON. Semantics: real
sections, `<h1 class="vh">`, self-describing rows (№, ARR, GAP labels are
visible text), focus rings amber, selection amber-on-ground, scrollbar
themed. Contrast: body/labels ≥4.5:1, large display ≥3:1.

## Voice

Deadpan-panic station announcements. Snark in the copy, facts in the fields;
every joke must survive a fact-check.
