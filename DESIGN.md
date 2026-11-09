# Design — 2shell.lol

The page is a **candy-sticker shellpocalypse scoreboard** — the user-pinned
direction ("rainbow, fun, meme-y — too black and corpo") replacing the first
shipped world (dark split-flap station board, roll 790bd77a). The split-flap
counter survives as the product's instrument; everything around it got loud.

## The semantic trick

The rainbow is data encoding, not decoration: **the 2026 wave is full
technicolor, the genesis era is sepia.** Each wave arrival takes the next hue
off a fixed seven-slot candy wheel; classic-era arrivals take the same chip
shape in vintage sepia. The board literally shows the genre going from black
& white to color. Era dividers agree: THE 2026 WAVE gets the rainbow-bar
artifact with a sticker label; THE GENESIS ERA gets a dashed sepia rule.

## Palette

| Role | Token | Notes |
|------|-------|-------|
| ground | `#fdf6e9` | cream paper, 1px ink dot-grid |
| ink | `#17141f` | the only text color; also every border |
| secondary | `#5b5442` | tinted from the cream, ≥7:1 |
| hue-1…7 | `#ffd23f #ff9838 #ff6482 #b78cff #6ecbff #5fd68a #ff5d5d` | all ≥6.9:1 with ink text |
| sepia | `#e8dcc2` | classic-era chip fill (ink text on top) |

Neobrutalist chrome is the world: 2–3px ink borders, hard block shadows
(`4–6px 4–6px 0 ink`), sticker chips. Hard shadows are earned by this
world — they are its depth system, not a costume.

## Type

Unchanged: **Departure Mono** (OFL, self-hosted) does everything — its pixel
terminal character is what makes the candy read as 90s-arcade rather than
SaaS-landing. Hierarchy by size, case, borders, chips, and hue.

## Components

- **Flap tiles**: hue-filled (one candy each, per-digit cycle), ink border +
  block shadow, split halves kept (`filter: brightness(1.07/.9)` + 2px ink
  seam). Counter digits spin the wheel; the brand spells 2SHELL in it.
- **Day-zero state**: when daysSince = 0, tiles run a `steps(1)` hue-cycle
  animation (reduced-motion: static).
- **Mood line**: a tiered sticker chip under the counter, first match wins
  (the copy slot — see the MOODS table in index.html): 0 days = rainbow
  "A NEW SHELL HAS ARRIVED"; 1 day = mint "ONE DAY OF CALM. SAVOR IT.";
  beyond the all-time record calm = lavender "LONGEST CALM IN RECORDED
  HISTORY"; ≥365 days = sky "A YEAR OF CALM"; past the over/under = yellow
  "THE OVER/UNDER SAYS ANY DAY NOW". Quiet days show no chip at all.
- **Header badges**: sticker chips — "THE SHELLPOCALYPSE SCOREBOARD",
  "100% ARTIFICIAL FLAVOR", live date, "BEST VIEWED AT 2AM".
- **NEXT SERVICE panel**: white sticker panel with dashed-ink rule; overdue
  state floods the ETA sticker red and the due line yellow.
- **Stats strip**: four hue-cycled sticker blocks (yellow/mint/sky/lavender).
- **Arrival row**: № in a hue chip (pops on hover: grows its block shadow),
  name+tech, CVE chips right-aligned, ARR date, tabular gap, SRC↗ ticket,
  one-line summary. Full-width ruled rows (2px ink) — the forge-raise kept.
- **Rainbow bar**: the GeoCities `<hr>` as a real component — era dividers
  and the 404 page.
- **Ticker**: a scrolling rainbow strip with ink text (aria-hidden,
  hover-pause, static under reduced-motion) — the world's own artifact.
- **Snippet**: the one dark element — an ink terminal sticker on cream.
- **Board states**: UNBOXING THE CHOCOLATES (loading), DEPARTURES
  UNAVAILABLE (error), THE BOARD IS EMPTY (no data).

## Motion

Settle-flap on load (unchanged), day-zero hue cycle, chip pop on row hover.
Reduced-motion renders every final state instantly.

## Easter egg

`console.log("hey look. It's js2shell lol")` fires on every load, first line
of the script. After the data lands, a second `%c`-styled console sticker
reports the current counter.

## Fallbacks & a11y

Same contract as v1: `prefers-reduced-motion` handled, noscript degrades to
the JSON link, `<h1 class="vh">`, self-describing rows, amber→hue focus
rings, themed selection/scrollbar. Contrast: ink-on-hues ≥6.9:1, dim ≥7:1.

## Voice

Same deadpan, louder packaging. "The old ones are in black & white — like
the history they are."
