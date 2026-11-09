console.log("hey look. It's js2shell lol");

// ——— the only two functions that touch untrusted JSON text ———
// data/vulns.json + data/eggs.json are community-PR'd. Everything they
// carry is hostile until proven otherwise: esc() before innerHTML,
// safeUrl() before href. No exceptions, no new innerHTML of raw fields.
const esc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;")
  .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
const SAFE_URL = /^https?:\/\/[^\s"'<>]+$/i;
const safeUrl = (u) => (u && SAFE_URL.test(u)) ? u : null;

/* ------------------------------------------------------------------ */
/* pure logic — no DOM (node-testable)                                 */
/* ------------------------------------------------------------------ */

const DAY = 86400000;

function parseVulns(data) {
  const vulns = (data.vulns || []).filter(v => v && v.name && v.date)
    .map(v => ({ ...v, ts: Date.parse(v.date + "T00:00:00Z") }))
    .filter(v => !isNaN(v.ts))
    .sort((a, b) => a.ts - b.ts);           // oldest first
  return vulns;
}

function median(xs) {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

function computeStats(vulns, nowMs) {
  const n = vulns.length;
  if (!n) return null;
  const latest = vulns[n - 1];
  const today = Math.floor(nowMs / DAY) * DAY;
  const daysSince = Math.max(0, Math.round((today - latest.ts) / DAY));
  const gaps = [];
  for (let i = 1; i < n; i++) gaps.push(Math.round((vulns[i].ts - vulns[i-1].ts) / DAY));
  const waveGaps = gaps.filter((g, i) =>
    vulns[i].era === "wave" && vulns[i + 1].era === "wave");
  const medianAll = median(gaps);
  const medianWave = median(waveGaps);
  const eta = medianWave != null ? medianWave : medianAll;
  const dueMs = latest.ts + (eta || 0) * DAY;
  const pct = gaps.length ? gaps.filter(g => g < daysSince).length / gaps.length : null;
  return {
    n, latest, daysSince, gaps, waveGaps,
    medianAll, medianWave, eta,
    overdue: daysSince > eta,
    dueMs, pct,
    longestCalm: gaps.length ? Math.max(...gaps) : null,
  };
}

function fmtDate(ts) {
  const M = ["JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC"];
  const d = new Date(ts);
  return `${String(d.getUTCDate()).padStart(2,"0")} ${M[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

function pad4(n) { return String(n).padStart(4, "0"); }

/* the candy wheel: hue for the i-th thing on the board */
function hueVar(i) { return `var(--hue-${(i % 7) + 1})`; }

/* ------------------------------------------------------------------ */
/* mood lines — live in data/vulns.json ("moods": [...]). The JSON     */
/* stands on its own: this function only evaluates the declarative     */
/* constraints. First match wins; missing block = no mood line.        */
/* ------------------------------------------------------------------ */

function moodMatches(m, s) {
  if (m.min_days != null && !(s.daysSince >= m.min_days)) return false;
  if (m.max_days != null && !(s.daysSince <= m.max_days)) return false;
  if (m.record && !(s.longestCalm != null && s.daysSince > s.longestCalm)) return false;
  if (m.overdue && !s.overdue) return false;
  return true;
}

function pickMood(stats, moods) {
  for (const m of moods || []) {
    if (m && m.line && moodMatches(m, stats)) return m;
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* DOM                                                                 */
/* ------------------------------------------------------------------ */

function flapTile(ch, hue) {
  const f = document.createElement("span");
  f.className = "flap";
  if (hue) f.style.setProperty("--th", hue);
  f.innerHTML = `<span class="fh fh-t"><i>${ch}</i></span><span class="fh fh-b"><i>${ch}</i></span>`;
  return f;
}

function setFlap(tile, ch) {
  tile.querySelectorAll("i").forEach(i => i.textContent = ch);
}

const FLIP_CHARS = "0123456789X2S";

function flapSettle(tile, finalChar, delay) {
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) { setFlap(tile, finalChar); return; }
  let ticks = 0;
  const total = 7 + Math.floor(Math.random() * 5);
  setTimeout(function tick() {
    if (ticks < total) {
      setFlap(tile, FLIP_CHARS[Math.floor(Math.random() * FLIP_CHARS.length)]);
      ticks++;
      setTimeout(tick, 55 + ticks * 9);
    } else setFlap(tile, finalChar);
  }, delay);
}

function renderCounter(stats, moods) {
  const display = document.getElementById("counter-display");
  const label = document.getElementById("counter-label");
  const sub = document.getElementById("counter-sub");
  display.innerHTML = "";
  display.setAttribute("aria-label",
    stats.daysSince + " days since the last 2Shell-named vulnerability");
  const chars = String(stats.daysSince).padStart(3, "0").split("");
  chars.forEach((ch, i) => {
    const tile = flapTile("0", hueVar(i));
    display.appendChild(tile);
    flapSettle(tile, ch, 350 + i * 180);
  });
  if (stats.daysSince === 0) document.getElementById("counter").classList.add("live-arrival");
  label.textContent = "DAYS SINCE THE LAST 2SHELL-NAMED VULNERABILITY";
  sub.innerHTML = `LAST ARRIVAL: <b>${esc(stats.latest.name.toUpperCase())}</b> · ${fmtDate(stats.latest.ts)}` +
    (stats.latest.era === "wave" ? "" : "  <span style='color:var(--dim)'>(the genre never really went away)</span>");
  const mood = pickMood(stats, moods);
  if (mood) {
    const chip = document.createElement("span");
    chip.className = "counter-mood " + (mood.class || "");
    chip.textContent = mood.line;
    sub.after(chip);
  }
}

function renderService(stats) {
  const svc = document.getElementById("service");
  document.getElementById("svc-eta").innerHTML = `~${stats.eta != null ? Math.round(stats.eta) : "—"} <small>DAYS</small>`;
  document.getElementById("median-wave").textContent = stats.medianWave != null ? stats.medianWave + "d" : "—";
  document.getElementById("median-all").textContent = stats.medianAll != null ? stats.medianAll + "d" : "—";
  document.getElementById("svc-due").textContent =
    "DUE: " + (stats.eta != null ? fmtDate(stats.latest.ts + stats.eta * DAY) : "—");
  if (stats.overdue) {
    svc.classList.add("overdue");
    document.getElementById("svc-due").textContent += ". OVERDUE. STATISTICALLY, WE ARE DUE.";
  }
}

function renderStats(stats) {
  const pctLine = stats.pct != null
    ? `LONGER THAN ${Math.round(stats.pct * 100)}% OF GAPS SO FAR`
    : "—";
  document.getElementById("stats").innerHTML = [
    ["SHELLS ON RECORD", pad4(stats.n)],
    ["MEDIAN INTER-ARRIVAL", (stats.medianAll ?? "—") + "<em>d</em>"],
    ["LONGEST CALM", (stats.longestCalm ?? "—") + "<em>d</em>"],
    ["THIS QUIET PERIOD", stats.daysSince + "<em>d</em> — " + pctLine],
  ].map(([k, v]) => `<div class="stat"><div class="k">${k}</div><div class="v">${v}</div></div>`).join("");
}

function renderBoard(vulns) {
  const board = document.getElementById("board");
  board.innerHTML = "";
  [...vulns].reverse().forEach((v, ri) => {
    const li = document.createElement("li");
    li.className = "arrival";
    const gap = ri < vulns.length - 1
      ? "+" + Math.round((v.ts - vulns[ri + 1].ts) / DAY) + "d"
      : "—";
    const num = pad4(vulns.length - ri);
    /* era encoding is the candy: wave = rainbow wheel, classic = sepia */
    li.style.setProperty("--chip",
      v.era === "wave" ? hueVar(vulns.length - ri - 1) : "var(--sepia)");
    const cves = (v.cves || []).map(c =>
      `<a href="https://nvd.nist.gov/vuln/detail/${esc(c)}" title="${esc(c)} on NVD" target="_blank" rel="noopener noreferrer">${esc(String(c).replace("CVE-", ""))}</a>`).join("<br>")
      || "<span style='color:var(--dim)'>none yet</span>";
    const url = safeUrl(v.url);
    const src = url ? `<a href="${esc(url)}" aria-label="source for ${esc(v.name)}" target="_blank" rel="noopener noreferrer">SRC↗</a>` : "—";
    li.innerHTML = `
      <span class="no">${num}</span>
      <span class="name">${url ? `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(v.name)}</a>` : esc(v.name)}<span class="tech">${esc(v.tech || "")}</span></span>
      <span class="cves">${cves}</span>
      <span class="arr"><small>ARR</small>${fmtDate(v.ts)}</span>
      <span class="gap">${gap}</span>
      <span class="src">${src}</span>
      <span class="sum">${esc(v.summary || "")}</span>`;
    board.appendChild(li);
  });
}

async function renderEggs() {
  const zone = document.getElementById("eggs");
  try {
    const res = await fetch("data/eggs.json?v=" + Date.now(), { cache: "no-store" });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();
    const eggs = data.eggs || [];
    if (!eggs.length) {
      zone.innerHTML = `<li class="board-state">THE INCUBATOR IS EMPTY. THE NAMING COMMITTEE IS RESTING.</li>`;
      return;
    }
    zone.innerHTML = eggs.map(e => `
      <li class="egg">
        <span class="st st-${esc(e.status)}">${esc((e.status || "quiet").toUpperCase())}</span>
        <span class="egg-domain"><a href="https://${esc(e.domain)}" target="_blank" rel="noopener noreferrer">${esc(e.domain)}</a></span>
        <span class="egg-score">${e.score ?? "—"}</span>
        <span class="egg-title">${esc(e.title)}</span>
      </li>`).join("");
  } catch {
    zone.closest(".eggs-zone").style.display = "none"; // incubator offline → quiet panel
  }
}

function renderTicker(stats) {
  const base = `IT HAS BEEN ${stats.daysSince} DAYS SINCE THE LAST 2SHELL` +
    ` · LAST ARRIVAL: ${esc(stats.latest.name.toUpperCase())} ${fmtDate(stats.latest.ts)}` +
    ` · ${stats.n} SHELLS ON RECORD` +
    ` · EST. WAIT TO NEXT: ~${Math.round(stats.eta)} DAYS (CONFIDENCE: NONE)` +
    ` · THIS BOARD IS MAINTAINED BY A BOT WITH A MASTODON PROBLEM AND BY WHOEVER IS READING THIS` +
    ` · `;
  document.getElementById("ticker").innerHTML = `<span>${base}</span><span>${base}</span>`;
}

function boardState(html) {
  document.getElementById("board").innerHTML =
    `<li class="board-state">${html}</li>`;
}

async function init() {
  document.getElementById("today-line").textContent = fmtDate(Date.now()) + " UTC";
  const brand = document.getElementById("brand-flaps");
  "2SHELL".split("").forEach((ch, i) => brand.appendChild(flapTile(ch, hueVar(i))));

  let data;
  try {
    const res = await fetch("data/vulns.json?v=" + Date.now(), { cache: "no-store" });
    if (!res.ok) throw new Error("HTTP " + res.status);
    data = await res.json();
  } catch (e) {
    boardState(`DEPARTURES UNAVAILABLE. THE BOARD CANNOT REACH <b>data/vulns.json</b>.<br>
      (Are you offline? The data file lives <a href="data/vulns.json" target="_blank" rel="noopener noreferrer">right here</a>.)`);
    for (let i = 0; i < 3; i++) {
      const t = flapTile("–", hueVar(i)); document.getElementById("counter-display").appendChild(t);
      setFlap(t, "–");
    }
    document.getElementById("counter-sub").textContent = "SIGNAL LOST";
    return;
  }
  const vulns = parseVulns(data);
  const stats = computeStats(vulns, Date.now());
  if (!stats) { boardState("THE BOARD IS EMPTY. WHICH IS TECHNICALLY GOOD NEWS."); return; }
  renderCounter(stats, Array.isArray(data.moods) ? data.moods : []);
  renderService(stats);
  renderStats(stats);
  renderBoard(vulns);
  renderTicker(stats);
  renderEggs();
  /* one more for the console gremlins */
  console.log("%c 2shell.lol %c " + stats.daysSince +
    " days since " + stats.latest.name + " · est. next in ~" +
    Math.round(stats.eta) + " days ",
    "background:#17141f;color:#ffd23f;border:2px solid #17141f;font-weight:bold",
    "color:#17141f");
}

if (typeof document !== "undefined" && document.getElementById("board")) {
  init();
}
/* node test hook */
if (typeof module !== "undefined" && module.exports) {
  module.exports = { parseVulns, computeStats, median, fmtDate, pad4, pickMood, moodMatches, DAY };
}
