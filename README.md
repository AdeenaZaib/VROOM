# gPTP Time-Synchronisation Attack Simulator — Zonal Automotive TSN

A single-file, dependency-free demo (`gptp-tsn-demo.html`) built for a final-year project
on federated intrusion detection for automotive Ethernet/TSN. It doubles as the numerical
de-risking model for that project's core claim:

> Features derived from the gPTP sync-tree structure (sibling residuals) detect stealthy
> timing attacks that a threshold on raw clock offset cannot — without false-alarming on
> benign thermal drift.

Open `gptp-tsn-demo.html` directly in a browser. No build step, no npm, no CDN, no network
access required.

## What it simulates

A central compute unit (CCU, gPTP grandmaster) syncs four zone controllers through one
bridge: **ZC-A** (perception), **ZC-B** (chassis), **ZC-C** (powertrain), **ZC-D** (body).
One scheduled (Qbv, time-triggered) stream — a 1ms-period brake command from CCU to ZC-B —
has a 180ns schedule margin; if ZC-B's clock offset exceeds that margin, the tick counts as
a missed deadline.

Four scenarios are selectable in the UI:

| Scenario | What happens |
|---|---|
| **Settled** | Noise only. False-positive control — nothing should fire. |
| **Cold Start** | Common-mode thermal warm-up on all four nodes (and implicitly the grandmaster). Offsets drift to ~500ns. The raw-offset detector is *expected* to false-positive here; the residual detector should not, because the drift is common-mode and mostly cancels out of the sibling residual. |
| **Delay Attack** | Settled baseline + an asymmetric-delay attack ramping on ZC-B's uplink, capped at 235ns by default — deliberately kept under both the raw threshold (250ns) and the cold-start envelope (~500ns) so it hides inside the range of offsets a benign node could legitimately show. This is the central claim: the raw detector should miss it, the residual-based detectors should not. |
| **FRER Loss** | A redundant (802.1CB FRER) stream's member path B degrades silently — inter-member arrival skew grows until path B stops delivering at tick 70 — while the application sees zero loss because FRER masks it with member A. Only the skew metric exposes the degradation before it becomes total loss. |

## Architecture

The file is one HTML document with three clearly separated, independently swappable
modules, each in its own `<script>` block:

1. **`sim.js`** — pure simulation core. No DOM access anywhere in this block. Produces a
   deterministic (seeded) stream of per-tick, per-node feature rows.
2. **`detect.js`** — detector implementations. Each detector is a pure function
   `detect(history, params) -> { fired, score, node, tick }` that reads the growing
   feature-row history and returns a verdict. No DOM access.
3. **`ui.js`** — rendering, controls, canvas charts, CSV export. Talks to the other two
   modules only through their public interfaces.

This split is deliberate: `sim.js` is meant to be replaced wholesale by CSV traces
exported from OMNeT++/INET once the network model is validated there, and `detect.js` is
meant to gain a trained (eventually federated) model. Neither swap should require
touching the other two modules — see the stub at the bottom of `detect.js`
(`LearnedModel_STUB`) for where a trained model plugs in with the exact same
`(history, params) -> verdict` signature the three implemented detectors use.

### Clock model (`sim.js`)

One tick = one gPTP sync interval = 125ms (discrete time). Per zone controller `i`:

```
offset_i(t) = noise_i(t) + thermal_i(t) + attack_i(t)
```

- **`noise_i`** — a mean-reverting bounded random walk (`noise = clamp(noise*0.4 + N(0,5), -20, 20)`).
  A pure driftless clamped walk spends an unrealistic amount of time sitting at its
  hard bound; a servo-disciplined oscillator's residual phase noise reverts toward its
  recent mean instead, so a reversion factor is applied before the fresh N(0, 5ns)
  innovation each tick. The ±20ns clamp is the hard physical/software guard-band.
- **`thermal_i`** — common-mode warm-up, `A*(1 - exp(-t/tau))`, `A = 500ns`, `tau = 55`
  ticks, scaled per node by a *fixed* factor in `[0.90, 1.10]` (not random — it models
  fixed manufacturing/placement variance in each node's oscillator thermal response).
  Common-mode is the point: the grandmaster's oscillator warms up too, so this term
  should mostly cancel out of a *sibling* residual even though it dominates the raw
  offset.
- **`attack_i`** — zero except in the attack scenarios.

Features computed per tick per node: `raw_offset`, `sibling_residual` (offset minus the
median offset of the other three nodes), and `link_delay_var` (rolling variance, window
10, of measured link delay — true delay plus any attack-induced asymmetry).

### Tuning invariant

The demo's entire argument depends on one inequality holding:

```
peak attack offset (235ns)  <  raw-offset threshold (250ns)  <  peak cold-start offset (~500ns)
```

If the attack peak isn't below the raw threshold, the raw detector legitimately catches
it and the demo proves nothing. `sim.js` checks this on every `createSimulation()` call
and prints a `console.warn` if it's violated — watch for it if you change
`attackCap`/`rawThreshold`/the thermal amplitude via the UI sliders or `runBatch` configs.

### Detectors (`detect.js`)

1. **`RawThreshold`** — `|raw_offset| > 250ns` for 3 consecutive ticks.
2. **`ResidualThreshold`** — `|sibling_residual| > 80ns` for 3 consecutive ticks; the
   node with the largest residual is reported as the localisation.
3. **`CUSUM`** — two-sided sequential change detection on `sibling_residual`
   (slack `k=10ns`, decision threshold `h=70`) — the "honest baseline" a reviewer will
   ask for: no windowing, two well-understood tuning knobs.

A lightweight fourth check, `FrerSkewDetector`, flags the FRER member-skew metric
against a threshold independently of the three main detectors.

**No ML is implemented.** `LearnedModel_STUB` in `detect.js` throws on call and exists
only to document the interface a trained (federated) model would need to match.

## Self-test

On every page load, `sim.js` + `detect.js` are run headlessly (no rendering) against the
default seed (42) and the results are asserted in the browser console:

- `settled`: neither `RawThreshold` nor `ResidualThreshold` fires over 200 ticks.
- `cold_start`: `RawThreshold` fires (expected false positive); `ResidualThreshold` does not.
- `delay_attack`: `RawThreshold` does not fire; `ResidualThreshold` fires, localises
  ZC-B, and fires at least 20 ticks before the first missed deadline.
- `frer_loss`: the skew detector fires before path B dies at tick 70.
- Determinism: the same seed produces byte-identical output across two runs.

Open the browser devtools console after loading the page to see `PASS`/`FAIL` for each
check. These checks were also verified programmatically with Node (extracting the
`sim.js`/`detect.js` script blocks and `eval`-ing them headlessly) across a 300-seed
sweep before shipping; the shipped defaults hold for ~99.7% of seeds — the residual
failures are rare noise-driven raw-offset excursions during the attack window, not a
flaw in the residual-based detectors.

## CSV export / training-set generation

- **Export CSV (this run)** downloads the full feature table for whatever scenario/seed
  is currently loaded in the UI: `tick, node, raw_offset, sibling_residual,
  link_delay_var, member_skew, label, scenario, seed`. `label` is the ground-truth
  attack/no-attack flag for that row.
- **`runBatch(configs)`** (also exposed as `window.runBatch`, and wired to the "Batch
  export" button with a default of 5 seeds × 4 scenarios) runs N seeded simulations
  headlessly — no rendering — and downloads one concatenated CSV. This is how the
  project generates its training set for the eventual learned/federated detector.

```js
// from the browser console, after loading the page:
runBatch([
  { scenario: 'settled',      seed: 1, ticks: 200 },
  { scenario: 'cold_start',   seed: 1, ticks: 200 },
  { scenario: 'delay_attack', seed: 1, ticks: 200 },
  { scenario: 'frer_loss',    seed: 1, ticks: 200 },
]);
```

## Swapping `sim.js` for real traces

Replace `createSimulation(config)` with an implementation that reads a CSV/JSON trace
exported from OMNeT++/INET and replays it tick-by-tick through the same `step()`
interface (`{ tick, rows: FeatureRow[], missedDeadlineThisTick, frer }`). Nothing in
`detect.js` or `ui.js` needs to change as long as each `FeatureRow` still carries
`raw_offset`, `sibling_residual`, `link_delay_var`, and `member_skew`.

## Notes

- All UI numbers are rounded for display; the underlying CSV export keeps full
  precision (3 decimal places).
- Charts are plain `<canvas>`, no charting library. The topology diagram is inline SVG.
- The page defines a light and a dark palette via CSS custom properties and
  `prefers-color-scheme`; no JS theme toggle is needed.
