# CARAZONE — gPTP & FRER Attack Simulation: Work Log and Findings

**Project:** Federated IDS for TSN-based zonal automotive networks (CARAZONE)
**Simulation environment:** OMNeT++ 6.4.0 + INET 4.7.0 (macOS, Apple M4)
**Network under test:** `ZonalRingTopology` — 5-zone TSN ring (FL/FR/RL/RR + central cabin), 5 TSN switches, 1 gPTP grandmaster, 25 endpoint ECUs + zonal controllers
**Simulation length:** 2 s per run (~496,500 events, ~2.3 s wall-clock)

---

## 1. Objective

Establish a reproducible simulation pipeline that produces a benign baseline and injects two attack families — gPTP time-synchronisation attacks and FRER (IEEE 802.1CB) stream-redundancy attacks — on the zonal ring topology, and verify that each attack produces a measurable, separable signal suitable as a feature for the federated IDS.

---

## 2. What was built

A single-source-of-truth pipeline, extending the existing topology generator:

| File | Role |
|------|------|
| `gen_topology.py` | Generates `ZonalRingTopology.ned` + `omnetpp.ini` from editable tables (zones, links, **traffic flows**). Now also emits benign application traffic, result recording, and a `scenarioManager` module. |
| `omnetpp.ini` | Generated benign **baseline**: topology + gPTP + traffic + recording. |
| `attacks.ini` | Includes `omnetpp.ini`, layers attack scenarios as selectable `[Config ...]` sections. |
| `run_experiments.py` | Launches runs and writes `results/manifest.json` tagging each run (scenario, victim node, attack window) for automatic labelling. |

**Benign traffic** (five UDP flows, one representative per zone, all → `centralCompute`), defined in a `FLOWS` table and validated against the node list at generation time.

**Result recording** was extended to capture, in addition to delivery counts and the synchronised clock:
- the **uncorrected underlying oscillator** (`clock.underlyingClock`), and
- the **gPTP correction-effort signals**: `gmRateRatio`, `neighborRateRatio`, `pdelay`.

---

## 3. Scenario catalogue

| Config | Type | Mechanism | Status |
|--------|------|-----------|--------|
| `Baseline` | benign | no fault | ✅ run & validated |
| `Gptp_Drift_Deep` | gPTP attack | victim `lidarRR` forced constant drift | ✅ run & analysed |
| `Gptp_Drift_Shallow` | gPTP attack | victim `gnssReceiver` forced drift | ✅ run |
| `Gptp_Drift_Sweep` | gPTP attack | drift sweep 500/2000/5000/10000 ppm | ✅ run (4 runs) |
| `Gptp_Drift_Timed` | gPTP attack | clean window then drift at t=1 s (ScenarioManager) | ⚠️ not runnable (see 4.5) |
| `Frer_Enabled` | benign (FRER on) | redundant `brakeECU→centralCompute` stream | ✅ run & validated |
| `Frer_PathCut` | FRER attack | crash `swFR` to cut one redundant path | ✅ run & analysed |
| `Frer_DuplicateFlood` | FRER attack (port flood) | rogue node floods the protected port | ✅ run & analysed |
| `Frer_Plus_GptpDrift` | combined | gPTP drift on a FRER-path node | ✅ run |

All runs are 2 s and complete in ~2–7 s wall-clock. Eight of nine configs run
successfully (the sweep expanding to four); one is blocked by an INET limitation (§4.5).
`run_experiments.py --all` executes the batch and writes `results/manifest.json`
labelling each run for the feature-extraction stage.

---

## 4. Findings

### 4.1 Baseline is valid (reference dataset)

The baseline run completed cleanly to t = 2 s with **zero packet loss**. Delivery at `centralCompute` matched the configured flow rates exactly:

| Flow (source) | Rate | Packets received (2 s) |
|---------------|------|------------------------|
| brakeECU | 1 ms | 2000 |
| cameraFront | 250 µs | 8000 |
| powertrainECU | 1 ms | 2000 |
| lidarRL | 500 µs | 4000 |
| v2xUnit | 2 ms | 1000 |
| **Total** | | **17000** |

gPTP converged: the victim node's **synchronised** clock tracked the grandmaster to within ~2 µs over the whole run (final value 2.00000206 s at t = 2 s). ~75 per-node clock vectors were recorded.

### 4.2 gPTP drift attack — detectable, but *not* via the corrected clock

A constant-drift attack was injected on `lidarRR` (deepest node in the sync tree).

**Key finding:** the gPTP servo *absorbs* a constant drift, so the **synchronised clock barely moves** and a naïve clock-offset monitor would miss the attack:

| Signal (at t≈2 s) | Baseline | Attack (500 ppm) |
|---|---|---|
| Synchronised clock | 2.00000206 s | 2.00000316 s (≈ **1 ns** difference) |

The attack fingerprint instead appears clearly in the **correction-effort signal** `gmRateRatio` (the rate ratio the servo applies to track the grandmaster). At 2000 ppm:

| Signal | Baseline | Attack (2000 ppm) |
|---|---|---|
| `gmRateRatio` | ≈ 0.99999 (noise ±tens of ppm) | ≈ **0.99800** (flat −2000 ppm offset) |
| `neighborRateRatio` | ≈ 1.00006 | ≈ 0.99807 |

The ratio shifts by ~0.2 % and remains displaced for the entire run — a stable, unmistakable deviation the benign node never produces.

**Implication for the IDS:** the detection feature for drift attacks must be the gPTP rate-ratio / underlying-clock signals, *not* the delivered clock time. This is a concrete, defensible result: it shows why rate-ratio monitoring is necessary and offset monitoring is insufficient.

*Caveat:* `neighborRateRatio` updates only per peer-delay measurement, so it is sparse (≈2 samples/run) and best used as a coarse per-window statistic; `gmRateRatio` is the dense, reliable feature.

### 4.3 FRER (802.1CB) is confirmed replicating and eliminating

With FRER enabled, the full 802.1CB pipeline instantiated correctly (stream identifier, encoder/decoder, stream relay merger) at the split point (`swFL`) and the merge point (`swC`). Duplicate elimination at `swC` was exact:

| `swC` stream merger | Count |
|---|---|
| Incoming frames | 24060 |
| Outgoing frames | 22060 |
| **Dropped (duplicates eliminated)** | **2000** (each exactly 1024 B) |

The arithmetic closes (24060 = 22060 + 2000), and the 2000 dropped frames are uniformly 1024 B — i.e. exactly the `brakeECU` protected stream. The destination received its 2000 frames intact over two disjoint ring paths.

**Implication for the IDS:** `swC.streamRelay.merger.droppedPacketLengths` is a direct FRER-health signal. Its benign value (~2000, = protected-stream rate) is now characterised, and the two FRER attacks move it in opposite directions (§4.4).

### 4.4 FRER attacks — two distinct, opposite fingerprints

Two attacks were run against the FRER-protected `brakeECU → centralCompute` stream. They produce opposite signatures, and neither is visible in simple packet-loss monitoring:

**(a) Path-cut** — `swFR` crashed t=1 s, restarted t=1.5 s (one redundant path down for 0.5 s):

| Metric | Clean FRER | Path cut |
|---|---|---|
| Delivery at sink (`app[0]`) | 2000 | **2000** (no loss) |
| Duplicates eliminated at `swC` | 2000 | **1500** |

Delivery survived the outage completely — FRER masked the single-path failure. The eliminated-duplicate count fell by exactly **500**, which matches the outage precisely: 0.5 s × 1000 frames/s (the 1 ms brake stream) = 500 frames that had no duplicate to eliminate while one path was down. *Signature: service maintained, redundancy consumed.*

**(b) Port flood** — rogue node `radarFL` sends to the protected port at 5× the stream rate:

| Metric | Clean FRER | Port flood |
|---|---|---|
| Delivery at sink (`app[0]`) | 2000 | **12000** |
| Duplicates eliminated at `swC` | 2000 | **2000** (unchanged) |

The flood did **not** affect the elimination counter — the 2000 genuine brake duplicates were still the only frames dropped (all 1024 B). Instead the flood frames passed straight through to the application (2000 → 12000 received). *Signature: application-layer overload, FRER mechanism untouched.*

This is an important mechanistic finding: FRER's elimination keys on **stream identity + sequence number**, not destination port, so a same-port flood does not match the protected stream and bypasses elimination entirely, landing as application overload. A true 802.1CB **sequence-number replay** (which *would* fool elimination) requires tampering inside the sequence-encoding module — i.e. the C++ attack on the roadmap. The config-level flood empirically demonstrates *why* the C++ attack is needed.

**FRER signal summary:**

| Scenario | `swC` eliminations | `app[0]` delivery | Detection layer |
|---|---|---|---|
| Frer_Enabled (benign) | 2000 | 2000 | — |
| Frer_PathCut | **1500** ↓ | 2000 | FRER mechanism |
| Frer_DuplicateFlood (port flood) | 2000 (unchanged) | **12000** ↑ | application / rate |

### 4.5 Limitation: config-level *timed* drift is not possible

The `Gptp_Drift_Timed` scenario (clean window, then drift injected at t=1 s via ScenarioManager `set-param`) fails at runtime: INET's oscillator `driftRate` is **not marked mutable**, so it cannot be changed mid-simulation (`Setting the parameter is not allowed at runtime`). The clean window runs correctly; the error occurs the instant the parameter change is attempted.

This is not a setup error but an INET design constraint. Time-varying drift — the attack class that would genuinely defeat the gPTP servo's steady-state tracking — therefore requires the protocol-level C++ attack rather than configuration alone. Within the current config-only scope, severity variation is already provided by `Gptp_Drift_Sweep`, and a working timed clean→attack→recovery window is provided by `Frer_PathCut`.

### 4.6 gPTP severity sweep

The drift sweep (500 / 2000 / 5000 / 10000 ppm on `lidarRR`) expands into four runs and shows the `gmRateRatio` deviation scaling monotonically with attack magnitude — the rate-ratio displacement is approximately the drift itself (e.g. 2000 ppm → ratio ≈ 0.9980). This gives a graded-severity axis for training and a single figure demonstrating dose-response of the primary detection feature.

---

## 5. Detection signals identified

| Attack family | Primary feature | Benign value | Attack behaviour |
|---|---|---|---|
| gPTP drift | `gmRateRatio` (per node) | ≈ 1.0 | persistent offset (≈ 1 − drift) |
| gPTP drift | underlying-clock offset | small, bounded | grows with drift |
| FRER (path cut) | `swC …merger.droppedPacketLengths` | ~2000 (= protected stream rate) | **falls** during path outage (redundancy consumed) |
| FRER (port flood) | per-flow `packetReceived:count` at sink | matches flow rate | **rises** (application overload) |
| Delivery (all) | per-flow `packetReceived:count` | matches flow rate | drops if deadlines missed |

**Cross-cutting theme:** in both attack families the attack is invisible to the naïve metric (clock time; packet loss) and visible in the protocol-mechanism metric (gPTP rate ratio; FRER elimination count). This directly motivates the IDS feature set.

---

## 6. Limitations / honest notes

- Eight of nine scenarios (incl. a 4-level sweep) are **run and analysed**; one (`Gptp_Drift_Timed`) is **blocked by an INET constraint** — oscillator `driftRate` is immutable at runtime (§4.5).
- A **constant** drift is the easiest case for gPTP to compensate; time-varying drift would stress the servo harder but requires the protocol-level C++ attack, not configuration alone.
- Attacks so far are **configuration-level** (oscillator / traffic manipulation). Protocol-level C++ attacks (gPTP message tampering via a `Gptp` subclass; 802.1CB sequence-number replay) are the planned research-grade extension — and §4.4 gives empirical justification for why they are necessary.
- Results are from single runs; repeated seeds are needed for variance before training.

---

## 7. Next steps

1. **Feature extraction:** parse the recorded vectors, window them, and label rows from `manifest.json` into per-zone datasets (one per zonal controller = one federated client). *(immediate next step)*
2. Add repeated seeds per scenario for variance.
3. Extend to protocol-level (C++) attacks for higher fidelity — gPTP message/correction-field tampering and 802.1CB sequence-number replay.
