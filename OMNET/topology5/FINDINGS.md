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
| `Gptp_Drift_Shallow` | gPTP attack | victim `gnssReceiver` forced drift | defined |
| `Gptp_Drift_Sweep` | gPTP attack | drift sweep 500/2000/5000/10000 ppm | defined |
| `Gptp_Drift_Timed` | gPTP attack | clean window then drift at t=1 s (ScenarioManager) | defined |
| `Frer_Enabled` | benign (FRER on) | redundant `brakeECU→centralCompute` stream | ✅ run & validated |
| `Frer_PathCut` | FRER attack | crash `swFR` to cut one redundant path | defined |
| `Frer_DuplicateFlood` | FRER attack | rogue node floods duplicate-like traffic | defined |
| `Frer_Plus_GptpDrift` | combined | gPTP drift on a FRER-path node | defined |

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

**Implication for the IDS:** `swC.streamRelay.merger.droppedPacketLengths` is a dual-purpose signal — it holds steady (~2000) when redundancy masks a path failure, and should spike under a duplicate-injection flood. Its benign value is now characterised.

---

## 5. Detection signals identified

| Attack family | Primary feature | Benign value | Attack behaviour |
|---|---|---|---|
| gPTP drift | `gmRateRatio` (per node) | ≈ 1.0 | persistent offset (≈ 1 − drift) |
| gPTP drift | underlying-clock offset | small, bounded | grows with drift |
| FRER | `swC …merger.droppedPacketLengths` | ~2000 (= protected stream rate) | rises under flood / changes under path cut |
| Delivery (all) | per-flow `packetReceived:count` | matches flow rate | drops if deadlines missed |

---

## 6. Limitations / honest notes

- Three attack scenarios (`Gptp_Drift_Deep`, `Frer_Enabled`) and the baseline are **run and analysed**; the remaining configs are **defined and ready** but not yet executed.
- A **constant** drift is the easiest case for gPTP to compensate; time-varying drift (the `Gptp_Drift_Timed` config) is expected to stress the servo harder and is a planned follow-up.
- Attacks so far are **configuration-level** (oscillator / traffic manipulation). Protocol-level C++ attacks (gPTP message tampering via a `Gptp` subclass; 802.1CB sequence-number manipulation) are the planned research-grade extension.
- Results are from single runs; repeated seeds are needed for variance before training.

---

## 7. Next steps

1. Run the remaining scenarios (`Gptp_Drift_Sweep`, `Gptp_Drift_Timed`, `Frer_PathCut`, `Frer_DuplicateFlood`, `Frer_Plus_GptpDrift`), e.g. via `run_experiments.py --all`.
2. Build the feature-extraction script: parse the recorded vectors, window them, and label rows from `manifest.json` into per-zone datasets (one per zonal controller = one federated client).
3. Extend to protocol-level (C++) attacks for higher fidelity.
