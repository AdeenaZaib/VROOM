# CARAZONE — benign + gPTP/FRER attack runs

- **`gen_topology.py`** — single source of truth. Now also emits benign traffic (from a `FLOWS` table), result recording, and a `scenarioManager` module into `omnetpp.ini`. Run `python3 gen_topology.py` to regenerate `ZonalRingTopology.ned` + `omnetpp.ini`.
- **`attacks.ini`** — `include`s `omnetpp.ini`, adds selectable attack `[Config ...]` sections.
- **`run_experiments.py`** — launches runs and writes `results/manifest.json` tagging each one.

Target toolchain: **OMNeT++ 6.4.0 + INET 4.7.0**.

## Regenerate, then run

```
python3 gen_topology.py                 # rebuilds .ned + omnetpp.ini (baseline)
python3 run_experiments.py Baseline      # clean reference run
python3 run_experiments.py Gptp_Drift_Deep Frer_Enabled Frer_PathCut
python3 run_experiments.py --all
```
By hand: `opp_run_release -u Cmdenv -c Baseline -n .:<INET>/src -l <INET>/src/INET attacks.ini`
(set `INET_ROOT` near the top of `run_experiments.py`, or pass `--run-cmd`).

## Suggested order

1. **`Baseline`** — confirm clocks converge, every flow arrives, link util < ~70%. Your reference dataset; attacks are only meaningful as a delta from it.
2. **`Gptp_Drift_Deep`** / **`_Shallow`** / **`_Timed`** — config-only gPTP attacks. `_Timed` gives a clean-then-attacked segment in one run.
3. **`Frer_Enabled`** — proves FRER is live (sink gets one copy/frame; elimination active at swC). Then **`Frer_PathCut`**, **`Frer_DuplicateFlood`**, **`Frer_Plus_GptpDrift`**.
4. **Custom C++** (later) — subclass `inet::Gptp`, override `sendFollowUp` / `processSync` / `computePropTime` for delay/replay/correction-field tampering; subclass the 802.1CB sequence-encoding module for sequence-number attacks. Highest research value, once the pipeline above is proven.

## Editing traffic or scenarios

- **Traffic** is the `FLOWS` table in `gen_topology.py` — add/remove a row, regenerate. The generator now validates that every flow endpoint is a real node, so a bad edit fails loudly instead of producing a broken INI.
- **Attacks** live in `attacks.ini` (hand-maintained, not generated — the attack set will keep evolving). Keep `run_experiments.py`'s `SCENARIOS` dict in sync so runs stay labelled.

## FRER path geometry (why this is valid)

Path A `brakeECU→swFL→swC→centralCompute` and path B `brakeECU→swFL→swFR→swC→centralCompute` split at **swFL** (replication) and merge at **swC** (elimination). swC has separate ports to swFL and swFR, so it receives both copies and eliminates the duplicate; `centralCompute` gets one frame over its single uplink. The INET multipath showcase used a shared destination MAC because its sink had two NICs — not needed here.

## Version caveat (INET 4.7 vs the 4.6 showcase)

The FRER config mirrors INET's `automaticmultipathconfiguration` showcase (verified on 4.6). On 4.7 the syntax should hold, but if `StreamRedundancyConfigurator` isn't found, check its package path under `src/inet/linklayer/configurator/` — it moved packages across versions. Same for `ScenarioManager` (`inet.common.scenario.ScenarioManager`) if the NED import errors.

## Key metrics

- **gPTP:** node clock offset from the grandmaster (`clock.timeChanged`). Victim-vs-clean-node offset is the label; deeper tree nodes show larger compounded error.
- **FRER:** sink `packetReceived` vs source sent, and duplicate-elimination counts at swC / destination.
