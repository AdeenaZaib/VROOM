# How to run the CARAZONE attack simulations

Quick guide for running the baseline and attack scenarios. Assumes OMNeT++ 6.4.0
and INET 4.7.0 are already installed (the same setup that runs the gPTP showcase).

## One-time setup

Put these files in a folder inside your OMNeT++ samples directory, e.g. `samples/ring/`:
`gen_topology.py`, `attacks.ini`, `run_experiments.py`
(running `gen_topology.py` creates `omnetpp.ini` and `ZonalRingTopology.ned`).

In the OMNeT++ IDE: the project must **reference INET** —
right-click the project → Properties → Project References → tick `inet-4.7.0`.

## Every new terminal

The IDE and `opp_run` need the OMNeT++ environment. In each new terminal:

```bash
cd ~/Documents/sim/omnetpp-6.4.0      # <-- your OMNeT++ install path
source setenv
export INET=~/Documents/sim/omnetpp-6.4.0/samples/inet-4.7.0   # <-- your INET path
cd samples/ring
```

## Step 1 — regenerate the files

Do this once, and again any time you edit `gen_topology.py`:

```bash
python3 gen_topology.py
```
Should print `OK ... flows=5`. This (re)writes `omnetpp.ini` + `ZonalRingTopology.ned`.

## Step 2 — run a scenario

Always launch **`attacks.ini`** (it pulls in the baseline). Pick a config with `-c`:

```bash
# benign baseline (run this first — it's the reference)
opp_run_release -u Cmdenv -c Baseline \
  -n .:$INET/src -l $INET/src/INET --cmdenv-log-level=warn attacks.ini

# a gPTP drift attack
opp_run_release -u Cmdenv -c Gptp_Drift_Deep \
  -n .:$INET/src -l $INET/src/INET --cmdenv-log-level=warn attacks.ini

# FRER enabled
opp_run_release -u Cmdenv -c Frer_Enabled \
  -n .:$INET/src -l $INET/src/INET --cmdenv-log-level=warn attacks.ini
```

A run is done when it prints `Simulation time limit reached -- at t=2s`.
Results land in `results/<Config>-#0.sca` (scalars) and `.vec` (vectors).

**Available configs:** `Baseline`, `Gptp_Drift_Shallow`, `Gptp_Drift_Deep`,
`Gptp_Drift_Sweep`, `Gptp_Drift_Timed`, `Frer_Enabled`, `Frer_PathCut`,
`Frer_DuplicateFlood`, `Frer_Plus_GptpDrift`.

**Run many at once** (edit `INET_ROOT` at the top of `run_experiments.py` first):
```bash
python3 run_experiments.py Baseline Gptp_Drift_Deep Frer_Enabled
python3 run_experiments.py --all
python3 run_experiments.py --list     # see all scenarios
```

## Step 3 — look at results

Export a vector to CSV with `opp_scavetool` (binary `.vec` can't be read directly).
Filter syntax: `=~ "pattern"`, combined with lowercase `and`.

```bash
# gPTP attack signal: rate ratio of the victim node (baseline ~1.0, attack shifts off it)
opp_scavetool export -f 'module =~ "*lidarRR.gptp*" and name =~ "gmRateRatio:vector"' \
  -o rr.csv results/Gptp_Drift_Deep-#0.vec

# FRER duplicate elimination: should be ~2000 dropped (1024 B each) at swC
opp_scavetool query -l results/Frer_Enabled-#0.vec | grep "swC.*merger.*dropped"

# delivery: packets received at the sink
grep -i "centralCompute.*packetReceived:count" results/Baseline-*.sca
```

## IDE alternative (GUI, slower)

Right-click `attacks.ini` → Run As → OMNeT++ Simulation → pick the config → `Qtenv`
to watch, or `Cmdenv` for speed. Use the terminal for batch runs.

## Common first-run errors

- **"The IDE was not started properly"** → launch the IDE with `omnetpp` from a
  terminal where you ran `source setenv`, not by double-clicking the app.
- **NED type not found (`TsnSwitch`, `ScenarioManager`)** → the `-n` path is wrong,
  or the IDE project reference to `inet-4.7.0` isn't set.
- **"cannot load library"** → INET was built in debug, not release. Use
  `opp_run_dbg` (or `opp_run`) instead of `opp_run_release`.
- **Running `omnetpp.ini` gives only the baseline** → run `attacks.ini` instead;
  the attack configs live there.
