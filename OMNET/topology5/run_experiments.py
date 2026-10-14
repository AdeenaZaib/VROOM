#!/usr/bin/env python3
"""
run_experiments.py -- launch CARAZONE baseline/attack runs and tag their output.

Each run becomes one labelled episode. The script invokes the simulation for a
list of configs defined in attacks.ini, then writes a manifest.json mapping each
results/ file to its scenario / victim / attack-window metadata, so your existing
feature-extraction script can label rows automatically instead of by hand.

It does NOT replace your feature extractor -- it drives the runs and records what
each one is, which is the part that's painful to track across dozens of runs.

Usage:
    python3 run_experiments.py --list
    python3 run_experiments.py Baseline Gptp_Drift_Deep Frer_Enabled
    python3 run_experiments.py --all
    python3 run_experiments.py Baseline --run-cmd "opp_run_release ..."   # custom launcher

Adjust RUN_CMD_TEMPLATE below to match how you launch INET sims locally
(IDE "Run" uses the same opp_run under the hood; `inet` from opp_env works too).
"""

import argparse
import json
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESULTS_DIR = HERE / "results"

# ---------------------------------------------------------------------------
# How to launch a run. {config} is substituted. Everything else is yours to set.
#   -u Cmdenv  : no GUI, fastest for batch
#   -c {config}: the [Config ...] section from attacks.ini
#   -n <paths> : NED folders -- point at your project src + the INET src
# Edit the INET path to your local install, or override with --run-cmd.
# ---------------------------------------------------------------------------
INET_ROOT = "~/omnetpp-6.4.0/samples/inet4.7"   # <-- set to your INET location
RUN_CMD_TEMPLATE = (
    f"opp_run_release -u Cmdenv -c {{config}} "
    f"-n .:{INET_ROOT}/src "
    f"-l {INET_ROOT}/src/INET "
    f"attacks.ini"
)

# ---------------------------------------------------------------------------
# Scenario metadata. Keep this in sync with attacks.ini. The attack_window is
# [start, end] in seconds; null start means "attack is active for the whole run"
# (constant drift), which your extractor should treat as all-attack.
# ---------------------------------------------------------------------------
SCENARIOS = {
    "Baseline":               {"label": "benign",     "attack": None,      "victim": None,          "window": None},
    "Gptp_Drift_Shallow":     {"label": "gptp_drift", "attack": "drift",   "victim": "gnssReceiver","window": None},
    "Gptp_Drift_Deep":        {"label": "gptp_drift", "attack": "drift",   "victim": "lidarRR",     "window": None},
    "Gptp_Drift_Sweep":       {"label": "gptp_drift", "attack": "drift",   "victim": "lidarRR",     "window": None},
    "Frer_Enabled":           {"label": "benign",     "attack": None,      "victim": None,          "window": None},
    "Frer_DuplicateFlood":    {"label": "frer_flood", "attack": "flood",   "victim": "radarFL",     "window": None},
    "Frer_Plus_GptpDrift":    {"label": "frer+gptp",  "attack": "combined","victim": "swFR",        "window": None},
    "Gptp_Drift_Timed":       {"label": "gptp_drift", "attack": "drift",   "victim": "lidarRR",     "window": [1.0, 2.0]},
    "Frer_PathCut":           {"label": "frer_cut",   "attack": "pathcut", "victim": "swFR",        "window": [1.0, 1.5]},
}


def run_one(config: str, run_cmd_template: str) -> dict:
    cmd = run_cmd_template.format(config=config)
    print(f"\n=== {config} ===\n$ {cmd}")
    started = datetime.now(timezone.utc).isoformat()
    proc = subprocess.run(shlex.split(cmd), cwd=HERE)
    ok = proc.returncode == 0
    if not ok:
        print(f"  !! {config} exited with code {proc.returncode}", file=sys.stderr)
    meta = dict(SCENARIOS.get(config, {"label": "unknown", "attack": None, "victim": None, "window": None}))
    meta.update({"config": config, "started_utc": started, "ok": ok, "cmd": cmd})
    return meta


def main():
    ap = argparse.ArgumentParser(description="Run and tag CARAZONE attack experiments.")
    ap.add_argument("configs", nargs="*", help="config names from attacks.ini")
    ap.add_argument("--all", action="store_true", help="run every known scenario")
    ap.add_argument("--list", action="store_true", help="list known scenarios and exit")
    ap.add_argument("--run-cmd", default=RUN_CMD_TEMPLATE, help="override the launch command template")
    args = ap.parse_args()

    if args.list:
        for name, m in SCENARIOS.items():
            print(f"{name:24s} label={m['label']:11s} victim={m['victim']}")
        return

    configs = list(SCENARIOS) if args.all else args.configs
    if not configs:
        ap.error("give one or more config names, or --all (see --list)")

    RESULTS_DIR.mkdir(exist_ok=True)
    manifest = []
    for cfg in configs:
        if cfg not in SCENARIOS:
            print(f"  (warning) {cfg} not in SCENARIOS -- running with minimal metadata")
        manifest.append(run_one(cfg, args.run_cmd))

    manifest_path = RESULTS_DIR / "manifest.json"
    existing = []
    if manifest_path.exists():
        existing = json.loads(manifest_path.read_text())
    (manifest_path).write_text(json.dumps(existing + manifest, indent=2))
    print(f"\nWrote {len(manifest)} run record(s) -> {manifest_path}")
    print("Feed manifest.json to your feature extractor to label rows by scenario/victim/window.")


if __name__ == "__main__":
    main()
