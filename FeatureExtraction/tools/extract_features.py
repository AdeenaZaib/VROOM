#!/usr/bin/env python3
"""
CARAZONE feature extraction layer.

Reads OMNeT++ .vec result files, turns each node's gPTP-corrected clock trace
into a time-offset series, and emits sliding-window features grouped per zone.

Offset is derived the way the INET docs describe for clock drift charts:
the clock's `timeChanged:vector` records the clock's own time at each change
event, so

    offset(t) = clock_time(t) - simulation_time(t)

is the node's error against the ideal timeline. Under gPTP the offset should
stay in a narrow band, punctuated by small corrections every syncInterval.
Each attack breaks that in a different way, which is what the features below
are built to separate.

Usage:
    python3 extract_features.py --results ../simulations/results \\
                                --out features.csv

Requires: pandas, numpy, and opp_scavetool on PATH (ships with OMNeT++).
"""

import argparse
import io
import os
import re
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd

# Attack taxonomy. Keep these ids stable — the FL code reads them.
CLASS_IDS = {
    "benign": 0,
    "delay": 1,
    "drift": 2,
    "starvation": 3,
}

CONFIG_TO_CLASS = {
    "Benign": "benign",
    "DelayAttack": "delay",
    "DriftAttack": "drift",
    "SyncStarvation": "starvation",
}

# When each scenario's attack begins, in seconds. Must match omnetpp.ini.
ATTACK_START = 4.0

# Configs whose attack is active for the entire run rather than from
# ATTACK_START. DriftAttack is here because INET 4.7 will not let
# ScenarioManager change driftRate at runtime (the parameter is not @mutable),
# so the victim's oscillator is manipulated from t=0 instead.
ALWAYS_ON_CONFIGS = {"DriftAttack"}

# Which nodes belong to which zone. zone[i] is the controller; ECUs are
# allocated ecusPerZone at a time.
ECUS_PER_ZONE = 2


def run_scavetool(vec_files, tmp_csv):
    """Export the clock vectors plus run metadata to a CSV OMNeT++ understands."""
    # No -f filter: opp_scavetool's match-expression syntax varies between
    # versions and a rejected expression aborts the export. Exporting
    # everything and filtering in pandas is slower and produces a larger
    # intermediate CSV, but it works on any version.
    cmd = [
        "opp_scavetool", "export",
        "-F", "CSV-R",
        "-o", str(tmp_csv),
    ] + [str(f) for f in vec_files]
    print("  $ " + " ".join(cmd[:6]) + f" ... ({len(vec_files)} files)")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit(
            "opp_scavetool failed:\n" + proc.stderr +
            "\nIs OMNeT++ 6.4's bin directory on your PATH?"
        )
    return tmp_csv


def load_export(csv_path):
    """Split the CSV-R export into a vector frame and a run-metadata frame."""
    df = pd.read_csv(csv_path, low_memory=False)

    vectors = df[df["type"] == "vector"].copy()
    # Keep only the clock traces; the export now contains every vector.
    vectors = vectors[
        vectors["name"].astype(str).str.startswith("timeChanged")
        & ~vectors["module"].astype(str).str.contains("underlyingClock")
    ].copy()
    if vectors.empty:
        sys.exit(
            "No timeChanged vectors found. Check that\n"
            "  **.clock.timeChanged.vector-recording = true\n"
            "is set in omnetpp.ini and that the runs actually completed."
        )

    meta = df[df["type"].isin(["runattr", "itervar"])]
    run_meta = {}
    for run, group in meta.groupby("run"):
        entry = {}
        for _, row in group.iterrows():
            entry[str(row["attrname"])] = str(row["attrvalue"])
        run_meta[run] = entry
    return vectors, run_meta


def parse_series(row):
    """CSV-R stores vectors as space-separated strings in two columns."""
    times = np.fromstring(str(row["vectime"]), sep=" ")
    values = np.fromstring(str(row["vecvalue"]), sep=" ")
    n = min(len(times), len(values))
    return times[:n], values[:n]


NODE_RE = re.compile(r"\.(?P<name>gm|cvc|backbone|zone\[\d+\]|ecu\[\d+\])\.")


def node_of(module_path):
    m = NODE_RE.search(module_path + ".")
    return m.group("name") if m else None


def zone_of(node):
    """Map a node name onto its zone index, or None if it isn't zonal."""
    if node is None:
        return None
    if node.startswith("zone["):
        return int(node[5:-1])
    if node.startswith("ecu["):
        return int(node[4:-1]) // ECUS_PER_ZONE
    return None


def window_features(times, offsets, w_start, w_end):
    """Features for one node over one window. Returns None if too sparse."""
    mask = (times >= w_start) & (times < w_end)
    t, o = times[mask], offsets[mask]

    # A window with no clock-change event at all is itself the signal for
    # sync starvation, so return a zero-event record rather than dropping it.
    if len(t) == 0:
        return {
            "n_events": 0.0,
            "mean_offset": np.nan,
            "std_offset": 0.0,
            "max_abs_offset": np.nan,
            "offset_range": 0.0,
            "mean_abs_step": 0.0,
            "max_abs_step": 0.0,
            "drift_slope": 0.0,
        }

    steps = np.abs(np.diff(o)) if len(o) > 1 else np.array([0.0])

    if len(t) > 1 and np.ptp(t) > 0:
        slope = float(np.polyfit(t - t[0], o, 1)[0])
    else:
        slope = 0.0

    return {
        "n_events": float(len(t)),
        "mean_offset": float(np.mean(o)),
        "std_offset": float(np.std(o)),
        "max_abs_offset": float(np.max(np.abs(o))),
        "offset_range": float(np.ptp(o)),
        "mean_abs_step": float(np.mean(steps)),
        "max_abs_step": float(np.max(steps)),
        "drift_slope": slope,
    }


def label_for(config, target_zone, zone, w_start):
    """Attacked if this is the victim zone and the attack is active."""
    cls = CONFIG_TO_CLASS.get(config, "benign")
    if cls == "benign":
        return CLASS_IDS["benign"]
    if target_zone is None or zone != target_zone:
        return CLASS_IDS["benign"]
    if config in ALWAYS_ON_CONFIGS or w_start >= ATTACK_START:
        return CLASS_IDS[cls]
    return CLASS_IDS["benign"]


def build(vectors, run_meta, window, stride, sim_limit):
    rows = []

    for run, group in vectors.groupby("run"):
        meta = run_meta.get(run, {})
        config = meta.get("configname", "Unknown")
        target_zone = meta.get("targetZone")
        target_zone = int(target_zone) if target_zone not in (None, "", "nan") else None

        # Collect every node's offset series for this run.
        series = {}
        for _, row in group.iterrows():
            node = node_of(str(row["module"]))
            if zone_of(node) is None:
                continue  # gm / cvc / backbone are not federated clients
            t, v = parse_series(row)
            if len(t) == 0:
                continue
            series[node] = (t, v - t)  # offset against ideal time

        if not series:
            continue

        by_zone = {}
        for node, data in series.items():
            by_zone.setdefault(zone_of(node), {})[node] = data

        for zone, nodes in sorted(by_zone.items()):
            w_start = 0.0
            while w_start + window <= sim_limit:
                w_end = w_start + window

                per_node = []
                ctrl = None
                for node, (t, o) in sorted(nodes.items()):
                    f = window_features(t, o, w_start, w_end)
                    per_node.append(f)
                    if node.startswith("zone["):
                        ctrl = f

                if ctrl is None:
                    w_start += stride
                    continue

                agg = {}
                for key in ctrl:
                    vals = [f[key] for f in per_node if not np.isnan(f[key])]
                    agg[f"zone_mean_{key}"] = float(np.mean(vals)) if vals else 0.0
                    agg[f"zone_std_{key}"] = float(np.std(vals)) if vals else 0.0

                record = {
                    "run": run,
                    "config": config,
                    "zone": zone,
                    "window_start": w_start,
                    "label": label_for(config, target_zone, zone, w_start),
                }
                # Controller-local features carry the "ctrl_" prefix; the
                # aggregate over the whole zone carries "zone_".
                record.update({f"ctrl_{k}": v for k, v in ctrl.items()})
                record.update(agg)
                rows.append(record)

                w_start += stride

    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="../simulations/results",
                    help="directory holding the .vec files")
    ap.add_argument("--out", default="features.csv")
    ap.add_argument("--window", type=float, default=0.25,
                    help="window length in seconds (default 2x syncInterval)")
    ap.add_argument("--stride", type=float, default=0.125)
    ap.add_argument("--sim-limit", type=float, default=10.0)
    args = ap.parse_args()

    results = Path(args.results)
    vec_files = sorted(results.glob("*.vec"))
    if not vec_files:
        sys.exit(f"No .vec files under {results.resolve()}")

    print(f"Found {len(vec_files)} result files.")
    tmp_csv = results / "_scave_export.csv"
    run_scavetool(vec_files, tmp_csv)

    vectors, run_meta = load_export(tmp_csv)
    print(f"Loaded {len(vectors)} vectors across {len(run_meta)} runs.")

    df = build(vectors, run_meta, args.window, args.stride, args.sim_limit)
    if df.empty:
        sys.exit("No windows produced — check the module name patterns.")

    df.to_csv(args.out, index=False)

    print(f"\nWrote {len(df)} windows to {args.out}")
    print("\nClass balance:")
    inv = {v: k for k, v in CLASS_IDS.items()}
    for label, count in df["label"].value_counts().sort_index().items():
        print(f"  {inv[label]:<12} {count:>6}")
    print("\nWindows per zone:")
    for zone, count in df["zone"].value_counts().sort_index().items():
        print(f"  zone {zone}: {count}")


if __name__ == "__main__":
    main()
