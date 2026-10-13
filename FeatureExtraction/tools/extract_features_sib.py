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

Two feature families are emitted:

  within-zone   ctrl_*        the zone controller's own window statistics
                zone_mean_*   mean/std of those statistics across the
                zone_std_*    controller and its member ECUs

  cross-zone    sibling_residual_*   the controller's value minus the median
                                     of the other zones' controllers for the
                                     SAME window

The cross-zone family is the one a generic traffic-feature detector cannot
construct: it exists only because gPTP gives every zone a common reference,
so "what should this zone read right now" is answerable from the other zones.
Computing it requires all zones to be in scope simultaneously, which is why
the window is the outer loop and the zone the inner one.

Usage:
    python3 extract_features.py --results ../simulations/results \\
                                --out features.csv

Requires: pandas, numpy, and opp_scavetool on PATH (ships with OMNeT++).
"""

import argparse
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

# Fallback only. The attack start is read from run metadata when the run
# records it; this constant is used when it does not. Keeping a scenario
# change in omnetpp.ini in sync with a constant here by hand is exactly the
# kind of silent mislabelling that is worth engineering out.
DEFAULT_ATTACK_START = 4.0
ATTACK_START_KEYS = ("attackStart", "attackStartTime", "tAttack")

# Configs whose attack is active for the entire run rather than from the
# attack start time. DriftAttack is here because the INET clock module does
# not declare driftRate @mutable, so ScenarioManager cannot change it at
# runtime and the victim's oscillator is manipulated from t=0 instead.
# NOTE: applied from t=0 this is a constant frequency offset, which the gPTP
# servo is designed to compensate. It is therefore not a runtime attack, and
# is retained as a documented framework limitation rather than a detection
# target. See report Section 7.6.
ALWAYS_ON_CONFIGS = {"DriftAttack"}

# Which nodes belong to which zone. zone[i] is the controller; ECUs are
# allocated ecusPerZone at a time.
ECUS_PER_ZONE = 2

# Base features for which a cross-zone residual is also emitted.
# mean_offset catches phase divergence; drift_slope catches rate divergence.
# A delay attack shows mainly in the first, a rate manipulation in the second.
RESIDUAL_FEATURES = ("mean_offset", "drift_slope")

FEATURE_KEYS = (
    "n_events",
    "mean_offset",
    "std_offset",
    "max_abs_offset",
    "offset_range",
    "mean_abs_step",
    "max_abs_step",
    "drift_slope",
)


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
    # underlyingClock is the free-running oscillator — we want the
    # gPTP-corrected clock, which is what the detector would actually see.
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


def meta_int(meta, key):
    """Read an int run attribute, tolerating absence and OMNeT++'s 'nan'."""
    raw = meta.get(key)
    if raw in (None, "", "nan", "None"):
        return None
    try:
        return int(float(raw))
    except (TypeError, ValueError):
        return None


def attack_start_of(meta):
    """Attack start from run metadata, falling back to the module constant."""
    for key in ATTACK_START_KEYS:
        raw = meta.get(key)
        if raw not in (None, "", "nan", "None"):
            try:
                return float(raw), True
            except (TypeError, ValueError):
                pass
    return DEFAULT_ATTACK_START, False


def window_features(times, offsets, w_start, w_end):
    """Features for one node over one window. Returns None if too sparse."""
    mask = (times >= w_start) & (times < w_end)
    t, o = times[mask], offsets[mask]

    # A window with no clock-change event at all is itself the signal for
    # sync starvation, so return a zero-event record rather than dropping it.
    # mean/max are NaN here by design: there is no offset to report. Training
    # code must handle these rows explicitly — dropping them would delete the
    # starvation signature.
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


def label_for(config, target_zone, zone, w_start, attack_start):
    """Attacked if this is the victim zone and the attack is active."""
    cls = CONFIG_TO_CLASS.get(config, "benign")
    if cls == "benign":
        return CLASS_IDS["benign"]
    if target_zone is None or zone != target_zone:
        return CLASS_IDS["benign"]
    if config in ALWAYS_ON_CONFIGS or w_start >= attack_start:
        return CLASS_IDS[cls]
    return CLASS_IDS["benign"]


def window_starts(window, stride, sim_limit):
    """Window start times as exact multiples of the stride.

    Accumulating `w_start += stride` lets float error drift over ~80
    iterations, which makes the window grid depend on arithmetic order and
    breaks exact reproducibility between runs. Indexing avoids that.
    """
    n = int(np.floor((sim_limit - window) / stride + 1e-9)) + 1
    return [i * stride for i in range(max(n, 0))]


def build(vectors, run_meta, window, stride, sim_limit, verbose=True):
    rows = []
    warned_meta = False

    for run, group in vectors.groupby("run"):
        meta = run_meta.get(run, {})
        config = meta.get("configname", "Unknown")
        target_zone = meta_int(meta, "targetZone")
        attack_start, from_meta = attack_start_of(meta)

        is_attack_cfg = CONFIG_TO_CLASS.get(config, "benign") != "benign"

        # A run configured as an attack but with no recorded victim would be
        # silently labelled all-benign, which is far worse than failing loudly.
        if is_attack_cfg and target_zone is None:
            sys.exit(
                f"Run {run} uses config '{config}' but records no targetZone.\n"
                "Every window in this run would be labelled benign.\n"
                "Add targetZone to omnetpp.ini as a run attribute or itervar,\n"
                "e.g.  **.targetZone = ${targetZone=0,1,2,3}"
            )
        if is_attack_cfg and not from_meta and not warned_meta:
            print(f"  ! attackStart not in run metadata; using the module "
                  f"default of {DEFAULT_ATTACK_START}s. Verify against omnetpp.ini.")
            warned_meta = True

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

        # --- window is the OUTER loop ---------------------------------
        # Every zone must be in scope at the same instant for the
        # cross-zone residual to exist. Iterating zones first, as an
        # earlier version did, makes that impossible.
        for w_start in window_starts(window, stride, sim_limit):
            w_end = w_start + window

            per_zone_nodes = {}   # zone -> {node: features}
            ctrl_feats = {}       # zone -> controller's features

            for zone, nodes in sorted(by_zone.items()):
                feats = {}
                for node, (t, o) in sorted(nodes.items()):
                    f = window_features(t, o, w_start, w_end)
                    feats[node] = f
                    if node.startswith("zone["):
                        ctrl_feats[zone] = f
                per_zone_nodes[zone] = feats

            for zone in sorted(per_zone_nodes):
                ctrl = ctrl_feats.get(zone)
                if ctrl is None:
                    continue  # zone has no controller trace in this run

                per_node = list(per_zone_nodes[zone].values())

                # Within-zone aggregate over the controller and its ECUs.
                agg = {}
                for key in FEATURE_KEYS:
                    vals = [f[key] for f in per_node if not np.isnan(f[key])]
                    agg[f"zone_mean_{key}"] = float(np.mean(vals)) if vals else 0.0
                    agg[f"zone_std_{key}"] = float(np.std(vals)) if vals else 0.0

                # Cross-zone residual against the other zones' controllers.
                # The median, not the mean, so a single compromised sibling
                # cannot drag the reference with it.
                resid = {}
                for key in RESIDUAL_FEATURES:
                    mine = ctrl[key]
                    others = [
                        ctrl_feats[z][key] for z in ctrl_feats
                        if z != zone and not np.isnan(ctrl_feats[z][key])
                    ]
                    if others and not np.isnan(mine):
                        resid[f"sibling_residual_{key}"] = float(mine - np.median(others))
                        resid[f"sibling_n_{key}"] = float(len(others))
                    else:
                        # No reference available (single-zone run, or this
                        # window had no events anywhere). 0.0 means "no
                        # evidence of divergence", which is the right
                        # default: it is what a healthy zone would produce.
                        resid[f"sibling_residual_{key}"] = 0.0
                        resid[f"sibling_n_{key}"] = float(len(others))

                record = {
                    "run": run,
                    "config": config,
                    "zone": zone,
                    "target_zone": target_zone if target_zone is not None else -1,
                    "window_start": w_start,
                    "label": label_for(config, target_zone, zone, w_start, attack_start),
                }
                # Controller-local features carry the "ctrl_" prefix; the
                # aggregate over the whole zone carries "zone_"; the
                # cross-zone comparison carries "sibling_".
                record.update({f"ctrl_{k}": v for k, v in ctrl.items()})
                record.update(agg)
                record.update(resid)
                rows.append(record)

    return pd.DataFrame(rows)


def sanity_checks(df):
    """Guards against the failure modes that would silently invalidate results."""
    problems, notes = [], []

    # 1. Within a single run, attack labels must be confined to one zone.
    #    Across runs the victim rotates, so an aggregate check would be wrong.
    for run, g in df.groupby("run"):
        atk = g[g["label"] != 0]
        if len(atk) and atk["zone"].nunique() > 1:
            problems.append(
                f"run {run}: attack labels span {atk['zone'].nunique()} zones "
                "(expected 1)"
            )
        if len(atk):
            tz = g["target_zone"].iloc[0]
            if tz >= 0 and set(atk["zone"].unique()) != {tz}:
                problems.append(
                    f"run {run}: labelled zone(s) {sorted(atk['zone'].unique())} "
                    f"!= targetZone {tz}"
                )

    # 2. Every zone should appear as victim in at least one run, or the
    #    classifier can learn zone identity instead of the timing signature.
    victims = set(df.loc[df["label"] != 0, "zone"].unique())
    allz = set(df["zone"].unique())
    if victims and victims != allz:
        notes.append(
            f"zones never attacked: {sorted(allz - victims)} — zone identity "
            "partially predicts the label; consider rotating the victim"
        )

    # 3. Equal window counts per zone.
    counts = df["zone"].value_counts()
    if counts.nunique() != 1:
        notes.append(f"uneven windows per zone: {counts.to_dict()}")

    # 4. NaNs reach the CSV by design for zero-event windows.
    nan_cols = {c: int(df[c].isna().sum()) for c in df.columns if df[c].isna().any()}
    if nan_cols:
        zero_ev = int((df["ctrl_n_events"] == 0).sum())
        notes.append(
            f"NaNs present in {len(nan_cols)} column(s); {zero_ev} windows have "
            "ctrl_n_events=0. These are the sync-starvation signature — impute "
            "at training time, do not drop the rows"
        )

    # 5. The residual must actually vary, or it carries no information.
    for key in RESIDUAL_FEATURES:
        col = f"sibling_residual_{key}"
        if col in df and float(df[col].abs().max()) == 0.0:
            problems.append(
                f"{col} is identically zero — the cross-zone reference is not "
                "being formed (check that >1 zone has a controller trace)"
            )

    return problems, notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="../simulations/results",
                    help="directory holding the .vec files")
    ap.add_argument("--out", default="features.csv")
    ap.add_argument("--window", type=float, default=0.25,
                    help="window length in seconds (default 2x syncInterval)")
    ap.add_argument("--stride", type=float, default=0.125)
    ap.add_argument("--sim-limit", type=float, default=10.0)
    ap.add_argument("--strict", action="store_true",
                    help="exit non-zero if any sanity check fails")
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
    print(f"Feature columns: {len([c for c in df.columns if c.startswith(('ctrl_','zone_','sibling_'))])}")

    print("\nClass balance:")
    inv = {v: k for k, v in CLASS_IDS.items()}
    for label, count in df["label"].value_counts().sort_index().items():
        print(f"  {inv[label]:<12} {count:>6}")

    print("\nWindows per zone:")
    for zone, count in df["zone"].value_counts().sort_index().items():
        atk = int(((df["zone"] == zone) & (df["label"] != 0)).sum())
        print(f"  zone {zone}: {count:>5}   ({atk} attack)")

    print("\nRuns per config:")
    for cfg, g in df.groupby("config"):
        print(f"  {cfg:<16} {g['run'].nunique():>3} run(s)")

    # The residual is the feature the protocol-native claim rests on, so its
    # separation is worth seeing on every extraction rather than only at
    # training time.
    print("\nCross-zone residual, benign vs attack (|value|):")
    for key in RESIDUAL_FEATURES:
        col = f"sibling_residual_{key}"
        if col not in df:
            continue
        b = df.loc[df["label"] == 0, col].abs()
        a = df.loc[df["label"] != 0, col].abs()
        if len(a) and len(b):
            ratio = (a.median() / b.median()) if b.median() else float("inf")
            print(f"  {col}")
            print(f"    benign median {b.median():.3e}   attack median {a.median():.3e}"
                  f"   ratio {ratio:.1f}x")

    problems, notes = sanity_checks(df)
    if notes:
        print("\nNotes:")
        for n in notes:
            print(f"  - {n}")
    if problems:
        print("\nFAILED CHECKS:")
        for p in problems:
            print(f"  ! {p}")
        if args.strict:
            sys.exit(1)
    else:
        print("\nAll sanity checks passed.")


if __name__ == "__main__":
    main()