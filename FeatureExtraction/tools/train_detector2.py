#!/usr/bin/env python3
"""
CARAZONE centralized detection baseline and feature ablation.

This answers success criterion SC-2: does the cross-zone residual add
detection power over within-zone timing statistics alone?

Three feature sets are compared on identical splits with identical models:

    within_zone   ctrl_* and zone_*        statistics computed inside one zone
    residual      sibling_residual_*       cross-zone comparison only
    combined      both

The within_zone arm is the control. Those features describe a single zone's
clock behaviour in isolation and need no knowledge of the network's structure.
The residual arm exists only because gPTP gives every zone a common reference.
If combined does not beat within_zone, the protocol-native claim is not
supported by this data, and that is a result worth reporting honestly.

SPLITTING: by run, never by window. The extraction stride is half the window
length, so consecutive windows share half their samples. A random window-level
split would place near-duplicate rows on both sides of the boundary and report
a score that cannot be reproduced on unseen runs.

Usage:
    python3 train_detector.py --features features.csv
    python3 train_detector.py --features features.csv --seeds 10 --out results/
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (classification_report, confusion_matrix, f1_score,
                             precision_recall_fscore_support)
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

CLASS_NAMES = {0: "benign", 1: "delay", 2: "drift", 3: "starvation"}

# Columns that must never reach a model. `target_zone` states which zone the
# attack targets, so it is the label in disguise; `zone` lets the model learn
# zone identity rather than timing behaviour; `run` and `config` are metadata.
LEAK_COLS = ("run", "config", "target_zone", "label", "zone", "window_start")


def feature_sets(df):
    cols = [c for c in df.columns if c not in LEAK_COLS]
    within = [c for c in cols if c.startswith(("ctrl_", "zone_"))]
    resid = [c for c in cols if c.startswith("sibling_residual_")]
    # sibling_n_* says how many references were available, not how far apart
    # they were. It is bookkeeping, not evidence; excluded from every arm.
    return {
        "within_zone": within,
        "residual": resid,
        "combined": within + resid,
    }


def split_by_run(df, seed, test_frac=0.3):
    """Hold out whole runs, keeping attack and benign runs in both halves."""
    rng = np.random.default_rng(seed)
    runs = df[["run", "config"]].drop_duplicates()

    train_runs, test_runs = [], []
    for cfg, g in runs.groupby("config"):
        r = g["run"].to_numpy()
        rng.shuffle(r)
        n_test = max(1, int(round(len(r) * test_frac)))
        # Always leave at least one run of this config in training.
        n_test = min(n_test, len(r) - 1) if len(r) > 1 else 0
        test_runs += list(r[:n_test])
        train_runs += list(r[n_test:])

    tr = df[df["run"].isin(train_runs)]
    te = df[df["run"].isin(test_runs)]
    return tr, te, sorted(train_runs), sorted(test_runs)


def models():
    return {
        "logreg": Pipeline([
            ("impute", SimpleImputer(strategy="median")),
            ("scale", StandardScaler()),
            ("clf", LogisticRegression(max_iter=2000, class_weight="balanced")),
        ]),
        "mlp": Pipeline([
            ("impute", SimpleImputer(strategy="median")),
            ("scale", StandardScaler()),
            ("clf", MLPClassifier(hidden_layer_sizes=(32, 16), max_iter=800,
                                  early_stopping=True, random_state=0)),
        ]),
        "rf": Pipeline([
            ("impute", SimpleImputer(strategy="median")),
            ("clf", RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                           random_state=0, n_jobs=-1)),
        ]),
    }


def threshold_baseline(tr, te, col="sibling_residual_mean_offset", q=0.995,
                       warmup=None):
    """Tuned threshold on |residual| — the non-ML detector to beat.

    Two thresholds are reported, because the difference between them is a
    result in its own right:

      max         the largest benign training value. Guarantees zero training
                  false positives, but is hostage to a single outlier.
      quantile    the q-th percentile of benign training values, which ignores
                  a small tail.

    If `max` collapses to zero recall while `quantile` does not, some benign
    window carries a residual as large as an attack. In this network that is
    the gPTP convergence transient at simulation start: before the servos
    lock, zones disagree by more than an attack moves them. Passing `warmup`
    excludes windows starting before that time and isolates the effect.
    """
    if col not in tr.columns:
        return None
    t, e = tr, te
    if warmup is not None:
        t = t[t["window_start"] >= warmup]
        e = e[e["window_start"] >= warmup]
    benign = t.loc[t["label"] == 0, col].abs()
    if benign.empty or e.empty:
        return None

    out = {}
    true = (e["label"] != 0).astype(int)
    for name, thr in (("max", float(benign.max())),
                      ("quantile", float(benign.quantile(q)))):
        pred = (e[col].abs() > thr).astype(int)
        p, r, f, _ = precision_recall_fscore_support(
            true, pred, average="binary", zero_division=0)
        out[name] = {"threshold": thr, "precision": float(p),
                     "recall": float(r), "f1": float(f)}
    return out


def detection_latency(te, y_pred, k=3):
    """Windows from attack onset to k consecutive positive predictions.

    Reported in windows; multiply by the stride to get seconds, or divide by
    (window / syncInterval) to express in synchronisation intervals.
    """
    d = te.copy()
    d["pred"] = y_pred
    lats = []
    for (run, zone), g in d.groupby(["run", "zone"], sort=False):
        g = g.sort_values("window_start")
        atk = g[g["label"] != 0]
        if atk.empty:
            continue
        onset = atk["window_start"].min()
        after = g[g["window_start"] >= onset]
        hits, fired = 0, None
        for _, row in after.iterrows():
            hits = hits + 1 if row["pred"] != 0 else 0
            if hits >= k:
                fired = row["window_start"]
                break
        if fired is not None:
            step = g["window_start"].diff().median()
            lats.append(int(round((fired - onset) / step)) if step else 0)
    return lats


def evaluate(df, seeds, k_consec, warmup=None):
    sets = feature_sets(df)
    rows = []
    per_class_store = {}

    for seed in range(seeds):
        tr, te, tr_runs, te_runs = split_by_run(df, seed)
        if te.empty or te["label"].nunique() < 2:
            continue

        y_tr, y_te = tr["label"].to_numpy(), te["label"].to_numpy()

        # Majority-class floor. Any arm that fails to beat this is reporting
        # the class imbalance, not detection.
        dummy = DummyClassifier(strategy="most_frequent").fit(
            np.zeros((len(y_tr), 1)), y_tr)
        rows.append({"seed": seed, "features": "—", "model": "majority",
                     "macro_f1": f1_score(y_te, dummy.predict(
                         np.zeros((len(y_te), 1))), average="macro",
                         zero_division=0)})

        thr = threshold_baseline(tr, te, warmup=warmup)
        if thr:
            for name, v in thr.items():
                rows.append({"seed": seed, "features": "residual",
                             "model": f"threshold-{name}", "macro_f1": np.nan,
                             "attack_f1": v["f1"], "attack_precision": v["precision"],
                             "attack_recall": v["recall"], "threshold": v["threshold"]})

        for fs_name, cols in sets.items():
            if not cols:
                continue
            X_tr, X_te = tr[cols].to_numpy(), te[cols].to_numpy()
            for m_name, pipe in models().items():
                pipe.fit(X_tr, y_tr)
                y_pred = pipe.predict(X_te)
                macro = f1_score(y_te, y_pred, average="macro", zero_division=0)
                p, r, f, _ = precision_recall_fscore_support(
                    y_te, y_pred, labels=[1], average="binary", pos_label=1,
                    zero_division=0)
                lats = detection_latency(te, y_pred, k=k_consec)
                rows.append({
                    "seed": seed, "features": fs_name, "model": m_name,
                    "macro_f1": macro, "attack_f1": float(f),
                    "attack_precision": float(p), "attack_recall": float(r),
                    "median_latency_windows": float(np.median(lats)) if lats else np.nan,
                    "n_test_runs": len(te_runs),
                })
                key = (fs_name, m_name)
                if key not in per_class_store:
                    per_class_store[key] = (y_te, y_pred)

    return pd.DataFrame(rows), per_class_store


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--features", default="features.csv")
    ap.add_argument("--seeds", type=int, default=5,
                    help="number of run-level resplits")
    ap.add_argument("--k-consec", type=int, default=3,
                    help="consecutive positive windows required to declare detection")
    ap.add_argument("--warmup", type=float, default=None,
                    help="ignore windows starting before this time, to exclude "
                         "the gPTP convergence transient")
    ap.add_argument("--out", default=None, help="directory for CSV/JSON artefacts")
    args = ap.parse_args()

    path = Path(args.features)
    if not path.exists():
        sys.exit(f"{path} not found. Run extract_features.py first.")
    df = pd.read_csv(path)

    print(f"Loaded {len(df)} windows, {df['run'].nunique()} runs, "
          f"{df['zone'].nunique()} zones.")
    print("Class balance:", {CLASS_NAMES.get(k, k): int(v)
                             for k, v in df["label"].value_counts().sort_index().items()})

    sets = feature_sets(df)
    for name, cols in sets.items():
        print(f"  {name:<12} {len(cols):>3} features")
    if not sets["residual"]:
        sys.exit("No sibling_residual_* columns found. Re-run extract_features.py.")

    col = "sibling_residual_mean_offset"
    if col in df:
        b = df[df["label"] == 0]
        early = b.loc[b["window_start"] < 1.0, col].abs()
        late = b.loc[b["window_start"] >= 1.0, col].abs()
        atk = df.loc[df["label"] != 0, col].abs()
        if len(early) and len(late):
            print(f"\nBenign residual, warm-up vs steady state (|{col}|):")
            print(f"  t < 1s   median {early.median():.3e}   max {early.max():.3e}")
            print(f"  t >= 1s  median {late.median():.3e}   max {late.max():.3e}")
            print(f"  attack   median {atk.median():.3e}   max {atk.max():.3e}")
            if early.max() > atk.median():
                print("  ! warm-up transient exceeds the median attack residual —")
                print("    no fixed threshold separates attack from all benign behaviour.")

    res, per_class = evaluate(df, args.seeds, args.k_consec, args.warmup)
    if res.empty:
        sys.exit("No usable splits — need at least 2 runs per configuration.")

    print(f"\n{'='*66}\nFeature ablation (mean over {args.seeds} run-level splits)\n{'='*66}")
    agg = (res[res["model"] != "threshold"]
           .groupby(["features", "model"])
           .agg(macro_f1=("macro_f1", "mean"),
                macro_f1_sd=("macro_f1", "std"),
                attack_recall=("attack_recall", "mean"),
                latency=("median_latency_windows", "mean"))
           .reset_index())
    print(f"{'features':<14}{'model':<12}{'macro-F1':>10}{'(sd)':>8}"
          f"{'atk recall':>12}{'latency(w)':>12}")
    for _, r in agg.iterrows():
        sd = "" if pd.isna(r.macro_f1_sd) else f"{r.macro_f1_sd:.3f}"
        lat = "" if pd.isna(r.latency) else f"{r.latency:.1f}"
        rec = "" if pd.isna(r.attack_recall) else f"{r.attack_recall:.3f}"
        print(f"{r.features:<14}{r.model:<12}{r.macro_f1:>10.3f}{sd:>8}"
              f"{rec:>12}{lat:>12}")

    thr = res[res["model"].astype(str).str.startswith("threshold")]
    if not thr.empty:
        print("\nThreshold baselines on |sibling_residual_mean_offset|:")
        for name, g in thr.groupby("model"):
            print(f"  {name:<20} attack-F1 {g['attack_f1'].mean():.3f}"
                  f"  (precision {g['attack_precision'].mean():.3f},"
                  f" recall {g['attack_recall'].mean():.3f})")
        mx = thr[thr["model"] == "threshold-max"]["attack_recall"].mean()
        qt = thr[thr["model"] == "threshold-quantile"]["attack_recall"].mean()
        if mx < 0.05 <= qt:
            print("  -> max-threshold collapses while the quantile does not:")
            print("     a benign window carries a residual as large as an attack.")
            print("     Re-run with --warmup 1.0 to test the convergence transient.")

    # The headline comparison: does the residual add anything?
    print(f"\n{'='*66}\nSC-2: does the cross-zone residual add detection power?\n{'='*66}")
    for m in ["logreg", "mlp", "rf"]:
        w = agg[(agg.features == "within_zone") & (agg.model == m)]["macro_f1"]
        c = agg[(agg.features == "combined") & (agg.model == m)]["macro_f1"]
        r = agg[(agg.features == "residual") & (agg.model == m)]["macro_f1"]
        if w.empty or c.empty:
            continue
        delta = float(c.iloc[0]) - float(w.iloc[0])
        verdict = "residual helps" if delta > 0.01 else (
            "no measurable gain" if delta > -0.01 else "residual hurts")
        print(f"  {m:<8} within {float(w.iloc[0]):.3f} -> combined "
              f"{float(c.iloc[0]):.3f}   delta {delta:+.3f}   "
              f"(residual alone {float(r.iloc[0]):.3f})   {verdict}")

    print(f"\n{'='*66}\nPer-class detail, combined features\n{'='*66}")
    for m in ["logreg", "mlp", "rf"]:
        if ("combined", m) not in per_class:
            continue
        y_te, y_pred = per_class[("combined", m)]
        labs = sorted(set(y_te) | set(y_pred))
        print(f"\n[{m}]")
        print(classification_report(
            y_te, y_pred, labels=labs,
            target_names=[CLASS_NAMES.get(l, str(l)) for l in labs],
            zero_division=0, digits=3))
        print("confusion matrix (rows=true, cols=pred):")
        print(confusion_matrix(y_te, y_pred, labels=labs))

    if args.out:
        out = Path(args.out); out.mkdir(parents=True, exist_ok=True)
        res.to_csv(out / "ablation_raw.csv", index=False)
        agg.to_csv(out / "ablation_summary.csv", index=False)
        (out / "run_config.json").write_text(json.dumps({
            "features_file": str(path), "seeds": args.seeds,
            "k_consec": args.k_consec,
            "feature_counts": {k: len(v) for k, v in sets.items()},
        }, indent=2))
        print(f"\nWrote artefacts to {out}/")


if __name__ == "__main__":
    main()