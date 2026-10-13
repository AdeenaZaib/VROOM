"""
CARAZONE pipeline tests.

These are regression tests on the parts of the pipeline that are easy to
break silently and expensive to notice later: the windowing arithmetic, the
labelling rule, and the cross-zone residual. Each test states the property it
protects so that a failure explains itself. 

Run:  pytest -v
"""
import numpy as np
import pandas as pd
import pytest

import extract_features as ef
import train_detector as td


# ---------------------------------------------------------------- windowing
def test_window_count_is_exact():
    """A 10 s run, 2 s windows, 1 s stride gives 9 windows, not 8 or 10.

    Off-by-one here changes every row count in the report.
    """
    assert ef.window_starts(window=2.0, stride=1.0, sim_limit=10.0) == \
        [0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]


def test_window_starts_never_exceeds_sim_limit():
    for limit in (5.0, 10.0, 12.5):
        starts = ef.window_starts(2.0, 1.0, limit)
        assert all(s + 2.0 <= limit + 1e-9 for s in starts)


def test_window_starts_handles_window_longer_than_run():
    assert ef.window_starts(window=20.0, stride=1.0, sim_limit=10.0) == []


# ---------------------------------------------------------------- labelling
def test_benign_config_is_never_labelled_attack():
    """No window of a benign run may carry an attack label, at any time."""
    for w in (0.0, 4.0, 9.0):
        assert ef.label_for("Benign", None, 0, w, 4.0) == 0


def test_only_the_target_zone_is_labelled_attack():
    """The central anti-shortcut property.

    If every zone were labelled during an attack interval, the detector could
    score well by learning 'is it after t=4s', which is not detection.
    """
    assert ef.label_for("DelayAttack", 2, 2, 5.0, 4.0) != 0
    for innocent in (0, 1, 3):
        assert ef.label_for("DelayAttack", 2, innocent, 5.0, 4.0) == 0


def test_windows_before_attack_start_are_benign_even_in_target_zone():
    assert ef.label_for("DelayAttack", 2, 2, 3.0, 4.0) == 0
    assert ef.label_for("DelayAttack", 2, 2, 4.0, 4.0) != 0


# ---------------------------------------------------- window feature values
def test_drift_slope_recovers_a_known_ramp():
    """A synthetic linear ramp of 1e-6 s/s must come back as the slope."""
    t = np.linspace(0.0, 2.0, 201)
    o = 1e-6 * t
    f = ef.window_features(t, o, 0.0, 2.0)
    assert f["drift_slope"] == pytest.approx(1e-6, rel=1e-6)


def test_empty_window_yields_nan_not_zero():
    """A window with no samples must not look like a window of perfect zeros."""
    t = np.array([5.0, 6.0])
    o = np.array([1e-9, 1e-9])
    f = ef.window_features(t, o, 0.0, 2.0)
    assert np.isnan(f["mean_offset"])


# -------------------------------------------------------------- leakage rule
def test_feature_sets_exclude_every_identifier():
    """No identifier may reach a model. target_zone in particular IS the label."""
    df = pd.DataFrame({
        "run": ["r0"], "config": ["DelayAttack"], "target_zone": [2],
        "label": [1], "zone": [2], "window_start": [5.0],
        "ctrl_mean_offset": [1e-7],
        "sibling_residual_mean_offset": [5e-6],
    })
    fs = td.feature_sets(df)
    for name, cols in fs.items():
        for leak in td.LEAK_COLS:
            assert leak not in cols, f"{leak} leaked into feature set {name}"


def test_feature_sets_are_non_empty_and_disjoint():
    df = pd.DataFrame({
        "run": ["r0"], "config": ["Benign"], "target_zone": [np.nan],
        "label": [0], "zone": [0], "window_start": [0.0],
        "ctrl_mean_offset": [1e-9], "zone_std_mean_offset": [1e-9],
        "sibling_residual_mean_offset": [0.0],
        "sibling_residual_drift_slope": [0.0],
    })
    fs = td.feature_sets(df)
    assert fs["within_zone"] and fs["residual"]
    assert not set(fs["within_zone"]) & set(fs["residual"])
    assert set(fs["combined"]) == set(fs["within_zone"]) | set(fs["residual"])


def test_split_by_run_shares_no_run_between_train_and_test():
    """Windows overlap by 50%, so a window-level split leaks. Runs must not
    appear on both sides."""
    df = pd.DataFrame({
        "run": [f"r{i // 4}" for i in range(40)],
        "config": ["Benign" if (i // 4) < 5 else "DelayAttack" for i in range(40)],
        "label": [0 if (i // 4) < 5 else 1 for i in range(40)],
        "window_start": [float(i % 4) for i in range(40)],
        "sibling_residual_mean_offset": np.random.default_rng(0).normal(size=40),
    })
    tr, te, train_runs, test_runs = td.split_by_run(df, seed=0)
    assert not set(tr["run"]) & set(te["run"]), "a run appears in both halves"
    assert len(tr) + len(te) == len(df), "rows were lost or duplicated"
    assert test_runs, "empty test set"
    # both classes must survive the split, or the metric is undefined
    assert tr["label"].nunique() > 1 and te["label"].nunique() > 1


# ------------------------------------------------------- dataset invariants
# These run only when a features.csv is present, so the suite still passes on
# a clean checkout. They are the tests that would have caught a mislabelled
# dataset.
@pytest.fixture(scope="module")
def features():
    import os
    path = os.environ.get("CARAZONE_FEATURES")
    if not path or not os.path.exists(path):
        pytest.skip("features.csv not found; dataset invariants skipped")
    return pd.read_csv(path)


def test_dataset_attack_rows_are_confined_to_target_zone(features):
    bad = features[(features["label"] != 0) &
                   (features["zone"] != features["target_zone"])]
    assert bad.empty, f"{len(bad)} attack rows outside the target zone"


def test_dataset_residual_is_not_identically_zero(features):
    col = "sibling_residual_mean_offset"
    assert col in features.columns, "residual feature missing; extraction is stale"
    assert features[col].abs().sum() > 0, \
        "residual is identically zero: zones are not being compared"


def test_dataset_victim_rotates_across_runs(features):
    atk = features[features["label"] != 0]
    if atk.empty:
        pytest.skip("no attack rows")
    assert atk["target_zone"].nunique() > 1, \
        "only one zone is ever the victim; the detector can memorise it"