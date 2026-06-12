"""
Unit tests for the fleet-level detection outbreak view (build_outbreaks).

Run: python -m pytest test_outbreaks.py -q
(or: python test_outbreaks.py  for a dependency-free run)

The data/ fixtures can't exercise a spreading severe detection, so these build
synthetic current scenes + a detection_history baseline to cover: emergence,
the rising-footprint "Spreading" curve, severity gating (benign spread stays
silent), endemic suppression, and the empty-on-first-run contract.
"""
import json
import os
from datetime import datetime, timezone

import pandas as pd

from consolidate import build_outbreaks

CFG = json.load(open(os.path.join(os.path.dirname(__file__), "config.json")))

NOW = datetime(2026, 6, 12, tzinfo=timezone.utc)
DAY = 86400.0


def _scenes(rows):
    """rows: list of (DetectionType, DeviceName, TacticCategory)."""
    return pd.DataFrame(
        [{"DetectionType": dt, "DeviceName": dev, "TacticCategory": tac}
         for dt, dev, tac in rows])


def _dethist(rows):
    """rows: list of (DetectionType, days_ago, device_count)."""
    recs = []
    for i, (dt, days_ago, dc) in enumerate(rows):
        recs.append({
            "RunId": f"run{i}",
            "RunTimestamp": "2026-01-01T00:00:00Z",
            "RunTimestampEpoch": NOW.timestamp() - days_ago * DAY,
            "DetectionType": dt,
            "SceneCount": dc,
            "DeviceCount": dc,
        })
    return pd.DataFrame(recs)


def run(scene_rows, hist_rows):
    return build_outbreaks(_scenes(scene_rows), _dethist(hist_rows), NOW, CFG)


def _devs(dt, n, tactic):
    """n distinct devices firing DetectionType dt."""
    return [(dt, f"DEV{i}", tactic) for i in range(n)]


# --- Emerging: a severe detection new to the fleet ---------------------------

def test_emerging_severe_detection():
    # NTDS Database Theft (severity 2.5) never seen before; baseline table has
    # other detections so we're past the first-run gate.
    hist = [("Discovery Command", 10, 5), ("Discovery Command", 6, 5)]
    out = run(_devs("NTDS Database Theft", 2, "CredentialAccess"), hist)
    row = out[out["DetectionType"] == "NTDS Database Theft"].iloc[0]
    assert row["OutbreakStatus"] == "Emerging"
    assert row["RunsSeenPrior"] == 0
    assert row["Tactic"] == "CredentialAccess"


# --- Spreading: rising device footprint on a severe detection ----------------

def test_spreading_rising_footprint():
    # Cloud Token Theft (severity 2.0) climbing 1 -> 2 -> 3 over prior runs, now 6.
    hist = [
        ("Cloud Token Theft", 12, 1),
        ("Cloud Token Theft", 9, 2),
        ("Cloud Token Theft", 6, 3),
    ]
    out = run(_devs("Cloud Token Theft", 6, "CredentialAccess"), hist)
    row = out[out["DetectionType"] == "Cloud Token Theft"].iloc[0]
    assert row["OutbreakStatus"] == "Spreading"
    assert row["DeviceCountNow"] == 6
    assert row["DeviceCountPrev"] == 3
    assert row["NewDevices"] == 3
    assert row["SpreadSlope"] > 0


# --- Severity gate: a benign detection spreading stays silent -----------------

def test_benign_spread_is_gated_out():
    # A detection with no multiplier (severity 1.0) spreading hard is NOT an
    # outbreak — that's weather, not an incident.
    hist = [
        ("Shadow AI Tooling", 12, 2),   # multiplier 1.0 in config
        ("Shadow AI Tooling", 9, 4),
        ("Shadow AI Tooling", 6, 8),
    ]
    out = run(_devs("Shadow AI Tooling", 20, "Execution"), hist)
    assert out[out["DetectionType"] == "Shadow AI Tooling"].empty


# --- Endemic: severe but steady (not rising) is not flagged ------------------

def test_endemic_steady_severe_is_silent():
    # C2 Beaconing (severity 1.8) steady at ~10 devices for many runs, still ~10.
    hist = [("C2 Beaconing", d, 10) for d in (15, 12, 9, 6, 3)]
    out = run(_devs("C2 Beaconing", 10, "CommandAndControl"), hist)
    assert out[out["DetectionType"] == "C2 Beaconing"].empty


# --- Thin baseline: not enough prior runs to call a trend --------------------

def test_thin_baseline_no_spreading():
    # Only 2 prior runs (< min_runs_for_trend=3) and already seen (so not
    # Emerging either) -> nothing.
    hist = [("MCP Config Tampered", 9, 2), ("MCP Config Tampered", 6, 3)]
    out = run(_devs("MCP Config Tampered", 5, "DefenseEvasion"), hist)
    # seen in 2 prior runs > emergence_max_prior_runs(1) -> not Emerging;
    # < min_runs_for_trend(3) -> not Spreading.
    assert out[out["DetectionType"] == "MCP Config Tampered"].empty


# --- Empty detection_history (first run) yields nothing -----------------------

def test_empty_history_is_empty():
    out = build_outbreaks(_scenes(_devs("NTDS Database Theft", 3, "CredentialAccess")),
                          pd.DataFrame(), NOW, CFG)
    assert out.empty


# --- Sorted by OutbreakScore, severe-emerging on top -------------------------

def test_sorted_by_score():
    hist = [("Discovery Command", 8, 5)]
    scenes = (_devs("NTDS Database Theft", 4, "CredentialAccess")
              + _devs("Archive Staging", 1, "Collection"))
    out = run(scenes, hist)
    assert list(out["OutbreakScore"]) == sorted(out["OutbreakScore"], reverse=True)
    # NTDS (sev 2.5, 4 devices) should outrank a single-device Archive Staging.
    assert out.iloc[0]["DetectionType"] == "NTDS Database Theft"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:
            failed += 1
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    raise SystemExit(1 if failed else 0)
