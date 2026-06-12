"""
Unit tests for the cross-run slow kill chain detector (Recommendation A).

Run: python -m pytest test_slow_chains.py -q
(or: python test_slow_chains.py  for a dependency-free run)

The data/ fixtures contain no Collection/Exfiltration tactics, so a genuine
espionage chain can't be exercised empirically — these build synthetic history +
season frames to cover the behaviours that matter: cross-run assembly, the
forward-ordering and multi-run requirements, the 2-of-3 staging alarm, and the
shared-thread confidence boost.
"""
import json
import os
from datetime import datetime, timezone, timedelta

import pandas as pd

from consolidate import build_slow_chains

CFG = json.load(open(os.path.join(os.path.dirname(__file__), "config.json")))

NOW = datetime(2026, 6, 12, tzinfo=timezone.utc)
DAY = 86400.0


def _hist(rows):
    """rows: list of dicts with days_ago, entity, tactics, pairing (+ optional type)."""
    recs = []
    for i, r in enumerate(rows):
        ep = NOW.timestamp() - r["days_ago"] * DAY
        recs.append({
            "EntityType": r.get("type", "Device"),
            "EntityName": r["entity"],
            "RunId": r.get("run_id", f"run{i}"),
            "RunTimestampEpoch": ep,
            "TacticSet": r["tactics"],
            "PairingSet": r.get("pairing", ""),
        })
    return pd.DataFrame(recs)


def _seasons(rows, etype, ecol):
    """Current-run season frame. rows: dicts with name, tactics, pairing, flags."""
    recs = []
    for r in rows:
        recs.append({
            ecol: r["name"],
            "TacticSet": r.get("tactics", ""),
            "PairingSet": r.get("pairing", ""),
            "IsSuppressed": r.get("suppressed", False),
            "EligibleForPriority": r.get("eligible", True),
        })
    return pd.DataFrame(recs)


def _empty_seasons(ecol):
    return pd.DataFrame(columns=[ecol, "TacticSet", "PairingSet",
                                 "IsSuppressed", "EligibleForPriority"])


def run(history, dev_rows=None, usr_rows=None):
    dev = _seasons(dev_rows, "Device", "DeviceName") if dev_rows else _empty_seasons("DeviceName")
    usr = _seasons(usr_rows, "User", "AccountName") if usr_rows else _empty_seasons("AccountName")
    return build_slow_chains(dev, usr, history, NOW, CFG)


# --- Positive: a true Complete chain assembled across runs -------------------

def test_complete_chain_across_runs_with_shared_thread():
    hist = _hist([
        {"days_ago": 40, "entity": "DEV01", "tactics": "CredentialAccess", "pairing": "alice"},
        {"days_ago": 20, "entity": "DEV01", "tactics": "Collection",       "pairing": "alice"},
    ])
    # Exfiltration lands on the current run -> chain completes now.
    out = run(hist, dev_rows=[{"name": "DEV01", "tactics": "Exfiltration", "pairing": "alice"}])
    assert len(out) >= 1
    row = out[out["ChainName"] == "Credential->Collection->Exfil"].iloc[0]
    assert row["ChainStatus"] == "Complete"
    assert row["RunsSpanned"] == 3
    assert row["SharedThread"] == "alice"          # same account threads every run
    assert row["MissingStage"] == ""
    assert row["ChainConfidence"] >= 60


# --- Positive: the 2-of-3 staging alarm (collected, not yet exfiltrated) -----

def test_staging_alarm_before_exfil():
    hist = _hist([
        {"days_ago": 30, "entity": "DEV02", "tactics": "CredentialAccess", "pairing": "bob"},
        {"days_ago": 10, "entity": "DEV02", "tactics": "Collection",       "pairing": "bob"},
    ])
    out = run(hist, dev_rows=[{"name": "DEV02", "tactics": "Discovery", "pairing": "bob"}])
    row = out[out["ChainName"] == "Credential->Collection->Exfil"].iloc[0]
    assert row["ChainStatus"] == "Staging"
    assert row["MissingStage"] == "Exfiltration"   # the actionable gap
    assert row["RunsSpanned"] == 2


# --- Negative: within-run co-occurrence is NOT a slow chain ------------------

def test_within_run_cooccurrence_is_not_a_chain():
    # Every run independently has Cred+Collection+Exfil together. That's the
    # episode layer's job; the slow-chain detector must stay silent.
    hist = _hist([
        {"days_ago": 20, "entity": "DEV03", "tactics": "CredentialAccess, Collection, Exfiltration", "pairing": "carol"},
    ])
    out = run(hist, dev_rows=[{"name": "DEV03",
                               "tactics": "CredentialAccess, Collection, Exfiltration",
                               "pairing": "carol"}])
    assert out[out["EntityName"] == "DEV03"].empty


# --- Negative: reverse order does not complete -------------------------------

def test_reverse_order_does_not_complete():
    # Exfiltration first, credential access later -> no forward chain.
    hist = _hist([
        {"days_ago": 30, "entity": "DEV04", "tactics": "Exfiltration",     "pairing": "dan"},
        {"days_ago": 10, "entity": "DEV04", "tactics": "CredentialAccess", "pairing": "dan"},
    ])
    out = run(hist, dev_rows=[{"name": "DEV04", "tactics": "Collection", "pairing": "dan"}])
    # Cred(10d ago) -> Collection(now) reaches depth 2 = Staging, but never Complete,
    # and Exfiltration predates the chain so it is not counted as the final stage.
    matched = out[out["ChainName"] == "Credential->Collection->Exfil"]
    assert matched.empty or (matched.iloc[0]["ChainStatus"] == "Staging")


# --- Negative: suppressed / ineligible entities are excluded -----------------

def test_suppressed_entity_excluded():
    hist = _hist([
        {"days_ago": 40, "entity": "DEV05", "tactics": "CredentialAccess", "pairing": "eve"},
        {"days_ago": 20, "entity": "DEV05", "tactics": "Collection",       "pairing": "eve"},
    ])
    out = run(hist, dev_rows=[{"name": "DEV05", "tactics": "Exfiltration",
                               "pairing": "eve", "suppressed": True}])
    assert out[out["EntityName"] == "DEV05"].empty


# --- Shared-thread absence lowers confidence (no persistent counterpart) -----

def test_no_shared_thread_has_lower_confidence():
    hist = _hist([
        {"days_ago": 40, "entity": "DEV06", "tactics": "CredentialAccess", "pairing": "u1"},
        {"days_ago": 20, "entity": "DEV06", "tactics": "Collection",       "pairing": "u2"},
    ])
    out = run(hist, dev_rows=[{"name": "DEV06", "tactics": "Exfiltration", "pairing": "u3"}])
    row = out[out["ChainName"] == "Credential->Collection->Exfil"].iloc[0]
    assert row["ChainStatus"] == "Complete"
    assert row["SharedThread"] == ""               # no counterpart common to all runs
    # 45 (complete) + 0 (no thread) + 9 (3 runs) + severity — well under a threaded chain.
    assert row["ChainConfidence"] < 80


# --- Empty history (first run) yields nothing --------------------------------

def test_empty_history_is_empty():
    out = run(pd.DataFrame(), dev_rows=[{"name": "DEV07",
              "tactics": "CredentialAccess, Collection, Exfiltration", "pairing": "x"}])
    assert out.empty


# --- Window: stages older than window_days are ignored -----------------------

def test_stage_outside_window_is_ignored():
    hist = _hist([
        {"days_ago": 200, "entity": "DEV08", "tactics": "CredentialAccess", "pairing": "z"},  # outside 90d
        {"days_ago": 10,  "entity": "DEV08", "tactics": "Collection",       "pairing": "z"},
    ])
    out = run(hist, dev_rows=[{"name": "DEV08", "tactics": "Exfiltration", "pairing": "z"}])
    # CredentialAccess fell outside the window, so only Collection(10d)+Exfil(now)
    # remain -> depth 2 on a chain whose first stage is Collection? No: the template
    # starts at CredentialAccess, which is gone, so the chain cannot start. Expect
    # no Credential->Collection->Exfil match.
    assert out[out["ChainName"] == "Credential->Collection->Exfil"].empty


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
