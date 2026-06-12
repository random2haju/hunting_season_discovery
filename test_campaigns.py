"""
Unit tests for the cross-layer campaign correlation (build_campaigns).

Run: python -m pytest test_campaigns.py -q
(or: python test_campaigns.py  for a dependency-free run)

A campaign is the John Snow overlay: a DetectionType that is BOTH an active
outbreak AND whose tactic threads >= min_chain_entities distinct slow-chain
entities. These build synthetic slow_chains + outbreaks frames to cover the
join, the entity-count threshold, and the both-layers-required contract.
"""
import json
import os

import pandas as pd

from consolidate import build_campaigns

CFG = json.load(open(os.path.join(os.path.dirname(__file__), "config.json")))


def _chains(rows):
    """rows: (EntityType, EntityName, StagesReached, ChainStatus, ChainConfidence)."""
    return pd.DataFrame(
        [{"EntityType": et, "EntityName": en, "StagesReached": sr,
          "ChainStatus": st, "ChainConfidence": cc} for et, en, sr, st, cc in rows])


def _outbreaks(rows):
    """rows: (DetectionType, Tactic, OutbreakStatus, OutbreakScore, DeviceCountNow)."""
    return pd.DataFrame(
        [{"DetectionType": dt, "Tactic": tac, "OutbreakStatus": st,
          "OutbreakScore": sc, "DeviceCountNow": dc} for dt, tac, st, sc, dc in rows])


# --- Positive: outbreak tactic threads >= 2 chains -> campaign ----------------

def test_campaign_fires_on_tactic_join():
    chains = _chains([
        ("Device", "DEV01", "CredentialAccess -> Collection", "Staging", 57.0),
        ("Device", "DEV02", "CredentialAccess -> Collection -> Exfiltration", "Complete", 80.0),
        ("User",   "alice", "Discovery -> Collection",        "Staging", 50.0),
    ])
    outs = _outbreaks([
        ("Cloud Token Theft", "CredentialAccess", "Spreading", 70.0, 6),
    ])
    camp = build_campaigns(chains, outs, CFG)
    assert len(camp) == 1
    row = camp.iloc[0]
    assert row["DetectionType"] == "Cloud Token Theft"
    assert row["LinkedEntityCount"] == 2          # DEV01 + DEV02 (alice lacks CredentialAccess)
    assert row["StagingChains"] == 1
    assert row["CompleteChains"] == 1
    assert row["CampaignScore"] > 0
    assert "common-source" in row["Rationale"]


# --- Negative: only one entity linked -> no campaign -------------------------

def test_single_entity_does_not_campaign():
    chains = _chains([
        ("Device", "DEV01", "CredentialAccess -> Collection", "Staging", 57.0),
    ])
    outs = _outbreaks([("NTDS Database Theft", "CredentialAccess", "Emerging", 74.0, 3)])
    assert build_campaigns(chains, outs, CFG).empty


# --- Negative: outbreak tactic matches no chain stage -----------------------

def test_no_tactic_overlap_no_campaign():
    chains = _chains([
        ("Device", "DEV01", "CredentialAccess -> Collection", "Staging", 57.0),
        ("Device", "DEV02", "CredentialAccess -> Collection", "Staging", 60.0),
    ])
    # Outbreak tactic is Exfiltration, which neither chain reached.
    outs = _outbreaks([("Exfiltration Tooling", "Exfiltration", "Spreading", 65.0, 5)])
    assert build_campaigns(chains, outs, CFG).empty


# --- Negative: either layer empty -> no campaign -----------------------------

def test_empty_layers():
    chains = _chains([
        ("Device", "DEV01", "CredentialAccess -> Collection", "Staging", 57.0),
        ("Device", "DEV02", "CredentialAccess -> Collection", "Staging", 60.0),
    ])
    outs = _outbreaks([("Cloud Token Theft", "CredentialAccess", "Spreading", 70.0, 6)])
    assert build_campaigns(pd.DataFrame(), outs, CFG).empty
    assert build_campaigns(chains, pd.DataFrame(), CFG).empty


# --- One entity with multiple chains counts once -----------------------------

def test_same_entity_multiple_chains_counts_once():
    chains = _chains([
        ("Device", "DEV01", "CredentialAccess -> Collection", "Staging", 57.0),
        ("Device", "DEV01", "CredentialAccess -> LateralMovement", "Staging", 62.0),
    ])
    outs = _outbreaks([("Cloud Token Theft", "CredentialAccess", "Spreading", 70.0, 6)])
    # Both chains are the same entity -> only 1 distinct entity -> below threshold.
    assert build_campaigns(chains, outs, CFG).empty


# --- Sorted by CampaignScore; stronger outbreak+chains rank higher -----------

def test_sorted_by_campaign_score():
    chains = _chains([
        ("Device", "DEV01", "CredentialAccess -> Collection -> Exfiltration", "Complete", 90.0),
        ("Device", "DEV02", "CredentialAccess -> Collection -> Exfiltration", "Complete", 88.0),
        ("Device", "DEV03", "Discovery -> Collection", "Staging", 50.0),
        ("User",   "bob",   "Discovery -> Collection", "Staging", 48.0),
    ])
    outs = _outbreaks([
        ("Cloud Token Theft", "CredentialAccess", "Spreading", 80.0, 8),  # strong
        ("Archive Staging",   "Collection",       "Spreading", 50.0, 4),  # weaker
    ])
    camp = build_campaigns(chains, outs, CFG)
    assert list(camp["CampaignScore"]) == sorted(camp["CampaignScore"], reverse=True)
    assert camp.iloc[0]["DetectionType"] == "Cloud Token Theft"


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
