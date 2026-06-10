"""
Unit tests for the triage state module (triage.py).

Run: python -m pytest test_triage.py -q

Covers the store rules (note required on verdicts, latest-row-wins, case-
insensitive entity keys) and the derived-state rules (Benign → Reopened on
newer activity, new-activity badge for Investigating/Escalated, strict-greater
timestamp comparison for the 72h window overlap, stale-Investigating flag).
"""
import time

import pandas as pd
import pytest

import triage


@pytest.fixture
def store(tmp_path):
    return str(tmp_path / "triage.db")


# --- append_triage validation ------------------------------------------------

def test_verdict_without_note_rejected(store):
    for status in ("Benign", "Escalated"):
        with pytest.raises(ValueError):
            triage.append_triage(store, "Device", "HOST-1", status)


def test_investigating_without_note_ok(store):
    rec = triage.append_triage(store, "Device", "HOST-1", "Investigating")
    assert rec["Status"] == "Investigating"
    assert rec["TriagedBy"]  # auto-captured from OS user


def test_invalid_status_and_type_rejected(store):
    with pytest.raises(ValueError):
        triage.append_triage(store, "Device", "HOST-1", "Reopened")  # derived, not settable
    with pytest.raises(ValueError):
        triage.append_triage(store, "Server", "HOST-1", "Investigating")
    with pytest.raises(ValueError):
        triage.append_triage(store, "Device", "   ", "Investigating")


# --- store semantics -----------------------------------------------------------

def test_latest_row_wins_and_key_is_case_insensitive(store):
    triage.append_triage(store, "Device", "HOST-1", "Investigating")
    triage.append_triage(store, "Device", "host-1", "Benign", note="reviewed")
    states = triage.load_current_states(store)
    assert len(states) == 1
    rec = states[("Device", "host-1")]
    assert rec["Status"] == "Benign"
    assert rec["EntityName"] == "host-1"  # most recent spelling kept for display


def test_log_is_newest_first_and_full(store):
    triage.append_triage(store, "User", "CONTOSO\\Alice", "Investigating")
    triage.append_triage(store, "User", "contoso\\alice", "Escalated", note="IR-123")
    log = triage.load_log(store, "User", "CONTOSO\\ALICE")
    assert [e["Status"] for e in log] == ["Escalated", "Investigating"]


def test_missing_store_loads_empty(tmp_path):
    missing = str(tmp_path / "nope" / "triage.db")
    assert triage.load_current_states(missing) == {}
    assert triage.load_log(missing, "Device", "X") == []


# --- effective_status: reopen rule ---------------------------------------------

def _benign(store, last_seen):
    triage.append_triage(store, "Device", "H", "Benign", note="ok", last_seen=last_seen)
    return triage.load_current_states(store)[("Device", "h")]


def test_untriaged_and_reset_are_new(store):
    assert triage.effective_status(None, "2026-06-09")["status"] == "New"
    triage.append_triage(store, "Device", "H", "Benign", note="ok", last_seen="2026-06-08")
    triage.append_triage(store, "Device", "H", "New")
    rec = triage.load_current_states(store)[("Device", "h")]
    assert triage.effective_status(rec, "2026-06-09")["status"] == "New"


def test_benign_reopens_only_on_strictly_newer_activity(store):
    rec = _benign(store, "2026-06-08T10:00:00")
    # equal timestamp = the 72h-window overlap re-exporting the same events
    same = triage.effective_status(rec, "2026-06-08T10:00:00")
    assert same["status"] == "Benign" and not same["has_new_activity"]
    newer = triage.effective_status(rec, "2026-06-08T10:00:01")
    assert newer["status"] == "Reopened" and newer["has_new_activity"]
    older = triage.effective_status(rec, "2026-06-07T00:00:00")
    assert older["status"] == "Benign"
    # no current activity at all → verdict stands
    assert triage.effective_status(rec, None)["status"] == "Benign"


def test_missing_snapshot_is_conservative(store):
    rec = _benign(store, None)
    assert triage.effective_status(rec, "2026-06-09")["status"] == "Reopened"


def test_investigating_and_escalated_keep_state_but_get_badge(store):
    triage.append_triage(store, "Device", "H", "Investigating", last_seen="2026-06-08")
    rec = triage.load_current_states(store)[("Device", "h")]
    eff = triage.effective_status(rec, "2026-06-09")
    assert eff["status"] == "Investigating" and eff["has_new_activity"]

    triage.append_triage(store, "Device", "H", "Escalated", note="IR-1", last_seen="2026-06-08")
    rec = triage.load_current_states(store)[("Device", "h")]
    eff = triage.effective_status(rec, "2026-06-09")
    assert eff["status"] == "Escalated" and eff["has_new_activity"]


# --- effective_status: stale flag ----------------------------------------------

def test_stale_investigating_flagged(store):
    triage.append_triage(store, "Device", "H", "Investigating", last_seen="2026-06-08")
    rec = triage.load_current_states(store)[("Device", "h")]
    fresh = triage.effective_status(rec, "2026-06-08", stale_days_=7)
    assert not fresh["is_stale"]
    later = time.time() + 8 * 86400
    stale = triage.effective_status(rec, "2026-06-08", stale_days_=7, now=later)
    assert stale["is_stale"]


def test_benign_never_stale(store):
    rec = _benign(store, "2026-06-08")
    eff = triage.effective_status(rec, "2026-06-08", stale_days_=0, now=time.time() + 365 * 86400)
    assert not eff["is_stale"]


# --- stamp_triage ----------------------------------------------------------------

def _priority_df():
    return pd.DataFrame([
        {"EntityType": "Device", "EntityName": "HOST-1", "LastSeen": pd.Timestamp("2026-06-08 10:00:00")},
        {"EntityType": "Device", "EntityName": "HOST-2", "LastSeen": pd.Timestamp("2026-06-08 11:00:00")},
        {"EntityType": "User",   "EntityName": "alice",  "LastSeen": pd.Timestamp("2026-06-08 12:00:00")},
    ])


def test_stamp_marks_triaged_and_untriaged_rows(store):
    triage.append_triage(store, "Device", "host-1", "Benign", note="dev box",
                         last_seen="2026-06-08T10:00:00", total_risk=12.5, tactic_set="Execution")
    triage.append_triage(store, "User", "ALICE", "Investigating", last_seen="2026-06-01")
    states = triage.load_current_states(store)
    out = triage.stamp_triage(_priority_df(), states, cfg={})

    by_name = out.set_index("EntityName")
    assert by_name.loc["HOST-1", "TriageStatus"] == "Benign"      # same LastSeen → not reopened
    assert by_name.loc["HOST-1", "TriageNote"] == "dev box"
    assert by_name.loc["HOST-2", "TriageStatus"] == "New"
    assert by_name.loc["alice", "TriageStatus"] == "Investigating"
    assert bool(by_name.loc["alice", "TriageHasNewActivity"])     # activity after triage


def test_stamp_reopens_on_newer_activity(store):
    triage.append_triage(store, "Device", "HOST-1", "Benign", note="ok", last_seen="2026-06-01")
    out = triage.stamp_triage(_priority_df(), triage.load_current_states(store), cfg={})
    assert out.set_index("EntityName").loc["HOST-1", "TriageStatus"] == "Reopened"


def test_stamp_empty_df_gets_columns(store):
    out = triage.stamp_triage(pd.DataFrame(columns=["EntityType", "EntityName"]), {}, cfg={})
    for col in triage.STAMP_COLUMNS:
        assert col in out.columns


if __name__ == "__main__":
    import pytest as _pytest
    raise SystemExit(_pytest.main([__file__, "-q"]))
