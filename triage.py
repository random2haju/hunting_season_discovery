"""
triage.py — analyst triage state for Priority Cases entities.

A triage state attaches to an entity (EntityType + case-insensitive EntityName)
and records the analyst's disposition of the activity seen *up to that moment*:

    New           — implicit default; no triage record exists (or state was reset)
    Investigating — an analyst has claimed the case (note optional)
    Benign        — reviewed and dispositioned as benign/expected (note required)
    Escalated     — handed off to IR / ticketing (note required)
    Reopened      — DERIVED, never stored: a Benign entity has activity newer
                    than the LastSeen snapshot taken when the verdict was set

The store is a single append-only SQLite table (`triage_log`) in its own DB file
(default output/triage.db — deliberately separate from hunt_history.db, whose
documented baseline-reset procedure is "delete the file"). The current state of
an entity is the most recent log row; the full history is the audit trail.

"Reopened", the new-activity badge on Investigating/Escalated cases, and the
stale-Investigating flag are all computed at read time by `effective_status()`,
so the store remains pure analyst input. consolidate.py uses `stamp_triage()`
to add triage columns to the Priority Cases sheet; the web backend uses the
same functions to stamp in-memory data and serve the triage API.

Config keys (config.json, "triage" block):
    store_path               — DB location relative to repo root (default output/triage.db)
    stale_investigating_days — Investigating older than this is flagged stale (default 7)
"""

import getpass
import os
import sqlite3
from datetime import datetime, timezone

import pandas as pd

DEFAULT_STORE_PATH = "output/triage.db"
DEFAULT_STALE_DAYS = 7

# States an analyst may set. "New" resets the entity to untriaged (the log row
# is still kept for audit; effective status simply becomes New again).
ANALYST_STATES = ("Investigating", "Benign", "Escalated", "New")
# Verdict states require a non-empty note.
VERDICT_STATES = ("Benign", "Escalated")
# Only Benign auto-reopens; Investigating/Escalated get a new-activity badge instead.
REOPEN_STATES = ("Benign",)


def resolve_store_path(cfg: dict, root_dir: str) -> str:
    raw = (cfg or {}).get("triage", {}).get("store_path", DEFAULT_STORE_PATH)
    return raw if os.path.isabs(raw) else os.path.join(root_dir, raw)


def stale_days(cfg: dict) -> float:
    return float((cfg or {}).get("triage", {}).get("stale_investigating_days", DEFAULT_STALE_DAYS))


def _connect(store_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(store_path) or ".", exist_ok=True)
    con = sqlite3.connect(store_path)
    con.execute("""
        CREATE TABLE IF NOT EXISTS triage_log (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            EntityType        TEXT NOT NULL,
            EntityName        TEXT NOT NULL,
            EntityKey         TEXT NOT NULL,
            Status            TEXT NOT NULL,
            Note              TEXT NOT NULL DEFAULT '',
            TriagedBy         TEXT NOT NULL DEFAULT '',
            TriagedAt         TEXT NOT NULL,
            TriagedAtEpoch    REAL NOT NULL,
            LastSeenSnapshot  TEXT NOT NULL DEFAULT '',
            TotalRiskSnapshot REAL,
            TacticSetSnapshot TEXT NOT NULL DEFAULT ''
        )
    """)
    con.execute("""
        CREATE INDEX IF NOT EXISTS idx_triage_entity
        ON triage_log (EntityType, EntityKey, TriagedAtEpoch DESC)
    """)
    return con


def _entity_key(entity_name: str) -> str:
    return str(entity_name).strip().lower()


def _parse_ts(value):
    """Parse any timestamp-ish value to a tz-naive UTC pandas Timestamp, or None."""
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    if isinstance(value, str) and not value.strip():
        return None
    ts = pd.to_datetime(value, errors="coerce")
    if ts is pd.NaT or ts is None:
        return None
    if ts.tzinfo is not None:
        ts = ts.tz_convert("UTC").tz_localize(None)
    return ts


_LOG_COLS = ["id", "EntityType", "EntityName", "Status", "Note", "TriagedBy",
             "TriagedAt", "TriagedAtEpoch", "LastSeenSnapshot",
             "TotalRiskSnapshot", "TacticSetSnapshot"]


def append_triage(
    store_path: str,
    entity_type: str,
    entity_name: str,
    status: str,
    note: str = "",
    triaged_by: str = "",
    last_seen=None,
    total_risk=None,
    tactic_set: str = "",
) -> dict:
    """Validate and append one triage action. Returns the stored record.

    Raises ValueError on bad entity_type/status, or a missing note for a
    verdict state (Benign/Escalated) — enforced here so every caller
    (web API, consolidate) gets identical rules.
    """
    if entity_type not in ("Device", "User"):
        raise ValueError("entity_type must be Device or User")
    entity_name = str(entity_name).strip()
    if not entity_name:
        raise ValueError("entity_name must not be empty")
    if status not in ANALYST_STATES:
        raise ValueError(f"status must be one of {ANALYST_STATES}")
    note = (note or "").strip()
    if status in VERDICT_STATES and not note:
        raise ValueError(f"a note is required for {status}")

    now = datetime.now(timezone.utc)
    seen = _parse_ts(last_seen)
    record = {
        "EntityType": entity_type,
        "EntityName": entity_name,
        "EntityKey": _entity_key(entity_name),
        "Status": status,
        "Note": note,
        "TriagedBy": (triaged_by or "").strip() or getpass.getuser(),
        "TriagedAt": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "TriagedAtEpoch": now.timestamp(),
        "LastSeenSnapshot": seen.isoformat() if seen is not None else "",
        "TotalRiskSnapshot": float(total_risk) if total_risk is not None and not pd.isna(total_risk) else None,
        "TacticSetSnapshot": str(tactic_set or ""),
    }
    con = _connect(store_path)
    try:
        con.execute(
            """INSERT INTO triage_log
               (EntityType, EntityName, EntityKey, Status, Note, TriagedBy,
                TriagedAt, TriagedAtEpoch, LastSeenSnapshot, TotalRiskSnapshot, TacticSetSnapshot)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (record["EntityType"], record["EntityName"], record["EntityKey"],
             record["Status"], record["Note"], record["TriagedBy"],
             record["TriagedAt"], record["TriagedAtEpoch"],
             record["LastSeenSnapshot"], record["TotalRiskSnapshot"],
             record["TacticSetSnapshot"]),
        )
        con.commit()
    finally:
        con.close()
    return record


def load_current_states(store_path: str) -> dict:
    """Return {(EntityType, entity_key): latest-log-row-dict}. Empty if no store."""
    if not os.path.exists(store_path):
        return {}
    con = _connect(store_path)
    try:
        rows = con.execute(f"""
            SELECT {", ".join(_LOG_COLS)} FROM triage_log
            ORDER BY TriagedAtEpoch ASC, id ASC
        """).fetchall()
    finally:
        con.close()
    result = {}
    for row in rows:  # ascending order → last write per entity wins
        rec = dict(zip(_LOG_COLS, row))
        result[(rec["EntityType"], _entity_key(rec["EntityName"]))] = rec
    return result


def load_log(store_path: str, entity_type: str, entity_name: str) -> list:
    """Full audit trail for one entity, newest first."""
    if not os.path.exists(store_path):
        return []
    con = _connect(store_path)
    try:
        rows = con.execute(f"""
            SELECT {", ".join(_LOG_COLS)} FROM triage_log
            WHERE EntityType = ? AND EntityKey = ?
            ORDER BY TriagedAtEpoch DESC, id DESC
        """, (entity_type, _entity_key(entity_name))).fetchall()
    finally:
        con.close()
    return [dict(zip(_LOG_COLS, row)) for row in rows]


def effective_status(record, current_last_seen, stale_days_: float = DEFAULT_STALE_DAYS, now=None) -> dict:
    """Compute the displayed triage state from a stored record + current data.

    Returns {status, has_new_activity, is_stale, note, triaged_by, triaged_at}.
    - No record (or last action was a reset to New) → New.
    - Benign with activity newer than the triage-time snapshot → Reopened.
    - Investigating/Escalated keep their state; new activity sets the badge flag.
    - Investigating older than stale_days_ → is_stale.
    """
    if record is None or record.get("Status") == "New":
        return {"status": "New", "has_new_activity": False, "is_stale": False,
                "note": "", "triaged_by": "", "triaged_at": ""}

    snapshot = _parse_ts(record.get("LastSeenSnapshot"))
    current = _parse_ts(current_last_seen)
    # Strict > : the 72h hunt window overlaps between runs, so re-exported events
    # keep the same max timestamp and must not count as new activity. A missing
    # snapshot is treated conservatively: any current activity counts as new.
    has_new = current is not None and (snapshot is None or current > snapshot)

    status = record["Status"]
    if status in REOPEN_STATES and has_new:
        status = "Reopened"

    is_stale = False
    if record["Status"] == "Investigating":
        now_ts = now if now is not None else datetime.now(timezone.utc).timestamp()
        is_stale = (now_ts - float(record["TriagedAtEpoch"])) > stale_days_ * 86400

    return {
        "status": status,
        "has_new_activity": has_new,
        "is_stale": is_stale,
        "note": record.get("Note", ""),
        "triaged_by": record.get("TriagedBy", ""),
        "triaged_at": record.get("TriagedAt", ""),
    }


def stamp_triage(df, states: dict, cfg: dict):
    """Add triage columns to a priority-cases-shaped DataFrame
    (needs EntityType / EntityName columns; LastSeen used for the reopen rule).

    Adds: TriageStatus, TriageNote, TriagedBy, TriagedDate,
          TriageHasNewActivity, TriageStale. Returns a stamped copy.
    """
    if df is None or df.empty:
        if df is not None:
            df = df.copy()
            for col in STAMP_COLUMNS:
                df[col] = pd.Series(dtype=object)
        return df

    days = stale_days(cfg)
    df = df.copy()
    statuses, notes, bys, dates, new_flags, stale_flags = [], [], [], [], [], []
    for _, row in df.iterrows():
        rec = states.get((row.get("EntityType"), _entity_key(row.get("EntityName", ""))))
        eff = effective_status(rec, row.get("LastSeen"), days)
        statuses.append(eff["status"])
        notes.append(eff["note"])
        bys.append(eff["triaged_by"])
        dates.append(eff["triaged_at"][:10] if eff["triaged_at"] else "")
        new_flags.append(eff["has_new_activity"])
        stale_flags.append(eff["is_stale"])
    df["TriageStatus"] = statuses
    df["TriageNote"] = notes
    df["TriagedBy"] = bys
    df["TriagedDate"] = dates
    df["TriageHasNewActivity"] = new_flags
    df["TriageStale"] = stale_flags
    return df


STAMP_COLUMNS = ["TriageStatus", "TriageNote", "TriagedBy", "TriagedDate",
                 "TriageHasNewActivity", "TriageStale"]
