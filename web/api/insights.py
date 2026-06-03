"""GET /api/insights — aggregated stats for the insights dashboard."""

import json
import os
import sqlite3

import pandas as pd
from fastapi import APIRouter

from state import ROOT_DIR, CONFIG_PATH, state, df_to_records

router = APIRouter()

_FLAG_COLS = ["IsScoreSpike", "IsNewHigh", "IsTacticExpansion", "IsAdaptingTactics", "IsEmergingEntity"]
_FLAG_LABELS = {
    "IsScoreSpike":      "Spike",
    "IsNewHigh":         "NewHigh",
    "IsTacticExpansion": "TacticExp",
    "IsAdaptingTactics": "Adapting",
    "IsEmergingEntity":  "Emerging",
}


def _db_path() -> str:
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        raw = cfg.get("history", {}).get("store_path", "output/hunt_history.db")
        return os.path.join(ROOT_DIR, raw)
    except Exception:
        return os.path.join(ROOT_DIR, "output", "hunt_history.db")


@router.get("/insights")
def get_insights():
    if not state.is_loaded:
        return {"loaded": False}

    pc = state.priority_cases
    ds = state.device_seasons
    us = state.user_seasons
    sc = state.scenes

    # ── Priority case counts ──────────────────────────────────────────────────
    total_priority_cases = len(pc) if pc is not None else 0
    high_risk_count = medium_risk_count = 0
    if pc is not None and "TotalRisk" in pc.columns:
        risk = pc["TotalRisk"].fillna(0)
        high_risk_count   = int((risk >= 50).sum())
        medium_risk_count = int(((risk >= 20) & (risk < 50)).sum())

    # ── Entity scope ──────────────────────────────────────────────────────────
    total_devices = len(ds) if ds is not None else 0
    total_users   = len(us) if us is not None else 0

    # ── Suppressed count ──────────────────────────────────────────────────────
    suppressed_count = 0
    for df in [ds, us]:
        if df is not None and "IsSuppressed" in df.columns:
            suppressed_count += int(df["IsSuppressed"].fillna(False).astype(bool).sum())

    # ── Anomaly flags ─────────────────────────────────────────────────────────
    flag_counts: dict = {}
    flagged_entity_names: set = set()
    if pc is not None:
        for f in _FLAG_COLS:
            if f in pc.columns:
                mask = pc[f].fillna(False).astype(bool)
                flag_counts[f] = int(mask.sum())
                flagged_entity_names.update(pc.loc[mask, "EntityName"].tolist())
            else:
                flag_counts[f] = 0

    # ── Tactic distribution from both season TacticSet columns ───────────────
    tactic_counter: dict = {}
    for df in [ds, us]:
        if df is not None and "TacticSet" in df.columns:
            for ts in df["TacticSet"].dropna():
                for t in str(ts).split(","):
                    t = t.strip()
                    if t:
                        tactic_counter[t] = tactic_counter.get(t, 0) + 1
    tactic_distribution = sorted(
        [{"tactic": k, "count": v} for k, v in tactic_counter.items()],
        key=lambda x: x["count"],
        reverse=True,
    )

    # ── Workflow class breakdown ───────────────────────────────────────────────
    wf_counter: dict = {}
    for df in [ds, us]:
        if df is not None and "PrimaryWorkflowClass" in df.columns:
            for wf in df["PrimaryWorkflowClass"].dropna():
                wf_counter[str(wf)] = wf_counter.get(str(wf), 0) + 1
    workflow_breakdown = [{"class": k, "count": v} for k, v in wf_counter.items()]

    # ── Top detection types from scenes ───────────────────────────────────────
    top_detections = []
    if sc is not None and "DetectionType" in sc.columns:
        top = sc["DetectionType"].value_counts().head(10)
        top_detections = [{"type": t, "count": int(c)} for t, c in top.items()]

    # ── Top flagged entities (max 10) ─────────────────────────────────────────
    top_flagged = []
    if pc is not None:
        flag_mask = None
        for f in _FLAG_COLS:
            if f in pc.columns:
                m = pc[f].fillna(False).astype(bool)
                flag_mask = m if flag_mask is None else (flag_mask | m)
        if flag_mask is not None:
            top_flagged = df_to_records(pc[flag_mask].head(10))

    # ── Historical run aggregates from DB ─────────────────────────────────────
    history_trend = []
    db = _db_path()
    if os.path.exists(db):
        try:
            con = sqlite3.connect(db)
            df_h = pd.read_sql(
                """
                SELECT RunTimestamp,
                       MIN(RunTimestampEpoch)              AS epoch,
                       COUNT(DISTINCT EntityName)          AS entity_count,
                       ROUND(SUM(SeasonScore), 2)          AS total_risk,
                       ROUND(AVG(SeasonScore), 2)          AS mean_score,
                       ROUND(AVG(UniqueTactics), 2)        AS mean_tactics,
                       ROUND(AVG(HistoricalPriority), 2)   AS mean_hp,
                       ROUND(SUM(HistoricalPriority), 2)   AS total_hp
                FROM hunt_history
                GROUP BY RunTimestamp
                ORDER BY epoch ASC
                """,
                con,
            )
            con.close()
            df_h["run_date"] = df_h["RunTimestamp"].str[:10]
            history_trend = df_h[
                ["run_date", "entity_count", "total_risk", "mean_score", "mean_tactics", "mean_hp", "total_hp"]
            ].to_dict(orient="records")
        except Exception:
            history_trend = []

    return {
        "loaded":               True,
        "total_priority_cases": total_priority_cases,
        "high_risk_count":      high_risk_count,
        "medium_risk_count":    medium_risk_count,
        "flagged_entity_count": len(flagged_entity_names),
        "total_devices":        total_devices,
        "total_users":          total_users,
        "suppressed_count":     suppressed_count,
        "flag_counts":          flag_counts,
        "tactic_distribution":  tactic_distribution,
        "workflow_breakdown":   workflow_breakdown,
        "top_detections":       top_detections,
        "top_flagged":          top_flagged,
        "history_trend":        history_trend,
    }
