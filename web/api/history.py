"""
GET /api/history                                — all entities that have history records (enriched for landing)
GET /api/history/{entity_type}/{entity_name}    — per-run score history for one entity
"""

import json
import os
import sqlite3

import pandas as pd
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from state import ROOT_DIR, CONFIG_PATH

router = APIRouter()


def _db_path() -> str:
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        raw = cfg.get("history", {}).get("store_path", "output/hunt_history.db")
        return os.path.join(ROOT_DIR, raw)
    except Exception:
        return os.path.join(ROOT_DIR, "output", "hunt_history.db")


def _emerging_threshold() -> float:
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        return float(cfg.get("history", {}).get("emerging_entity_score_threshold", 10.0))
    except Exception:
        return 10.0


def _compute_entity_summary(grp: pd.DataFrame) -> dict:
    """Compute per-entity landing summary from all its history rows (sorted by run time asc)."""
    scores = grp["SeasonScore"].tolist()
    n = len(scores)
    latest = scores[-1]
    prev = scores[-2] if n >= 2 else None
    delta = round(latest - prev, 1) if prev is not None else None
    max_s = max(scores)
    hist = scores[:-1]

    # Z-score vs historical mean/std (excluding current run)
    z = None
    mean_h = latest
    if len(hist) >= 2:
        mean_h = sum(hist) / len(hist)
        variance = sum((s - mean_h) ** 2 for s in hist) / len(hist)
        std_h = variance ** 0.5
        z = round((latest - mean_h) / std_h, 2) if std_h > 0 else 0.0

    # Tactic-based flags from TacticSet column
    tactic_sets = grp["TacticSet"].fillna("").tolist() if "TacticSet" in grp.columns else []
    tactics_counts = grp["UniqueTactics"].tolist() if "UniqueTactics" in grp.columns else []
    latest_tset = set()
    prior_tset = set()
    if tactic_sets:
        for t in tactic_sets[-1].split(","):
            t = t.strip()
            if t:
                latest_tset.add(t)
        for ts in tactic_sets[:-1]:
            for t in ts.split(","):
                t = t.strip()
                if t:
                    prior_tset.add(t)
    max_prior_tactics = max(tactics_counts[:-1]) if len(tactics_counts) > 1 else 0

    emerging_thresh = _emerging_threshold()
    is_spike = z is not None and z >= 2.5
    is_new_high = latest >= max_s and n > 1
    is_emerging = n <= 2 and latest >= emerging_thresh
    is_tactic_exp = len(tactics_counts) > 1 and tactics_counts[-1] > max_prior_tactics
    is_adapting = n > 1 and bool(latest_tset - prior_tset)

    flag_count = sum([is_spike, is_new_high, is_emerging, is_tactic_exp, is_adapting])

    timestamps = grp["RunTimestamp"].tolist()
    top_tactic = grp["TopTactic"].iloc[-1] if "TopTactic" in grp.columns and not grp.empty else ""
    top_family = grp["TopBehaviorFamily"].iloc[-1] if "TopBehaviorFamily" in grp.columns and not grp.empty else ""

    return {
        "RunCount": n,
        "LatestScore": round(latest, 1),
        "PrevScore": round(prev, 1) if prev is not None else None,
        "ScoreDelta": delta,
        "MaxScore": round(max_s, 1),
        "BaselineMean": round(mean_h, 1),
        "ZScore": z,
        "FirstSeen": timestamps[0][:10] if timestamps else None,
        "LastSeen": timestamps[-1][:10] if timestamps else None,
        "Sparkline": [round(s, 1) for s in scores[-10:]],
        "TopTactic": str(top_tactic) if top_tactic and str(top_tactic) != "nan" else "",
        "TopBehaviorFamily": str(top_family) if top_family and str(top_family) != "nan" else "",
        "IsScoreSpike": is_spike,
        "IsNewHigh": is_new_high,
        "IsEmergingEntity": is_emerging,
        "IsTacticExpansion": is_tactic_exp,
        "IsAdaptingTactics": is_adapting,
        "FlagCount": flag_count,
    }


@router.get("/history")
def list_entities_with_history():
    """Return all entities that have history records with enriched landing data."""
    db = _db_path()
    if not os.path.exists(db):
        return {"data": [], "meta": {}}
    try:
        con = sqlite3.connect(db)
        df = pd.read_sql(
            """
            SELECT EntityType, EntityName, RunTimestampEpoch, RunTimestamp,
                   SeasonScore, UniqueTactics, TacticSet, TopBehaviorFamily, TopTactic
            FROM hunt_history
            ORDER BY EntityType, EntityName, RunTimestampEpoch ASC
            """,
            con,
        )
        con.close()

        if df.empty:
            return {"data": [], "meta": {}}

        results = []
        for (entity_type, entity_name), grp in df.groupby(
            ["EntityType", "EntityName"], sort=False
        ):
            summary = _compute_entity_summary(grp)
            results.append({"EntityType": entity_type, "EntityName": entity_name, **summary})

        all_last = [r["LastSeen"] for r in results if r["LastSeen"]]
        meta = {
            "TotalEntities": len(results),
            "EntitiesWithFlags": sum(1 for r in results if r["FlagCount"] > 0),
            "TrendingUp": sum(1 for r in results if (r["ScoreDelta"] or 0) > 0),
            "TrendingDown": sum(1 for r in results if (r["ScoreDelta"] or 0) < 0),
            "LatestRunDate": max(all_last) if all_last else None,
        }

        return {"data": results, "meta": meta}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/history/{entity_type}/{entity_name:path}")
def get_entity_history(entity_type: str, entity_name: str):
    if entity_type not in ("Device", "User"):
        return JSONResponse(status_code=400, content={"error": "entity_type must be Device or User"})

    db = _db_path()
    if not os.path.exists(db):
        return {"data": [], "entity_name": entity_name, "entity_type": entity_type}

    try:
        con = sqlite3.connect(db)
        df = pd.read_sql(
            """
            SELECT RunTimestamp, SeasonScore, EpisodeCount, SceneCount,
                   UniqueTactics, TopBehaviorFamily, TopTactic, TacticSet
            FROM hunt_history
            WHERE EntityType = ? AND EntityName = ?
            ORDER BY RunTimestampEpoch ASC
            """,
            con,
            params=(entity_type, entity_name.lower()),
        )
        con.close()
        return {
            "entity_name": entity_name,
            "entity_type": entity_type,
            "data": df.to_dict(orient="records"),
        }
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
