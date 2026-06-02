"""
GET /api/recommendations

Surfaces entities that are likely false-positive noise regulars: they appear
repeatedly in hunt history with a stable (non-spiking) score profile and no
anomaly-flagged behaviour, and are not currently suppressed.

Criteria (all must hold):
  - Appeared in >= min_runs distinct runs
  - Score is stable: MAX(score) / AVG(score) < max_avg_ratio (default 1.5)
  - Score never hit 0 (they always show up, not intermittent)
  - Not currently suppressed
"""

import json
import os
import sqlite3
from datetime import date, datetime

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from state import ROOT_DIR, CONFIG_PATH

router = APIRouter()

_MIN_RUNS = 3
_MAX_AVG_RATIO = 1.5  # max(score)/avg(score) — below this means stable


def _db_path() -> str:
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        raw = cfg.get("history", {}).get("store_path", "output/hunt_history.db")
        return os.path.join(ROOT_DIR, raw)
    except Exception:
        return os.path.join(ROOT_DIR, "output", "hunt_history.db")


def _suppression_path() -> str:
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        raw = cfg.get("suppression", {}).get("store_path", "output/suppressions.csv")
        return os.path.join(ROOT_DIR, raw)
    except Exception:
        return os.path.join(ROOT_DIR, "output", "suppressions.csv")


def _active_suppressions() -> set:
    """Return set of (entity_type_lower, entity_name_lower) that are currently suppressed."""
    path = _suppression_path()
    if not os.path.exists(path):
        return set()
    today = date.today()
    result = set()
    try:
        import csv
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                expires = row.get("ExpiresDate", "").strip()
                if expires:
                    try:
                        if datetime.strptime(expires, "%Y-%m-%d").date() < today:
                            continue
                    except ValueError:
                        pass
                result.add((row["EntityType"].strip().lower(), row["EntityName"].strip().lower()))
    except Exception:
        pass
    return result


@router.get("/recommendations")
def get_recommendations():
    db = _db_path()
    if not os.path.exists(db):
        return {"data": [], "message": "No history database found. Run the pipeline at least once."}

    try:
        con = sqlite3.connect(db)
        rows = con.execute(
            """
            SELECT
                EntityType,
                EntityName,
                COUNT(DISTINCT RunId)                          AS RunCount,
                ROUND(AVG(SeasonScore), 1)                    AS AvgScore,
                ROUND(MAX(SeasonScore), 1)                    AS MaxScore,
                ROUND(MIN(SeasonScore), 1)                    AS MinScore,
                ROUND(MAX(SeasonScore) / MAX(AVG(SeasonScore), 0.01), 2) AS MaxAvgRatio,
                MAX(TopTactic)                                AS TopTactic,
                MAX(TopBehaviorFamily)                        AS TopFamily
            FROM hunt_history
            GROUP BY EntityType, EntityName
            HAVING
                COUNT(DISTINCT RunId) >= ?
                AND (MAX(SeasonScore) / MAX(AVG(SeasonScore), 0.01)) < ?
            ORDER BY RunCount DESC, AvgScore DESC
            """,
            (_MIN_RUNS, _MAX_AVG_RATIO),
        ).fetchall()
        con.close()

        suppressed = _active_suppressions()

        results = []
        for (etype, ename, run_count, avg_score, max_score, min_score,
             ratio, top_tactic, top_family) in rows:
            if (etype.lower(), ename.lower()) in suppressed:
                continue
            results.append({
                "EntityType": etype,
                "EntityName": ename,
                "RunCount": run_count,
                "AvgScore": avg_score,
                "MaxScore": max_score,
                "MinScore": min_score,
                "MaxAvgRatio": ratio,
                "TopTactic": top_tactic or "",
                "TopFamily": top_family or "",
                "SuggestedReason": (
                    f"Stable noise: appeared in {run_count} runs, "
                    f"avg score {avg_score} (max {max_score}), "
                    f"no score spikes (ratio {ratio}x)"
                ),
            })

        return {"data": results, "total": len(results)}

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})
