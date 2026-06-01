"""
GET /api/history                                — all entities that have history records
GET /api/history/{entity_type}/{entity_name}    — per-run score history for one entity
"""

import os
import sqlite3

import pandas as pd
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from state import ROOT_DIR, CONFIG_PATH
import json

router = APIRouter()


def _db_path() -> str:
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        raw = cfg.get("history", {}).get("store_path", "output/hunt_history.db")
        return os.path.join(ROOT_DIR, raw)
    except Exception:
        return os.path.join(ROOT_DIR, "output", "hunt_history.db")


@router.get("/history")
def list_entities_with_history():
    """Return all entities that have history records — used to populate the entity selector."""
    db = _db_path()
    if not os.path.exists(db):
        return {"data": []}
    try:
        con = sqlite3.connect(db)
        df = pd.read_sql(
            """
            SELECT EntityType, EntityName, COUNT(*) AS RunCount, MAX(SeasonScore) AS MaxScore
            FROM hunt_history
            GROUP BY EntityType, EntityName
            ORDER BY MaxScore DESC
            """,
            con,
        )
        con.close()
        return {"data": df.to_dict(orient="records")}
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
