"""GET /api/stacking?family=all|ai"""

from fastapi import APIRouter, Query
from state import state, df_to_records

router = APIRouter()


@router.get("/stacking")
def get_stacking(family: str = Query("all", pattern="^(all|ai)$")):
    if not state.is_loaded:
        return {"data": [], "loaded": False, "family": family}
    df = state.ai_stacking if family == "ai" else state.stacking
    return {"data": df_to_records(df), "loaded": True, "family": family}
