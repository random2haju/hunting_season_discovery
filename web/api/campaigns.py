"""
GET /api/campaigns — cross-layer campaign correlation (the John Snow overlay).

Read-only view over the Campaigns sheet held in AppState: detection types that
are BOTH an active outbreak AND threaded through >= 2 entities' slow kill chains
— the common-source signal where the fleet epidemic curve and individual case
histories line up on the same technique.
"""

from fastapi import APIRouter

from state import state, df_to_records

router = APIRouter()


@router.get("/campaigns")
def get_campaigns():
    if not state.is_loaded or state.campaigns is None:
        return {"data": [], "loaded": state.is_loaded, "meta": {}}

    df = state.campaigns
    records = df_to_records(df)
    meta = {
        "total": len(records),
        "linked_entities": int(df["LinkedEntityCount"].sum())
        if (not df.empty and "LinkedEntityCount" in df.columns) else 0,
    }
    return {"data": records, "loaded": True, "meta": meta}
