"""
GET /api/outbreaks — fleet-level detection outbreak surveillance.

Read-only view over the Detection Outbreaks sheet held in AppState: severe
detection types whose device footprint is climbing run-over-run (Spreading) or
that are newly appearing on the fleet (Emerging). The population-scale
complement to slow chains; carries no entity names by design.
"""

from fastapi import APIRouter

from state import state, df_to_records

router = APIRouter()


@router.get("/outbreaks")
def get_outbreaks():
    if not state.is_loaded or state.outbreaks is None:
        return {"data": [], "loaded": state.is_loaded, "meta": {}}

    df = state.outbreaks
    records = df_to_records(df)

    def _count(status):
        if df.empty or "OutbreakStatus" not in df.columns:
            return 0
        return int((df["OutbreakStatus"] == status).sum())

    meta = {
        "total": len(records),
        "emerging": _count("Emerging"),
        "spreading": _count("Spreading"),
    }
    return {"data": records, "loaded": True, "meta": meta}
