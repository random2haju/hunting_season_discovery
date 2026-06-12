"""
GET /api/slow-chains — cross-run "slow kill chain" detections (Recommendation A).

Read-only view over the Slow Kill Chains sheet held in AppState: entities that
walked a dangerous tactic sequence in forward order across multiple hunt runs.
Staging rows (collected, not yet exfiltrated) are the pre-exfil alarm.
"""

from fastapi import APIRouter

from state import state, df_to_records

router = APIRouter()


@router.get("/slow-chains")
def get_slow_chains():
    if not state.is_loaded or state.slow_chains is None:
        return {"data": [], "loaded": state.is_loaded, "meta": {}}

    df = state.slow_chains
    records = df_to_records(df)

    def _count(status):
        if df.empty or "ChainStatus" not in df.columns:
            return 0
        return int((df["ChainStatus"] == status).sum())

    meta = {
        "total": len(records),
        "staging": _count("Staging"),
        "complete": _count("Complete"),
    }
    return {"data": records, "loaded": True, "meta": meta}
