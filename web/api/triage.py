"""
GET    /api/triage                                   — effective state for all triaged entities
POST   /api/triage                                   — set a state (Investigating/Benign/Escalated/New)
GET    /api/triage/log/{entity_type}/{entity_name}   — full audit trail for one entity

State semantics live in the shared root-level triage module (one implementation
of the reopen/stale rules for both this API and consolidate.py). After any
write, the in-memory priority_cases is re-stamped immediately so the table
reflects the change without a pipeline re-run — same pattern as suppressions.
"""

import json

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import triage as triage_store
from state import state, _apply_triage, _load_config, triage_store_path

router = APIRouter()


class TriageRequest(BaseModel):
    entity_type: str
    entity_name: str
    status: str            # Investigating | Benign | Escalated | New (= reset)
    note: str = ""         # required by the store for Benign/Escalated
    also_suppress: bool = False  # Benign only: also add a permanent entity suppression


def _entity_snapshot(entity_type: str, entity_name: str):
    """LastSeen/TotalRisk/TacticSet for an entity from in-memory seasons (or Nones)."""
    df, col = (
        (state.device_seasons, "DeviceName") if entity_type == "Device"
        else (state.user_seasons, "AccountName")
    )
    if df is None or df.empty or col not in df.columns:
        return None, None, ""
    m = df[df[col].astype(str).str.strip().str.lower() == entity_name.strip().lower()]
    if m.empty:
        return None, None, ""
    row = m.iloc[0]
    return row.get("LastSeen"), row.get("TotalRisk"), row.get("TacticSet", "")


@router.get("/triage")
def list_triage():
    cfg = _load_config()
    days = triage_store.stale_days(cfg)
    out = []
    for (etype, _key), rec in triage_store.load_current_states(triage_store_path()).items():
        last_seen, _, _ = _entity_snapshot(etype, rec["EntityName"])
        eff = triage_store.effective_status(rec, last_seen, days)
        out.append({
            "EntityType": etype,
            "EntityName": rec["EntityName"],
            "StoredStatus": rec["Status"],
            "EffectiveStatus": eff["status"],
            "HasNewActivity": eff["has_new_activity"],
            "IsStale": eff["is_stale"],
            "Note": rec["Note"],
            "TriagedBy": rec["TriagedBy"],
            "TriagedAt": rec["TriagedAt"],
        })
    return {"data": out}


@router.post("/triage")
def set_triage(req: TriageRequest):
    last_seen, total_risk, tactic_set = _entity_snapshot(req.entity_type, req.entity_name)
    try:
        record = triage_store.append_triage(
            triage_store_path(),
            req.entity_type, req.entity_name, req.status,
            note=req.note,
            last_seen=last_seen, total_risk=total_risk, tactic_set=tactic_set,
        )
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})

    suppress_error = None
    if req.also_suppress and req.status == "Benign":
        from api.suppressions import SuppressRequest, add_suppression
        resp = add_suppression(SuppressRequest(
            entity_type=req.entity_type,
            entity_name=req.entity_name,
            reason=f"Triaged benign: {req.note}",
        ))
        if isinstance(resp, JSONResponse) and resp.status_code >= 400:
            try:
                suppress_error = json.loads(resp.body).get("error", "suppression failed")
            except Exception:
                suppress_error = "suppression failed"

    # add_suppression already rebuilt priority_cases (and re-stamped triage via
    # _apply_suppressions); calling again is cheap and covers the no-suppress path.
    _apply_triage()
    return {"ok": True, "status": record["Status"], "suppress_error": suppress_error}


@router.get("/triage/log/{entity_type}/{entity_name:path}")
def triage_log(entity_type: str, entity_name: str):
    if entity_type not in ("Device", "User"):
        return JSONResponse(status_code=400, content={"error": "entity_type must be Device or User"})
    rows = triage_store.load_log(triage_store_path(), entity_type, entity_name)
    return {"data": rows}
