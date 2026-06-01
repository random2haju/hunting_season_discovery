"""
GET    /api/suppressions                                — list all suppressions
POST   /api/suppressions                                — add a suppression
DELETE /api/suppressions/{entity_type}/{entity_name}    — remove a suppression
POST   /api/suppressions/expire                         — prune expired entries

After any write operation, the in-memory state is updated immediately so
Priority Cases reflects the change without a pipeline re-run.
"""

import csv
import os
from datetime import date, datetime
from typing import Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from state import _suppression_store_path, _apply_suppressions

router = APIRouter()

_COLS = ["EntityType", "EntityName", "Reason", "AddedDate", "ExpiresDate"]


def _load(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _save(path: str, rows: list[dict]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=_COLS)
        w.writeheader()
        w.writerows(rows)


def _is_active(row: dict) -> bool:
    expires = row.get("ExpiresDate", "").strip()
    if not expires:
        return True
    try:
        return datetime.strptime(expires, "%Y-%m-%d").date() >= date.today()
    except ValueError:
        return True


class SuppressRequest(BaseModel):
    entity_type: str
    entity_name: str
    reason: str
    expires: Optional[str] = None  # YYYY-MM-DD or omitted for permanent


@router.get("/suppressions")
def list_suppressions():
    path = _suppression_store_path()
    rows = _load(path)
    today = date.today()
    result = []
    for r in rows:
        expires = r.get("ExpiresDate", "").strip()
        expired = False
        if expires:
            try:
                expired = datetime.strptime(expires, "%Y-%m-%d").date() < today
            except ValueError:
                pass
        result.append({**r, "expired": expired, "active": not expired})
    return {"data": result}


@router.post("/suppressions")
def add_suppression(req: SuppressRequest):
    if req.entity_type not in ("Device", "User"):
        return JSONResponse(status_code=400, content={"error": "entity_type must be Device or User"})
    if req.expires:
        try:
            datetime.strptime(req.expires, "%Y-%m-%d")
        except ValueError:
            return JSONResponse(status_code=400, content={"error": "expires must be YYYY-MM-DD"})

    path = _suppression_store_path()
    rows = _load(path)

    if any(
        r["EntityType"].lower() == req.entity_type.lower()
        and r["EntityName"].lower() == req.entity_name.lower()
        for r in rows
    ):
        return JSONResponse(status_code=409, content={"error": "Already suppressed. Remove it first to update."})

    rows.append({
        "EntityType": req.entity_type,
        "EntityName": req.entity_name,
        "Reason": req.reason,
        "AddedDate": date.today().isoformat(),
        "ExpiresDate": req.expires or "",
    })
    _save(path, rows)
    _apply_suppressions()
    return {"ok": True}


@router.delete("/suppressions/{entity_type}/{entity_name:path}")
def remove_suppression(entity_type: str, entity_name: str):
    path = _suppression_store_path()
    rows = _load(path)
    kept = [
        r for r in rows
        if not (
            r["EntityType"].lower() == entity_type.lower()
            and r["EntityName"].lower() == entity_name.lower()
        )
    ]
    if len(kept) == len(rows):
        return JSONResponse(status_code=404, content={"error": "Suppression not found"})
    _save(path, kept)
    _apply_suppressions()
    return {"ok": True}


@router.post("/suppressions/expire")
def expire_suppressions():
    path = _suppression_store_path()
    rows = _load(path)
    kept = [r for r in rows if _is_active(r)]
    dropped = len(rows) - len(kept)
    if dropped:
        _save(path, kept)
        _apply_suppressions()
    return {"ok": True, "dropped": dropped}
