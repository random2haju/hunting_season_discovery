"""
GET    /api/patterns            — list all pattern suppressions
POST   /api/patterns            — create a new pattern
DELETE /api/patterns/{name}     — delete a pattern by name
POST   /api/patterns/expire     — prune expired patterns

After any write, in-memory state is re-applied immediately.
"""

import json
import os
from datetime import date, datetime
from typing import List, Optional

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator

from state import _apply_suppressions as _reapply, ROOT_DIR, CONFIG_PATH

router = APIRouter()

_VALID_FIELDS = {"EntityType", "PrimaryWorkflowClass", "UniqueTactics", "TotalRisk", "AIWorkflowScenePct"}
_CATEGORICAL  = {"EntityType", "PrimaryWorkflowClass"}
_NUMERIC      = {"UniqueTactics", "TotalRisk", "AIWorkflowScenePct"}
_VALID_OPS    = {"=", "<", "<=", ">", ">="}
_CAT_VALUES   = {
    "EntityType":           {"Device", "User"},
    "PrimaryWorkflowClass": {"AIWorkflow", "DeveloperAutomation", "ServiceAutomation", "Operational"},
}


def _pattern_store_path() -> str:
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        raw = cfg.get("suppression", {}).get("pattern_store_path", "output/pattern_suppressions.json")
        return os.path.join(ROOT_DIR, raw)
    except Exception:
        return os.path.join(ROOT_DIR, "output", "pattern_suppressions.json")


def _load(path: str) -> list:
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def _save(path: str, patterns: list) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(patterns, f, indent=2)


def _is_active(p: dict) -> bool:
    expires = p.get("expires_date") or ""
    if not expires:
        return True
    try:
        return datetime.strptime(expires, "%Y-%m-%d").date() >= date.today()
    except ValueError:
        return True


class ConditionIn(BaseModel):
    field: str
    op: str
    value: str  # always string from JSON; validated as number where needed

    @field_validator("field")
    @classmethod
    def check_field(cls, v):
        if v not in _VALID_FIELDS:
            raise ValueError(f"field must be one of {sorted(_VALID_FIELDS)}")
        return v

    @field_validator("op")
    @classmethod
    def check_op(cls, v):
        if v not in _VALID_OPS:
            raise ValueError(f"op must be one of {sorted(_VALID_OPS)}")
        return v


class PatternIn(BaseModel):
    name: str
    reason: str
    conditions: List[ConditionIn]
    expires_date: Optional[str] = None

    @field_validator("name")
    @classmethod
    def check_name(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("name must not be empty")
        return v

    @field_validator("conditions")
    @classmethod
    def check_conditions(cls, v):
        if not v:
            raise ValueError("at least one condition required")
        return v


def _validate_condition_value(field: str, op: str, value: str) -> str:
    if field in _CATEGORICAL:
        if op != "=":
            return f"field '{field}' only supports op '='"
        allowed = _CAT_VALUES.get(field, set())
        if allowed and value not in allowed:
            return f"value for '{field}' must be one of {sorted(allowed)}"
    else:
        try:
            float(value)
        except ValueError:
            return f"value for numeric field '{field}' must be a number"
    return ""


@router.get("/patterns")
def list_patterns():
    path = _pattern_store_path()
    patterns = _load(path)
    today = date.today()
    result = []
    for p in patterns:
        expires = p.get("expires_date") or ""
        expired = False
        if expires:
            try:
                expired = datetime.strptime(expires, "%Y-%m-%d").date() < today
            except ValueError:
                pass
        result.append({**p, "expired": expired, "active": not expired})
    return {"data": result}


@router.post("/patterns")
def create_pattern(req: PatternIn):
    # Validate all condition values
    for cond in req.conditions:
        err = _validate_condition_value(cond.field, cond.op, cond.value)
        if err:
            return JSONResponse(status_code=400, content={"error": err})

    if req.expires_date:
        try:
            datetime.strptime(req.expires_date, "%Y-%m-%d")
        except ValueError:
            return JSONResponse(status_code=400, content={"error": "expires_date must be YYYY-MM-DD"})

    path = _pattern_store_path()
    patterns = _load(path)

    if any(p["name"].lower() == req.name.lower() for p in patterns):
        return JSONResponse(status_code=409, content={"error": f"Pattern '{req.name}' already exists"})

    patterns.append({
        "name":        req.name,
        "reason":      req.reason,
        "added_date":  date.today().isoformat(),
        "expires_date": req.expires_date or None,
        "conditions":  [{"field": c.field, "op": c.op, "value": c.value} for c in req.conditions],
    })
    _save(path, patterns)
    _reapply()
    return {"ok": True}


@router.delete("/patterns/{name:path}")
def delete_pattern(name: str):
    path = _pattern_store_path()
    patterns = _load(path)
    kept = [p for p in patterns if p["name"].lower() != name.lower()]
    if len(kept) == len(patterns):
        return JSONResponse(status_code=404, content={"error": f"Pattern '{name}' not found"})
    _save(path, kept)
    _reapply()
    return {"ok": True}


@router.post("/patterns/expire")
def expire_patterns():
    path = _pattern_store_path()
    patterns = _load(path)
    kept = [p for p in patterns if _is_active(p)]
    dropped = len(patterns) - len(kept)
    if dropped:
        _save(path, kept)
        _reapply()
    return {"ok": True, "dropped": dropped}
