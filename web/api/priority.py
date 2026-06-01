"""GET /api/priority-cases"""

from fastapi import APIRouter
from state import state, df_to_records

router = APIRouter()


@router.get("/priority-cases")
def get_priority_cases():
    if not state.is_loaded:
        return {"data": [], "loaded": False}
    return {"data": df_to_records(state.priority_cases), "loaded": True}
