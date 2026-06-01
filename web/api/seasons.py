"""GET /api/seasons/devices  and  GET /api/seasons/users"""

from fastapi import APIRouter
from state import state, df_to_records

router = APIRouter()


@router.get("/seasons/devices")
def get_device_seasons():
    if not state.is_loaded:
        return {"data": [], "loaded": False}
    return {"data": df_to_records(state.device_seasons), "loaded": True}


@router.get("/seasons/users")
def get_user_seasons():
    if not state.is_loaded:
        return {"data": [], "loaded": False}
    return {"data": df_to_records(state.user_seasons), "loaded": True}
