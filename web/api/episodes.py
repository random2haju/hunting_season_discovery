"""
GET /api/episodes                     — all device episodes (for timeline module)
GET /api/episodes/{device_name}       — episodes + scenes for one device
"""

from fastapi import APIRouter
from state import state, df_to_records
import pandas as pd

router = APIRouter()


@router.get("/episodes")
def get_all_episodes():
    if not state.is_loaded or state.device_episodes is None:
        return {"data": [], "loaded": False}
    return {"data": df_to_records(state.device_episodes), "loaded": True}


@router.get("/episodes/{device_name:path}")
def get_device_episodes(device_name: str):
    """
    Returns episode summaries and raw scenes for a single device.
    Scenes are sorted ascending by Timestamp so the frontend can render
    a chronological timeline.
    """
    if not state.is_loaded:
        return {"episodes": [], "scenes": [], "loaded": False}

    eps: pd.DataFrame = pd.DataFrame()
    if state.device_episodes is not None and not state.device_episodes.empty:
        eps = state.device_episodes[
            state.device_episodes["DeviceName"].str.lower() == device_name.lower()
        ]

    scenes: pd.DataFrame = pd.DataFrame()
    if state.scenes is not None and not state.scenes.empty:
        scenes = state.scenes[
            state.scenes["DeviceName"].str.lower() == device_name.lower()
        ].sort_values("Timestamp", ascending=True)

    return {
        "episodes": df_to_records(eps),
        "scenes": df_to_records(scenes),
        "loaded": True,
    }
