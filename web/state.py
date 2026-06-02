"""
In-memory application state — populated on startup and on explicit reload.

All route handlers read from the singleton `state` object. The pipeline
endpoint writes to it after a successful run or reload.
"""

import glob
import json
import os
import sqlite3
from dataclasses import dataclass, field
from typing import Optional

import pandas as pd

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(ROOT_DIR, "output")
CONFIG_PATH = os.path.join(ROOT_DIR, "config.json")
DATA_DIR = os.path.join(ROOT_DIR, "data")


@dataclass
class AppState:
    is_loaded: bool = False
    is_running: bool = False
    error: Optional[str] = None
    loaded_file: Optional[str] = None

    priority_cases: Optional[pd.DataFrame] = None
    device_seasons: Optional[pd.DataFrame] = None
    user_seasons: Optional[pd.DataFrame] = None
    device_episodes: Optional[pd.DataFrame] = None
    user_episodes: Optional[pd.DataFrame] = None
    attack_chains: Optional[pd.DataFrame] = None
    historical_anomalies: Optional[pd.DataFrame] = None
    scenes: Optional[pd.DataFrame] = None
    stacking: Optional[pd.DataFrame] = None
    ai_stacking: Optional[pd.DataFrame] = None


state = AppState()


def find_latest_excel() -> Optional[str]:
    files = glob.glob(os.path.join(OUTPUT_DIR, "threat_hunt_*.xlsx"))
    return max(files, key=os.path.getmtime) if files else None


def _read_sheet(xl: pd.ExcelFile, name: str) -> Optional[pd.DataFrame]:
    if name not in xl.sheet_names:
        return None
    df = xl.parse(name)
    return df if not df.empty else pd.DataFrame(columns=df.columns)


def load_from_excel(path: str) -> None:
    """
    Read all module data from the given Excel workbook into memory.
    Also re-applies current suppressions so the in-memory state reflects
    any changes made via the suppression manager without a full pipeline re-run.
    """
    xl = pd.ExcelFile(path, engine="openpyxl")
    state.priority_cases = _read_sheet(xl, "Priority Cases")
    state.device_seasons = _read_sheet(xl, "Device Seasons")
    state.user_seasons = _read_sheet(xl, "User Seasons")
    state.device_episodes = _read_sheet(xl, "Episodes")
    state.user_episodes   = _read_sheet(xl, "User Episodes")
    state.attack_chains = _read_sheet(xl, "Attack Chains")
    state.historical_anomalies = _read_sheet(xl, "Historical Anomalies")
    state.scenes = _read_sheet(xl, "All Scenes")
    state.stacking = _read_sheet(xl, "Stacking Analysis")
    state.ai_stacking = _read_sheet(xl, "AI Threat Summary")
    state.loaded_file = os.path.basename(path)
    state.is_loaded = True
    xl.close()
    _apply_suppressions()


def _apply_suppressions() -> None:
    """
    Re-apply suppressions.csv to in-memory seasons and rebuild priority_cases.
    Called after load_from_excel and after any suppression add/remove.
    """
    suppressions = _load_suppression_map()
    if state.device_seasons is not None:
        state.device_seasons = _stamp_suppressed(state.device_seasons, "DeviceName", "Device", suppressions)
    if state.user_seasons is not None:
        state.user_seasons = _stamp_suppressed(state.user_seasons, "AccountName", "User", suppressions)
    _rebuild_priority_cases()


def _load_suppression_map() -> dict:
    """Return {(EntityType, entity_name_lower): reason} for active suppressions."""
    from datetime import datetime, timezone
    store_path = _suppression_store_path()
    if not os.path.exists(store_path):
        return {}
    today = datetime.now(timezone.utc).date()
    result = {}
    try:
        df = pd.read_csv(store_path, dtype=str).fillna("")
        for _, row in df.iterrows():
            expires = row.get("ExpiresDate", "").strip()
            if expires:
                try:
                    if datetime.strptime(expires, "%Y-%m-%d").date() < today:
                        continue
                except ValueError:
                    pass
            key = (row["EntityType"].strip(), row["EntityName"].strip().lower())
            result[key] = row.get("Reason", "").strip()
    except Exception:
        pass
    return result


def _stamp_suppressed(df: pd.DataFrame, entity_col: str, entity_type: str, suppressions: dict) -> pd.DataFrame:
    df = df.copy()
    df["IsSuppressed"] = False
    df["SuppressReason"] = ""
    for idx, row in df.iterrows():
        key = (entity_type, str(row[entity_col]).lower())
        if key in suppressions:
            df.at[idx, "IsSuppressed"] = True
            df.at[idx, "SuppressReason"] = suppressions[key]
    return df


def _rebuild_priority_cases() -> None:
    """Rebuild the priority_cases from current device/user seasons (respects IsSuppressed)."""
    if state.device_seasons is None and state.user_seasons is None:
        return

    priority_cols = [
        "EntityType", "EntityName", "TotalRisk", "RiskPercentile",
        "EpisodeCount", "TotalScenes", "UniqueTactics", "TacticSet",
        "PrimaryWorkflowClass", "AIWorkflowScenePct",
        "MaxEpisodeRisk", "FirstSeen", "LastSeen",
        "ZScore", "IsNewHigh", "IsScoreSpike", "IsTacticExpansion",
        "IsAdaptingTactics", "IsEmergingEntity", "NewTactics",
    ]

    parts = []
    for df, etype, ecol in [
        (state.device_seasons, "Device", "DeviceName"),
        (state.user_seasons, "User", "AccountName"),
    ]:
        if df is None or df.empty:
            continue
        elig = df["EligibleForPriority"].fillna(True).astype(bool) if "EligibleForPriority" in df.columns \
               else pd.Series(True, index=df.index)
        supp = df["IsSuppressed"].fillna(False).astype(bool) if "IsSuppressed" in df.columns \
               else pd.Series(False, index=df.index)
        d = df[elig & ~supp].copy()
        d["EntityType"] = etype
        d = d.rename(columns={ecol: "EntityName"})
        parts.append(d)

    if not parts:
        state.priority_cases = pd.DataFrame(columns=priority_cols)
        return

    combined = pd.concat(parts, ignore_index=True)
    available = [c for c in priority_cols if c in combined.columns]
    state.priority_cases = combined[available].sort_values("TotalRisk", ascending=False).reset_index(drop=True)


def _suppression_store_path() -> str:
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        raw = cfg.get("suppression", {}).get("store_path", "output/suppressions.csv")
        return os.path.join(ROOT_DIR, raw)
    except Exception:
        return os.path.join(OUTPUT_DIR, "suppressions.csv")


def df_to_records(df: Optional[pd.DataFrame]) -> list:
    """Serialize a DataFrame to JSON-safe list of dicts."""
    if df is None or df.empty:
        return []
    out = df.copy()
    for col in out.select_dtypes(include=["datetime64[ns]", "datetimetz"]).columns:
        out[col] = out[col].dt.strftime("%Y-%m-%dT%H:%M:%S")
    return json.loads(out.to_json(orient="records", date_format="iso"))
