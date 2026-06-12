"""
In-memory application state — populated on startup and on explicit reload.

All route handlers read from the singleton `state` object. The pipeline
endpoint writes to it after a successful run or reload.
"""

import glob
import json
import math
import os
import sqlite3
import sys
from dataclasses import dataclass, field
from typing import Optional

import pandas as pd

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(ROOT_DIR, "output")
CONFIG_PATH = os.path.join(ROOT_DIR, "config.json")
DATA_DIR = os.path.join(ROOT_DIR, "data")

# triage.py lives at the repo root (shared with consolidate.py)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
import triage as triage_store  # noqa: E402
import casecluster  # noqa: E402


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
    slow_chains: Optional[pd.DataFrame] = None
    outbreaks: Optional[pd.DataFrame] = None
    campaigns: Optional[pd.DataFrame] = None
    scenes: Optional[pd.DataFrame] = None


state = AppState()


def find_latest_excel() -> Optional[str]:
    files = glob.glob(os.path.join(OUTPUT_DIR, "threat_hunt_*.xlsx"))
    return max(files, key=os.path.getmtime) if files else None


def _read_sheet(xl: pd.ExcelFile, name: str) -> Optional[pd.DataFrame]:
    if name not in xl.sheet_names:
        return None
    df = xl.parse(name)
    return df if not df.empty else pd.DataFrame(columns=df.columns)


def _enrich_behavior_families(
    seasons_df: Optional[pd.DataFrame],
    entity_col: str,
    episodes_df: Optional[pd.DataFrame],
) -> Optional[pd.DataFrame]:
    """Add BehaviorFamilies column to a seasons DataFrame by aggregating from episodes."""
    if seasons_df is None or seasons_df.empty:
        return seasons_df
    if episodes_df is None or episodes_df.empty or "BehaviorFamilies" not in episodes_df.columns:
        seasons_df = seasons_df.copy()
        seasons_df["BehaviorFamilies"] = ""
        return seasons_df

    entity_to_families: dict = {}
    for entity, group in episodes_df.groupby(entity_col):
        families: set = set()
        for bf_str in group["BehaviorFamilies"].dropna():
            for f in str(bf_str).split(","):
                f = f.strip()
                if f and f != "Unknown":
                    families.add(f)
        entity_to_families[entity] = ", ".join(sorted(families))

    seasons_df = seasons_df.copy()
    seasons_df["BehaviorFamilies"] = seasons_df[entity_col].map(entity_to_families).fillna("")
    return seasons_df


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
    state.slow_chains = _read_sheet(xl, "Slow Kill Chains")
    state.outbreaks = _read_sheet(xl, "Detection Outbreaks")
    state.campaigns = _read_sheet(xl, "Campaigns")
    state.scenes = _read_sheet(xl, "All Scenes")
    state.loaded_file = os.path.basename(path)
    state.is_loaded = True
    xl.close()
    state.device_seasons = _enrich_behavior_families(state.device_seasons, "DeviceName", state.device_episodes)
    state.user_seasons   = _enrich_behavior_families(state.user_seasons,   "AccountName", state.user_episodes)
    _apply_suppressions()


def _apply_suppressions() -> None:
    """
    Re-apply entity and pattern suppressions to in-memory seasons, then rebuild priority_cases.
    Called after load_from_excel and after any suppression/pattern add/remove.
    """
    suppressions = _load_suppression_map()
    patterns = _load_active_patterns()
    if state.device_seasons is not None:
        state.device_seasons = _stamp_suppressed(
            state.device_seasons, "DeviceName", "Device", suppressions, patterns
        )
    if state.user_seasons is not None:
        state.user_seasons = _stamp_suppressed(
            state.user_seasons, "AccountName", "User", suppressions, patterns
        )
    _rebuild_priority_cases()
    _apply_triage()


def _load_config() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def triage_store_path() -> str:
    return triage_store.resolve_store_path(_load_config(), ROOT_DIR)


def _apply_triage() -> None:
    """Stamp triage columns onto the in-memory priority_cases.

    Called after every priority rebuild and after every triage write, so the
    table reflects analyst state immediately. Triage never removes or re-ranks
    rows — display columns only (the web UI does its own Benign filtering).
    """
    if state.priority_cases is None:
        return
    cfg = _load_config()
    try:
        states = triage_store.load_current_states(triage_store.resolve_store_path(cfg, ROOT_DIR))
        states = triage_store.states_with_cluster_propagation(state.priority_cases, states)
        state.priority_cases = triage_store.stamp_triage(state.priority_cases, states, cfg)
    except Exception:
        pass  # a broken triage store must never take down the dashboard


def _load_suppression_map() -> dict:
    """Return {(EntityType, entity_name_lower): reason} for active entity suppressions."""
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


def _load_active_patterns() -> list:
    """Return active (non-expired) pattern suppression rules from JSON."""
    from datetime import datetime
    path = _pattern_store_path()
    if not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            patterns = json.load(f)
        today = datetime.now().date()
        active = []
        for p in patterns:
            expires = p.get("expires_date") or ""
            if expires:
                try:
                    if datetime.strptime(expires, "%Y-%m-%d").date() < today:
                        continue
                except ValueError:
                    pass
            active.append(p)
        return active
    except Exception:
        return []


def _evaluate_pattern(row: pd.Series, entity_type: str, pattern: dict) -> bool:
    """Return True if this season row matches all conditions in the pattern (AND logic)."""
    for cond in pattern.get("conditions", []):
        field = cond["field"]
        op    = cond["op"]
        value = cond["value"]

        if field == "EntityType":
            row_val = entity_type
        else:
            row_val = row.get(field)
            if row_val is None or (isinstance(row_val, float) and pd.isna(row_val)):
                return False

        try:
            if field in ("UniqueTactics", "TotalRisk", "AIWorkflowScenePct"):
                rv, cv = float(row_val), float(value)
                if op == "="  and not (rv == cv): return False
                if op == "<"  and not (rv <  cv): return False
                if op == "<=" and not (rv <= cv): return False
                if op == ">"  and not (rv >  cv): return False
                if op == ">=" and not (rv >= cv): return False
            else:
                if str(row_val) != str(value):
                    return False
        except (ValueError, TypeError):
            return False
    return True


def _format_pattern_reason(pattern: dict) -> str:
    cond_strs = [f"{c['field']}{c['op']}{c['value']}" for c in pattern.get("conditions", [])]
    return f"Pattern '{pattern['name']}': {pattern['reason']} [{', '.join(cond_strs)}]"


def _stamp_suppressed(
    df: pd.DataFrame,
    entity_col: str,
    entity_type: str,
    suppressions: dict,
    patterns: list,
) -> pd.DataFrame:
    df = df.copy()
    df["IsSuppressed"]  = False
    df["SuppressReason"] = ""
    df["SuppressType"]  = ""
    for idx, row in df.iterrows():
        # Entity suppression takes priority
        key = (entity_type, str(row[entity_col]).lower())
        if key in suppressions:
            df.at[idx, "IsSuppressed"]   = True
            df.at[idx, "SuppressReason"] = suppressions[key]
            df.at[idx, "SuppressType"]   = "Entity"
            continue
        # Pattern suppression (OR across patterns)
        for pattern in patterns:
            if _evaluate_pattern(row, entity_type, pattern):
                df.at[idx, "IsSuppressed"]   = True
                df.at[idx, "SuppressReason"] = _format_pattern_reason(pattern)
                df.at[idx, "SuppressType"]   = "Pattern"
                break
    return df


def _historical_priority(row: pd.Series) -> float:
    """Mirror of consolidate._compute_priority — kept in sync manually."""
    zscore = float(row.get("ZScore") or 0)
    base = max(0.0, min(zscore, 10.0))
    bonuses = (
        (3.0 if row.get("IsScoreSpike")      else 0.0) +
        (2.0 if row.get("IsNewHigh")          else 0.0) +
        (2.5 if row.get("IsTacticExpansion")  else 0.0) +
        (2.5 if row.get("IsAdaptingTactics")  else 0.0) +
        (2.5 if row.get("IsNewDevicePairing") else 0.0) +
        (1.5 if row.get("IsEmergingEntity")   else 0.0) +
        (1.0 if row.get("IsZScoreAnomaly")    else 0.0)
    )
    total_risk = float(row.get("TotalRisk") or 0)
    dampener = math.log10(total_risk + 1) / math.log10(101)
    return round((base + bonuses) * dampener, 2)


def _rebuild_priority_cases() -> None:
    """Rebuild the priority_cases from current device/user seasons (respects IsSuppressed).

    Ranked by CompositeScore = TotalRisk + HistoricalPriority * priority_history_weight
    so that anomalous entities surface above equally-risky stable ones.
    """
    if state.device_seasons is None and state.user_seasons is None:
        return

    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
    except Exception:
        cfg = {}
    history_weight = float(cfg.get("priority_history_weight", 0.5))
    min_score = float(cfg.get("priority_min_composite_score", 0) or 0)
    max_cases = int(cfg.get("priority_max_cases", 0) or 0)

    priority_cols = [
        "EntityType", "EntityName", "CompositeScore", "TotalRisk", "HistoricalPriority",
        "RiskPercentile", "EpisodeCount", "TotalScenes", "UniqueTactics", "TacticSet",
        "BehaviorFamilies",
        "PrimaryWorkflowClass", "AIWorkflowScenePct",
        "MaxEpisodeRisk", "FirstSeen", "LastSeen",
        "ZScore", "IsNewHigh", "IsScoreSpike", "IsTacticExpansion",
        "IsAdaptingTactics", "IsNewDevicePairing", "IsEmergingEntity",
        "NewTactics", "NewPairings",
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
    combined["HistoricalPriority"] = combined.apply(_historical_priority, axis=1)
    combined["CompositeScore"] = (
        combined["TotalRisk"].fillna(0) + combined["HistoricalPriority"] * history_weight
    ).round(2)
    available = [c for c in priority_cols if c in combined.columns]
    ranked = combined[available].sort_values("CompositeScore", ascending=False).reset_index(drop=True)
    ranked = casecluster.cluster_priority_cases(ranked, state.scenes, cfg)
    if min_score > 0:
        ranked = ranked[ranked["CompositeScore"].fillna(0) >= min_score].reset_index(drop=True)
    if max_cases > 0 and len(ranked) > max_cases:
        ranked = ranked.head(max_cases).reset_index(drop=True)
    state.priority_cases = ranked


def _suppression_store_path() -> str:
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        raw = cfg.get("suppression", {}).get("store_path", "output/suppressions.csv")
        return os.path.join(ROOT_DIR, raw)
    except Exception:
        return os.path.join(OUTPUT_DIR, "suppressions.csv")


def _pattern_store_path() -> str:
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        raw = cfg.get("suppression", {}).get("pattern_store_path", "output/pattern_suppressions.json")
        return os.path.join(ROOT_DIR, raw)
    except Exception:
        return os.path.join(OUTPUT_DIR, "pattern_suppressions.json")


def df_to_records(df: Optional[pd.DataFrame]) -> list:
    """Serialize a DataFrame to JSON-safe list of dicts."""
    if df is None or df.empty:
        return []
    out = df.copy()
    for col in out.select_dtypes(include=["datetime64[ns]", "datetimetz"]).columns:
        out[col] = out[col].dt.strftime("%Y-%m-%dT%H:%M:%S")
    return json.loads(out.to_json(orient="records", date_format="iso"))
