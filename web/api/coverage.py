"""GET /api/coverage — detection sensor health and landscape view."""

import json
import os
import sqlite3

from fastapi import APIRouter

from state import ROOT_DIR, CONFIG_PATH, state

router = APIRouter()


def _db_path() -> str:
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        raw = cfg.get("history", {}).get("store_path", "output/hunt_history.db")
        return os.path.join(ROOT_DIR, raw)
    except Exception:
        return os.path.join(ROOT_DIR, "output", "hunt_history.db")


def _load_config_inventory() -> tuple[list[str], dict[str, str]]:
    """Return (ordered list of DetectionTypes, family map) from config behavior_families."""
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        families: dict[str, str] = cfg.get("behavior_families", {})
        return list(families.keys()), families
    except Exception:
        return [], {}


def _current_stats(inventory: list[str]) -> dict:
    """Per-DetectionType stats from the currently loaded scenes DataFrame."""
    result = {dt: {"scene_count": 0, "device_count": 0, "top_devices": []} for dt in inventory}
    sc = state.scenes
    if sc is None or sc.empty or "DetectionType" not in sc.columns:
        return result

    for dt, grp in sc.groupby("DetectionType"):
        if dt not in result:
            result[dt] = {"scene_count": 0, "device_count": 0, "top_devices": []}
        result[dt]["scene_count"] = int(len(grp))
        if "DeviceName" in grp.columns:
            result[dt]["device_count"] = int(grp["DeviceName"].nunique())
            top = (
                grp.groupby("DeviceName")
                .size()
                .sort_values(ascending=False)
                .head(5)
            )
            result[dt]["top_devices"] = [
                {"device": dev, "scenes": int(cnt)} for dev, cnt in top.items()
            ]
    return result


def _history_stats(inventory: list[str]) -> tuple[dict, int]:
    """
    Per-DetectionType history stats from detection_history table.
    Returns (stats_dict, total_runs_recorded).
    stats_dict keys: last_seen_ts, runs_fired, prev_device_count
    """
    default = {"last_seen_ts": None, "runs_fired": 0, "prev_device_count": None}
    result = {dt: dict(default) for dt in inventory}
    total_runs = 0

    db = _db_path()
    if not os.path.exists(db):
        return result, total_runs

    try:
        con = sqlite3.connect(db)

        # Check table exists
        tbl = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='detection_history'"
        ).fetchone()
        if tbl is None:
            con.close()
            return result, total_runs

        # Total distinct runs ever recorded
        total_runs = con.execute(
            "SELECT COUNT(DISTINCT RunId) FROM detection_history"
        ).fetchone()[0] or 0

        if total_runs == 0:
            con.close()
            return result, total_runs

        # Ordered run epochs (most recent first) to find previous run
        run_epochs = [
            r[0] for r in con.execute(
                "SELECT DISTINCT RunTimestampEpoch FROM detection_history ORDER BY RunTimestampEpoch DESC"
            ).fetchall()
        ]
        prev_epoch = run_epochs[1] if len(run_epochs) >= 2 else None

        # Per-detection aggregate stats
        rows = con.execute("""
            SELECT DetectionType,
                   MAX(RunTimestamp)      AS last_seen_ts,
                   COUNT(DISTINCT RunId)  AS runs_fired
            FROM   detection_history
            GROUP  BY DetectionType
        """).fetchall()

        for dt, last_ts, fired in rows:
            if dt in result:
                result[dt]["last_seen_ts"] = last_ts
                result[dt]["runs_fired"] = int(fired)

        # Previous-run device counts (for trend indicator)
        if prev_epoch is not None:
            prev_rows = con.execute(
                "SELECT DetectionType, DeviceCount FROM detection_history WHERE RunTimestampEpoch = ?",
                (prev_epoch,),
            ).fetchall()
            for dt, dc in prev_rows:
                if dt in result:
                    result[dt]["prev_device_count"] = int(dc)

        con.close()
    except Exception:
        pass

    return result, total_runs


@router.get("/coverage")
def get_coverage():
    inventory, families = _load_config_inventory()
    current = _current_stats(inventory)
    history, total_runs = _history_stats(inventory)

    detections = []
    for dt in inventory:
        cur = current.get(dt, {"scene_count": 0, "device_count": 0, "top_devices": []})
        hist = history.get(dt, {"last_seen_ts": None, "runs_fired": 0, "prev_device_count": None})

        scene_count  = cur["scene_count"]
        device_count = cur["device_count"]
        runs_fired   = hist["runs_fired"]
        last_seen_ts = hist["last_seen_ts"]
        prev_dc      = hist["prev_device_count"]

        if device_count > 0:
            status = "Active"
        elif runs_fired > 0:
            status = "Silent"
        else:
            status = "Never seen"

        # Trend: % change in device count vs previous run (None if not enough history)
        trend_pct = None
        trend_dir = None
        if prev_dc is not None:
            if prev_dc == 0 and device_count > 0:
                trend_dir = "up"
                trend_pct = None  # new appearance — show arrow without a %
            elif prev_dc > 0:
                delta = device_count - prev_dc
                trend_pct = round(delta / prev_dc * 100, 1)
                trend_dir = "up" if delta > 0 else ("down" if delta < 0 else "flat")

        detections.append({
            "detection_type":    dt,
            "family":            families.get(dt, "Unknown"),
            "status":            status,
            "scene_count":       scene_count,
            "device_count":      device_count,
            "last_seen_ts":      last_seen_ts,
            "runs_fired":        runs_fired,
            "total_runs":        total_runs,
            "top_devices":       cur["top_devices"],
            "prev_device_count": prev_dc,
            "trend_dir":         trend_dir,
            "trend_pct":         trend_pct,
        })

    return {
        "loaded":     state.is_loaded,
        "total_runs": total_runs,
        "detections": detections,
    }
