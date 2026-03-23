"""
Threat Hunt Consolidation Script
=================================
Loads KQL export CSVs from data/, clusters scenes into episodes,
aggregates into device/user seasons, detects cross-device attack chains,
and writes a ranked Excel workbook to output/.

Expected CSV schema (all KQL queries must project these columns):
    Timestamp, DeviceName, AccountName, DetectionType, TacticCategory, Evidence

Usage:
    python consolidate.py [--data-dir data/] [--config config.json] [--out output/]
"""

import argparse
import json
import os
import sys
import warnings
from datetime import datetime, timezone

import pandas as pd

REQUIRED_COLUMNS = {"Timestamp", "DeviceName", "AccountName", "DetectionType", "TacticCategory", "Evidence"}


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    with open(path, "r") as f:
        cfg = json.load(f)
    assert "tactic_weights" in cfg, "config.json missing 'tactic_weights'"
    assert "episode_window_hours" in cfg, "config.json missing 'episode_window_hours'"
    return cfg


def load_scenes(data_dir: str, tactic_weights: dict) -> pd.DataFrame:
    """Load all CSV files from data_dir into a single scenes DataFrame."""
    frames = []
    for fname in sorted(os.listdir(data_dir)):
        if not fname.lower().endswith(".csv"):
            continue
        fpath = os.path.join(data_dir, fname)
        try:
            df = pd.read_csv(fpath)
        except Exception as e:
            print(f"  [WARN] Could not read {fname}: {e}")
            continue

        missing = REQUIRED_COLUMNS - set(df.columns)
        if missing:
            print(f"  [WARN] Skipping {fname} — missing columns: {missing}")
            continue

        # Parse tactic from filename prefix (e.g. execution_lolbin.csv -> Execution)
        tactic_prefix = fname.split("_")[0].capitalize()
        # Normalise TacticCategory in data to match config keys
        # The KQL writes it as e.g. "Execution" — use the file prefix as fallback
        df["SourceFile"] = fname

        # Warn if tactic not in config
        tactics_in_file = df["TacticCategory"].unique()
        for t in tactics_in_file:
            if t not in tactic_weights:
                print(f"  [WARN] {fname}: unknown TacticCategory '{t}' — will score as 1")

        frames.append(df)
        print(f"  [OK]   {fname}: {len(df)} scene(s)")

    if not frames:
        print("[ERROR] No valid CSV files found in data/. Exiting.")
        sys.exit(1)

    scenes = pd.concat(frames, ignore_index=True)
    scenes["Timestamp"] = pd.to_datetime(scenes["Timestamp"], utc=True, errors="coerce")
    scenes = scenes.dropna(subset=["Timestamp"])
    scenes["ScoreContribution"] = scenes["TacticCategory"].map(tactic_weights).fillna(1).astype(int)
    scenes["DeviceName"] = scenes["DeviceName"].str.strip().str.lower()
    scenes["AccountName"] = scenes["AccountName"].str.strip().str.lower()
    return scenes


# ---------------------------------------------------------------------------
# Episode clustering
# ---------------------------------------------------------------------------

def assign_episodes(scenes: pd.DataFrame, window_hours: float, entity_col: str) -> pd.DataFrame:
    """
    Group scenes on the same entity into episodes where any two consecutive
    scenes are within window_hours of each other.
    Returns scenes with added EpisodeID column (scoped to entity_col).
    """
    df = scenes.sort_values([entity_col, "Timestamp"]).copy()
    episode_ids = []
    ep_counter = 0
    prev_entity = None
    prev_ts = None
    window = pd.Timedelta(hours=window_hours)

    for _, row in df.iterrows():
        entity = row[entity_col]
        ts = row["Timestamp"]
        if entity != prev_entity or (prev_ts is not None and (ts - prev_ts) > window):
            ep_counter += 1
        episode_ids.append(ep_counter)
        prev_entity = entity
        prev_ts = ts

    df[f"EpisodeID_{entity_col}"] = episode_ids
    return df


def build_episodes(scenes: pd.DataFrame, entity_col: str, tactic_weights: dict) -> pd.DataFrame:
    """Aggregate scenes into episode-level summary."""
    ep_col = f"EpisodeID_{entity_col}"
    grp = scenes.groupby([entity_col, ep_col])

    records = []
    for (entity, ep_id), g in grp:
        tactics = g["TacticCategory"].unique().tolist()
        records.append({
            entity_col: entity,
            "EpisodeID": ep_id,
            "StartTime": g["Timestamp"].min(),
            "EndTime": g["Timestamp"].max(),
            "DurationHours": round((g["Timestamp"].max() - g["Timestamp"].min()).total_seconds() / 3600, 2),
            "SceneCount": len(g),
            "TacticCount": len(tactics),
            "Tactics": ", ".join(sorted(tactics)),
            "EpisodeRiskScore": int(g["ScoreContribution"].sum()),
        })

    return pd.DataFrame(records).sort_values("EpisodeRiskScore", ascending=False)


# ---------------------------------------------------------------------------
# Season aggregation
# ---------------------------------------------------------------------------

def build_seasons(episodes: pd.DataFrame, entity_col: str, tactic_weights: dict, scenes: pd.DataFrame) -> pd.DataFrame:
    """Aggregate episodes into season-level summary per entity."""
    tactic_cols = list(tactic_weights.keys())

    # Per-entity tactic score breakdown from scenes
    tactic_scores = (
        scenes.groupby([entity_col, "TacticCategory"])["ScoreContribution"]
        .sum()
        .unstack(fill_value=0)
        .reindex(columns=tactic_cols, fill_value=0)
    )
    tactic_scores.columns = [f"Score_{c}" for c in tactic_scores.columns]

    ep_summary = episodes.groupby(entity_col).agg(
        EpisodeCount=("EpisodeID", "count"),
        TotalRisk=("EpisodeRiskScore", "sum"),
        TotalScenes=("SceneCount", "sum"),
        MaxEpisodeRisk=("EpisodeRiskScore", "max"),
        FirstSeen=("StartTime", "min"),
        LastSeen=("EndTime", "max"),
        UniqueTactics=("TacticCount", "max"),
    )

    seasons = ep_summary.join(tactic_scores, how="left").fillna(0)
    seasons["TotalRisk"] = seasons["TotalRisk"].astype(int)
    seasons = seasons.sort_values("TotalRisk", ascending=False).reset_index()
    return seasons


# ---------------------------------------------------------------------------
# Attack chain detection
# ---------------------------------------------------------------------------

def build_attack_chains(device_seasons: pd.DataFrame, scenes: pd.DataFrame) -> pd.DataFrame:
    """
    Link devices that share an AccountName into attack chains.
    Returns a summary of chains with pivot accounts and combined risk.
    """
    # Build map: account -> set of devices
    account_devices = (
        scenes.groupby("AccountName")["DeviceName"]
        .apply(lambda x: set(x.tolist()))
        .reset_index()
    )
    # Only accounts that appear on more than one device
    account_devices = account_devices[account_devices["DeviceName"].apply(len) > 1]

    if account_devices.empty:
        return pd.DataFrame(columns=["ChainID", "Devices", "PivotAccounts", "DeviceCount", "ChainRiskScore"])

    # Union-Find to merge overlapping device sets
    parent = {}

    def find(x):
        while parent.get(x, x) != x:
            parent[x] = parent.get(parent.get(x, x), parent.get(x, x))
            x = parent.get(x, x)
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for _, row in account_devices.iterrows():
        devices = list(row["DeviceName"])
        for d in devices[1:]:
            union(devices[0], d)

    # Group devices by chain root
    all_devices = scenes["DeviceName"].unique().tolist()
    chain_map = {}
    for d in all_devices:
        root = find(d)
        chain_map.setdefault(root, set()).add(d)

    # Only keep chains with >1 device
    chains = {root: devs for root, devs in chain_map.items() if len(devs) > 1}

    if not chains:
        return pd.DataFrame(columns=["ChainID", "Devices", "PivotAccounts", "DeviceCount", "ChainRiskScore"])

    # Build chain risk scores using device_seasons
    device_risk = device_seasons.set_index("DeviceName")["TotalRisk"].to_dict()

    records = []
    for chain_id, (root, devs) in enumerate(chains.items(), start=1):
        pivot_accounts = account_devices[
            account_devices["DeviceName"].apply(lambda s: len(s & devs) > 1)
        ]["AccountName"].tolist()
        chain_risk = sum(device_risk.get(d, 0) for d in devs)
        records.append({
            "ChainID": chain_id,
            "Devices": " | ".join(sorted(devs)),
            "PivotAccounts": " | ".join(sorted(pivot_accounts)),
            "DeviceCount": len(devs),
            "ChainRiskScore": chain_risk,
        })

    return pd.DataFrame(records).sort_values("ChainRiskScore", ascending=False).reset_index(drop=True)


# ---------------------------------------------------------------------------
# Excel output
# ---------------------------------------------------------------------------

def auto_width(worksheet, df: pd.DataFrame, max_width: int = 80):
    """Set column widths based on content."""
    for i, col in enumerate(df.columns):
        max_len = max(
            df[col].astype(str).map(len).max() if len(df) > 0 else 0,
            len(str(col))
        )
        worksheet.set_column(i, i, min(max_len + 2, max_width))


def write_excel(
    output_path: str,
    scenes: pd.DataFrame,
    device_episodes: pd.DataFrame,
    device_seasons: pd.DataFrame,
    user_seasons: pd.DataFrame,
    attack_chains: pd.DataFrame,
    tactic_weights: dict,
):
    with pd.ExcelWriter(output_path, engine="xlsxwriter") as writer:
        wb = writer.book

        # Formats
        header_fmt = wb.add_format({"bold": True, "bg_color": "#1F3864", "font_color": "#FFFFFF", "border": 1})
        risk_high = wb.add_format({"bg_color": "#FF4444", "font_color": "#FFFFFF"})
        risk_med  = wb.add_format({"bg_color": "#FFA500"})
        risk_low  = wb.add_format({"bg_color": "#FFFF88"})

        def write_sheet(name: str, df: pd.DataFrame, freeze_col: int = 1):
            if df.empty:
                df = pd.DataFrame(columns=df.columns if hasattr(df, "columns") else [])
            # Excel doesn't support timezone-aware datetimes — strip tz info
            df = df.copy()
            for col in df.select_dtypes(include=["datetimetz"]).columns:
                df[col] = df[col].dt.tz_localize(None)
            df.to_excel(writer, sheet_name=name, index=False)
            ws = writer.sheets[name]
            for col_num, col_name in enumerate(df.columns):
                ws.write(0, col_num, col_name, header_fmt)
            auto_width(ws, df)
            if freeze_col:
                ws.freeze_panes(1, freeze_col)

        # 1. Device Seasons
        write_sheet("Device Seasons", device_seasons)

        # 2. User Seasons
        write_sheet("User Seasons", user_seasons)

        # 3. Attack Chains
        write_sheet("Attack Chains", attack_chains)

        # 4. Episodes (device-centric)
        write_sheet("Episodes", device_episodes)

        # 5. Per-tactic sheets
        for tactic in sorted(tactic_weights.keys()):
            tactic_scenes = scenes[scenes["TacticCategory"] == tactic].copy()
            tactic_scenes = tactic_scenes.sort_values("Timestamp", ascending=False)
            # Drop internal columns before export
            export_cols = ["Timestamp", "DeviceName", "AccountName", "DetectionType", "TacticCategory", "Evidence", "SourceFile"]
            tactic_scenes = tactic_scenes[[c for c in export_cols if c in tactic_scenes.columns]]
            write_sheet(tactic, tactic_scenes)

        # 6. All Scenes
        all_scenes = scenes.sort_values("Timestamp", ascending=False)
        export_cols = ["Timestamp", "DeviceName", "AccountName", "DetectionType", "TacticCategory", "Evidence", "SourceFile"]
        all_scenes = all_scenes[[c for c in export_cols if c in all_scenes.columns]]
        write_sheet("All Scenes", all_scenes)

    print(f"\n[OK] Workbook written: {output_path}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Threat Hunt Consolidation Script")
    parser.add_argument("--data-dir", default="data", help="Directory containing CSV exports")
    parser.add_argument("--config", default="config.json", help="Path to config.json")
    parser.add_argument("--out", default="output", help="Output directory for Excel workbook")
    args = parser.parse_args()

    # Resolve paths relative to script location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir   = os.path.join(script_dir, args.data_dir)
    config_path = os.path.join(script_dir, args.config)
    out_dir    = os.path.join(script_dir, args.out)
    os.makedirs(out_dir, exist_ok=True)

    print(f"[*] Loading config: {config_path}")
    cfg = load_config(config_path)
    tactic_weights = cfg["tactic_weights"]
    episode_window = cfg["episode_window_hours"]
    print(f"    Tactic weights: {tactic_weights}")
    print(f"    Episode window: {episode_window}h")

    print(f"\n[*] Loading scenes from: {data_dir}")
    scenes = load_scenes(data_dir, tactic_weights)
    print(f"    Total scenes loaded: {len(scenes)}")

    print("\n[*] Clustering scenes into episodes (device-centric)...")
    scenes_dev = assign_episodes(scenes, episode_window, "DeviceName")
    device_episodes = build_episodes(scenes_dev, "DeviceName", tactic_weights)
    print(f"    Episodes found: {len(device_episodes)}")

    print("[*] Clustering scenes into episodes (user-centric)...")
    scenes_usr = assign_episodes(scenes, episode_window, "AccountName")
    user_episodes = build_episodes(scenes_usr, "AccountName", tactic_weights)

    print("[*] Aggregating device seasons...")
    device_seasons = build_seasons(device_episodes, "DeviceName", tactic_weights, scenes)
    print(f"    Devices in scope: {len(device_seasons)}")

    print("[*] Aggregating user seasons...")
    user_seasons = build_seasons(user_episodes, "AccountName", tactic_weights, scenes)
    print(f"    Users in scope: {len(user_seasons)}")

    print("[*] Detecting attack chains...")
    attack_chains = build_attack_chains(device_seasons, scenes)
    print(f"    Chains detected: {len(attack_chains)}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(out_dir, f"threat_hunt_{timestamp}.xlsx")
    print(f"\n[*] Writing Excel workbook...")
    write_excel(output_path, scenes, device_episodes, device_seasons, user_seasons, attack_chains, tactic_weights)

    # Summary to console
    print("\n" + "="*60)
    print("SEASON SUMMARY — TOP DEVICES BY RISK")
    print("="*60)
    top = device_seasons.head(10)[["DeviceName", "EpisodeCount", "TotalRisk", "TotalScenes"]]
    print(top.to_string(index=False))

    if not attack_chains.empty:
        print("\n" + "="*60)
        print("ATTACK CHAINS DETECTED")
        print("="*60)
        print(attack_chains[["ChainID", "Devices", "PivotAccounts", "ChainRiskScore"]].to_string(index=False))

    print("\nDone.")


if __name__ == "__main__":
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        main()
