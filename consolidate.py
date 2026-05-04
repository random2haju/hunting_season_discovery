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
import math
import os
import re
import sqlite3
import sys
import uuid
import warnings
from collections import Counter
from datetime import datetime, timezone

import numpy as np
import pandas as pd

REQUIRED_COLUMNS = {"Timestamp", "DeviceName", "AccountName", "DetectionType", "TacticCategory", "Evidence"}
HISTORY_OUTPUT_VERSION = 1


# ---------------------------------------------------------------------------
# Context classification helpers
# ---------------------------------------------------------------------------

def _build_tier_lookup(cfg: dict) -> dict:
    """Build O(1) process-name → tier-name dict from execution_trust_tiers config."""
    lookup = {}
    for tier, procs in cfg.get("execution_trust_tiers", {}).items():
        for p in procs:
            lookup[p.lower()] = tier
    return lookup


# Normalise variant key names from different KQL queries into canonical forms.
# This lets downstream code use consistent keys regardless of which query produced the row.
_CANONICAL_KEY_MAP: dict = {
    # Network destination (IP, URL, or domain)
    "remoteurl":  "destination",
    "url":        "destination",
    "dest":       "destination",
    "remoteip":   "destination",
    "destip":     "destination",
    # Registry
    "registrykey": "registry_key",
    "regkey":      "registry_key",
    # Scheduled task
    "scheduledtask": "scheduled_task",
    "task":          "scheduled_task",
    # Service
    "servicename": "service_name",
    "service":     "service_name",
    # File hash
    "sha256": "file_hash",
    "md5":    "file_hash",
    "hash":   "file_hash",
}


def parse_evidence_fields(evidence_str: str) -> dict:
    """
    Parse pipe-delimited 'Key: value | Key2: value2' Evidence string into a
    lowercase-key dict.  Segments without ': ' are silently ignored.
    Keys are normalised via _CANONICAL_KEY_MAP so callers see consistent names
    regardless of which KQL query produced the evidence string.
    """
    result = {}
    if not isinstance(evidence_str, str) or not evidence_str.strip():
        return result
    for segment in evidence_str.split(" | "):
        if ": " in segment:
            key, _, value = segment.partition(": ")
            k = key.strip().lower()
            result[_CANONICAL_KEY_MAP.get(k, k)] = value.strip()
    return result


def _extract_destination(pe: dict) -> str:
    """Return the destination field from a parsed evidence dict, or empty string."""
    return pe.get("destination", "")


def classify_execution_tier(detection_type: str, parsed_ev: dict, tier_lookup: dict) -> str:
    """
    Return the execution trust tier for a scene.
    Only classifies shell/execution detection types; all others return 'not_classified'.
    """
    execution_types = {"Jupyter Shell Execution", "Shadow AI Tooling"}
    if detection_type not in execution_types:
        return "not_classified"
    process = parsed_ev.get("process", "").lower()
    return tier_lookup.get(process, "unknown")


def classify_execution_context(parsed_ev: dict, dev_parents_lower: list) -> str:
    """
    Derive execution context from the Parent field in parsed Evidence.
    Returns 'DeveloperTooling' | 'SuspiciousShape' | 'Unknown'.
    """
    parent = parsed_ev.get("parent", "").lower()
    if not parent:
        return "Unknown"
    if parent in dev_parents_lower:
        return "DeveloperTooling"
    if parent in {"svchost.exe", "services.exe", "lsass.exe", "winlogon.exe"}:
        return "SuspiciousShape"
    return "Unknown"


def score_commandline_shape(parsed_ev: dict, cfg: dict) -> float:
    """
    Score the CmdLine field from parsed Evidence for suspicious vs benign patterns.
    Returns a float multiplier: high_risk=2.0, medium_risk=1.3, low_risk=0.4, neutral=1.0.
    Patterns are checked in priority order; first match wins.
    """
    cmdline = parsed_ev.get("cmdline", "")
    if not cmdline:
        return 1.0
    risk_patterns = cfg.get("cmdline_risk_patterns", {})
    risk_multipliers = cfg.get("cmdline_risk_multipliers", {})
    cmdline_lower = cmdline.lower()
    for tier in ("high_risk", "medium_risk", "low_risk"):
        for pattern in risk_patterns.get(tier, []):
            if ".*" in pattern:
                if re.search(pattern, cmdline, flags=re.IGNORECASE):
                    return risk_multipliers.get(tier, 1.0)
            elif pattern.lower() in cmdline_lower:
                return risk_multipliers.get(tier, 1.0)
    return risk_multipliers.get("neutral", 1.0)


def compute_context_multiplier(tier: str, context: str, cmdline_score: float, cfg: dict) -> float:
    """
    Combine execution tier multiplier × developer-context discount × command-line shape score.
    Floor at 0.05 so every scene stays visible to analysts.
    """
    tier_mults = cfg.get("execution_tier_multipliers", {})
    # Unclassified scenes are not adjusted by tier
    tier_mult = 1.0 if tier == "not_classified" else tier_mults.get(tier, 1.0)
    dev_discount = 1.0
    # Dev discount only applies to baseline-common tier — contextual/high-signal are suspicious regardless of parent
    if context == "DeveloperTooling" and tier == "baseline_common":
        dev_discount = cfg.get("dev_context_discount", 0.25)
    # Suspicious parent escalates contextual tier to high-signal scoring
    if context == "SuspiciousShape" and tier == "contextual":
        tier_mult = tier_mults.get("high_signal", 1.8)  # noqa: no config key change needed — tier names unchanged
    return max(round(tier_mult * dev_discount * cmdline_score, 3), 0.05)


def classify_workflow_class(evidence_str: str, parsed_ev: dict, execution_context: str, cfg: dict) -> tuple:
    """
    Classify a scene's workflow context for eligibility gating and analyst routing.

    Returns (workflow_class, reasons_str):
      workflow_class: "AIWorkflow" | "DeveloperAutomation" | "Unknown"
      reasons_str:    human-readable explanation included in the AI/Dev Outliers sheet

    AIWorkflow fires when the evidence string, process name, or parent process name
    contains known AI agent indicators (e.g. /.claude/ paths, claude.exe).
    DeveloperAutomation fires when the parent is a known IDE/terminal but no AI
    indicators are present.
    """
    wf_cfg           = cfg.get("workflow_classification", {})
    ai_path_patterns = wf_cfg.get("ai_path_patterns", ["/.claude/", "\\.claude\\"])

    def _stem(name: str) -> str:
        """Strip .exe/.cmd/.bat extension for comparison so 'bash' matches 'bash.exe'."""
        n = name.lower()
        for ext in (".exe", ".cmd", ".bat", ".sh"):
            if n.endswith(ext):
                return n[: -len(ext)]
        return n

    ai_process_stems = {_stem(n) for n in wf_cfg.get("ai_process_names", ["claude", "claude.exe", "claude-code"])}
    ai_parent_stems  = {_stem(n) for n in wf_cfg.get("ai_parent_names",  ["claude.exe", "claude-code", "claude"])}

    ai_pairs = [
        (_stem(pair[0]), _stem(pair[1]))
        for pair in wf_cfg.get("ai_process_parent_pairs", [["bash", "bash"]])
        if len(pair) == 2
    ]

    reasons = []
    process = parsed_ev.get("process", "").lower()
    parent  = parsed_ev.get("parent",  "").lower()
    process_stem = _stem(process)
    parent_stem  = _stem(parent)

    if process_stem in ai_process_stems:
        reasons.append(f"process={process}")
    if parent_stem in ai_parent_stems:
        reasons.append(f"parent={parent}")

    for proc_s, par_s in ai_pairs:
        if process_stem == proc_s and parent_stem == par_s:
            reasons.append(f"process-parent pair {process}->{parent}")
            break

    ev_lower = (evidence_str or "").lower()
    for pat in ai_path_patterns:
        if pat.lower() in ev_lower:
            reasons.append(f"path contains {pat}")
            break

    if reasons:
        return "AIWorkflow", "; ".join(reasons)

    if execution_context == "DeveloperTooling":
        return "DeveloperAutomation", "parent is a known developer tool"

    return "Unknown", ""


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_config(path: str) -> dict:
    with open(path, "r") as f:
        cfg = json.load(f)
    assert "tactic_weights" in cfg, "config.json missing 'tactic_weights'"
    assert "episode_window_hours" in cfg, "config.json missing 'episode_window_hours'"
    log_base = cfg.get("season_diminishing_returns", {}).get("diminishing_log_base", 2.0)
    assert log_base > 1.0, (
        f"config.json: season_diminishing_returns.diminishing_log_base must be > 1.0 (got {log_base})"
    )
    return cfg


def load_scenes(data_dir: str, tactic_weights: dict, cfg: dict) -> pd.DataFrame:
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
    n_before = len(scenes)
    scenes = scenes.dropna(subset=["Timestamp"])
    dropped = n_before - len(scenes)
    if dropped:
        print(f"  [WARN] Dropped {dropped} row(s) with unparseable timestamps")
    scenes["ScoreContribution"] = scenes["TacticCategory"].map(tactic_weights).fillna(1).astype(int)

    # Optional per-DetectionType multipliers — fine-grained tuning on top of tactic weights
    dt_mult = cfg.get("detection_type_multipliers", {})
    if dt_mult:
        scenes["ScoreContribution"] = (
            scenes["ScoreContribution"]
            * scenes["DetectionType"].map(dt_mult).fillna(1.0)
        ).round(1)

    # --- Context classification pipeline ---
    # Parses Evidence string once and derives LOLBin tier, parent context, and
    # command-line shape; combines them into a ContextMultiplier applied to ScoreContribution.
    tier_lookup = _build_tier_lookup(cfg)
    dev_parents_lower = {p.lower() for p in cfg.get("developer_parent_processes", [])}
    behavior_families_map = cfg.get("behavior_families", {})

    parsed_evs = scenes["Evidence"].apply(parse_evidence_fields)

    scenes["ExecutionTier"] = [
        classify_execution_tier(dt, pe, tier_lookup)
        for dt, pe in zip(scenes["DetectionType"], parsed_evs)
    ]
    scenes["ExecutionContext"] = [
        classify_execution_context(pe, dev_parents_lower) for pe in parsed_evs
    ]
    scenes["CommandLineRiskScore"] = [
        score_commandline_shape(pe, cfg) for pe in parsed_evs
    ]
    scenes["ContextMultiplier"] = [
        compute_context_multiplier(tier, ctx, clrs, cfg)
        for tier, ctx, clrs in zip(
            scenes["ExecutionTier"], scenes["ExecutionContext"], scenes["CommandLineRiskScore"]
        )
    ]
    scenes["ScoreContribution"] = (
        scenes["ScoreContribution"] * scenes["ContextMultiplier"]
    ).round(2)
    scenes["BehaviorFamily"] = scenes["DetectionType"].map(behavior_families_map).fillna("Unknown")
    scenes["TrustContext"] = np.where(
        (scenes["ExecutionContext"] == "DeveloperTooling") & (scenes["ExecutionTier"] == "baseline_common"),
        "DevContext",
        np.where(
            (scenes["ExecutionContext"] == "SuspiciousShape") | (scenes["CommandLineRiskScore"] >= 1.3),
            "Suspicious", "Neutral"
        )
    )

    # --- Workflow classification ---
    # Runs after context classification so ExecutionContext is available.
    # Produces WorkflowClass (AIWorkflow / DeveloperAutomation / Unknown) and a
    # human-readable WorkflowReasons string used in analyst-facing output sheets.
    wf_results = [
        classify_workflow_class(ev, pe, ctx, cfg)
        for ev, pe, ctx in zip(scenes["Evidence"], parsed_evs, scenes["ExecutionContext"])
    ]
    scenes["WorkflowClass"]   = [r[0] for r in wf_results]
    scenes["WorkflowReasons"] = [r[1] for r in wf_results]

    scenes["DeviceName"] = scenes["DeviceName"].str.strip().str.lower()
    scenes["AccountName"] = scenes["AccountName"].str.strip().str.lower()

    # Tag each scene with its detection family (AI vs Traditional) for analyst filtering
    families = cfg.get("detection_families", {})
    scenes["Family"] = scenes["DetectionType"].map(families).fillna("Traditional")

    # Extract network destination for pivot / stacking enrichment
    scenes["SceneDestination"] = [_extract_destination(pe) for pe in parsed_evs]

    return scenes


# ---------------------------------------------------------------------------
# Prevalence scoring
# ---------------------------------------------------------------------------

def apply_prevalence_scoring(scenes: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """
    Adjust ScoreContribution based on environment-wide prevalence.

    Environment-wide device count per EvidenceNormalized pattern:
        Rare patterns (few devices) get a boost; widespread patterns get suppressed
        — widespread = likely sanctioned tooling, not a novel threat.

    Evidence normalization:
        evidence_normalizations in config.json is a list of {pattern, replacement}
        regex pairs applied in sequence to create EvidenceNormalized. This collapses
        user-specific path segments (e.g. C:\\Users\\alice\\ → C:\\Users\\<user>\\)
        so the same command run by different users is counted as one pattern.
        Original Evidence is preserved for display.
    """
    supp_threshold = cfg.get("prevalence_suppression_threshold", 10)
    boost_threshold = cfg.get("prevalence_boost_threshold", 3)
    supp_mult  = cfg.get("prevalence_suppression_multiplier", 0.2)
    boost_mult = cfg.get("prevalence_boost_multiplier", 1.5)

    # --- Evidence normalization ---
    normalizations = cfg.get("evidence_normalizations", [])
    scenes["EvidenceNormalized"] = scenes["Evidence"].astype(str)
    for norm in normalizations:
        scenes["EvidenceNormalized"] = scenes["EvidenceNormalized"].str.replace(
            norm["pattern"], norm["replacement"], regex=True
        )

    # --- Auto-clustering via Drain3 (opt-in) ---
    if cfg.get("use_evidence_clustering", False):
        scenes["EvidenceNormalized"] = cluster_evidence(scenes, cfg)

    # --- Env-wide suppression/boost ---
    env_counts = (
        scenes.groupby("EvidenceNormalized")["DeviceName"]
        .nunique()
        .rename("EnvDeviceCount")
        .reset_index()
    )
    scenes = scenes.merge(env_counts, on="EvidenceNormalized", how="left")

    def _multiplier(count):
        if count > supp_threshold:
            return supp_mult
        if count <= boost_threshold:
            return boost_mult
        return 1.0

    scenes["PrevalenceMultiplier"] = scenes["EnvDeviceCount"].apply(_multiplier)
    scenes["ScoreContribution"] = (
        scenes["ScoreContribution"] * scenes["PrevalenceMultiplier"]
    ).round(1)

    suppressed = env_counts[env_counts["EnvDeviceCount"] > supp_threshold]
    for _, row in suppressed.iterrows():
        preview = str(row["EvidenceNormalized"])[:80]
        print(f"  [PREVALENCE] Pattern seen on {row['EnvDeviceCount']} devices "
              f"— score multiplier {supp_mult}x: {preview}...")

    return scenes


# ---------------------------------------------------------------------------
# Evidence auto-clustering (Drain3)
# ---------------------------------------------------------------------------

def cluster_evidence(scenes: pd.DataFrame, cfg: dict) -> pd.Series:
    """
    Use Drain3 log template extraction to auto-cluster EvidenceNormalized strings
    into canonical templates (e.g. 'Process: csc.exe | CmdLine: <*>').

    Groups by DetectionType first so strings with the same KQL structure are
    clustered together, not cross-pollinated between detection types.

    Returns a Series of template strings aligned to scenes.index.
    Requires: pip install drain3
    """
    try:
        import logging
        from drain3 import TemplateMiner
        from drain3.template_miner_config import TemplateMinerConfig
        logging.getLogger("drain3").setLevel(logging.WARNING)
    except ImportError:
        print("  [WARN] drain3 not installed — skipping evidence clustering. "
              "Run: pip install drain3")
        return scenes["EvidenceNormalized"]

    sim_th = cfg.get("evidence_clustering_sim_threshold", 0.5)
    result = scenes["EvidenceNormalized"].copy()

    for det_type, group in scenes.groupby("DetectionType"):
        unique_strings = group["EvidenceNormalized"].unique()
        if len(unique_strings) < 2:
            continue  # Nothing to cluster

        tmpl_cfg = TemplateMinerConfig()
        tmpl_cfg.drain_sim_th = sim_th
        tmpl_cfg.drain_depth = 4
        tmpl_cfg.parametrize_numeric_tokens = True

        miner = TemplateMiner(config=tmpl_cfg)

        template_map = {}
        for ev in unique_strings:
            res = miner.add_log_message(str(ev))
            template_map[ev] = res["template_mined"]

        result.loc[group.index] = group["EvidenceNormalized"].map(template_map)

        n_templates = len(set(template_map.values()))
        if n_templates < len(unique_strings):
            print(f"  [CLUSTER] {det_type}: {len(unique_strings)} unique → {n_templates} template(s)")

    return result


# ---------------------------------------------------------------------------
# Scene cap — prevent volume inflation from repetitive patterns
# ---------------------------------------------------------------------------

def apply_scene_cap(scenes: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """
    Cap how many times a single normalized evidence pattern contributes score
    per device. Prevents repetitive-but-benign tooling (e.g. bash invoked by
    Claude Code / IDE terminals) from dominating TotalRisk through sheer volume.

    Scenes beyond the cap have ScoreContribution zeroed out rather than dropped
    so they still appear in analyst views (All Scenes / per-tactic sheets).

    Config key: max_scenes_per_pattern_per_device (0 = disabled, default 3)
    """
    cap = cfg.get("max_scenes_per_pattern_per_device", 3)
    if not cap:
        return scenes

    ev_col = "EvidenceNormalized" if "EvidenceNormalized" in scenes.columns else "Evidence"
    scenes = scenes.copy()

    # Rank each scene within its (device, pattern) group by time — earliest ranks lowest.
    # Sort first, compute cumcount on the sorted frame, then align back by index.
    sorted_scenes = scenes.sort_values("Timestamp")
    seq = sorted_scenes.groupby(["DeviceName", ev_col]).cumcount() + 1
    scenes["_seq"] = seq.reindex(scenes.index)
    over_cap = scenes["_seq"] > cap
    if over_cap.any():
        print(f"  [CAP] {over_cap.sum()} scene(s) beyond cap of {cap}/pattern/device → ScoreContribution zeroed")
    scenes.loc[over_cap, "ScoreContribution"] = 0.0
    scenes = scenes.drop(columns=["_seq"])
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


def build_variation_clusters(g: "pd.DataFrame", cfg: dict) -> "tuple[int, int, bool, str]":
    """
    Detect automated / adaptive behavior within a single episode group.

    An attacker (or AI agent) operating in try-and-adjust mode will reuse the
    same tool class (DetectionType) against many distinct targets or with many
    distinct argument sets in rapid succession.  A human operator rarely does this
    within a single 4-hour window.

    Logic:
      - Use EvidenceNormalized if present, else Evidence.
      - Group the episode by (DeviceName, DetectionType).
      - Count n_variants = number of unique evidence strings per group.
      - If any group has n_variants >= variation_cluster_min_size, the episode
        is flagged as exhibiting adaptive behavior.

    Returns:
      cluster_count    — how many (device, detection_type) groups are variation clusters
      largest_cluster  — max n_variants seen across all groups
      flag             — True if at least one cluster meets the threshold
      reason_str       — human-readable description for the Evidence column
    """
    ab_cfg    = cfg.get("adaptive_behavior", {})
    min_size  = int(ab_cfg.get("variation_cluster_min_size", 3))
    ev_col    = "EvidenceNormalized" if "EvidenceNormalized" in g.columns else "Evidence"

    cluster_count   = 0
    largest_cluster = 0
    reasons: list   = []

    for (device, det_type), sub in g.groupby(["DeviceName", "DetectionType"]):
        n_variants = len(sub[ev_col].unique())
        if n_variants > largest_cluster:
            largest_cluster = n_variants
        if n_variants >= min_size:
            cluster_count += 1
            reasons.append(
                f"{n_variants} variants of {det_type} on {device}"
            )

    flag       = cluster_count > 0
    reason_str = "; ".join(reasons) if reasons else ""
    return cluster_count, largest_cluster, flag, reason_str


def compute_transition_bonus(tactic_set: set, cfg: dict) -> "tuple[float, list[str]]":
    """
    Compute a multiplicative bonus for episodes whose tactic set spans one or more
    known ATT&CK progression pairs (e.g. CredentialAccess + LateralMovement).

    Pairs are defined in config.json under `tactic_transitions.pairs`.  All matching
    pair multipliers stack multiplicatively, capped at `tactic_transitions.max_multiplier`.

    Returns (multiplier, list_of_matched_pair_labels).
    """
    trans_cfg = cfg.get("tactic_transitions", {})
    pairs     = trans_cfg.get("pairs", [])
    max_mult  = float(trans_cfg.get("max_multiplier", 2.0))

    multiplier   = 1.0
    found: list  = []
    for pair in pairs:
        tactics = pair.get("tactics", [])
        if len(tactics) == 2 and tactics[0] in tactic_set and tactics[1] in tactic_set:
            multiplier *= float(pair.get("multiplier", 1.0))
            found.append(f"{tactics[0]}\u2192{tactics[1]}")

    return min(multiplier, max_mult), found


def build_episodes(scenes: pd.DataFrame, entity_col: str, tactic_weights: dict, cfg: dict = None) -> pd.DataFrame:
    """
    Aggregate scenes into episode-level summary.

    New behaviour (when cfg supplied):
    - Per-behavior-family cap within each episode: same-family scenes beyond
      episode_family_cap are multiplied by episode_family_cap_multipliers[family]
      instead of contributing full score.  Mirrors the scene-level cap but at
      the family level, so a 20-scene bash episode still only counts a few times.
    - Corroboration multiplier: episodes that mix multiple behavior families
      earn a bonus multiplier (e.g. ShellExecution + CredentialDump = 1.4×).
    """
    cfg = cfg or {}
    ep_col = f"EpisodeID_{entity_col}"
    grp = scenes.groupby([entity_col, ep_col])

    family_cap      = cfg.get("episode_family_cap", 3)
    family_cap_mults = cfg.get("episode_family_cap_multipliers", {})
    corr_cfg        = cfg.get("corroboration_bonus", {})
    min_fam         = corr_cfg.get("min_families_for_bonus", 2)
    bonus_per       = corr_cfg.get("bonus_per_additional_family", 1.4)
    max_bonus       = corr_cfg.get("max_bonus_multiplier", 5.0)

    records = []
    for (entity, ep_id), g in grp:
        g = g.sort_values("Timestamp")

        # Per-family cap: count occurrences per family; scenes beyond cap get a reduced multiplier.
        # Also track per-family adjusted score so we can pick the dominant family by contribution,
        # not alphabetically.
        family_counter: dict = {}
        family_scores: dict = {}   # family -> total adjusted score (excludes "Unknown")
        adj_scores = []
        for _, row in g.iterrows():
            fam = row.get("BehaviorFamily", "Unknown")
            family_counter[fam] = family_counter.get(fam, 0) + 1
            if family_counter[fam] > family_cap:
                if fam not in family_cap_mults and fam != "Unknown":
                    print(f"  [WARN] BehaviorFamily '{fam}' not in episode_family_cap_multipliers — defaulting to 0.2")
                over_cap_mult = family_cap_mults.get(fam, 0.2)
                adj = row["ScoreContribution"] * over_cap_mult
            else:
                adj = row["ScoreContribution"]
            adj_scores.append(adj)
            if fam != "Unknown":
                family_scores[fam] = family_scores.get(fam, 0.0) + adj

        base_score = sum(adj_scores)

        # Corroboration bonus: reward episodes with multiple distinct behavior families
        unique_fams = set(g["BehaviorFamily"].dropna()) - {"Unknown"}
        n_fams = len(unique_fams)
        if n_fams >= min_fam:
            corr_mult = min(bonus_per ** (n_fams - min_fam + 1), max_bonus)
        else:
            corr_mult = 1.0

        # Dominant family = highest adjusted-score contributor (not alphabetically first)
        dominant_family = max(family_scores, key=family_scores.get) if family_scores else "Unknown"

        # ATT&CK transition bonus: multiplicative reward for known kill-chain progressions
        tactics = g["TacticCategory"].unique().tolist()
        transition_mult, transitions_found = compute_transition_bonus(set(tactics), cfg or {})

        # Variation clustering: detect try-and-adjust / AI-agent automated behavior
        var_clusters, largest_cluster, adaptive_flag, adaptive_reason = \
            build_variation_clusters(g, cfg or {})
        ab_cfg = (cfg or {}).get("adaptive_behavior", {})
        variation_mult = (
            float(ab_cfg.get("variation_score_bonus", 1.15))
            if adaptive_flag else 1.0
        )

        records.append({
            entity_col:               entity,
            "EpisodeID":              ep_id,
            "StartTime":              g["Timestamp"].min(),
            "EndTime":                g["Timestamp"].max(),
            "DurationHours":          round((g["Timestamp"].max() - g["Timestamp"].min()).total_seconds() / 3600, 2),
            "SceneCount":             len(g),
            "TacticCount":            len(tactics),
            "Tactics":                ", ".join(sorted(tactics)),
            "BehaviorFamilies":       ", ".join(sorted(unique_fams)),
            "DominantFamily":         dominant_family,
            "FamilyCount":            n_fams,
            "CorroborationMult":      round(corr_mult, 3),
            "TacticTransitionMult":   round(transition_mult, 3),
            "TacticTransitions":      ", ".join(transitions_found),
            "VariationClusterCount":  var_clusters,
            "LargestVariationCluster": largest_cluster,
            "AdaptiveBehaviorFlag":   adaptive_flag,
            "AdaptiveBehaviorReason": adaptive_reason,
            "EpisodeRiskScore":       round(base_score * corr_mult * transition_mult * variation_mult, 2),
        })

    return pd.DataFrame(records).sort_values("EpisodeRiskScore", ascending=False)


# ---------------------------------------------------------------------------
# Season aggregation
# ---------------------------------------------------------------------------

def build_seasons(episodes: pd.DataFrame, entity_col: str, tactic_weights: dict, scenes: pd.DataFrame, cfg: dict = None) -> pd.DataFrame:
    """
    Aggregate episodes into season-level summary per entity.

    TotalRisk uses diminishing-returns weighting rather than a plain sum so
    that story quality beats story length:
      - Episodes sorted descending by EpisodeRiskScore; each successive episode
        earns a lower rank_weight via 1/log2(rank+2).
      - Repeated same-dominant-family episodes decay exponentially so a device
        with 20 identical bash episodes scores much lower than one with
        bash + credential dump + lateral movement across a handful of episodes.
    """
    cfg = cfg or {}
    tactic_cols = list(tactic_weights.keys())

    # Per-entity tactic score breakdown from scenes (unchanged)
    tactic_scores = (
        scenes.groupby([entity_col, "TacticCategory"])["ScoreContribution"]
        .sum()
        .unstack(fill_value=0)
        .reindex(columns=tactic_cols, fill_value=0)
    )
    tactic_scores.columns = [f"Score_{c}" for c in tactic_scores.columns]

    # Diminishing-returns config
    dr_cfg       = cfg.get("season_diminishing_returns", {})
    log_base     = dr_cfg.get("diminishing_log_base", 2.0)
    decay_after  = dr_cfg.get("same_family_decay_after", 1)
    decay_factor = dr_cfg.get("same_family_decay_factor", 0.5)

    # True unique tactic count = union of all TacticCategory values seen in scenes per entity,
    # not the max TacticCount from a single episode (which under-counts multi-episode seasons).
    entity_tactic_counts = scenes.groupby(entity_col)["TacticCategory"].nunique()

    # TacticSet: sorted comma-joined string of unique tactics — used for cross-run tactic
    # adaptation detection (IsAdaptingTactics) and analyst readability.
    entity_tactic_sets = (
        scenes.groupby(entity_col)["TacticCategory"]
        .apply(lambda x: ", ".join(sorted(x.dropna().unique())))
    )

    season_records = []
    for entity, ep_group in episodes.groupby(entity_col):
        ep_group = ep_group.sort_values("EpisodeRiskScore", ascending=False)
        dom_counter: dict = {}
        total_risk = 0.0
        for rank, (_, ep_row) in enumerate(ep_group.iterrows()):
            ep_score = ep_row["EpisodeRiskScore"]
            # Dominant family = highest score contributor in this episode (set by build_episodes)
            dominant = ep_row.get("DominantFamily", "Unknown") or "Unknown"

            # Log-based rank weight: best episode gets 1.0, each subsequent gets less
            rank_weight = 1.0 / math.log(rank + 2, log_base)

            # Exponential decay for repeated same-dominant-family episodes
            prior = dom_counter.get(dominant, 0)
            family_weight = decay_factor ** max(0, prior - decay_after + 1) if prior >= decay_after else 1.0
            dom_counter[dominant] = prior + 1

            total_risk += ep_score * rank_weight * family_weight

        season_records.append({
            entity_col:       entity,
            "TotalRisk":      round(total_risk, 1),
            "EpisodeCount":   len(ep_group),
            "TotalScenes":    ep_group["SceneCount"].sum(),
            "MaxEpisodeRisk": ep_group["EpisodeRiskScore"].max(),
            "FirstSeen":      ep_group["StartTime"].min(),
            "LastSeen":       ep_group["EndTime"].max(),
            # Union of all tactics across all episodes — correct cross-episode count
            "UniqueTactics":  int(entity_tactic_counts.get(entity, 0)),
            # Sorted comma-joined tactic names — used for cross-run tactic adaptation detection
            "TacticSet":      entity_tactic_sets.get(entity, ""),
            # Variation cluster rollup: max cluster size and count of adaptive episodes
            "MaxEpisodeVariationCluster": int(
                ep_group["LargestVariationCluster"].max()
                if "LargestVariationCluster" in ep_group.columns else 0
            ),
            "AdaptiveEpisodeCount": int(
                ep_group["AdaptiveBehaviorFlag"].sum()
                if "AdaptiveBehaviorFlag" in ep_group.columns else 0
            ),
        })

    ep_summary = pd.DataFrame(season_records).set_index(entity_col)
    seasons = ep_summary.join(tactic_scores, how="left").fillna(0)

    # Behavioral diversity: unique normalized evidence patterns and detection methods per entity
    ev_col = "EvidenceNormalized" if "EvidenceNormalized" in scenes.columns else "Evidence"
    diversity = scenes.groupby(entity_col).agg(
        UniqueEvidenceCount=(ev_col, "nunique"),
        UniqueDetectionTypes=("DetectionType", "nunique"),
    )
    seasons = seasons.join(diversity, how="left").fillna(0)
    seasons["UniqueEvidenceCount"] = seasons["UniqueEvidenceCount"].astype(int)
    seasons["UniqueDetectionTypes"] = seasons["UniqueDetectionTypes"].astype(int)

    seasons = seasons.sort_values("TotalRisk", ascending=False).reset_index()
    # Percentile rank so analysts have immediate context for raw scores
    if len(seasons) > 1:
        seasons["RiskPercentile"] = (
            seasons["TotalRisk"].rank(pct=True, ascending=True) * 100
        ).round(0).astype(int)
    else:
        seasons["RiskPercentile"] = 100
    return seasons


def enrich_seasons_with_workflow(
    seasons: pd.DataFrame, entity_col: str, scenes: pd.DataFrame, cfg: dict
) -> pd.DataFrame:
    """
    Add workflow classification and priority eligibility columns to a seasons DataFrame.

    New columns:
      PrimaryWorkflowClass  — dominant workflow class across the entity's scenes
                              ("AIWorkflow" | "DeveloperAutomation" | "Operational")
      AIWorkflowScenePct    — % of scenes classified as AIWorkflow
      EligibleForPriority   — False when the entity is AI/Dev-dominated with < N tactics
      ExclusionReason       — human-readable explanation for ineligible entities

    Eligibility gate: entities whose scenes are dominated by AIWorkflow or DeveloperAutomation
    AND have fewer than workflow_classification.priority_min_tactics_for_ai_dev distinct MITRE
    tactics are excluded from Priority Investigation Cases and routed to AI/Dev Outliers.
    """
    min_tactics = int(cfg.get("workflow_classification", {}).get("priority_min_tactics_for_ai_dev", 2))

    seasons = seasons.copy()
    seasons["PrimaryWorkflowClass"] = "Operational"
    seasons["AIWorkflowScenePct"]   = 0.0
    seasons["EligibleForPriority"]  = True
    seasons["ExclusionReason"]      = ""

    if "WorkflowClass" not in scenes.columns:
        return seasons

    wf_counts = (
        scenes.groupby([entity_col, "WorkflowClass"])
        .size()
        .unstack(fill_value=0)
    )

    for idx, row in seasons.iterrows():
        entity = row[entity_col]
        if entity not in wf_counts.index:
            continue
        counts = wf_counts.loc[entity]
        total  = int(counts.sum())
        if total == 0:
            continue

        ai_count  = int(counts.get("AIWorkflow", 0))
        dev_count = int(counts.get("DeveloperAutomation", 0))
        other     = total - ai_count - dev_count

        ai_pct = round(ai_count / total * 100, 1)
        seasons.at[idx, "AIWorkflowScenePct"] = ai_pct

        # Dominant class: whichever automated class outnumbers all non-automated scenes
        if ai_count > other:
            primary = "AIWorkflow"
        elif dev_count > other:
            primary = "DeveloperAutomation"
        else:
            primary = "Operational"
        seasons.at[idx, "PrimaryWorkflowClass"] = primary

        # Hard eligibility gate
        tactics = int(row["UniqueTactics"])
        if primary in ("AIWorkflow", "DeveloperAutomation") and tactics < min_tactics:
            seasons.at[idx, "EligibleForPriority"] = False
            seasons.at[idx, "ExclusionReason"] = (
                f"{primary} entity with {tactics} distinct MITRE tactic(s); "
                f"minimum {min_tactics} required for priority ranking"
            )

    return seasons


def build_priority_cases(device_seasons: pd.DataFrame, user_seasons: pd.DataFrame) -> pd.DataFrame:
    """
    Combine eligible device and user season rows into a ranked Priority Investigation Cases table.
    Entities classified as AIWorkflow or DeveloperAutomation with fewer than the minimum required
    distinct MITRE tactics are excluded and routed to the AI/Dev Outliers sheet instead.
    """
    def _prep(df, entity_type, entity_col):
        elig = df["EligibleForPriority"].fillna(True).astype(bool) if "EligibleForPriority" in df.columns \
               else pd.Series(True, index=df.index)
        d = df[elig].copy()
        d["EntityType"] = entity_type
        return d.rename(columns={entity_col: "EntityName"})

    combined = pd.concat(
        [_prep(device_seasons, "Device", "DeviceName"),
         _prep(user_seasons,   "User",   "AccountName")],
        ignore_index=True,
    )

    if combined.empty:
        return combined

    priority_cols = [
        "EntityType", "EntityName", "TotalRisk", "RiskPercentile",
        "EpisodeCount", "TotalScenes", "UniqueTactics", "TacticSet",
        "PrimaryWorkflowClass", "AIWorkflowScenePct",
        "MaxEpisodeRisk", "FirstSeen", "LastSeen",
        "ZScore", "IsNewHigh", "IsScoreSpike", "IsAdaptingTactics", "NewTactics",
    ]
    available = [c for c in priority_cols if c in combined.columns]
    return combined[available].sort_values("TotalRisk", ascending=False).reset_index(drop=True)


# ---------------------------------------------------------------------------
# Attack chain detection
# ---------------------------------------------------------------------------

def build_attack_chains(device_seasons: pd.DataFrame, scenes: pd.DataFrame, cfg: dict = None) -> pd.DataFrame:
    """
    Link devices that share an AccountName into attack chains.
    Returns a summary of chains with pivot accounts and combined risk.

    Account hygiene (config key: attack_chain_hygiene):
    - Null/empty AccountNames are always excluded.
    - Machine accounts (ending with $) are excluded by default.
    - A configurable exclusion list covers common service/shared accounts.
    - Optionally, only devices meeting minimum SeasonScore or UniqueTactics thresholds
      are eligible for chaining, reducing noise from low-signal devices.
    """
    cfg = cfg or {}
    chain_cfg = cfg.get("attack_chain_hygiene", {})
    exclude_machine  = chain_cfg.get("exclude_machine_accounts", True)
    excluded_accounts = {a.lower() for a in chain_cfg.get("excluded_accounts", [])}
    min_chain_score   = float(chain_cfg.get("min_device_season_score", 0))
    min_chain_tactics = int(chain_cfg.get("min_unique_tactics", 0))

    # Work on a filtered copy so we don't mutate the scenes DataFrame used elsewhere
    chain_scenes = scenes[
        scenes["AccountName"].notna() & scenes["AccountName"].ne("")
    ].copy()

    if exclude_machine:
        chain_scenes = chain_scenes[~chain_scenes["AccountName"].str.endswith("$")]

    if excluded_accounts:
        chain_scenes = chain_scenes[
            ~chain_scenes["AccountName"].str.lower().isin(excluded_accounts)
        ]

    # Restrict to devices that meet the minimum signal thresholds (if configured)
    if min_chain_score > 0 or min_chain_tactics > 0:
        eligible = device_seasons[
            (device_seasons["TotalRisk"] >= min_chain_score) &
            (device_seasons["UniqueTactics"] >= min_chain_tactics)
        ]["DeviceName"]
        chain_scenes = chain_scenes[chain_scenes["DeviceName"].isin(eligible)]

    # Build map: account -> set of devices
    account_devices = (
        chain_scenes.groupby("AccountName")["DeviceName"]
        .apply(lambda x: set(x.tolist()))
        .reset_index()
    )
    # Only accounts that appear on more than one device
    account_devices = account_devices[account_devices["DeviceName"].apply(len) > 1]

    if account_devices.empty:
        return pd.DataFrame(columns=["ChainID", "Devices", "PivotAccounts", "DeviceCount",
                                     "ChainRiskScore", "IsFanOut", "MaxAccountFanOut"])

    # Union-Find to merge overlapping device sets
    parent = {}

    def find(x):
        # Pass 1: walk to root
        root = x
        while parent.get(root, root) != root:
            root = parent[root]
        # Pass 2: path compression — point every node on the path directly to root
        while parent.get(x, x) != root:
            parent[x], x = root, parent[x]
        return root

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for _, row in account_devices.iterrows():
        devices = list(row["DeviceName"])
        for d in devices[1:]:
            union(devices[0], d)

    # Group devices by chain root (eligible devices only)
    all_devices = chain_scenes["DeviceName"].unique().tolist()
    chain_map = {}
    for d in all_devices:
        root = find(d)
        chain_map.setdefault(root, set()).add(d)

    # Only keep chains with >1 device
    chains = {root: devs for root, devs in chain_map.items() if len(devs) > 1}

    if not chains:
        return pd.DataFrame(columns=["ChainID", "Devices", "PivotAccounts", "DeviceCount",
                                     "ChainRiskScore", "IsFanOut", "MaxAccountFanOut"])

    # Build chain risk scores using device_seasons
    device_risk = device_seasons.set_index("DeviceName")["TotalRisk"].to_dict()

    fan_out_threshold = cfg.get("attack_chain_hygiene", {}).get("fan_out_threshold", 3)

    records = []
    for chain_id, (root, devs) in enumerate(chains.items(), start=1):
        pivot_accounts = account_devices[
            account_devices["DeviceName"].apply(lambda s: len(s & devs) > 1)
        ]["AccountName"].tolist()
        chain_risk = sum(device_risk.get(d, 0) for d in devs)

        # Fan-out: flag when a pivot account spreads across many devices in this chain
        chain_acct_rows = account_devices[account_devices["AccountName"].isin(pivot_accounts)]
        max_fanout = max(
            (len(row["DeviceName"] & devs) for _, row in chain_acct_rows.iterrows()),
            default=1,
        )

        records.append({
            "ChainID":          chain_id,
            "Devices":          " | ".join(sorted(devs)),
            "PivotAccounts":    " | ".join(sorted(pivot_accounts)),
            "DeviceCount":      len(devs),
            "ChainRiskScore":   chain_risk,
            "IsFanOut":         max_fanout >= fan_out_threshold,
            "MaxAccountFanOut": max_fanout,
        })

    return pd.DataFrame(records).sort_values("ChainRiskScore", ascending=False).reset_index(drop=True)


# ---------------------------------------------------------------------------
# Historical score persistence
# ---------------------------------------------------------------------------

_HISTORY_COLS = [
    "RunId", "RunTimestamp", "RunTimestampEpoch", "OutputVersion",
    "EntityType", "EntityName", "SeasonScore", "EpisodeCount",
    "SceneCount", "UniqueTactics", "BehaviorFamilyCount", "TopBehaviorFamily",
    "HasMDEAlert", "CrossDeviceLink", "TopEpisodeScore", "TopTactic",
    "TacticSet",
]


def _resolve_store_path(cfg: dict) -> str:
    hist_cfg = cfg.get("history", {})
    raw = hist_cfg.get("store_path", "output/hunt_history.db")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, raw)


def load_history(cfg: dict) -> pd.DataFrame:
    """Load hunt_history from SQLite. Returns empty DataFrame on first run or if disabled."""
    empty = pd.DataFrame(columns=_HISTORY_COLS)
    hist_cfg = cfg.get("history", {})
    if not hist_cfg.get("enabled", True):
        return empty
    store_path = _resolve_store_path(cfg)
    if not os.path.exists(store_path):
        return empty
    # max_runs_per_entity: how many of the most-recent runs to load per entity.
    # Accepts the new key; falls back to the old name for backward compatibility.
    max_runs = int(hist_cfg.get("max_runs_per_entity", hist_cfg.get("max_lookback_runs", 90)))
    try:
        con = sqlite3.connect(store_path)
        tbl = con.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='hunt_history'"
        ).fetchone()
        if tbl is None:
            con.close()
            return empty
        if max_runs > 0:
            sql = """
                SELECT *
                FROM hunt_history
                WHERE (EntityType || '|' || EntityName || '|' || RunTimestampEpoch) IN (
                    SELECT EntityType || '|' || EntityName || '|' || RunTimestampEpoch
                    FROM (
                        SELECT EntityType, EntityName, RunTimestampEpoch,
                               DENSE_RANK() OVER (
                                   PARTITION BY EntityType, EntityName
                                   ORDER BY RunTimestampEpoch DESC
                               ) AS rn
                        FROM hunt_history
                    )
                    WHERE rn <= ?
                )
                ORDER BY EntityType, EntityName, RunTimestampEpoch ASC
            """
            df = pd.read_sql(sql, con, params=(max_runs,))
        else:
            df = pd.read_sql(
                "SELECT * FROM hunt_history ORDER BY EntityType, EntityName, RunTimestampEpoch ASC",
                con,
            )
        con.close()
        return df
    except Exception as exc:
        print(f"  [WARN] Could not load history from {store_path}: {exc}")
        return empty


def _build_history_row(
    row: "pd.Series",
    entity_type: str,
    entity_col: str,
    run_id: str,
    run_ts: datetime,
    episodes_df: "pd.DataFrame",
    scenes: "pd.DataFrame",
    attack_chains: "pd.DataFrame",
    cfg: dict,
) -> dict:
    """Build one history record dict from a season row."""
    entity_name = row[entity_col]

    # BehaviorFamily derivation from episodes
    ent_eps = episodes_df[episodes_df[entity_col] == entity_name]
    all_families: list = []
    for bf_str in ent_eps["BehaviorFamilies"].dropna():
        all_families.extend(
            f.strip() for f in str(bf_str).split(",")
            if f.strip() and f.strip() != "Unknown"
        )
    family_counts = Counter(all_families)
    behavior_family_count = len(family_counts)
    top_behavior_family = family_counts.most_common(1)[0][0] if family_counts else ""

    ent_scenes = scenes[scenes[entity_col] == entity_name]
    has_mde_alert = 0

    # CrossDeviceLink
    cross_device_link = 0
    if not attack_chains.empty:
        if entity_type == "Device" and "Devices" in attack_chains.columns:
            for dev_str in attack_chains["Devices"].dropna():
                if entity_name in [d.strip() for d in str(dev_str).split(" | ")]:
                    cross_device_link = 1
                    break
        elif entity_type == "User" and "PivotAccounts" in attack_chains.columns:
            for piv_str in attack_chains["PivotAccounts"].dropna():
                if entity_name in [p.strip() for p in str(piv_str).split(" | ")]:
                    cross_device_link = 1
                    break

    # TopTactic
    tactic_cols = [c for c in row.index if c.startswith("Score_")]
    top_tactic = ""
    if tactic_cols:
        vals = row[tactic_cols]
        if vals.max() > 0:
            top_tactic = vals.idxmax().replace("Score_", "")

    return {
        "RunId":               run_id,
        "RunTimestamp":        run_ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "RunTimestampEpoch":   run_ts.timestamp(),
        "OutputVersion":       HISTORY_OUTPUT_VERSION,
        "EntityType":          entity_type,
        "EntityName":          entity_name,
        "SeasonScore":         float(row["TotalRisk"]),
        "EpisodeCount":        int(row["EpisodeCount"]),
        "SceneCount":          int(row["TotalScenes"]),
        "UniqueTactics":       int(row["UniqueTactics"]),
        "BehaviorFamilyCount": behavior_family_count,
        "TopBehaviorFamily":   top_behavior_family,
        "HasMDEAlert":         has_mde_alert,
        "CrossDeviceLink":     cross_device_link,
        "TopEpisodeScore":     float(row["MaxEpisodeRisk"]),
        "TopTactic":           top_tactic,
        "TacticSet":           str(row.get("TacticSet", "")),
    }


def append_to_history(
    device_seasons: "pd.DataFrame",
    user_seasons: "pd.DataFrame",
    device_episodes: "pd.DataFrame",
    user_episodes: "pd.DataFrame",
    scenes: "pd.DataFrame",
    attack_chains: "pd.DataFrame",
    run_id: str,
    run_ts: datetime,
    cfg: dict,
) -> None:
    """Append current run records to the SQLite history store. Creates DB on first call."""
    hist_cfg = cfg.get("history", {})
    if not hist_cfg.get("enabled", True):
        return
    store_path = _resolve_store_path(cfg)
    os.makedirs(os.path.dirname(store_path), exist_ok=True)

    records = []
    for _, row in device_seasons.iterrows():
        records.append(_build_history_row(
            row, "Device", "DeviceName", run_id, run_ts,
            device_episodes, scenes, attack_chains, cfg,
        ))
    for _, row in user_seasons.iterrows():
        records.append(_build_history_row(
            row, "User", "AccountName", run_id, run_ts,
            user_episodes, scenes, attack_chains, cfg,
        ))
    if not records:
        return

    df_write = pd.DataFrame(records)
    # Only write the schema columns (exclude any extra baseline cols on seasons)
    df_write = df_write[[c for c in _HISTORY_COLS if c in df_write.columns]]

    con = sqlite3.connect(store_path)
    try:
        con.execute("""
            CREATE TABLE IF NOT EXISTS hunt_history (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                RunId               TEXT    NOT NULL,
                RunTimestamp        TEXT    NOT NULL,
                RunTimestampEpoch   REAL    NOT NULL,
                OutputVersion       INTEGER NOT NULL DEFAULT 1,
                EntityType          TEXT    NOT NULL,
                EntityName          TEXT    NOT NULL,
                SeasonScore         REAL    NOT NULL,
                EpisodeCount        INTEGER NOT NULL,
                SceneCount          INTEGER NOT NULL,
                UniqueTactics       INTEGER NOT NULL,
                BehaviorFamilyCount INTEGER NOT NULL,
                TopBehaviorFamily   TEXT    NOT NULL DEFAULT '',
                HasMDEAlert         INTEGER NOT NULL DEFAULT 0,
                CrossDeviceLink     INTEGER NOT NULL DEFAULT 0,
                TopEpisodeScore     REAL    NOT NULL,
                TopTactic           TEXT    NOT NULL DEFAULT '',
                TacticSet           TEXT    NOT NULL DEFAULT ''
            )
        """)
        # Schema migration: add columns introduced in later versions if they are missing.
        existing_cols = {r[1] for r in con.execute("PRAGMA table_info(hunt_history)").fetchall()}
        if "TacticSet" not in existing_cols:
            con.execute("ALTER TABLE hunt_history ADD COLUMN TacticSet TEXT NOT NULL DEFAULT ''")
            print("  [HISTORY] Schema migrated: added TacticSet column")
        con.execute("""
            CREATE INDEX IF NOT EXISTS idx_entity
            ON hunt_history (EntityType, EntityName, RunTimestampEpoch DESC)
        """)
        con.execute("""
            CREATE INDEX IF NOT EXISTS idx_run ON hunt_history (RunId)
        """)
        df_write.to_sql("hunt_history", con, if_exists="append", index=False,
                        method="multi", chunksize=500)
        con.commit()
        print(f"  [HISTORY] Appended {len(records)} record(s) (RunId: {run_id[:8]}...)")
    except Exception as exc:
        print(f"  [WARN] Failed to write history to {store_path}: {exc}")
        try:
            con.rollback()
        except Exception:
            pass
    finally:
        con.close()


def compute_historical_baselines(
    current_seasons: "pd.DataFrame",
    history: "pd.DataFrame",
    entity_col: str,
    entity_type: str,
    current_run_id: str,
    cfg: dict,
) -> "pd.DataFrame":
    """Enrich current_seasons with historical baseline columns computed from prior runs only."""
    hist_cfg = cfg.get("history", {})
    min_runs        = int(hist_cfg.get("minimum_runs_for_baseline", 3))
    spike_mult      = float(hist_cfg.get("score_spike_multiplier", 2.5))
    spike_min_mean  = float(hist_cfg.get("score_spike_min_mean", 1.0))
    zscore_threshold = float(hist_cfg.get("zscore_threshold", 2.0))
    emerg_thresh    = float(hist_cfg.get("emerging_entity_score_threshold", 10.0))
    emerg_max_runs  = int(hist_cfg.get("emerging_entity_max_runs", 2))
    tactic_exp      = int(hist_cfg.get("tactic_expansion_threshold", 1))

    seasons = current_seasons.copy()

    # Pre-populate baseline columns
    for col in ["PreviousScore", "BaselineMean", "BaselineMedian", "BaselineStdDev",
                "HistoricalMax", "RunCount", "ScoreDelta", "ScoreDeltaPct", "ZScore"]:
        seasons[col] = float("nan")
    for col in ["IsNewHigh", "IsScoreSpike", "IsZScoreAnomaly", "IsEmergingEntity",
                "IsTacticExpansion", "IsAdaptingTactics"]:
        seasons[col] = False
    seasons["NewTactics"] = ""

    if history.empty:
        emerg_mask = seasons["TotalRisk"] >= emerg_thresh
        seasons.loc[emerg_mask, "IsEmergingEntity"] = True
        seasons.loc[emerg_mask, "RunCount"] = 0
        return seasons

    prior = history[
        (history["EntityType"] == entity_type) &
        (history["RunId"] != current_run_id)
    ].copy()

    if prior.empty:
        emerg_mask = seasons["TotalRisk"] >= emerg_thresh
        seasons.loc[emerg_mask, "IsEmergingEntity"] = True
        seasons.loc[emerg_mask, "RunCount"] = 0
        return seasons

    prior_grouped = prior.groupby("EntityName")

    for idx, row in seasons.iterrows():
        entity_name = row[entity_col]

        if entity_name not in prior_grouped.groups:
            seasons.at[idx, "RunCount"] = 0
            if float(row["TotalRisk"]) >= emerg_thresh:
                seasons.at[idx, "IsEmergingEntity"] = True
            continue

        ent_hist = prior_grouped.get_group(entity_name).sort_values("RunTimestampEpoch")
        scores = ent_hist["SeasonScore"].to_numpy(dtype=float)
        run_count = len(scores)
        current_score = float(row["TotalRisk"])
        current_tactics = int(row["UniqueTactics"])

        prev_score    = float(scores[-1])
        base_mean     = float(scores.mean())
        base_median   = float(np.median(scores))
        base_std      = float(scores.std(ddof=0))   # 0.0 when n=1
        hist_max      = float(scores.max())

        score_delta   = current_score - prev_score
        score_delta_pct = (score_delta / prev_score * 100) if prev_score != 0 else float("nan")
        zscore        = (current_score - base_mean) / base_std if base_std > 0 else 0.0

        seasons.at[idx, "PreviousScore"]  = prev_score
        seasons.at[idx, "BaselineMean"]   = round(base_mean, 2)
        seasons.at[idx, "BaselineMedian"] = round(base_median, 2)
        seasons.at[idx, "BaselineStdDev"] = round(base_std, 2)
        seasons.at[idx, "HistoricalMax"]  = hist_max
        seasons.at[idx, "RunCount"]       = run_count
        seasons.at[idx, "ScoreDelta"]     = round(score_delta, 2)
        seasons.at[idx, "ScoreDeltaPct"]  = round(score_delta_pct, 1) if pd.notna(score_delta_pct) else float("nan")
        seasons.at[idx, "ZScore"]         = round(zscore, 2)

        if run_count >= min_runs:
            seasons.at[idx, "IsNewHigh"] = bool(current_score > hist_max)
            seasons.at[idx, "IsScoreSpike"] = bool(
                current_score > base_mean * spike_mult and base_mean >= spike_min_mean
            )
            # IsZScoreAnomaly: statistical anomaly regardless of multiplier — fires when
            # the entity's score is zscore_threshold standard deviations above its mean.
            # base_std == 0 is safe: zscore was set to 0.0, so this will never fire (correct
            # behaviour — a perfectly flat baseline is not anomalous).
            seasons.at[idx, "IsZScoreAnomaly"] = bool(zscore >= zscore_threshold)
            hist_tactics_max = int(ent_hist["UniqueTactics"].max())
            seasons.at[idx, "IsTacticExpansion"] = bool(
                current_tactics >= hist_tactics_max + tactic_exp
            )

            # IsAdaptingTactics: fires when any tactic in the current run was NEVER seen
            # in any prior run.  Complements IsTacticExpansion (which only catches count
            # growth) by also catching tactic *substitution* — e.g. swapping Discovery for
            # CredentialAccess at the same breadth, which is invisible to IsTacticExpansion.
            if "TacticSet" in ent_hist.columns:
                current_ts = {
                    t.strip()
                    for t in str(row.get("TacticSet", "")).split(",")
                    if t.strip()
                }
                hist_ts_union: set = set()
                for ts_str in ent_hist["TacticSet"].dropna():
                    hist_ts_union.update(
                        t.strip() for t in str(ts_str).split(",") if t.strip()
                    )
                new_tactics = current_ts - hist_ts_union
                if new_tactics:
                    seasons.at[idx, "IsAdaptingTactics"] = True
                    seasons.at[idx, "NewTactics"] = ", ".join(sorted(new_tactics))

        seasons.at[idx, "IsEmergingEntity"] = bool(
            run_count <= emerg_max_runs and current_score >= emerg_thresh
        )

    return seasons


def _compute_priority(row: "pd.Series") -> float:
    """
    HistoricalPriority = (clamp(ZScore,0,10) + flag_bonuses) * log-dampener

    Bonuses: IsScoreSpike=3, IsNewHigh=2, IsTacticExpansion=2.5, IsEmergingEntity=1.5
    Dampener: log10(TotalRisk+1)/log10(101)  — suppresses trivially-low absolute scores.
    """
    zscore = float(row.get("ZScore") or 0)
    base = max(0.0, min(zscore, 10.0))
    bonuses = (
        (3.0 if row.get("IsScoreSpike") else 0.0) +
        (2.0 if row.get("IsNewHigh") else 0.0) +
        (2.5 if row.get("IsTacticExpansion") else 0.0) +
        (2.5 if row.get("IsAdaptingTactics") else 0.0) +
        (1.5 if row.get("IsEmergingEntity") else 0.0) +
        (1.0 if row.get("IsZScoreAnomaly") else 0.0)   # additive: Z already in base, this rewards it
    )
    total_risk = float(row.get("TotalRisk") or 0)
    dampener = math.log10(total_risk + 1) / math.log10(101)
    return round((base + bonuses) * dampener, 2)


def generate_historical_anomalies(
    device_seasons: "pd.DataFrame",
    user_seasons: "pd.DataFrame",
) -> "pd.DataFrame":
    """
    Collect all entities where any anomaly flag is True, compute HistoricalPriority,
    and return sorted by priority descending.
    """
    flag_cols = ["IsNewHigh", "IsScoreSpike", "IsZScoreAnomaly", "IsEmergingEntity",
                 "IsTacticExpansion", "IsAdaptingTactics"]
    output_cols = [
        "EntityType", "EntityName", "TotalRisk", "HistoricalPriority",
        "PreviousScore", "ScoreDelta", "ScoreDeltaPct", "ZScore",
        "BaselineMean", "BaselineStdDev", "HistoricalMax", "RunCount",
        "IsNewHigh", "IsScoreSpike", "IsZScoreAnomaly", "IsEmergingEntity",
        "IsTacticExpansion", "IsAdaptingTactics", "NewTactics",
    ]

    def _prep(df, entity_type, entity_col):
        d = df.copy()
        d["EntityType"] = entity_type
        return d.rename(columns={entity_col: "EntityName"})

    combined = pd.concat(
        [_prep(device_seasons, "Device", "DeviceName"),
         _prep(user_seasons, "User", "AccountName")],
        ignore_index=True,
    )

    # Exclude ineligible (AI/Dev-dominated single-tactic) entities so they don't
    # pollute the Historical Anomalies sheet — they go to AI/Dev Outliers instead.
    if "EligibleForPriority" in combined.columns:
        combined = combined[combined["EligibleForPriority"].fillna(True).astype(bool)]

    any_flag = combined[flag_cols].apply(
        lambda col: col.fillna(False).astype(bool)
    ).any(axis=1)
    anomalies = combined[any_flag].copy()

    if anomalies.empty:
        return pd.DataFrame(columns=output_cols)

    anomalies["HistoricalPriority"] = anomalies.apply(_compute_priority, axis=1)
    anomalies = anomalies.sort_values("HistoricalPriority", ascending=False).reset_index(drop=True)
    return anomalies[[c for c in output_cols if c in anomalies.columns]]


# ---------------------------------------------------------------------------
# Excel output
# ---------------------------------------------------------------------------

def auto_width(worksheet, df: pd.DataFrame, max_width: int = 80):
    """Set column widths based on content."""
    for i, col in enumerate(df.columns):
        if len(df) > 0:
            # .str.len() handles NaN safely (returns NaN for them, not a TypeError)
            max_data_len = df[col].astype(str).str.len().max()
            max_data_len = int(max_data_len) if pd.notna(max_data_len) else 0
        else:
            max_data_len = 0
        max_len = max(max_data_len, len(str(col)))
        worksheet.set_column(i, i, min(max_len + 2, max_width))


def write_excel(
    output_path: str,
    scenes: pd.DataFrame,
    device_episodes: pd.DataFrame,
    device_seasons: pd.DataFrame,
    user_seasons: pd.DataFrame,
    attack_chains: pd.DataFrame,
    historical_anomalies: pd.DataFrame,
    priority_cases: pd.DataFrame,
    tactic_weights: dict,
    cfg: dict,
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

        # 1. Priority Investigation Cases — eligible entities only, ranked by TotalRisk.
        #    Entities dominated by AIWorkflow or DeveloperAutomation with < 2 MITRE tactics
        #    are excluded here and appear in the AI/Dev Outliers sheet instead.
        write_sheet("Priority Cases", priority_cases)

        # 2. Device Seasons — all devices (includes PrimaryWorkflowClass, EligibleForPriority)
        write_sheet("Device Seasons", device_seasons)

        # 3. User Seasons
        write_sheet("User Seasons", user_seasons)

        # 4. Historical Anomalies — anomaly-flagged eligible entities only
        if not historical_anomalies.empty:
            write_sheet("Historical Anomalies", historical_anomalies)

        # 5. AI/Dev Automation Outliers — entities excluded from priority ranking
        def _build_outliers():
            def _prep_outlier(df, etype, ecol):
                if "EligibleForPriority" not in df.columns:
                    return pd.DataFrame()
                mask = ~df["EligibleForPriority"].fillna(True).astype(bool)
                d = df[mask].copy()
                if d.empty:
                    return pd.DataFrame()
                d["EntityType"] = etype
                return d.rename(columns={ecol: "EntityName"})
            parts = [
                _prep_outlier(device_seasons, "Device", "DeviceName"),
                _prep_outlier(user_seasons,   "User",   "AccountName"),
            ]
            parts = [p for p in parts if not p.empty]
            if not parts:
                return pd.DataFrame()
            merged = pd.concat(parts, ignore_index=True)
            outlier_cols = [
                "EntityType", "EntityName", "TotalRisk", "EpisodeCount", "TotalScenes",
                "UniqueTactics", "TacticSet", "PrimaryWorkflowClass", "AIWorkflowScenePct",
                "FirstSeen", "LastSeen", "ExclusionReason",
            ]
            return merged[[c for c in outlier_cols if c in merged.columns]].sort_values(
                "TotalRisk", ascending=False
            )

        outliers = _build_outliers()
        if not outliers.empty:
            write_sheet("AI Dev Outliers", outliers)

        # 6. Attack Chains
        write_sheet("Attack Chains", attack_chains)

        # Shared prevalence multiplier function used by both stacking sheets
        supp_threshold = cfg.get("prevalence_suppression_threshold", 10)
        boost_threshold = cfg.get("prevalence_boost_threshold", 3)
        supp_mult  = cfg.get("prevalence_suppression_multiplier", 0.2)
        boost_mult = cfg.get("prevalence_boost_multiplier", 1.5)

        def _stack_mult(row):
            combined = max(row["EnvDeviceCount"], row["UniqueAccounts"])
            if combined > supp_threshold:
                return supp_mult
            if combined <= boost_threshold:
                return boost_mult
            return 1.0

        def _build_stacking(src_scenes):
            src = src_scenes.copy()
            src["EvidenceNormalized"] = src["EvidenceNormalized"].str[:120]
            stk = (
                src.groupby(["TacticCategory", "DetectionType", "EvidenceNormalized"])
                .agg(
                    EnvDeviceCount=("DeviceName", "nunique"),
                    UniqueAccounts=("AccountName", "nunique"),
                    TotalHits=("DeviceName", "count"),
                    TopDestinations=("SceneDestination",
                        lambda x: ", ".join(sorted({v for v in x if v})[:5])),
                )
                .reset_index()
                .rename(columns={"EvidenceNormalized": "Evidence"})
                .sort_values("EnvDeviceCount")
            )
            stk["PrevalenceMultiplier"] = stk.apply(_stack_mult, axis=1)
            return stk

        # 7. AI Threat Summary — stacking filtered to AI-family detections only
        ai_scenes = scenes[scenes["Family"] == "AI"].copy()
        if not ai_scenes.empty:
            write_sheet("AI Threat Summary", _build_stacking(ai_scenes))

        # 8. Stacking Analysis — all detections, rarest patterns first
        write_sheet("Stacking Analysis", _build_stacking(scenes))

        # 9. Episodes (device-centric)
        write_sheet("Episodes", device_episodes)

        # 10. Per-tactic sheets
        for tactic in sorted(tactic_weights.keys()):
            tactic_scenes = scenes[scenes["TacticCategory"] == tactic].copy()
            tactic_scenes = tactic_scenes.sort_values("Timestamp", ascending=False)
            export_cols = ["Timestamp", "DeviceName", "AccountName", "DetectionType",
                           "TacticCategory", "Family", "BehaviorFamily", "WorkflowClass",
                           "TrustContext", "ExecutionTier", "ExecutionContext",
                           "CommandLineRiskScore", "ContextMultiplier", "Evidence",
                           "EnvDeviceCount", "PrevalenceMultiplier", "SourceFile"]
            tactic_scenes = tactic_scenes[[c for c in export_cols if c in tactic_scenes.columns]]
            write_sheet(tactic, tactic_scenes)

        # 11. All Scenes — full detail including workflow classification for analyst drilling
        all_scenes = scenes.sort_values("Timestamp", ascending=False)
        export_cols = ["Timestamp", "DeviceName", "AccountName", "DetectionType",
                       "TacticCategory", "Family", "BehaviorFamily",
                       "WorkflowClass", "WorkflowReasons",
                       "TrustContext", "ExecutionTier", "ExecutionContext",
                       "CommandLineRiskScore", "ContextMultiplier", "Evidence",
                       "EnvDeviceCount", "PrevalenceMultiplier", "SourceFile"]
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
    scenes = load_scenes(data_dir, tactic_weights, cfg)
    print(f"    Total scenes loaded: {len(scenes)}")

    print("[*] Applying prevalence scoring...")
    print(f"    Suppress if > {cfg.get('prevalence_suppression_threshold', 10)} devices "
          f"(multiplier {cfg.get('prevalence_suppression_multiplier', 0.2)}x), "
          f"boost if <= {cfg.get('prevalence_boost_threshold', 3)} devices "
          f"(multiplier {cfg.get('prevalence_boost_multiplier', 1.5)}x)")
    scenes = apply_prevalence_scoring(scenes, cfg)

    print("[*] Applying per-pattern scene cap...")
    scenes = apply_scene_cap(scenes, cfg)

    print("\n[*] Clustering scenes into episodes (device-centric)...")
    scenes_dev = assign_episodes(scenes, episode_window, "DeviceName")
    device_episodes = build_episodes(scenes_dev, "DeviceName", tactic_weights, cfg)
    print(f"    Episodes found: {len(device_episodes)}")

    print("[*] Clustering scenes into episodes (user-centric)...")
    scenes_usr = assign_episodes(scenes, episode_window, "AccountName")
    user_episodes = build_episodes(scenes_usr, "AccountName", tactic_weights, cfg)

    print("[*] Aggregating device seasons...")
    device_seasons = build_seasons(device_episodes, "DeviceName", tactic_weights, scenes, cfg)
    print(f"    Devices in scope: {len(device_seasons)}")

    print("[*] Aggregating user seasons...")
    user_seasons = build_seasons(user_episodes, "AccountName", tactic_weights, scenes, cfg)
    print(f"    Users in scope: {len(user_seasons)}")

    print("[*] Classifying entity workflow context...")
    device_seasons = enrich_seasons_with_workflow(device_seasons, "DeviceName", scenes, cfg)
    user_seasons   = enrich_seasons_with_workflow(user_seasons,   "AccountName", scenes, cfg)
    n_excluded = (
        (~device_seasons["EligibleForPriority"].fillna(True).astype(bool)).sum() +
        (~user_seasons["EligibleForPriority"].fillna(True).astype(bool)).sum()
    )
    if n_excluded:
        print(f"    {n_excluded} entity/entities routed to AI/Dev Automation Outliers")

    print("[*] Detecting attack chains...")
    attack_chains = build_attack_chains(device_seasons, scenes, cfg)
    print(f"    Chains detected: {len(attack_chains)}")

    # --- Historical analysis ---
    run_id = str(uuid.uuid4())
    run_ts = datetime.now(timezone.utc)

    print("[*] Loading historical baselines...")
    history = load_history(cfg)   # load BEFORE appending current run

    device_seasons = compute_historical_baselines(
        device_seasons, history, "DeviceName", "Device", run_id, cfg
    )
    user_seasons = compute_historical_baselines(
        user_seasons, history, "AccountName", "User", run_id, cfg
    )

    historical_anomalies = generate_historical_anomalies(device_seasons, user_seasons)
    if not historical_anomalies.empty:
        print(f"  [HISTORY] {len(historical_anomalies)} historical anomaly flag(s) detected")

    append_to_history(
        device_seasons, user_seasons,
        device_episodes, user_episodes,
        scenes, attack_chains,
        run_id, run_ts, cfg,
    )

    print("[*] Building priority investigation cases...")
    priority_cases = build_priority_cases(device_seasons, user_seasons)
    print(f"    Priority cases: {len(priority_cases)}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(out_dir, f"threat_hunt_{timestamp}.xlsx")
    print(f"\n[*] Writing Excel workbook...")
    write_excel(output_path, scenes, device_episodes, device_seasons, user_seasons,
                attack_chains, historical_anomalies, priority_cases, tactic_weights, cfg)

    # Summary to console
    print("\n" + "="*60)
    print("PRIORITY INVESTIGATION CASES — TOP 10")
    print("="*60)
    if not priority_cases.empty:
        disp_cols = [c for c in ["EntityType", "EntityName", "TotalRisk", "UniqueTactics",
                                  "TacticSet", "PrimaryWorkflowClass"] if c in priority_cases.columns]
        print(priority_cases.head(10)[disp_cols].to_string(index=False))
    else:
        print("  (none — all entities are AI/Dev workflow with a single MITRE tactic)")

    print("\n" + "="*60)
    print("TOP DEVICES BY BEHAVIORAL DIVERSITY (eligible entities)")
    print("="*60)
    elig_devices = device_seasons[device_seasons["EligibleForPriority"].fillna(True).astype(bool)] \
        if "EligibleForPriority" in device_seasons.columns else device_seasons
    top_div = elig_devices.sort_values("UniqueEvidenceCount", ascending=False).head(10)
    print(top_div[["DeviceName", "UniqueEvidenceCount", "UniqueDetectionTypes", "TotalRisk"]].to_string(index=False))

    if not attack_chains.empty:
        print("\n" + "="*60)
        print("ATTACK CHAINS DETECTED")
        print("="*60)
        display = attack_chains[["ChainID", "Devices", "PivotAccounts", "ChainRiskScore"]].copy()
        for col in ("Devices", "PivotAccounts"):
            display[col] = display[col].where(
                display[col].str.len() <= 60,
                display[col].str[:57] + "..."
            )
        print(display.to_string(index=False))

    print("\nDone.")


if __name__ == "__main__":
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        main()
