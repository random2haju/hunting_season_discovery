# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the consolidation script

```bash
# Standard run — reads from data/, writes Excel to output/
python consolidate.py

# Scheduled run (self-gates: skips weekends, enforces min 3-day interval)
python run_hunt.py

# Force a run regardless of schedule
python run_hunt.py --force

# Custom paths
python consolidate.py --data-dir data/ --config config.json --out output/
```

Dependencies: `pandas`, `xlsxwriter`, `drain3` (optional, for evidence clustering). Install with `pip install pandas xlsxwriter drain3`.

### Scheduling (Windows Task Scheduler)
Set up a daily trigger pointing to `python run_hunt.py`. The script skips Saturday/Sunday and enforces the `--min-days` interval (default 3) via `output/last_run.txt`. Use `--min-days 2` if you want Mon/Wed/Fri cadence instead.

## How the system works

This is an **AI-focused cyber threat hunting pipeline** for Microsoft Defender for Endpoint (MDE). The pipeline targets AI-specific threats — MCP abuse, agentic AI attacks, model theft, token theft — where native EDR coverage is thin. The workflow has two distinct stages:

### Stage 1 — KQL queries (run manually in ADX)
The `kql/` directory contains 15 standalone KQL queries, all targeting AI-specific threat categories. Each query is self-contained and must be run separately in ADX against MDE tables. Export results as CSV to `data/` named with the pattern `{tactic}_{detection}.csv` (e.g. `persistence_mcp_config.csv`). The filename prefix determines the tactic category used for scoring.

**Query inventory:**
| File | DetectionType | Signal |
|---|---|---|
| `persistence_mcp_config.kql` | MCP Server Installed | Unexpected process writes MCP config file |
| `execution_mcp_server.kql` | MCP Server Execution | AI agent spawning suspicious MCP server binary |
| `defense_evasion_mcp_tamper.kql` | MCP Config Tampered | Non-AI process modifying MCP config |
| `c2_mcp_network.kql` | MCP Unexpected Network | MCP child process phoning home to unknown IP |
| `execution_agent_spawn.kql` | Unexpected Agent Process Spawn | AI agent + post-exploitation cmdline patterns |
| `persistence_agent_persist.kql` | Agent Persistence Mechanism | AI agent creating Run keys / scheduled tasks |
| `lateral_movement_agent_ipc.kql` | Agent IPC Abuse | AI agent connecting to sensitive localhost ports |
| `credential_access_ai_keys.kql` | AI API Key Read | Non-IDE process reading AI secrets files |
| `persistence_ai_memory.kql` | AI Agent Memory Write | AI agent memory dir creation or injection |
| `exfiltration_ai_apis.kql` | AI Data Exfiltration | Non-browser process calling AI provider APIs |
| `execution_jupyter_abuse.kql` | Jupyter Shell Execution | Shell child spawned from Jupyter parent |
| `execution_shadow_ai.kql` | Shadow AI Tooling | Local LLM binary execution or model file drop |
| `exfiltration_model_weights.kql` | AI Model Weight Exfiltration | Non-AI process reading .gguf/.safetensors/.pt |
| `collection_rag_access.kql` | RAG Unusual Access | Non-AI process hitting local vector DB ports |
| `credential_access_browser_ai_tokens.kql` | Browser AI Token Theft | Non-browser process reading browser credential stores |

Every query outputs exactly 6 columns: `Timestamp, DeviceName, AccountName, DetectionType, TacticCategory, Evidence`. This contract must not be broken — the Python script validates it on load.

Each KQL query has three tuning variables at the top:
- `hunt_window` — how recent the reported events must be (default `1d`)
- `baseline_window` — total lookback including baseline (default `3d`, stay under ~7d to avoid timeouts)
- `prevalence_threshold` — suppress patterns seen on more than this many devices (default `5`)

### Stage 2 — Python consolidation (`consolidate.py`)
The script implements a **scenes → episodes → seasons** model:
- **Scene**: one detection row from a CSV
- **Episode**: scenes on the same device within a 4-hour window (configurable via `episode_window_hours`)
- **Season**: all episodes aggregated per device or user account
- **Attack Chain**: devices linked by a shared `AccountName` (lateral movement pivot), detected via Union-Find

Pipeline order: `load_scenes` → `apply_prevalence_scoring` → `assign_episodes` → `build_episodes` → `build_seasons` → `build_attack_chains` → `write_excel`

### Prevalence scoring
`apply_prevalence_scoring()` adjusts each scene's `ScoreContribution` using per-`Evidence` device counts (not per `DetectionType` — that would incorrectly collapse all hits of one detection type into one bucket). Thresholds and multipliers live in `config.json`.

### Excel output structure
Sheets in order:
1. **Priority Cases** — primary analyst view; eligible entities only, ranked by `TotalRisk`. AI/Dev-dominated single-tactic entities are excluded here.
2. **Device Seasons** — all devices including `PrimaryWorkflowClass`, `EligibleForPriority`, `ExclusionReason` columns.
3. **User Seasons** — same as Device Seasons but user-centric.
4. **Historical Anomalies** — anomaly-flagged eligible entities (Z-score spikes, new highs, tactic expansion). Ineligible entities filtered out.
5. **AI Dev Outliers** — entities excluded from priority ranking because they are AI/Dev-workflow-dominated with fewer than `priority_min_tactics_for_ai_dev` (default 2) distinct MITRE tactics. Includes `ExclusionReason` column.
6. **Attack Chains** — cross-device lateral movement chains.
7. **AI Threat Summary** — stacking view filtered to AI-family detections.
8. **Stacking Analysis** — all detections, patterns sorted by `EnvDeviceCount` ascending (rarest first).
9. **Episodes** — device-centric episode detail.
10. Per-tactic sheets — one sheet per MITRE tactic.
11. **All Scenes** — full raw scene list with `WorkflowClass` and `WorkflowReasons` columns.

## Adding a new detection

1. Write a new `.kql` file in `kql/` following the naming convention and outputting the 6-column schema
2. Export results as CSV to `data/`
3. Run `consolidate.py` — no code changes needed

New tactic categories not already in `config.json` will score as 1 and log a warning.

## config.json keys

| Key | Purpose |
|---|---|
| `tactic_weights` | Score per scene by tactic (CredentialAccess=10 down to Discovery=3) |
| `episode_window_hours` | Max gap between scenes to be in the same episode |
| `prevalence_suppression_threshold` | Evidence on > N devices → 0.2x score multiplier |
| `prevalence_boost_threshold` | Evidence on ≤ N devices → 1.5x score multiplier |
| `prevalence_suppression_multiplier` | Multiplier applied when above suppression threshold |
| `prevalence_boost_multiplier` | Multiplier applied when at or below boost threshold |
| `evidence_normalizations` | List of `{pattern, replacement}` regex pairs applied to Evidence before prevalence grouping |
| `use_evidence_clustering` | Enable Drain3 auto-clustering of Evidence strings into templates (default false) |
| `evidence_clustering_sim_threshold` | Drain3 similarity threshold 0–1 (default 0.5); higher = less aggressive clustering |
| `detection_type_multipliers` | Optional per-DetectionType score multiplier applied on top of tactic weights and severity |
| `max_scenes_per_pattern_per_device` | Cap on how many times a single evidence pattern contributes score per device (0 = disabled, default 3); prevents volume inflation from repetitive benign tooling |
| `execution_trust_tiers` | Three lists of process names: `baseline_common` (bash, python, node), `contextual` (wscript, rundll32), `high_signal` (certutil, mshta). Applied to Jupyter and Shadow AI scenes for tiered scoring. |
| `execution_tier_multipliers` | Score multiplier per tier: `baseline_common`=0.3, `contextual`=1.0, `high_signal`=1.8 |
| `developer_parent_processes` | Process names treated as trusted dev parents (code.exe, claude.exe, etc.). Baseline-common execution scenes with these parents receive `dev_context_discount`. |
| `dev_context_discount` | Additional multiplier applied to baseline-common execution scenes whose parent is a dev tool (default 0.25). Combined with the tier multiplier, floored at 0.05. |
| `cmdline_risk_patterns` | Three pattern lists: `high_risk` (base64 -d, IEX, certutil -decode), `medium_risk` (whoami, net user, curl\|bash), `low_risk` (git, npm, pip). Matched against the `CmdLine` field in Evidence — applies to all AI detection types. |
| `cmdline_risk_multipliers` | Multipliers per pattern tier: `high_risk`=2.0, `medium_risk`=1.3, `low_risk`=0.4, `neutral`=1.0 |
| `behavior_families` | Maps each DetectionType to a BehaviorFamily string (e.g. `LOLBin Execution` → `ShellExecution`). Used for per-episode family caps and corroboration bonuses. |
| `episode_family_cap` | Max scenes per BehaviorFamily per episode that contribute full score (default 3). Beyond this, `episode_family_cap_multipliers[family]` is applied. |
| `episode_family_cap_multipliers` | Per-family over-cap multiplier (e.g. `ShellExecution`=0.15). High-value families like CredentialDump default to 1.0 (no reduction). |
| `corroboration_bonus` | Reward episodes that mix behavior families. `min_families_for_bonus`=2, `bonus_per_additional_family`=1.4 (2 families → 1.4×, 3 → 1.96×), `max_bonus_multiplier`=5.0. |
| `tactic_transitions` | Reward episodes whose tactic set spans known ATT&CK progressions (e.g. CredentialAccess+LateralMovement). Each matching pair contributes a multiplier; all matching pairs stack multiplicatively, capped at `max_multiplier` (default 2.0). Adds `TacticTransitionMult` and `TacticTransitions` columns to Episodes sheet. |
| `adaptive_behavior.variation_cluster_min_size` | Minimum number of distinct Evidence strings within one (device, DetectionType) group in a single episode to declare a variation cluster (default 3). A cluster indicates automated try-and-adjust behavior — the same tool used against many distinct targets in rapid succession. |
| `adaptive_behavior.variation_score_bonus` | Multiplicative bonus applied to `EpisodeRiskScore` when at least one variation cluster is detected (default 1.15 = +15%). Intentionally small to surface adaptive episodes slightly higher without overriding tactic weight or prevalence. Raise to 1.3–1.5 in high-confidence environments. |
| `attack_chain_hygiene.fan_out_threshold` | Accounts appearing on ≥ N devices within a chain are flagged `IsFanOut=True` (default 3). Adds `IsFanOut` and `MaxAccountFanOut` columns to Attack Chains sheet. |
| `season_diminishing_returns` | Controls the season TotalRisk formula. `diminishing_log_base`=2.0 (rank weight = 1/log2(rank+2)), `same_family_decay_after`=1, `same_family_decay_factor`=0.5 (2nd same-family episode = 0.5×, 3rd = 0.25×). |
| `workflow_classification.ai_path_patterns` | Evidence strings containing these substrings (e.g. `/.claude/`) mark a scene as `AIWorkflow` |
| `workflow_classification.ai_process_names` | Process names (e.g. `claude.exe`) that indicate an AI agent scene |
| `workflow_classification.ai_parent_names` | Parent process names that indicate an AI agent launched the child process |
| `workflow_classification.priority_min_tactics_for_ai_dev` | AIWorkflow/DeveloperAutomation entities need at least this many distinct MITRE tactics to appear in Priority Cases (default 2) |
| `history.enabled` | Toggle historical analysis on/off (default true). When false the script behaves exactly as before this feature was added. |
| `history.store_path` | Path to the SQLite history file relative to the script directory (default `output/hunt_history.db`). |
| `history.minimum_runs_for_baseline` | Minimum prior runs required before IsNewHigh / IsScoreSpike / IsTacticExpansion can fire (default 3). Prevents noisy flags from thin baselines. |
| `history.score_spike_multiplier` | Current score must exceed `mean × multiplier` to trigger IsScoreSpike (default 2.5). |
| `history.score_spike_min_mean` | Baseline mean must be at least this value for IsScoreSpike to fire (default 1.0). Suppresses false positives from near-zero baselines. |
| `history.zscore_threshold` | Z-score above this value is considered anomalous; informational only — the HistoricalPriority formula uses ZScore directly. |
| `history.emerging_entity_score_threshold` | Score threshold for IsEmergingEntity flag (default 10.0). |
| `history.emerging_entity_max_runs` | Entity must have appeared in ≤ this many prior runs to be flagged as emerging (default 2). |
| `history.tactic_expansion_threshold` | Current UniqueTactics must exceed historical max by at least this delta to trigger IsTacticExpansion (default 1). |
| `history.max_runs_per_entity` | Limit how many prior runs per entity are loaded for baseline calculation (default 90, 0=unlimited). |

## Historical score persistence

After each run the script appends one record per device and user to `output/hunt_history.db` (SQLite). On the next run this baseline is loaded, and Device Seasons / User Seasons gain extra columns:

`PreviousScore`, `BaselineMean`, `BaselineMedian`, `BaselineStdDev`, `HistoricalMax`, `RunCount`, `ScoreDelta`, `ScoreDeltaPct`, `ZScore`, `IsNewHigh`, `IsScoreSpike`, `IsEmergingEntity`, `IsTacticExpansion`, `IsAdaptingTactics`, `NewTactics`

Episodes sheet also gains: `VariationClusterCount`, `LargestVariationCluster`, `AdaptiveBehaviorFlag`, `AdaptiveBehaviorReason`.

Device/User Seasons sheets also gain: `TacticSet`, `MaxEpisodeVariationCluster`, `AdaptiveEpisodeCount`.

**`IsAdaptingTactics`**: fires when the current run's tactic set contains a tactic never seen in any prior run for that entity. This is the canonical low-and-slow AI-agent signal — unlike `IsTacticExpansion` (which only catches count growth), `IsAdaptingTactics` also catches tactic *substitution*. `NewTactics` lists the specific new tactics as a comma-joined string. Protected by `minimum_runs_for_baseline`.

A **Historical Anomalies** sheet (3rd in the workbook, before Attack Chains) surfaces entities where any flag is True, sorted by `HistoricalPriority` — a formula that rewards relative change weighted by absolute score magnitude. `IsAdaptingTactics` carries the same +2.5 priority bonus as `IsTacticExpansion` so that quietly-adapting entities surface even when their ZScore is low.

**First run**: no history exists, DB is created automatically, all flags are False (except `IsEmergingEntity` for entities above the score threshold).

**If config scoring weights change significantly** (e.g. tactic weight increase), the existing baseline will produce inflated Z-scores for all entities. In that case, reset the baseline by deleting `output/hunt_history.db` or pointing `history.store_path` to a new file.

**Schema upgrades**: back up `hunt_history.db` before deploying script changes that modify the history schema. The `OutputVersion` constant in the script tracks schema versions.

## What stays out of git

`data/*.csv`, `output/*.xlsx`, and `output/*.db` are gitignored — hunt results may contain sensitive telemetry and should never be committed.
