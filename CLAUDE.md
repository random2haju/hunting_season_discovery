# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running the consolidation script

```bash
# Standard run — reads from data/, writes Excel to output/
python consolidate.py

# Custom paths
python consolidate.py --data-dir data/ --config config.json --out output/
```

Dependencies: `pandas`, `xlsxwriter`, `drain3` (optional, for evidence clustering). Install with `pip install pandas xlsxwriter drain3`.

## How the system works

This is a **cyber threat hunting pipeline** for Microsoft Defender for Endpoint (MDE). The workflow has two distinct stages:

### Stage 1 — KQL queries (run manually in ADX)
The `kql/` directory contains 8 standalone KQL queries, each targeting a specific MITRE ATT&CK tactic. Each query is self-contained and must be run separately in ADX against MDE tables. Export results as CSV to `data/` named with the pattern `{tactic}_{detection}.csv` (e.g. `execution_lolbin.csv`). The filename prefix determines the tactic category used for scoring.

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
`apply_prevalence_scoring()` adjusts each scene's `ScoreContribution` using per-`Evidence` device counts (not per `DetectionType` — that would incorrectly collapse all LOLBin hits into one bucket). Thresholds and multipliers live in `config.json`.

### Excel output structure
Sheets in order: Device Seasons → User Seasons → Attack Chains → **Stacking Analysis** → Episodes → per-tactic sheets → All Scenes. The **Stacking Analysis** sheet is the primary analyst view — patterns sorted by `EnvDeviceCount` ascending (rarest first).

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
| `mde_alert_frequency_boost_threshold` | Min alert occurrences on same device to boost MDE alert score |
| `mde_alert_frequency_boost_multiplier` | Multiplier applied to MDE alerts at or above frequency threshold |
| `evidence_normalizations` | List of `{pattern, replacement}` regex pairs applied to Evidence before prevalence grouping |
| `use_evidence_clustering` | Enable Drain3 auto-clustering of Evidence strings into templates (default false) |
| `evidence_clustering_sim_threshold` | Drain3 similarity threshold 0–1 (default 0.5); higher = less aggressive clustering |
| `detection_type_multipliers` | Optional per-DetectionType score multiplier applied on top of tactic weights and severity |
| `max_scenes_per_pattern_per_device` | Cap on how many times a single evidence pattern contributes score per device (0 = disabled, default 3); prevents volume inflation from repetitive benign tooling |
| `lolbin_trust_tiers` | Three lists of process names: `baseline_common` (bash, python, node), `contextual` (wscript, rundll32), `high_signal` (certutil, mshta). Shell/execution scenes are classified into a tier for scoring. |
| `lolbin_tier_base_multipliers` | Score multiplier per tier: `baseline_common`=0.3, `contextual`=1.0, `high_signal`=1.8 |
| `developer_parent_processes` | Process names treated as trusted dev parents (code.exe, claude.exe, etc.). Baseline-common LOLBins with these parents receive `dev_context_discount`. |
| `dev_context_discount` | Additional multiplier applied to baseline-common LOLBins whose parent is a dev tool (default 0.25). Combined with the tier multiplier: bash+claude.exe gets ×0.3×0.25=0.075, floored at 0.05. |
| `cmdline_risk_patterns` | Three pattern lists: `high_risk` (base64 -d, IEX, certutil -decode), `medium_risk` (whoami, net user, curl\|bash), `low_risk` (git, npm, pip). Matched against the `CmdLine` field in Evidence. |
| `cmdline_risk_multipliers` | Multipliers per pattern tier: `high_risk`=2.0, `medium_risk`=1.3, `low_risk`=0.4, `neutral`=1.0 |
| `behavior_families` | Maps each DetectionType to a BehaviorFamily string (e.g. `LOLBin Execution` → `ShellExecution`). Used for per-episode family caps and corroboration bonuses. |
| `episode_family_cap` | Max scenes per BehaviorFamily per episode that contribute full score (default 3). Beyond this, `episode_family_cap_multipliers[family]` is applied. |
| `episode_family_cap_multipliers` | Per-family over-cap multiplier (e.g. `ShellExecution`=0.15). High-value families like CredentialDump default to 1.0 (no reduction). |
| `corroboration_bonus` | Reward episodes that mix behavior families. `min_families_for_bonus`=2, `bonus_per_additional_family`=1.4 (2 families → 1.4×, 3 → 1.96×), `max_bonus_multiplier`=5.0. |
| `season_diminishing_returns` | Controls the season TotalRisk formula. `diminishing_log_base`=2.0 (rank weight = 1/log2(rank+2)), `same_family_decay_after`=1, `same_family_decay_factor`=0.5 (2nd same-family episode = 0.5×, 3rd = 0.25×). |

## What stays out of git

`data/*.csv` and `output/*.xlsx` are gitignored — hunt results may contain sensitive telemetry and should never be committed.
