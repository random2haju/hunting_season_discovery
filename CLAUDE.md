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

## What stays out of git

`data/*.csv` and `output/*.xlsx` are gitignored — hunt results may contain sensitive telemetry and should never be committed.
