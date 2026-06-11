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

## Running the web dashboard

```bash
# Install Python dependencies
pip install -r web/requirements.txt

# Start the backend (auto-loads latest Excel on startup, opens browser)
python web/app.py
# → http://localhost:8000

# Frontend development (hot-reload via Vite dev server at :5173)
cd web/frontend && npm install && npm run build   # production build (required for python web/app.py to serve)
cd web/frontend && npm run dev                    # dev server — CORS allowed from :8000 backend
```

The backend (`web/app.py`) is a FastAPI server that:
- Serves the built React SPA from `web/frontend/dist/`
- Exposes REST endpoints under `/api/` for all data modules
- Runs `consolidate.py` as a subprocess and streams progress via SSE (`GET /api/pipeline/run`)
- Holds all hunt data in a singleton `AppState` (defined in `web/state.py`)

**Frontend routes** map 1-to-1 to API modules:

| Route | Page | Key API endpoint |
|---|---|---|
| `/` | Attack graph (Cytoscape.js) | `GET /api/graph` |
| `/priority` | Priority Cases table (incl. triage status column) | `GET /api/priority-cases`, `GET/POST /api/triage` |
| `/seasons` | Device + User Seasons | `GET /api/seasons/devices`, `/users` |
| `/episodes` | Episode timeline | `GET /api/episodes`, `/user-episodes` |
| `/history` | Historical trends (Plotly) | `GET /api/history` |
| `/stacking` | Stacking Analysis | `GET /api/stacking?family=` |
| `/suppressions` | Suppression Manager | `GET/POST/DELETE /api/suppressions` |

**Adding a new API module**: create `web/api/<name>.py` with an `APIRouter`, register it in `web/app.py` under `prefix="/api"`, and add the fetch wrapper to `web/frontend/src/api.js`.

**State management**: `AppContext.jsx` holds `pipelineStatus` and drawer state. All page components fetch their own data on mount — there is no global data store beyond what `AppState` holds server-side.

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
- `hunt_window` — how recent the reported events must be (default `72h`; covers Mon/Wed/Fri cadence including full weekend gaps)
- `baseline_window` — total lookback including baseline (default `7d`; safe ceiling for ADX — do not exceed without testing for timeouts)
- `prevalence_threshold` — suppress patterns seen on more than this many devices (default `5`)

Recommended run cadence: **Mon / Wed / Fri** with the 72h window. Monday's run covers the full weekend. Traditional queries (`execution_lolbin.kql`, `alerts_mde.kql`, etc.) retain their original defaults and are managed separately.

### Stage 2 — Python consolidation (`consolidate.py`)
The script implements a **scenes → episodes → seasons** model:
- **Scene**: one detection row from a CSV
- **Episode**: scenes on the same device within a 4-hour window (configurable via `episode_window_hours`)
- **Season**: all episodes aggregated per device or user account
- **Attack Chain**: devices linked by a shared `AccountName` (lateral movement pivot), detected via Union-Find
- **Case**: a cluster of Device/User priority rows describing one incident, collapsed for the Priority Cases sheet (see Case clustering below)

Pipeline order: `load_scenes` → `apply_prevalence_scoring` → `assign_episodes` → `build_episodes` → `build_seasons` → `build_attack_chains` → `build_priority_cases` (clusters cases) → `write_excel`

### Case clustering (`casecluster.py`)
The hunt produces one season row per Device and one per User, so a single user active on a single device surfaces as **two** Priority Cases rows for the same scenes — at fleet scale this roughly doubles the list. `cluster_priority_cases()` collapses rows that share scenes into one **case** via Union-Find over Device↔User nodes, keeping the highest-`CompositeScore` member as the anchor (ties → Device). It is **score-neutral** — like triage it only changes which row fronts the list and what is folded behind it (`CaseClusterId`, `ClusterMemberCount`, `RelatedEntities`); folded-in members stay fully visible in Device/User Seasons.

The grouping preserves the signal each entity view exists for: one user on one device → one case; several users on one device → the device anchors; **one user across several devices → the user anchors** (the roaming/lateral-movement signal is never discarded). Linking reuses `attack_chain_hygiene` account hygiene (null/machine/service accounts never link; names domain-stripped + case-folded), and a **fan-out guard** (`priority_clustering.link_fan_out_threshold`, default = `attack_chain_hygiene.fan_out_threshold`) stops a high-prevalence admin/scanner account from welding the whole fleet into one mega-case — such an account still stands as its own case, it just doesn't absorb every device. Triage state propagates across a cluster: an anchor inherits the most-recent disposition among its members (`triage.states_with_cluster_propagation`), so a verdict set on a now-folded member doesn't resurface as New.

### Prevalence scoring
`apply_prevalence_scoring()` adjusts each scene's `ScoreContribution` using per-`Evidence` device counts (not per `DetectionType` — that would incorrectly collapse all hits of one detection type into one bucket). Thresholds and multipliers live in `config.json`.

### Episode multiplier model & AI damping
`build_episodes()` computes `EpisodeRiskScore = BaseEpisodeScore × EffectiveMultiplier`, where:
- **`BaseEpisodeScore`** — sum of per-scene `ScoreContribution` after the per-family cap (zeroed scenes contribute 0 and do not consume cap budget).
- **`EffectiveMultiplier`** = `min(corroboration_eff × transition_eff × variation, max_episode_multiplier)`.

**AI damping** replaces the old binary "all-AI → no bonus" gate. Each structural bonus is scaled toward 1.0 by the episode's AI share:
```
ai_share        = Σ(AI-family adjusted score) / BaseEpisodeScore      # 0 when base is 0
corroboration_eff = 1 + (CorroborationMult   − 1) × (1 − ai_share)
transition_eff    = 1 + (TacticTransitionMult − 1) × (1 − ai_share)
```
A pure-AI episode (`ai_share = 1`) collapses both bonuses to 1.0 (preserving the old behavior at the extreme); a pure-traditional episode (`ai_share = 0`) keeps the full bonus; mixed episodes are damped in proportion to AI-score dominance. **Variation/adaptive bonus is never damped** — try-and-adjust is the canonical AI signal. The `CorroborationMult` and `TacticTransitionMult` columns store the **raw structural** bonus (no longer zeroed for AI episodes); `AIShare` and `EffectiveMultiplier` columns let an analyst reconstruct the final score.

### Excel output structure
Sheets in order:
1. **Priority Cases** — primary analyst view; eligible entities only, ranked by `CompositeScore`. AI/Dev-dominated single-tactic entities and analyst-suppressed entities are excluded here. Duplicate Device/User rows describing the same incident are collapsed into a single **case** (see Case clustering below) — the columns `CaseClusterId`, `ClusterMemberCount`, and `RelatedEntities` record the grouping. The list is then cut to actionable size by `priority_min_composite_score` (score floor) and `priority_max_cases` (top-N cap), counting cases not rows — entities below the floor (and folded-in members) remain visible in Device/User Seasons. The console prints a CompositeScore percentile distribution each run for tuning the floor. Includes triage columns (`TriageStatus`, `TriageNote`, `TriagedBy`, `TriagedDate`, `TriageHasNewActivity`, `TriageStale`) stamped from `output/triage.db`; all rows stay in rank order regardless of triage state.
2. **Device Seasons** — all devices including `PrimaryWorkflowClass`, `EligibleForPriority`, `ExclusionReason`, `IsSuppressed`, `SuppressReason` columns.
3. **User Seasons** — same as Device Seasons but user-centric.
4. **Historical Anomalies** — anomaly-flagged eligible entities (Z-score spikes, new highs, tactic expansion). Ineligible entities filtered out.
5. **AI Dev Outliers** — entities excluded from priority ranking because they are automation-dominated (`AIWorkflow` / `DeveloperAutomation` / `ServiceAutomation`) with fewer than `priority_min_tactics_for_ai_dev` (default 2) distinct MITRE tactics. Entities meeting the severity escape hatch (`priority_score_override` or a `non_discountable_detection_types` hit) are retained in Priority Cases instead. Includes `ExclusionReason` column.
6. **Suppressed Entities** — analyst-dispositioned false positives excluded from Priority Cases. Shown for audit. Only present when suppressions exist.
7. **Attack Chains** — cross-device lateral movement chains.
8. **AI Threat Summary** — stacking view filtered to AI-family detections.
9. **Stacking Analysis** — all detections, patterns sorted by `EnvDeviceCount` ascending (rarest first).
10. **Episodes** — device-centric episode detail.
11. Per-tactic sheets — one sheet per MITRE tactic.
12. **All Scenes** — full raw scene list with `WorkflowClass` and `WorkflowReasons` columns.

## Managing false-positive suppressions

Use `suppress.py` to exclude known-benign entities from Priority Cases without deleting their data. Suppressed entities remain visible in Device/User Seasons sheets (with `IsSuppressed=True` and `SuppressReason`) and appear in a dedicated **Suppressed Entities** audit sheet.

```bash
# Suppress a device permanently
python suppress.py add --type Device --name "LAPTOP-AI-DEV01" --reason "Known AI developer workstation"

# Suppress a user account until a date (auto-reinstated after expiry)
python suppress.py add --type User --name "svc-scanner" --reason "Automated scanner" --expires 2026-12-31

# List all active suppressions
python suppress.py list

# Lift a suppression
python suppress.py remove --type Device --name "LAPTOP-AI-DEV01"

# Remove all expired entries
python suppress.py expire
```

Suppressions are stored in `output/suppressions.csv` (gitignored). Expired entries are skipped automatically by `consolidate.py` — run `suppress.py expire` periodically to prune the file. The `suppression.store_path` config key controls the file location.

## Triage states for Priority Cases

Triage tracks the analyst's disposition of each Priority Cases entity across runs, so the same stable entities are not re-reviewed every Mon/Wed/Fri. States: **New** (implicit — no record) → **Investigating** (claimed; note optional) → **Benign** | **Escalated** (verdicts; note **required**). **Reopened** is derived, never stored: a Benign entity whose `LastSeen` is strictly newer than the snapshot taken at triage time flips to Reopened (strictly-newer matters — the 72h hunt window overlaps between runs, so re-exported events must not reopen cases). Investigating/Escalated keep their state on new activity but get a new-activity badge (●); Investigating older than `triage.stale_investigating_days` is flagged stale.

All semantics live in the shared root-level `triage.py` module — one implementation used by both `consolidate.py` (stamps `TriageStatus`/`TriageNote`/`TriagedBy`/`TriagedDate`/`TriageHasNewActivity`/`TriageStale` columns onto the Priority Cases sheet) and the web backend (`web/api/triage.py`: `GET/POST /api/triage`, `GET /api/triage/log/{type}/{name}`; in-memory stamping in `web/state.py::_apply_triage`).

The store is a single append-only `triage_log` table in `output/triage.db` (gitignored): current state = latest row per (EntityType, case-insensitive EntityName); full history is the audit trail, shown in the entity detail drawer. The store is deliberately **separate from `hunt_history.db`** so the documented baseline-reset procedure (delete `hunt_history.db`) never destroys analyst dispositions. `TriagedBy` is auto-captured from the OS username; verdict rows snapshot `LastSeen`/`TotalRisk`/`TacticSet` so the log shows what the analyst saw.

In the dashboard: the Priority Cases status column is click-to-change, status filter chips default to hiding Benign, the right-click context menu has a Triage submenu (also on Seasons), and the Benign modal offers an "also suppress permanently" shortcut. Triage never changes scores or ranking — display and filtering only. Marking Benign is per-activity (auto-reopens on new activity); recurring benign noise should be suppressed instead.

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
| `corroboration_bonus` | Reward episodes that mix behavior families. `min_families_for_bonus`=2, `bonus_per_additional_family`=1.4 (2 families → 1.4×, 3 → 1.96×), `max_bonus_multiplier`=5.0. Counts only families that contributed non-zero score, after collapsing them via `corroboration_groups`. The structural bonus (`CorroborationMult` column) is then **damped** by the episode's AI share before being applied — see AI damping below. |
| `corroboration_groups` | Optional map of BehaviorFamily → group name, applied **only** when counting families for the corroboration bonus. Variants of one underlying behavior (e.g. `LolbinExecution`/`JupyterExecution`/`ShadowAI` → `Execution`) collapse to a single group so they don't earn a corroboration multiplier for being "the same behavior done several ways." Families absent from the map are their own group. Capping, `DominantFamily`, `FamilyCount` and the Episodes display still use the real family. |
| `tactic_transitions` | Reward episodes whose tactic set spans known ATT&CK relationship pairs (e.g. CredentialAccess+LateralMovement). **Matching is order-insensitive co-occurrence within the episode window, not temporal progression** — the "transition" name is historical. Symmetric duplicate pairs are deduped so one relationship can't double-count. Each matching pair contributes a multiplier; all stack multiplicatively, capped at `max_multiplier` (default 2.0). The structural bonus (`TacticTransitionMult` column) is then damped by AI share. Adds `TacticTransitionMult` and `TacticTransitions` columns to Episodes sheet. |
| `max_episode_multiplier` | Aggregate cap on the compounded episode multiplier (default 6.0). `EpisodeRiskScore = BaseEpisodeScore × min(corroboration_eff × transition_eff × variation, max_episode_multiplier)`. Bounds correlated signals (corroboration + transition + variation) from stacking without limit — worst case was ~14.4× before this cap. |
| `adaptive_behavior.variation_cluster_min_size` | Minimum number of distinct Evidence strings within one (device, DetectionType) group in a single episode to declare a variation cluster (default 3). A cluster indicates automated try-and-adjust behavior — the same tool used against many distinct targets in rapid succession. |
| `adaptive_behavior.variation_score_bonus` | Multiplicative bonus applied to `EpisodeRiskScore` when at least one variation cluster is detected (default 1.15 = +15%). Intentionally small to surface adaptive episodes slightly higher without overriding tactic weight or prevalence. Raise to 1.3–1.5 in high-confidence environments. |
| `attack_chain_hygiene.fan_out_threshold` | Accounts appearing on ≥ N devices within a chain are flagged `IsFanOut=True` (default 3). Adds `IsFanOut` and `MaxAccountFanOut` columns to Attack Chains sheet. |
| `attack_chain_hygiene.strip_account_domain` | Normalize account names before chaining so case variants and `DOMAIN\` prefixes (`CONTOSO\Alice`, `alice`, `ALICE`) link as one pivot account (default true). Grouping/exclusion run on the normalized key; the most common original spelling is kept for display. |
| `season_diminishing_returns` | Controls the season TotalRisk formula. `diminishing_log_base`=2.0 (rank weight = 1/log2(rank+2)), `same_family_decay_after`=1, `same_family_decay_factor`=0.5 (2nd same-family episode = 0.5×, 3rd = 0.25×). |
| `workflow_classification.ai_path_patterns` | Evidence strings containing these substrings (e.g. `/.claude/`, `mcp.json`) mark a scene as `AIWorkflow`. Matched against the whole Evidence string, so robust to which KQL query produced it. |
| `workflow_classification.ai_process_names` | AI agent process names (claude, cursor, windsurf, copilot, aider, ollama, …). Matched against the canonical `Process:` actor key only — **not** `Writer:`/`Reader:`/`ReadBy:`, since those keys belong to detections that deliberately fire on *non-AI* actors touching AI assets (e.g. Browser AI Token Theft) and must keep full score. |
| `workflow_classification.ai_parent_names` | Parent process names that indicate an AI agent launched the child process. Checked against both `Parent:` and `JupyterParent:` Evidence keys. |
| `workflow_classification.ai_process_parent_pairs` | Optional list of `[process, parent]` stem pairs that mark a scene `AIWorkflow`. Empty by default (the old `[bash, bash]` heuristic was too generic). |
| `workflow_classification.ai_actor_detection_types` | DetectionTypes whose KQL filters on `InitiatingProcessFileName in~ (ai_agent_processes)` — i.e. the AI agent is the actor by construction (Unexpected Agent Process Spawn, Agent IPC Abuse, Agent Persistence Mechanism, MCP Server Execution). These are classified `AIWorkflow` from the DetectionType directly, independent of Evidence string parsing. |
| `workflow_classification.service_account_patterns` | Marks a scene `ServiceAutomation` when its AccountName matches `exact` names, `prefixes` (svc-, sa-), or `suffixes` (`$` machine accounts). |
| `workflow_classification.priority_min_tactics_for_ai_dev` | AIWorkflow/DeveloperAutomation/ServiceAutomation entities need at least this many distinct MITRE tactics to appear in Priority Cases (default 2) |
| `workflow_classification.priority_score_override` | Severity escape hatch: an automation-dominated entity below the tactic minimum is still retained in Priority Cases when its `TotalRisk` ≥ this value (default 25.0; 0 disables). |
| `workflow_classification.non_discountable_detection_types` | An automation-dominated entity below the tactic minimum is also retained in Priority Cases if any of its scenes carries one of these high-severity detections (MCP Config Tampered, credential dumps, agent persistence, …) — so a single critical hit on an AI/service host is never silently hidden. |
| `ai_workflow_detection_discounts` | Per-DetectionType score multiplier applied only to scenes classified as `AIWorkflow`. Reduces noise from detections that are expected behaviour for AI agents (e.g. Claude calling AI provider APIs triggers "AI Data Exfiltration" but is not suspicious). Detection types not listed keep their full score (1.0). High-severity detections (credential theft, persistence, MCP tampering) should not be discounted. |
| `priority_min_composite_score` | Minimum `CompositeScore` for a row to appear in Priority Cases (default 10.0; 0 disables). Below-floor entities stay in Device/User Seasons. Tune using the percentile distribution printed each run. |
| `priority_max_cases` | Hard top-N cap on Priority Cases rows, applied after the score floor (default 150; 0 disables). Counts clustered cases, not raw rows. |
| `priority_clustering.enabled` | Collapse duplicate Device/User priority rows that share scenes into one anchored case (default true). When false, every eligible entity stays its own row. |
| `priority_clustering.link_fan_out_threshold` | An account on ≥ this many devices is treated as fan-out and is **not** used to link/merge cases (default falls back to `attack_chain_hygiene.fan_out_threshold` = 3). Prevents one shared admin/scanner account from welding the fleet into a single cluster. |
| `suppression.store_path` | Path to the analyst suppression CSV relative to the script directory (default `output/suppressions.csv`). Managed via `suppress.py`. |
| `suppression.pattern_store_path` | Path to the pattern suppression JSON file (default `output/pattern_suppressions.json`). Managed via the web dashboard Pattern Rules tab. |
| `triage.store_path` | Path to the analyst triage SQLite store (default `output/triage.db`). Append-only `triage_log` table; deliberately separate from `hunt_history.db` so baseline resets never delete triage state. |
| `triage.stale_investigating_days` | Cases sitting in Investigating longer than this many days are flagged `TriageStale` (default 7 ≈ 3 hunt runs). |
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

`PreviousScore`, `BaselineMean`, `BaselineMedian`, `BaselineStdDev`, `HistoricalMax`, `RunCount`, `ScoreDelta`, `ScoreDeltaPct`, `ZScore`, `IsNewHigh`, `IsScoreSpike`, `IsEmergingEntity`, `IsTacticExpansion`, `IsAdaptingTactics`, `NewTactics`, `IsNewDevicePairing`, `NewPairings`

Episodes sheet also gains: `VariationClusterCount`, `LargestVariationCluster`, `AdaptiveBehaviorFlag`, `AdaptiveBehaviorReason`, `BaseEpisodeScore`, `AIShare`, `EffectiveMultiplier`.

Device/User Seasons sheets also gain: `TacticSet`, `PairingSet`, `MaxEpisodeVariationCluster`, `AdaptiveEpisodeCount`.

**`IsAdaptingTactics`**: fires when the current run's tactic set contains a tactic never seen in any prior run for that entity. This is the canonical low-and-slow AI-agent signal — unlike `IsTacticExpansion` (which only catches count growth), `IsAdaptingTactics` also catches tactic *substitution*. `NewTactics` lists the specific new tactics as a comma-joined string. Protected by `minimum_runs_for_baseline`.

**`IsNewDevicePairing`**: fires when the entity tripped alarms with a counterpart it has never been paired with in its baseline — for a **user**, a device outside its historical device set; for a **device**, a new account on it. This is the "stranger in the house" signal: residents, the janitor, and long-roaming admins are all in the baseline's memory, so a genuinely new pairing cleanly separates a long-established roaming account (huge historical set, nothing new) from one that *started* roaming this run. `NewPairings` lists the specific new counterpart names. Backed by the per-entity `PairingSet` column persisted to `hunt_history` (built from scored scenes only, so fully-discounted benign tooling registers no pairing). Protected by `minimum_runs_for_baseline`; carries the same +2.5 `HistoricalPriority` bonus as `IsAdaptingTactics`.

A **Historical Anomalies** sheet (3rd in the workbook, before Attack Chains) surfaces entities where any flag is True, sorted by `HistoricalPriority` — a formula that rewards relative change weighted by absolute score magnitude. `IsAdaptingTactics` carries the same +2.5 priority bonus as `IsTacticExpansion` so that quietly-adapting entities surface even when their ZScore is low.

**First run**: no history exists, DB is created automatically, all flags are False (except `IsEmergingEntity` for entities above the score threshold).

**If config scoring weights change significantly** (e.g. tactic weight increase), the existing baseline will produce inflated Z-scores for all entities. In that case, reset the baseline by deleting `output/hunt_history.db` or pointing `history.store_path` to a new file. Analyst triage state lives in the separate `output/triage.db` and survives a baseline reset.

**Schema upgrades**: back up `hunt_history.db` before deploying script changes that modify the history schema. The `OutputVersion` constant in the script tracks schema versions (currently 2 — v2 added the `PairingSet` column; older DBs are auto-migrated via `ALTER TABLE` on the next run, and `IsNewDevicePairing` simply stays False until `minimum_runs_for_baseline` runs of pairing history accumulate).

## What stays out of git

`data/*.csv`, `output/*.xlsx`, `output/*.db`, and `output/*.csv` (including `suppressions.csv`) are gitignored — hunt results and suppression lists may contain sensitive entity names and should never be committed.
