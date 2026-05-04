# Hunting Season — AI Threat Hunting Pipeline

A threat hunting pipeline for **Microsoft Defender for Endpoint (MDE)** focused exclusively on AI-specific threats — MCP abuse, agentic AI attacks, model theft, token theft, and shadow AI. KQL queries export raw detections; a Python consolidation script scores, correlates, and surfaces prioritised anomalies in an Excel workbook.

Traditional ATT&CK detections (LOLBins, network scans, lateral movement, credential dumping) are intentionally out of scope — native MDE and CrowdStrike Falcon analytics cover those well. This pipeline targets the gap where native EDR coverage is thin.

---

## How it works

```
KQL queries (ADX)  →  CSV exports  →  consolidate.py  →  Excel workbook
```

### Stage 1 — KQL detection queries

Fifteen standalone KQL queries in `kql/` target AI-specific threat categories. Each query is self-contained with three tuning variables at the top:

| Variable | Default | Purpose |
|---|---|---|
| `hunt_window` | `1d` | How recent reported events must be |
| `baseline_window` | `3d` | Total lookback including baseline |
| `prevalence_threshold` | `5` | Suppress patterns seen on more than N devices |

Every query outputs exactly six columns: `Timestamp`, `DeviceName`, `AccountName`, `DetectionType`, `TacticCategory`, `Evidence`.

Run each query in ADX and export results as CSV to `data/`, named `{tactic}_{detection}.csv` (e.g. `persistence_mcp_config.csv`).

### Stage 2 — Python consolidation

`consolidate.py` implements a **scenes → episodes → seasons** model:

- **Scene** — one detection row from a CSV
- **Episode** — scenes on the same device within a 4-hour window
- **Season** — all episodes aggregated per device or user account
- **Attack Chain** — devices linked by a shared `AccountName` (lateral movement pivot)

Scoring pipeline: `load_scenes` → `apply_prevalence_scoring` → `assign_episodes` → `build_episodes` → `build_seasons` → `build_attack_chains` → `write_excel`

---

## Quick start

```bash
pip install pandas xlsxwriter drain3   # drain3 optional

# Place exported CSVs in data/, then:
python consolidate.py

# Custom paths
python consolidate.py --data-dir data/ --config config.json --out output/

# Scheduled run (skips weekends, enforces min 3-day interval)
python run_hunt.py
python run_hunt.py --force
```

Output is written to `output/hunt_YYYYMMDD_HHMMSS.xlsx`.

---

## KQL queries

### Tier 1 — MCP (Model Context Protocol) abuse

MCP servers extend AI agents with access to local files, databases, APIs, and OS commands. Planting a malicious MCP server or hijacking a legitimate one gives attacker-controlled code everything the AI agent can reach.

| File | DetectionType | Signal |
|---|---|---|
| `persistence_mcp_config.kql` | MCP Server Installed | Unexpected process writes `claude_desktop_config.json` or `mcp.json` |
| `execution_mcp_server.kql` | MCP Server Execution | AI agent spawning a process with MCP-specific command-line patterns or from a suspicious path |
| `defense_evasion_mcp_tamper.kql` | MCP Config Tampered | Non-AI process modifying an MCP config file — highest-confidence signal |
| `c2_mcp_network.kql` | MCP Unexpected Network | MCP child process making outbound connections to non-whitelisted external destinations |

### Tier 2 — Autonomous agent attacks

| File | DetectionType | Signal |
|---|---|---|
| `execution_agent_spawn.kql` | Unexpected Agent Process Spawn | AI agent parent + post-exploitation command-line patterns (encoded payloads, credential tools, raw network) |
| `persistence_agent_persist.kql` | Agent Persistence Mechanism | AI agent creating Run keys, scheduled task XMLs, or startup folder items |
| `lateral_movement_agent_ipc.kql` | Agent IPC Abuse | AI agent process connecting to sensitive localhost ports (SMB 445, RDP 3389, SQL, Redis, etc.) |

### Tier 3 — Credential access and data threats

| File | DetectionType | Signal |
|---|---|---|
| `credential_access_ai_keys.kql` | AI API Key Read | Non-IDE process reading secrets files or command lines embedding AI key identifiers |
| `credential_access_browser_ai_tokens.kql` | Browser AI Token Theft | Non-browser process reading browser credential stores (Login Data, Cookies, LevelDB) |
| `exfiltration_ai_apis.kql` | AI Data Exfiltration | Non-browser process making outbound connections to AI provider API endpoints |
| `exfiltration_model_weights.kql` | AI Model Weight Exfiltration | Non-AI process reading model weight files (`.gguf`, `.safetensors`, `.pt`) |
| `collection_rag_access.kql` | RAG Unusual Access | Non-AI process connecting to local vector DB ports (ChromaDB, Qdrant, Weaviate, Milvus) |

### Tier 3 — Execution and persistence

| File | DetectionType | Signal |
|---|---|---|
| `persistence_ai_memory.kql` | AI Agent Memory Write | AI agent memory directory creation or non-AI process writing into an agent memory path (prompt injection) |
| `execution_jupyter_abuse.kql` | Jupyter Shell Execution | Shell or network process spawned directly from a Jupyter/IPython parent |
| `execution_shadow_ai.kql` | Shadow AI Tooling | Local LLM binary execution (ollama, llama-server, LM Studio) or model weight file drops in user-writable paths |

---

## Scoring model

### Tactic weights

| Tactic | Weight |
|---|---|
| CredentialAccess | 10 |
| Impact | 10 |
| Exfiltration | 9 |
| CommandAndControl | 9 |
| LateralMovement | 8 |
| DefenseEvasion | 8 |
| Persistence | 7 |
| Collection | 6 |
| Execution | 5 |
| Discovery | 3 |

### Detection type multipliers

High-signal detections carry additional multipliers on top of tactic weights:

| DetectionType | Multiplier |
|---|---|
| MCP Config Tampered | 2.5× |
| AI Model Weight Exfiltration | 2.5× |
| Browser AI Token Theft | 2.5× |
| MCP Unexpected Network | 2.0× |
| Unexpected Agent Process Spawn | 2.0× |
| Agent Persistence Mechanism | 2.0× |
| Agent IPC Abuse | 1.8× |
| AI Data Exfiltration | 1.8× |
| MCP Server Installed | 1.5× |
| MCP Server Execution | 1.5× |
| AI API Key Read | 1.5× |
| RAG Unusual Access | 1.5× |

### Episode scoring

Each episode score starts from the sum of its scenes' adjusted `ScoreContribution` values, then applies three multiplicative layers:

1. **Corroboration bonus** — reward for mixing multiple behavior families (2 families → 1.4×, 3 → 1.96×, capped at 5×)
2. **ATT&CK transition bonus** — reward for known kill-chain progressions (e.g. CredentialAccess → Exfiltration = 1.5×), all matching pairs stack multiplicatively, capped at 2.5×
3. **Variation clustering bonus** — +15% when the same tool class is used with 3+ distinct evidence strings in one episode (automated try-and-adjust behavior)

### Season scoring

Episodes are ranked by score descending. Each successive episode contributes less via `1/log2(rank+2)` weighting. Repeated episodes with the same dominant behavior family decay exponentially (2nd = 0.5×, 3rd = 0.25×), so a device with 20 identical repeated events scores far lower than one mixing credential access, C2 activity, and persistence.

### Prevalence suppression

Evidence patterns seen across many devices are automatically suppressed (>10 devices → 0.2× multiplier). Rare patterns are boosted (≤3 devices → 1.5× multiplier).

### Command-line shape scoring

The `CmdLine` field in Evidence is scanned against three pattern lists. First match wins:

| Tier | Examples | Multiplier |
|---|---|---|
| `high_risk` | base64 -d, IEX, certutil -decode, DownloadString | 2.0× |
| `medium_risk` | whoami, net user, curl\|bash, nmap | 1.3× |
| `low_risk` | git, npm, pip, pytest | 0.4× |
| neutral | (no match) | 1.0× |

---

## Workflow classification and priority gating

Every scene is classified as `AIWorkflow`, `DeveloperAutomation`, or `Unknown` based on process names, parent processes, and Evidence path patterns (configured under `workflow_classification` in `config.json`).

Entities dominated by `AIWorkflow` or `DeveloperAutomation` with fewer than 2 distinct MITRE tactics are excluded from Priority Cases and routed to the **AI Dev Outliers** sheet. This prevents legitimate AI developer tool activity (Claude Code, Cursor, bash→bash chains) from dominating the priority list.

---

## Excel output

| Sheet | Purpose |
|---|---|
| **Priority Cases** | Primary analyst view — eligible entities only, ranked by TotalRisk. AI/Dev single-tactic entities excluded. |
| **Device Seasons** | All devices including `PrimaryWorkflowClass`, `EligibleForPriority`, `ExclusionReason`. |
| **User Seasons** | Same, pivoted by AccountName. |
| **Historical Anomalies** | Entities with anomaly flags (score spike, new high, tactic expansion, tactic adaptation). Sorted by HistoricalPriority. |
| **AI Dev Outliers** | Entities excluded from priority ranking due to AI/Dev workflow dominance with a single MITRE tactic. |
| **Attack Chains** | Devices linked by shared accounts. Fan-out accounts flagged. |
| **AI Threat Summary** | Stacking view filtered to AI-family detections only. |
| **Stacking Analysis** | All evidence patterns sorted rarest-first. |
| **Episodes** | Raw episode records with scoring breakdown and adaptive behavior flags. |
| *Per-tactic sheets* | One sheet per MITRE tactic with matching scenes. |
| **All Scenes** | Every raw detection row including WorkflowClass and scoring columns. |

---

## Historical anomaly detection

After each run the script appends one record per entity to `output/hunt_history.db` (SQLite). From run 3 onwards the following flags appear on Device/User Seasons and the Historical Anomalies sheet:

| Flag | Fires when |
|---|---|
| `IsNewHigh` | Current score exceeds the entity's historical maximum |
| `IsScoreSpike` | Current score > baseline mean × 2.5 (and mean ≥ 1.0) |
| `IsZScoreAnomaly` | Z-score ≥ 2.0 |
| `IsEmergingEntity` | Entity appeared in ≤ 2 prior runs and score ≥ 10 |
| `IsTacticExpansion` | Unique tactic count exceeds historical max |
| `IsAdaptingTactics` | Current tactic set contains a tactic **never seen in any prior run** — catches low-and-slow substitution that IsTacticExpansion misses |

`IsAdaptingTactics` is the primary signal for AI-agent / adaptive attacker behavior: an entity quietly swapping one tactic for another across weeks will not trigger a score spike or Z-score anomaly but will surface here.

**Resetting the baseline**: delete `output/hunt_history.db`. Required when changing KQL hunt windows significantly or after major scoring weight changes (scores from different configurations are not comparable).

---

## Configuration

All scoring parameters live in `config.json`. Key sections:

- `tactic_weights` — base score per tactic
- `detection_type_multipliers` — per-DetectionType score multiplier on top of tactic weight
- `execution_trust_tiers` + `execution_tier_multipliers` — tiered scoring for shell/execution scenes (Jupyter, Shadow AI)
- `cmdline_risk_patterns` + `cmdline_risk_multipliers` — command-line shape scoring applied to all AI scenes
- `behavior_families` + `episode_family_cap` — per-episode family caps (MCPAbuse, AgentAttack, ModelTheft, etc.)
- `corroboration_bonus` — cross-family corroboration reward
- `tactic_transitions` — ATT&CK kill-chain progression pairs and multipliers
- `adaptive_behavior` — variation cluster threshold and score bonus
- `attack_chain_hygiene` — account exclusion lists and fan-out threshold
- `season_diminishing_returns` — log-based rank weighting and family decay
- `workflow_classification` — AI/Dev workflow detection patterns and priority gate threshold
- `history` — history store path, baseline thresholds, and anomaly flag parameters

See `CLAUDE.md` for a full key-by-key reference.

---

## Adding a new detection

1. Write a new `.kql` file in `kql/` following the six-column schema and the `hunt_window` / `baseline_window` / `prevalence_threshold` pattern
2. Add the `DetectionType` to `behavior_families` and `detection_families` in `config.json`
3. Optionally add a `detection_type_multipliers` entry
4. Export results as CSV to `data/` and run `consolidate.py` — no other code changes needed

New tactic categories not already in `tactic_weights` will score as 1 and log a warning.

---

## What stays out of git

`data/*.csv`, `output/*.xlsx`, and `output/*.db` are gitignored — hunt results may contain sensitive telemetry.
