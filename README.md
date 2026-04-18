# Hunting Season — MDE Threat Hunting Pipeline

A threat hunting pipeline for **Microsoft Defender for Endpoint (MDE)**. KQL queries export raw detections; a Python consolidation script scores, correlates, and surfaces prioritised anomalies in an Excel workbook.

---

## How it works

```
KQL queries (ADX)  →  CSV exports  →  consolidate.py  →  Excel workbook
```

### Stage 1 — KQL detection queries

Nineteen standalone KQL queries in `kql/` target specific MITRE ATT&CK tactics. Each query is self-contained with three tuning variables at the top:

| Variable | Default | Purpose |
|---|---|---|
| `hunt_window` | `1d` | How recent reported events must be |
| `baseline_window` | `3d` | Total lookback including baseline |
| `prevalence_threshold` | `5` | Suppress patterns seen on more than N devices |

Every query outputs exactly six columns: `Timestamp`, `DeviceName`, `AccountName`, `DetectionType`, `TacticCategory`, `Evidence`.

Run each query in ADX and export results as CSV to the `data/` directory, named `{tactic}_{detection}.csv` (e.g. `execution_lolbin.csv`).

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
```

Output is written to `output/hunt_YYYYMMDD_HHMMSS.xlsx`.

---

## KQL queries

| File | Tactic | What it detects |
|---|---|---|
| `execution_lolbin.kql` | Execution | Living-off-the-land binaries: certutil, mshta, wscript, etc. with dev-context discount |
| `execution_jupyter_abuse.kql` | Execution | Jupyter kernels spawning shells or running suspicious commands |
| `execution_shadow_ai.kql` | Execution | Local LLM tooling (ollama, llama-server, LM Studio) and model weight file drops |
| `discovery_commands.kql` | Discovery | Reconnaissance commands: whoami, net user, ipconfig, nltest, etc. |
| `discovery_network_scan.kql` | Discovery | SMB/RDP/WinRM port scanning across 3+ distinct destination IPs |
| `persistence_scheduled_tasks.kql` | Persistence | Scheduled task creation via schtasks or Task Scheduler COM |
| `persistence_run_keys.kql` | Persistence | Registry Run/RunOnce key modifications |
| `persistence_startup_folder.kql` | Persistence | Executable drops into user or system startup folders |
| `persistence_ai_memory.kql` | Persistence | Writes to AI agent memory stores (Claude, Copilot, AutoGPT paths) |
| `credential_access_lsass.kql` | CredentialAccess | LSASS memory dump and suspicious handle opens |
| `credential_access_ai_keys.kql` | CredentialAccess | Reads of AI API key files (OpenAI, Anthropic, etc.) |
| `lateral_movement_logon.kql` | LateralMovement | Suspicious remote interactive and network logons |
| `lateral_movement_process.kql` | LateralMovement | Remote execution tools: PsExec, WMI, WinRM, DCOM |
| `defense_evasion_av_tampering.kql` | DefenseEvasion | AV exclusion additions and security service disabling |
| `defense_evasion_log_tampering.kql` | DefenseEvasion | Event log clearing and shadow copy deletion |
| `exfiltration_ai_apis.kql` | Exfiltration | Unusual process outbound connections to AI API endpoints |
| `c2_beaconing.kql` | CommandAndControl | Non-browser processes making repeated outbound connections across 2+ hours |
| `alerts_mde.kql` | *(multi-tactic)* | Native MDE alerts surfaced alongside custom detections for corroboration |

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
| Persistence | 5 |
| Discovery | 3 |
| Execution | 2 |

### Episode scoring

Each episode score starts from the sum of its scenes' adjusted `ScoreContribution` values, then applies three multiplicative layers:

1. **Corroboration bonus** — reward for mixing multiple behavior families (e.g. ShellExecution + CredentialDump = 1.4×, three families = 1.96×, capped at 5×)
2. **ATT&CK transition bonus** — reward for known kill-chain progressions (e.g. CredentialAccess → LateralMovement = 1.5×), all matching pairs stack multiplicatively, capped at 2×
3. **Variation clustering bonus** — +15% when the same tool class is used with 3+ distinct evidence strings in one episode (automated try-and-adjust behavior)

### Season scoring

Episodes are ranked by score descending. Each successive episode contributes less via `1/log2(rank+2)` weighting. Repeated episodes with the same dominant behavior family decay exponentially (2nd = 0.5×, 3rd = 0.25×), so a device with 20 identical bash episodes scores far lower than one mixing credential dumps, lateral movement, and shell execution.

### Prevalence suppression

Evidence patterns seen across many devices are automatically suppressed (>10 devices → 0.2× multiplier). Rare patterns are boosted (≤3 devices → 1.5× multiplier).

### LOLBin trust tiers

| Tier | Examples | Base multiplier |
|---|---|---|
| `baseline_common` | bash, python, node | 0.3× |
| `contextual` | wscript, rundll32, regsvr32 | 1.0× |
| `high_signal` | certutil, mshta, cmstp | 1.8× |

Baseline-common LOLBins spawned by a known developer parent (VS Code, cursor, terminal) receive a further 0.25× dev-context discount.

---

## Excel output

Sheets in priority order:

| Sheet | Purpose |
|---|---|
| **Device Seasons** | One row per device, sorted by TotalRisk. Primary triage view. |
| **User Seasons** | Same, pivoted by AccountName for lateral movement triage. |
| **Historical Anomalies** | Entities with anomaly flags (score spike, new high, tactic expansion, tactic adaptation). Sorted by HistoricalPriority. |
| **Attack Chains** | Devices linked by shared accounts. Fan-out accounts flagged. |
| **Stacking Analysis** | Evidence patterns sorted rarest-first. Highest-signal analyst view. |
| **Episodes** | Raw episode records with scoring breakdown and adaptive behavior flags. |
| *Per-tactic sheets* | One sheet per tactic with matching scenes. |
| **All Scenes** | Every raw detection row. |

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

**Resetting the baseline**: delete `output/hunt_history.db`. Required when changing KQL hunt windows significantly (scores from different windows are not comparable) or after schema-changing updates to the pipeline.

---

## Configuration

All scoring parameters live in `config.json`. Key sections:

- `tactic_weights` — base score per tactic
- `lolbin_trust_tiers` + `lolbin_tier_base_multipliers` — LOLBin scoring tiers
- `cmdline_risk_patterns` + `cmdline_risk_multipliers` — command-line shape scoring
- `behavior_families` + `episode_family_cap` — per-episode family caps
- `corroboration_bonus` — cross-family corroboration reward
- `tactic_transitions` — ATT&CK kill-chain progression pairs and multipliers
- `adaptive_behavior` — variation cluster threshold and score bonus
- `attack_chain_hygiene` — account exclusion lists and fan-out threshold
- `season_diminishing_returns` — log-based rank weighting and family decay
- `history` — history store path, baseline thresholds, and anomaly flag parameters

See `CLAUDE.md` for a full key-by-key reference.

---

## Adding a new detection

1. Write a new `.kql` file in `kql/` following the six-column schema and the `hunt_window` / `baseline_window` / `prevalence_threshold` pattern
2. Add the `DetectionType` to `behavior_families` in `config.json`
3. Optionally add a `detection_type_multipliers` entry
4. Export results as CSV to `data/` and run `consolidate.py` — no other code changes needed

---

## What stays out of git

`data/*.csv`, `output/*.xlsx`, and `output/*.db` are gitignored — hunt results may contain sensitive telemetry.
