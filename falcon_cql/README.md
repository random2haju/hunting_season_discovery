# Falcon CQL — AI Threat Hunting Queries

CrowdStrike Falcon Advanced Event Search queries covering the same AI-specific threat categories as the KQL queries in `../kql/`. Written in **LogScale Query Language (HQL)** — the query language used by Falcon's Advanced Event Search.

## How to use

Paste any query directly into **Investigate > Event Search** (Advanced Search mode). Set the time range in the Falcon UI before running — queries do not include time filters.

## Event source mapping

| MDE table (KQL) | CrowdStrike event (CQL) |
|---|---|
| `DeviceProcessEvents` | `ProcessRollup2` |
| `DeviceNetworkEvents` | `NetworkConnectIP4`, `DnsRequest` |
| `DeviceFileEvents` | `PeFileWritten`, FDR file events (limited) |
| `DeviceRegistryEvents` | `AsepValueUpdate`, `RegKeyValueSet` |

## Telemetry gaps

CrowdStrike's standard telemetry does **not** capture write events for arbitrary file types (JSON, text config files). Queries that rely on file write detection in MDE have been adapted to use:
- **Command-line references** to the target file path as a proxy signal
- **DNS telemetry** (`DnsRequest`) for network-based detections

For full file-write coverage equivalent to MDE's `DeviceFileEvents`, enable **Falcon Data Replicator (FDR)** with `FileCreate` / `FileWrite` event forwarding.

## Query inventory

| File | DetectionType | Primary event |
|---|---|---|
| `persistence_mcp_config.cql` | MCP Server Installed | `ProcessRollup2` (cmdline path reference) |
| `execution_mcp_server.cql` | MCP Server Execution | `ProcessRollup2` (AI parent + MCP cmdline) |
| `defense_evasion_mcp_tamper.cql` | MCP Config Tampered | `ProcessRollup2` (non-AI + config path) |
| `c2_mcp_network.cql` | MCP Unexpected Network | `NetworkConnectIP4` (AI child + outbound) |
| `c2_mcp_dns.cql` | MCP Unexpected Network (DNS) | `DnsRequest` (AI child + unknown domain) |
| `execution_agent_spawn.cql` | Unexpected Agent Process Spawn | `ProcessRollup2` (AI parent + high-risk cmdline) |
| `persistence_agent_persist.cql` | Agent Persistence Mechanism (registry) | `AsepValueUpdate` |
| `persistence_agent_persist_schtasks.cql` | Agent Persistence Mechanism (tasks) | `ProcessRollup2` (schtasks lineage) |
| `lateral_movement_agent_ipc.cql` | Agent IPC Abuse | `NetworkConnectIP4` (AI + sensitive ports) |
| `credential_access_ai_keys.cql` | AI API Key Read | `ProcessRollup2` (secrets file cmdline) |
| `persistence_ai_memory.cql` | AI Agent Memory Write | `ProcessRollup2` (memory path cmdline) |
| `exfiltration_ai_apis.cql` | AI Data Exfiltration | `DnsRequest` (non-browser + AI domains) |
| `execution_jupyter_abuse.cql` | Jupyter Shell Execution | `ProcessRollup2` (Jupyter parent + shell child) |
| `execution_shadow_ai.cql` | Shadow AI Tooling | `ProcessRollup2` (LLM binary names) |
| `exfiltration_model_weights.cql` | AI Model Weight Exfiltration | `ProcessRollup2` (model file path cmdline) |
| `collection_rag_access.cql` | RAG Unusual Access | `NetworkConnectIP4` (vector DB ports) |
| `credential_access_browser_ai_tokens.cql` | Browser AI Token Theft | `ProcessRollup2` (browser profile path cmdline) |

> Note: MCP network detection is split into two queries — `c2_mcp_network.cql` (IP-based) and `c2_mcp_dns.cql` (DNS-based) — to match how CrowdStrike separates these telemetry streams. Agent persistence is similarly split between registry (`AsepValueUpdate`) and scheduled tasks (`ProcessRollup2`).
