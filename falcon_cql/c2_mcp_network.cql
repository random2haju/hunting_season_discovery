// ============================================================
// MCP Server Making Unexpected Outbound Network Connection
// TacticCategory: CommandAndControl
// Source: NetworkConnectIP4, DnsRequest
//
// MCP servers communicate with their parent AI client via local
// stdio/socket — they have no legitimate reason to make outbound
// internet connections except to sanctioned AI provider APIs.
//
// Detects child processes of AI agent clients (1-hop) making
// outbound connections to destinations outside the sanctioned
// AI provider domain list.
//
// Two signals:
//   1. NetworkConnectIP4: raw IP connection from AI agent child
//   2. DnsRequest: DNS lookup to non-sanctioned domain by AI agent child
// ============================================================

// --- Signal 1: Raw outbound IP connection from AI agent child ---
#event_simpleName=NetworkConnectIP4

// Initiated by a direct child of an AI agent
| ParentBaseFileName=/(Claude|Cursor|windsurf|code)\.exe/i

// Exclude the AI clients themselves from this rule
| FileName != /^(Chrome|msedge|firefox|brave|svchost|lsass|MsMpEng|CSFalconService|CSFalconServiceHost)\.exe$/i

// Only outbound connections on standard web ports
| RemotePort in (80, 443, 8080, 8443)

// Exclude sanctioned AI provider IPs is impractical — use DnsRequest
// signal below for domain-based allowlisting instead

| UserName != /\$$/

| table(
    [timestamp, ComputerName, UserName,
     FileName, FilePath, CommandLine,
     ParentBaseFileName,
     RemoteAddressIP4, RemotePort, LocalAddressIP4],
    limit=1000
)
| sort(timestamp, order=desc)
