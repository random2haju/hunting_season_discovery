// ============================================================
// MCP Server Installation Detected
// TacticCategory: Persistence
// Source: ProcessRollup2
//
// Detects processes writing to MCP configuration files used by
// Claude Desktop, Cursor, and the generic MCP standard.
//
// CrowdStrike telemetry note: Falcon does not capture arbitrary
// file write events for JSON/text files in standard telemetry.
// This query uses process command-line patterns to detect when
// a process explicitly targets an MCP config path — covering
// shell scripts, installers, and direct file writes via CLI.
//
// For full file-write coverage, enable Falcon Data Replicator (FDR)
// with FileCreate/FileWrite event forwarding and supplement with
// the TargetFileName approach in the FDR variant below.
//
// Time range: set in the Falcon UI (recommended: last 24h for hunting,
// last 7d for investigation)
// ============================================================

#event_simpleName=ProcessRollup2

// Target: processes whose command line references an MCP config file path
| CommandLine=/claude_desktop_config\.json|mcp\.json|\.cursor[\/\\]mcp|\.mcp[\/\\]/i

// Exclude the AI clients writing their own config
| FileName != /^(Claude|Cursor|windsurf|node|npm|npx)\.exe$/i

// Exclude system noise
| UserName != /\$$/  // machine accounts

| table(
    [timestamp, ComputerName, UserName, FileName, FilePath, CommandLine,
     ParentBaseFileName, ParentCommandLine],
    limit=1000
)
| sort(timestamp, order=desc)
