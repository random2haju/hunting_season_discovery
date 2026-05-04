// ============================================================
// MCP Configuration Tampered by Non-AI Process
// TacticCategory: DefenseEvasion
// Source: ProcessRollup2
//
// Detects non-AI processes explicitly targeting MCP config files
// via their command line. More restrictive than persistence_mcp_config:
// the AI clients themselves (Claude.exe, Cursor.exe) are allowed;
// any other process targeting these paths is suspicious.
//
// High-confidence signal: cmd.exe, powershell.exe, python.exe,
// or any shell writing to claude_desktop_config.json or mcp.json
// indicates an attacker or prompt-injected agent planting a
// malicious MCP server definition.
// ============================================================

#event_simpleName=ProcessRollup2

// Target: processes referencing MCP config paths in their command line
| CommandLine=/claude_desktop_config\.json|mcp\.json|\.cursor[\/\\]mcp\.json|\.mcp[\/\\]/i

// Exclude the AI clients — they're allowed to write their own config
| FileName != /^(Claude|Cursor|windsurf)\.exe$/i

// Exclude node/npm only when running directly under a known IDE
| !(
    FileName=/(node|npm|npx)\.exe/i
    AND ParentBaseFileName=/(code|Cursor|windsurf|Claude|WindowsTerminal|wt)\.exe/i
)

// Exclude system processes
| FileName != /^(svchost|TrustedInstaller|MsMpEng|SenseIR|SearchIndexer)\.exe$/i
| UserName != /\$$/

| table(
    [timestamp, ComputerName, UserName,
     FileName, FilePath, CommandLine,
     ParentBaseFileName, ParentCommandLine],
    limit=1000
)
| sort(timestamp, order=desc)
