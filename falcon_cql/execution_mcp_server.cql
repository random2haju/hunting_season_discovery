// ============================================================
// MCP Server Process Execution
// TacticCategory: Execution
// Source: ProcessRollup2
//
// Detects MCP server processes spawned by AI agent clients.
// Legitimate MCP servers are launched by Claude Desktop, Cursor,
// or VS Code with command-line patterns containing MCP-specific
// strings, or from high-risk paths (Temp, Downloads, Desktop).
//
// Signal 1: AI agent parent + MCP command-line indicator
// Signal 2: AI agent parent + child running from a suspicious path
// ============================================================

#event_simpleName=ProcessRollup2

// Parent must be an AI agent client
| ParentBaseFileName=/(Claude|Cursor|windsurf|code)\.exe/i

| case {
    // Signal 1: MCP-specific command-line pattern
    CommandLine=/(--mcp|mcp-server|mcp_server|@modelcontextprotocol|mcp-filesystem|mcp-git|mcp-fetch|uvx mcp)/i =>
        | Detection := "MCP cmdline indicator" ;

    // Signal 2: child launched from suspicious user-writable path
    FilePath=/(\\AppData\\Local\\Temp|\\AppData\\Roaming\\Temp|\\Downloads\\|\\Desktop\\|\\Public\\|\\ProgramData\\)/i
    AND FilePath !=/\\node_modules\\|\\npm\\|\\uv\\|\\AppData\\Local\\uv\\|\\AppData\\Roaming\\npm\\/i =>
        | Detection := "Suspicious path for AI agent child" ;

    // Discard unmatched rows
    * => drop()
}

| UserName != /\$$/

| table(
    [timestamp, ComputerName, UserName, Detection,
     FileName, FilePath, CommandLine,
     ParentBaseFileName, ParentCommandLine],
    limit=1000
)
| sort(timestamp, order=desc)
