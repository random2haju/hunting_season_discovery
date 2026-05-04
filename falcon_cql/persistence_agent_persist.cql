// ============================================================
// AI Agent Creating System Persistence Mechanism
// TacticCategory: Persistence
// Source: AsepValueUpdate (Run keys), ProcessRollup2 (scheduled tasks)
//
// AI agents should not create OS-level persistence. Run key writes,
// scheduled task creation, and startup folder drops by AI agent
// processes (or their shell children) indicate prompt injection or
// a compromised agent framework.
//
// Two signals:
//   1. AsepValueUpdate: Run/RunOnce key written by AI agent or its child
//   2. ProcessRollup2: schtasks.exe spawned by AI agent chain
// ============================================================

// --- Signal 1: Registry ASEP write by AI agent or its direct shell child ---
#event_simpleName=AsepValueUpdate

| case {
    // AI agent directly writing the Run key
    FileName=/(Claude|Cursor|windsurf|code|ollama|python)\.exe/i =>
        | Detection := "AI agent writing ASEP registry key" ;
    // Shell child of AI agent writing the Run key
    ParentBaseFileName=/(Claude|Cursor|windsurf|code|ollama|python)\.exe/i =>
        | Detection := "AI agent shell child writing ASEP registry key" ;
    * => drop()
}

| UserName != /\$$/

| table(
    [timestamp, ComputerName, UserName, Detection,
     FileName, CommandLine,
     ParentBaseFileName, ParentCommandLine,
     RegKeyPath, RegValueName, RegStringValue],
    limit=500
)
| sort(timestamp, order=desc)
