// ============================================================
// AI Agent Creating Scheduled Task Persistence
// TacticCategory: Persistence
// Source: ProcessRollup2
//
// Companion to persistence_agent_persist.cql.
// Detects schtasks.exe or at.exe spawned within an AI agent
// process lineage (direct child or grandchild of AI agent).
// ============================================================

#event_simpleName=ProcessRollup2

// Scheduled task or startup utility
| FileName=/(schtasks|at|taskeng|taskhost|taskhostw)\.exe/i

// Must be in an AI agent lineage
| case {
    ParentBaseFileName=/(Claude|Cursor|windsurf|code|ollama|python)\.exe/i =>
        | Detection := "schtasks spawned directly by AI agent" ;
    ParentBaseFileName=/(cmd|powershell|bash|sh|wscript|cscript)\.exe/i =>
        // Grandparent check — if shell's parent was an AI agent
        | Detection := "schtasks spawned by shell under AI agent" ;
    * => drop()
}

// Must be creating or modifying — not querying
| CommandLine=/(\/create|\/change|\/run)/i

| UserName != /\$$/

| table(
    [timestamp, ComputerName, UserName, Detection,
     FileName, CommandLine,
     ParentBaseFileName, ParentCommandLine],
    limit=500
)
| sort(timestamp, order=desc)
