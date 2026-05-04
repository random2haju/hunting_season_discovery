// ============================================================
// AI Agent Memory File Persistence
// TacticCategory: Persistence
// Source: ProcessRollup2
//
// Detects two scenarios via process command-line patterns:
//   1. Any process referencing AI agent memory directory paths
//      (first-time agent deployment indicator)
//   2. Non-AI processes explicitly writing to those paths
//      (prompt injection via memory manipulation)
//
// Memory paths covered: .letta, .memgpt, .autogpt, .crewai,
// .agentops, .continue, agent_workspace, .claude\memory
//
// CrowdStrike note: file create/write events for arbitrary
// directories require FDR. This query catches command-line
// references to these paths as a proxy signal.
// ============================================================

#event_simpleName=ProcessRollup2

// Target: processes referencing AI agent memory directory paths
| CommandLine=/(
    [\/\\]\.letta[\/\\]|
    [\/\\]\.memgpt[\/\\]|
    [\/\\]\.autogpt[\/\\]|
    [\/\\]\.crewai[\/\\]|
    [\/\\]\.agentops[\/\\]|
    [\/\\]\.continue[\/\\]|
    [\/\\]agent_workspace[\/\\]|
    [\/\\]agent_memory[\/\\]|
    [\/\\]\.claude[\/\\]memory[\/\\]
)/ix

| UserName != /\$$/

| case {
    // Known AI tool processes reading their own memory — lower priority
    FileName=/(node|claude|claude-code|Code|Cursor|windsurf|python|ollama)\.exe/i =>
        | Detection := "AI tool accessing own memory path" ;

    // Anything else: suspicious
    * =>
        | Detection := "Non-AI process accessing AI agent memory path" ;
}

| table(
    [timestamp, ComputerName, UserName, Detection,
     FileName, FilePath, CommandLine,
     ParentBaseFileName, ParentCommandLine],
    limit=1000
)
| sort(Detection, timestamp, order=desc)
