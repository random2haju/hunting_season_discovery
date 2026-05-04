// ============================================================
// Unexpected High-Risk Process Spawned by AI Agent
// TacticCategory: Execution
// Source: ProcessRollup2
//
// AI agents legitimately spawn shells to run code. What is NOT
// expected is post-exploitation patterns in those child processes:
// encoded payloads, credential-touching binaries, raw network
// tools invoked with suspicious arguments.
//
// Parent: Claude.exe, Cursor.exe, windsurf.exe, code.exe,
//         ollama.exe, python.exe (running agent frameworks)
// Child:  any process whose CommandLine matches high-risk patterns
// ============================================================

#event_simpleName=ProcessRollup2

// AI agent process as the direct parent
| ParentBaseFileName=/(Claude|Cursor|windsurf|code|ollama|python)\.exe/i

// High-risk command-line patterns in the child
| CommandLine=/(
    -EncodedCommand|
    \-enc\s|
    \bIEX\b|
    Invoke-Expression|
    FromBase64String|
    base64\s+-d|
    base64\s+-D|
    certutil\s+-decode|
    certutil\s+-urlcache|
    bitsadmin\s+\/transfer|
    DownloadString|
    DownloadFile|
    WebClient|
    net\s+user\s+\/add|
    net\s+localgroup\s+administrators|
    reg\s+(save|export)\s+hklm\\\\sam|
    sekurlsa|
    mimikatz|
    procdump|
    \/dev\/tcp|
    nc(\.exe)?\s+-e|
    ncat\s+-e|
    schtasks\s+\/create
)/ix

| UserName != /\$$/

| table(
    [timestamp, ComputerName, UserName,
     FileName, FilePath, CommandLine,
     ParentBaseFileName, ParentCommandLine,
     SHA256HashData],
    limit=1000
)
| sort(timestamp, order=desc)
