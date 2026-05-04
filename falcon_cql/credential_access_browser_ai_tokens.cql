// ============================================================
// Browser AI Token Theft
// TacticCategory: CredentialAccess
// Source: ProcessRollup2
//
// AI provider session tokens (claude.ai, chatgpt.com, etc.) are
// stored in browser profile directories. Non-browser processes
// reading these directories are likely infostealers harvesting
// AI session cookies alongside other credentials.
//
// Detects processes whose command lines reference browser
// credential store paths (Login Data, Cookies, LevelDB/Local Storage).
//
// CrowdStrike note: direct file read telemetry requires FDR.
// Command-line path references serve as the primary signal.
// This query catches tools explicitly targeting these paths
// (stealer scripts, manual attacker access via shell).
// ============================================================

#event_simpleName=ProcessRollup2

// Command line references browser credential store paths
| CommandLine=/(
    [\/\\]Google[\/\\]Chrome[\/\\]User\s?Data|
    [\/\\]Microsoft[\/\\]Edge[\/\\]User\s?Data|
    [\/\\]BraveSoftware[\/\\]Brave-Browser[\/\\]User\s?Data|
    [\/\\]Mozilla[\/\\]Firefox[\/\\]Profiles|
    [\/\\]Opera\s?Software[\/\\]Opera\s?Stable|
    Login\s?Data|
    Local\s?Storage[\/\\]leveldb|
    Session\s?Storage|
    Cookies
)/ix

// Exclude browsers reading their own stores
| FileName != /^(chrome|msedge|firefox|brave|opera|vivaldi|iexplore)\.exe$/i

// Exclude legitimate backup / search / AV processes
| FileName != /^(OneDrive|googledrivesync|robocopy|xcopy|BackupEngine|wbengine|SearchIndexer|MsMpEng|SenseIR|CSFalconService|CSFalconServiceHost|svchost)\.exe$/i

| UserName != /\$$/

| table(
    [timestamp, ComputerName, UserName,
     FileName, FilePath, CommandLine,
     ParentBaseFileName, ParentCommandLine,
     SHA256HashData],
    limit=1000
)
| sort(timestamp, order=desc)
