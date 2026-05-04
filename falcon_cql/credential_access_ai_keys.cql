// ============================================================
// AI API Key Access
// TacticCategory: CredentialAccess
// Source: ProcessRollup2
//
// Detects two patterns:
//   1. Processes whose command line references known AI secrets
//      file paths (.env, api_keys.json, .netrc, credentials files)
//   2. Command lines embedding AI API key identifier strings
//      (OPENAI_API_KEY, sk-ant-, sk-proj-, etc.)
//
// CrowdStrike note: file read events are not available for
// all file types in standard Falcon telemetry. This query
// uses command-line evidence. For full coverage, supplement
// with FDR FileRead events if available.
// ============================================================

#event_simpleName=ProcessRollup2

// Exclude known-good IDEs — they legitimately read .env files
| FileName != /^(Code|Cursor|windsurf|pycharm64|idea64|PyCharm|intellij)\.exe$/i
| FileName != /^(svchost|SearchIndexer|MsMpEng|SenseIR)\.exe$/i
| UserName != /\$$/

| case {
    // Signal 1: command line references AI secrets files
    CommandLine=/(
        [\/\\]\.env\b|
        api_keys?\.json|
        \.netrc\b|
        credentials\.json|
        secrets\.json|
        \.anthropic|
        \.openai|
        OPENAI_API_KEY|
        ANTHROPIC_API_KEY|
        GOOGLE_API_KEY|
        MISTRAL_API_KEY|
        COHERE_API_KEY
    )/ix =>
        | Detection := "AI secrets file referenced in command line" ;

    // Signal 2: API key identifiers embedded in command line
    CommandLine=/(sk-ant-|sk-proj-|sk-or-v1-|gsk_[A-Za-z0-9]{20})/i =>
        | Detection := "AI API key identifier in command line" ;

    * => drop()
}

| table(
    [timestamp, ComputerName, UserName, Detection,
     FileName, FilePath, CommandLine,
     ParentBaseFileName, ParentCommandLine],
    limit=1000
)
| sort(timestamp, order=desc)
