// ============================================================
// AI Model Weight Exfiltration
// TacticCategory: Exfiltration
// Source: ProcessRollup2, NetworkConnectIP4
//
// Model weight files (.gguf, .safetensors, .pt, .ggml) represent
// significant IP. This query detects:
//   1. Processes referencing model weight file extensions in their
//      command line from non-AI tools (staging/reading for exfil)
//   2. Processes making network connections shortly after accessing
//      model weight paths (exfil correlation — requires joining
//      signals in an investigation)
//
// CrowdStrike note: direct file read telemetry for arbitrary
// file types requires FDR. Command-line references serve as
// the primary signal here.
// ============================================================

// --- Signal 1: Process command line references model weight files ---
#event_simpleName=ProcessRollup2

// Must reference a model weight file extension
| CommandLine=/(
    \.gguf\b|
    \.ggml\b|
    \.safetensors\b|
    \.pt\b|
    \.pth\b|
    [\/\\]models[\/\\]|
    [\/\\]\.ollama[\/\\]models[\/\\]|
    [\/\\]\.cache[\/\\]huggingface[\/\\]|
    [\/\\]lm-studio[\/\\]models[\/\\]
)/ix

// Exclude known-good AI tool readers
| FileName != /^(ollama|llama-server|llama-cli|python|lm-studio|lms|gpt4all|koboldcpp|jan|vllm)\.exe$/i

// Exclude system noise
| FileName != /^(svchost|SearchIndexer|MsMpEng|SenseIR|WinRAR|7z)\.exe$/i
| UserName != /\$$/

| table(
    [timestamp, ComputerName, UserName,
     FileName, FilePath, CommandLine,
     ParentBaseFileName, ParentCommandLine],
    limit=1000
)
| sort(timestamp, order=desc)
