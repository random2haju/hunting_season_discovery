// ============================================================
// Shadow AI Tooling — Local LLM Execution
// TacticCategory: Execution
// Source: ProcessRollup2
//
// Detects execution of local LLM binaries on endpoints where
// they are not expected. Threat scenarios:
//   - Employees bypassing corporate DLP/proxy with local models
//   - Attackers deploying local models for payload generation
//     or to evade AI-based email/web content filtering
//   - Insider staging a model for exfiltration
//
// Covered binaries: ollama, llama-server/llama.cpp, LM Studio,
// GPT4All, Jan, KoboldCpp, text-generation-webui, LocalAI, vllm
// ============================================================

#event_simpleName=ProcessRollup2

// Local LLM server/runner binaries
| FileName=/(
    ollama|
    llama-server|
    llama\.cpp|
    llama-cli|
    lm-studio|
    lms|
    gpt4all|
    jan\.exe|
    koboldcpp|
    koboldcpp_nocuda|
    text-generation-webui|
    localai|
    vllm|
    llamafile
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
