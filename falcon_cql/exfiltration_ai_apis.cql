// ============================================================
// Data Exfiltration to AI Provider APIs
// TacticCategory: Exfiltration
// Source: DnsRequest
//
// Detects non-browser processes resolving AI provider API domains.
// DNS telemetry is the most reliable signal in CrowdStrike for
// catching outbound AI API usage since provider IPs span large
// CDN ranges that cannot be IP-allowlisted practically.
//
// Covers: OpenAI, Anthropic, Google AI, Mistral, Cohere, Groq,
// Together, Perplexity, OpenRouter, Bedrock, Azure OpenAI,
// Replicate, HuggingFace
// ============================================================

#event_simpleName=DnsRequest

// Match AI provider API domains
| DomainName=/(
    api\.openai\.com|
    api\.anthropic\.com|
    generativelanguage\.googleapis\.com|
    api\.mistral\.ai|
    api\.cohere\.ai|
    api\.together\.xyz|
    api\.groq\.com|
    openrouter\.ai|
    api\.perplexity\.ai|
    bedrock-runtime\.amazonaws\.com|
    cognitiveservices\.azure\.com|
    api\.replicate\.com|
    api\.huggingface\.co|
    inference\.huggingface\.co
)/i

// Exclude browsers — legitimate user AI sessions
| FileName != /^(chrome|msedge|firefox|brave|opera|vivaldi|iexplore)\.exe$/i

// Exclude VS Code Copilot: node.exe under Code.exe/Cursor.exe
| !(
    FileName=/(node)\.exe/i
    AND ParentBaseFileName=/(code|Cursor|windsurf)\.exe/i
)

// Exclude CrowdStrike sensor processes
| FileName != /^(CSFalconService|CSFalconServiceHost|cswindiag)\.exe$/i

| UserName != /\$$/

| groupBy(
    [ComputerName, UserName, FileName, DomainName],
    function=count(as=QueryCount)
)
| sort(QueryCount, order=desc)
