// ============================================================
// MCP Server DNS Lookup to Non-Sanctioned Domain
// TacticCategory: CommandAndControl
// Source: DnsRequest
//
// Companion query to c2_mcp_network.cql. Uses DNS telemetry to
// catch MCP server children resolving non-sanctioned domains,
// which is more reliable than IP-based allowlisting since AI
// providers use large CDN IP ranges.
//
// A child of an AI agent resolving a domain outside the known-good
// list is a high-confidence indicator of MCP server C2 activity.
// ============================================================

#event_simpleName=DnsRequest

// Request made by a direct child of an AI agent client
| ParentBaseFileName=/(Claude|Cursor|windsurf|code)\.exe/i

// Exclude browsers and known-good system processes
| FileName != /^(Chrome|msedge|firefox|brave|svchost|lsass|MsMpEng|CSFalconService|CSFalconServiceHost)\.exe$/i

// Exclude sanctioned AI provider and developer domains
| DomainName != /(anthropic\.com|openai\.com|googleapis\.com|azure\.com|microsoft\.com|github\.com|githubusercontent\.com|npmjs\.com|pypi\.org|python\.org|huggingface\.co|cursor\.sh|codeium\.com|copilot\.microsoft\.com|cloudfront\.net|fastly\.net|akamai|amazonaws\.com)/i

| UserName != /\$$/

| table(
    [timestamp, ComputerName, UserName,
     FileName, FilePath, CommandLine,
     ParentBaseFileName, DomainName],
    limit=1000
)
| sort(timestamp, order=desc)
