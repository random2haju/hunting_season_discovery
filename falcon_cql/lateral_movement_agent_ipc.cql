// ============================================================
// AI Agent Connecting to Sensitive Localhost Service Port
// TacticCategory: LateralMovement
// Source: NetworkConnectIP4
//
// AI agents connecting to sensitive localhost ports (SMB, RDP,
// WinRM, Kerberos, LDAP, SQL, NoSQL databases) may indicate:
//   - An agent acting as a local relay for lateral movement
//   - A malicious MCP server creating a local backdoor
//   - An agent probing internal services it discovered
//
// Safe AI/dev ports (Ollama, LM Studio, Flask, dev servers)
// are excluded to reduce noise.
// ============================================================

#event_simpleName=NetworkConnectIP4

// AI agent or framework process
| FileName=/(Claude|Cursor|windsurf|code|ollama|python|node)\.exe/i

// Only localhost connections
| LocalAddressIP4=/(^127\.|^::1|^0\.0\.0\.0)/

// Sensitive service ports — these should never be accessed by AI agents
| RemotePort in (
    22,     // SSH
    23,     // Telnet
    88,     // Kerberos
    135,    // RPC
    139,    // NetBIOS
    389,    // LDAP
    445,    // SMB
    636,    // LDAPS
    1433,   // MSSQL
    3306,   // MySQL
    3389,   // RDP
    5432,   // PostgreSQL
    5985,   // WinRM HTTP
    5986,   // WinRM HTTPS
    6379,   // Redis
    27017   // MongoDB
)

| UserName != /\$$/

| table(
    [timestamp, ComputerName, UserName,
     FileName, FilePath, CommandLine,
     ParentBaseFileName,
     LocalAddressIP4, RemoteAddressIP4, RemotePort],
    limit=1000
)
| sort(timestamp, order=desc)
