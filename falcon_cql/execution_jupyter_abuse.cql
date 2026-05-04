// ============================================================
// Jupyter Shell Execution
// TacticCategory: Execution
// Source: ProcessRollup2
//
// Detects suspicious child processes spawned directly by Jupyter
// or IPython kernel parents. Threat scenarios:
//   - Stolen Jupyter token allowing OS command execution via !cmd
//   - Insider using notebooks as a shell proxy to avoid logging
//   - Prompt injection into a notebook-based AI pipeline
//
// Suspicious children: cmd, powershell, curl, certutil, net,
// netcat, python with network/encoding patterns, wscript, etc.
// ============================================================

#event_simpleName=ProcessRollup2

// Parent must be a Jupyter/IPython process
| ParentBaseFileName=/(jupyter|ipython|jupyter-kernel|ipykernel_launcher|nbconvert)/i

// Child must be a suspicious process
| case {
    FileName=/(cmd|powershell|pwsh)\.exe/i =>
        | Detection := "Shell spawned from Jupyter" ;

    FileName=/(wscript|cscript|mshta|regsvr32|rundll32)\.exe/i =>
        | Detection := "Script host spawned from Jupyter" ;

    FileName=/(curl|wget|certutil|bitsadmin)\.exe/i =>
        | Detection := "Network download tool spawned from Jupyter" ;

    FileName=/(net|nltest|whoami|ipconfig|systeminfo|tasklist|reg)\.exe/i =>
        | Detection := "Reconnaissance tool spawned from Jupyter" ;

    FileName=/python\.exe/i
    AND CommandLine=/(http|socket|subprocess|base64|urllib|requests\.get|eval\()/i =>
        | Detection := "Python with network/eval patterns from Jupyter" ;

    * => drop()
}

| UserName != /\$$/

| table(
    [timestamp, ComputerName, UserName, Detection,
     FileName, FilePath, CommandLine,
     ParentBaseFileName, ParentCommandLine],
    limit=1000
)
| sort(timestamp, order=desc)
