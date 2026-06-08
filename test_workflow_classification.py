"""
Unit tests for workflow classification (consolidate.classify_workflow_class).

Run: python -m pytest test_workflow_classification.py -q
(or: python test_workflow_classification.py  for a dependency-free run)

These cover the classification rules that have no AI sample data in data/ to
exercise them empirically — in particular the detection-type-based AI-actor rule
and the actor/parent key handling for the AI KQL Evidence formats.
"""
import json
import os

from consolidate import (
    classify_workflow_class,
    is_service_account,
    parse_evidence_fields,
)

CFG = json.load(open(os.path.join(os.path.dirname(__file__), "config.json")))


def classify(evidence, detection_type, account="alice", ctx="Unknown"):
    pe = parse_evidence_fields(evidence)
    return classify_workflow_class(evidence, pe, ctx, detection_type, account, CFG)[0]


# --- Finding 1b: AI-actor by DetectionType, robust to Evidence layout -------

def test_agent_spawn_is_ai_even_when_actor_under_Agent_key():
    # execution_agent_spawn emits "Agent:", not "Process:" — the old classifier missed this
    ev = "Child: cmd.exe | CmdLine: whoami | Agent: claude.exe | AgPath: C:\\x | Parent: bash.exe"
    assert classify(ev, "Unexpected Agent Process Spawn") == "AIWorkflow"


def test_agent_ipc_is_ai_with_no_parent_field():
    ev = "AgentProcess: claude.exe | LocalPort: 9000"
    assert classify(ev, "Agent IPC Abuse") == "AIWorkflow"


def test_mcp_server_execution_is_ai():
    ev = "MCPProcess: mcp-server.exe | Path: C:\\x | CmdLine: x | Parent: claude.exe | PPath: y"
    assert classify(ev, "MCP Server Execution") == "AIWorkflow"


# --- Non-AI-actor detections must NOT be promoted (keep full score) ---------

def test_browser_token_theft_by_ai_named_process_stays_unflagged():
    # Reader: claude.exe reading a browser cred store is suspicious, not benign AI work.
    # It must NOT be classified AIWorkflow (which would discount it).
    ev = "CredFile: Login Data | Action: read | Reader: claude.exe | RPath: x | CmdLine: y | Parent: explorer.exe"
    assert classify(ev, "Browser AI Token Theft") != "AIWorkflow"


def test_ai_key_read_by_writer_key_not_promoted():
    ev = "Secret: .env | ReadBy: python.exe | CmdLine: cat .env | Parent: bash.exe"
    assert classify(ev, "AI API Key Read") != "AIWorkflow"


# --- Finding 1a/2: indicator-based AI detection ----------------------------

def test_ai_process_via_standard_process_key():
    ev = "Process: claude.exe | Parent: bash.exe | CmdLine: x | Destination: api.anthropic.com"
    assert classify(ev, "AI Data Exfiltration") == "AIWorkflow"

def test_expanded_vendor_process_name():
    ev = "Process: ollama.exe | Parent: explorer.exe"
    assert classify(ev, "Shadow AI Tooling") == "AIWorkflow"

def test_jupyter_parent_key_is_recognized():
    ev = "ShellSpawned: bash.exe | CmdLine: x | JupyterParent: cursor.exe | ParentCmdLine: y"
    assert classify(ev, "Jupyter Shell Execution") == "AIWorkflow"

def test_ai_path_pattern_mcp_json():
    ev = "ConfigFile: C:\\Users\\a\\mcp.json | Action: write | Writer: python.exe | Parent: explorer.exe"
    assert classify(ev, "MCP Config Tampered") == "AIWorkflow"


# --- DeveloperAutomation / ServiceAutomation / Operational -----------------

def test_developer_automation():
    ev = "Process: python.exe | Parent: code.exe | CmdLine: pytest"
    assert classify(ev, "Jupyter Shell Execution", ctx="DeveloperTooling") == "DeveloperAutomation"

def test_service_automation_machine_account():
    ev = "Process: svchost.exe | Parent: services.exe"
    assert classify(ev, "Discovery Command", account="WORKSTATION-A$") == "ServiceAutomation"

def test_service_automation_svc_prefix():
    ev = "Process: backup.exe | Parent: taskeng.exe"
    assert classify(ev, "Discovery Command", account="svc_backup") == "ServiceAutomation"

def test_operational_fallback():
    ev = "Process: notepad.exe | Parent: explorer.exe"
    assert classify(ev, "Discovery Command", account="alice") == "Operational"


# --- is_service_account helper ---------------------------------------------

def test_is_service_account():
    wf = CFG["workflow_classification"]
    assert is_service_account("MACHINE$", wf)
    assert is_service_account("svc-scanner", wf)
    assert is_service_account("SYSTEM", wf)
    assert not is_service_account("jsmith", wf)
    assert not is_service_account("", wf)


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
        except Exception:
            failed += 1
            print(f"  FAIL  {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    raise SystemExit(1 if failed else 0)
