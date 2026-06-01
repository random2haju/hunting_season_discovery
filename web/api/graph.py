"""
GET /api/graph

Returns graph nodes (devices + users) and edges (device-user from scenes,
device-device from attack chains) for Cytoscape.js rendering.
"""

from fastapi import APIRouter
from state import state

router = APIRouter()

_ANOMALY_FLAGS = [
    "IsScoreSpike", "IsNewHigh", "IsTacticExpansion",
    "IsAdaptingTactics", "IsEmergingEntity",
]


def _season_node(row, entity_col: str, node_type: str) -> dict:
    entity = str(row.get(entity_col, ""))
    flags = [f for f in _ANOMALY_FLAGS if row.get(f) is True]
    return {
        "id": f"{node_type}:{entity}",
        "label": entity,
        "type": node_type,
        "risk": float(row.get("TotalRisk") or 0),
        "eligible": bool(row.get("EligibleForPriority", True)),
        "workflowClass": str(row.get("PrimaryWorkflowClass") or "Operational"),
        "episodeCount": int(row.get("EpisodeCount") or 0),
        "uniqueTactics": int(row.get("UniqueTactics") or 0),
        "tacticSet": str(row.get("TacticSet") or ""),
        "anomalyFlags": flags,
        "isSuppressed": bool(row.get("IsSuppressed", False)),
    }


@router.get("/graph")
def get_graph():
    if not state.is_loaded:
        return {"nodes": [], "edges": [], "loaded": False}

    nodes = []
    node_ids: set[str] = set()

    if state.device_seasons is not None and not state.device_seasons.empty:
        for _, row in state.device_seasons.iterrows():
            n = _season_node(row, "DeviceName", "device")
            nodes.append(n)
            node_ids.add(n["id"])

    if state.user_seasons is not None and not state.user_seasons.empty:
        for _, row in state.user_seasons.iterrows():
            n = _season_node(row, "AccountName", "user")
            nodes.append(n)
            node_ids.add(n["id"])

    edges = []
    seen: set[tuple] = set()
    eid = 0

    # Device-user edges derived from scene co-occurrences
    if state.scenes is not None and not state.scenes.empty:
        pairs = (
            state.scenes[["DeviceName", "AccountName"]]
            .dropna()
            .drop_duplicates()
        )
        for _, row in pairs.iterrows():
            src = f"device:{row['DeviceName']}"
            tgt = f"user:{row['AccountName']}"
            if src not in node_ids or tgt not in node_ids:
                continue
            key = (src, tgt)
            if key in seen:
                continue
            seen.add(key)
            edges.append({"id": f"e{eid}", "source": src, "target": tgt, "type": "device_user"})
            eid += 1

    # Device-device edges from attack chains
    if state.attack_chains is not None and not state.attack_chains.empty:
        for _, row in state.attack_chains.iterrows():
            devices = [d.strip() for d in str(row.get("Devices", "")).split(" | ") if d.strip()]
            accounts = [a.strip() for a in str(row.get("PivotAccounts", "")).split(" | ") if a.strip()]
            for i, d1 in enumerate(devices):
                for d2 in devices[i + 1:]:
                    src, tgt = f"device:{d1}", f"device:{d2}"
                    if src not in node_ids or tgt not in node_ids:
                        continue
                    key = (min(src, tgt), max(src, tgt))
                    if key in seen:
                        continue
                    seen.add(key)
                    edges.append({
                        "id": f"e{eid}",
                        "source": src,
                        "target": tgt,
                        "type": "shared_account",
                        "accounts": ", ".join(accounts),
                    })
                    eid += 1

    return {"nodes": nodes, "edges": edges, "loaded": True}
