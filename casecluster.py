"""
casecluster.py — collapse duplicate Priority Cases rows into single incidents.

The hunt opens one season row per Device and one per User. When one user is
active on one device, that activity surfaces as *two* priority rows describing
the same scenes — pure duplication. At fleet scale this roughly doubles the
Priority Cases list.

`cluster_priority_cases` staples together the rows that share underlying scenes
and keeps a single anchor per cluster, while preserving the signals that the
two entity views exist for:

  - 1 user on 1 device                 → one case (the duplicate is folded in)
  - several users on one device        → the device anchors; users fold in
  - one user across several devices     → the user anchors; devices fold in
    (this is the lateral-movement / roaming signal — never discarded)

Linking reuses the same account hygiene as attack-chain detection
(`attack_chain_hygiene`): null/machine/service accounts never link, names are
domain-stripped and case-folded. A **fan-out guard** stops a high-prevalence
account (an admin or scanner present on many hosts — the "janitor with keys to
every house") from welding the whole fleet into one mega-cluster: an account on
>= `link_fan_out_threshold` devices is not used as a linking edge. The account's
own row still stands as its own case; it simply does not absorb every device.

Clustering is **score-neutral** — like triage, it changes which row fronts the
list and what is folded behind it, never any score. The floor/cap in
`build_priority_cases` then counts *cases*, not rows.
"""

import re

import pandas as pd


def _normalize_account(name: str, strip_domain: bool) -> str:
    key = str(name).strip()
    if strip_domain:
        key = re.sub(r"^[^\\]+\\", "", key)
    return key.lower()


def _account_device_map(scenes: pd.DataFrame, cfg: dict) -> dict:
    """Return {normalized_account_key: set(device_names)} after account hygiene."""
    hy = (cfg or {}).get("attack_chain_hygiene", {})
    exclude_machine   = hy.get("exclude_machine_accounts", True)
    excluded_accounts = {a.lower() for a in hy.get("excluded_accounts", [])}
    strip_domain      = hy.get("strip_account_domain", True)

    s = scenes[scenes["AccountName"].notna() & scenes["AccountName"].astype(str).str.strip().ne("")].copy()
    if s.empty:
        return {}
    s["AccountKey"] = s["AccountName"].map(lambda n: _normalize_account(n, strip_domain))
    if exclude_machine:
        s = s[~s["AccountKey"].str.endswith("$")]
    if excluded_accounts:
        s = s[~s["AccountKey"].isin(excluded_accounts)]
    if s.empty:
        return {}
    return (
        s.groupby("AccountKey")["DeviceName"]
        .apply(lambda x: set(x.astype(str)))
        .to_dict()
    )


def cluster_priority_cases(ranked: pd.DataFrame, scenes: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """Collapse Device/User priority rows that share scenes into single anchored cases.

    `ranked` must be sorted by CompositeScore descending and carry EntityType /
    EntityName / CompositeScore columns. Returns anchor rows only (in their
    original score order) with three added columns:
        CaseClusterId       — 1-based id, shared by all rows of one incident
        ClusterMemberCount  — number of entity rows folded into this case
        RelatedEntities     — "Type:Name, ..." of the folded-in members ("" if singleton)
    Non-anchor members are dropped here but remain visible in Device/User Seasons.
    """
    cfg = cfg or {}
    pc_cfg = cfg.get("priority_clustering", {})
    if not pc_cfg.get("enabled", True):
        return ranked
    if ranked is None or ranked.empty:
        return ranked
    if (scenes is None or scenes.empty
            or "AccountName" not in scenes.columns or "DeviceName" not in scenes.columns):
        return ranked

    hy = cfg.get("attack_chain_hygiene", {})
    strip_domain = hy.get("strip_account_domain", True)
    fan_out = int(pc_cfg.get("link_fan_out_threshold", hy.get("fan_out_threshold", 3)))

    ranked = ranked.reset_index(drop=True)
    nodes = list({(r.EntityType, r.EntityName) for r in ranked.itertuples()})
    device_nodes = {name for (t, name) in nodes if t == "Device"}
    acct_devices = _account_device_map(scenes, cfg)

    # Union-Find over the candidate entity nodes.
    parent = {n: n for n in nodes}

    def find(x):
        root = x
        while parent[root] != root:
            root = parent[root]
        while parent[x] != root:
            parent[x], x = root, parent[x]
        return root

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    # Edge: a (non-fan-out) user account links to each device it appears on.
    for r in ranked.itertuples():
        if r.EntityType != "User":
            continue
        devs = acct_devices.get(_normalize_account(r.EntityName, strip_domain), set())
        if len(devs) >= fan_out:
            continue  # fan-out account — does not bridge clusters
        unode = (r.EntityType, r.EntityName)
        for d in devs:
            if d in device_nodes:
                union(unode, ("Device", d))

    score = {(r.EntityType, r.EntityName): float(getattr(r, "CompositeScore", 0) or 0)
             for r in ranked.itertuples()}

    # Group nodes by component root, choose anchor per component.
    components: dict = {}
    for n in nodes:
        components.setdefault(find(n), []).append(n)

    # anchor = highest CompositeScore; tie → Device before User, then name.
    def _anchor_key(n):
        return (score.get(n, 0.0), n[0] == "Device", n[1])

    anchor_of: dict = {}
    members_of: dict = {}
    cluster_id: dict = {}
    for cid, (_, members) in enumerate(components.items(), start=1):
        anchor = max(members, key=_anchor_key)
        members_of[anchor] = members
        for m in members:
            anchor_of[m] = anchor
            cluster_id[m] = cid

    keep_rows, ids, counts, related = [], [], [], []
    for i, r in enumerate(ranked.itertuples()):
        node = (r.EntityType, r.EntityName)
        if anchor_of.get(node) != node:
            continue  # folded-in member — drop from Priority Cases
        members = members_of.get(node, [node])
        keep_rows.append(i)
        ids.append(cluster_id[node])
        counts.append(len(members))
        others = sorted(m for m in members if m != node)
        related.append(", ".join(f"{t}:{n}" for (t, n) in others))

    out = ranked.iloc[keep_rows].copy()
    out["CaseClusterId"] = ids
    out["ClusterMemberCount"] = counts
    out["RelatedEntities"] = related
    return out.reset_index(drop=True)
