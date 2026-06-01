#!/usr/bin/env python3
"""
suppress.py — manage analyst false-positive suppressions for the threat hunt pipeline.

Commands:
  add     --type Device|User --name NAME --reason "..." [--expires YYYY-MM-DD]
  remove  --type Device|User --name NAME
  list
  expire  (remove all entries whose ExpiresDate has passed)

The suppression list is read by consolidate.py on each run. Suppressed entities are
excluded from Priority Cases but remain visible in Device/User Seasons and the
Suppressed Entities audit sheet.
"""

import argparse
import csv
import json
import os
import sys
from datetime import date, datetime

COLUMNS = ["EntityType", "EntityName", "Reason", "AddedDate", "ExpiresDate"]
DEFAULT_STORE = "output/suppressions.csv"


def _resolve_path() -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, "config.json")
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                cfg = json.load(f)
            raw = cfg.get("suppression", {}).get("store_path", DEFAULT_STORE)
            return os.path.join(script_dir, raw)
        except Exception:
            pass
    return os.path.join(script_dir, DEFAULT_STORE)


def _load(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _save(path: str, rows: list[dict]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def _match(row: dict, entity_type: str, name: str) -> bool:
    return (
        row["EntityType"].strip().lower() == entity_type.lower()
        and row["EntityName"].strip().lower() == name.lower()
    )


def cmd_add(args) -> None:
    path = _resolve_path()
    rows = _load(path)

    if any(_match(r, args.type, args.name) for r in rows):
        print(f"[!] Already suppressed: {args.type} '{args.name}'. Use 'remove' first to update.")
        sys.exit(1)

    if args.expires:
        try:
            datetime.strptime(args.expires, "%Y-%m-%d")
        except ValueError:
            print("[!] --expires must be in YYYY-MM-DD format.")
            sys.exit(1)

    rows.append({
        "EntityType":  args.type,
        "EntityName":  args.name,
        "Reason":      args.reason,
        "AddedDate":   date.today().isoformat(),
        "ExpiresDate": args.expires or "",
    })
    _save(path, rows)
    expiry_note = f" (expires {args.expires})" if args.expires else " (permanent)"
    print(f"[+] Suppressed {args.type} '{args.name}'{expiry_note}: {args.reason}")


def cmd_remove(args) -> None:
    path = _resolve_path()
    rows = _load(path)
    before = len(rows)
    rows = [r for r in rows if not _match(r, args.type, args.name)]
    if len(rows) == before:
        print(f"[!] Not found: {args.type} '{args.name}'")
        sys.exit(1)
    _save(path, rows)
    print(f"[-] Removed suppression for {args.type} '{args.name}'")


def cmd_list(args) -> None:
    path = _resolve_path()
    rows = _load(path)
    if not rows:
        print("(no suppressions)")
        return
    today = date.today()
    fmt = "{:<8} {:<35} {:<12} {:<12} {}"
    print(fmt.format("Type", "Name", "Added", "Expires", "Reason"))
    print("-" * 90)
    for r in sorted(rows, key=lambda x: (x["EntityType"], x["EntityName"])):
        expires = r.get("ExpiresDate", "").strip()
        expired_flag = ""
        if expires:
            try:
                if datetime.strptime(expires, "%Y-%m-%d").date() < today:
                    expired_flag = " [EXPIRED]"
            except ValueError:
                pass
        print(fmt.format(
            r["EntityType"],
            r["EntityName"][:35],
            r.get("AddedDate", ""),
            expires or "permanent",
            r.get("Reason", "") + expired_flag,
        ))


def cmd_expire(args) -> None:
    path = _resolve_path()
    rows = _load(path)
    today = date.today()
    kept, dropped = [], []
    for r in rows:
        expires = r.get("ExpiresDate", "").strip()
        if expires:
            try:
                if datetime.strptime(expires, "%Y-%m-%d").date() < today:
                    dropped.append(r)
                    continue
            except ValueError:
                pass
        kept.append(r)
    if not dropped:
        print("(no expired entries)")
        return
    _save(path, kept)
    for r in dropped:
        print(f"[-] Removed expired suppression: {r['EntityType']} '{r['EntityName']}'")


def main():
    parser = argparse.ArgumentParser(
        description="Manage analyst false-positive suppressions for the hunt pipeline."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="Suppress an entity")
    p_add.add_argument("--type", required=True, choices=["Device", "User"],
                       help="Entity type")
    p_add.add_argument("--name", required=True, help="Device hostname or account name")
    p_add.add_argument("--reason", required=True, help="Why this entity is suppressed")
    p_add.add_argument("--expires", default="", metavar="YYYY-MM-DD",
                       help="Optional expiry date; omit for permanent suppression")

    p_rem = sub.add_parser("remove", help="Lift a suppression")
    p_rem.add_argument("--type", required=True, choices=["Device", "User"])
    p_rem.add_argument("--name", required=True)

    sub.add_parser("list", help="Show all suppressions")
    sub.add_parser("expire", help="Remove expired entries")

    args = parser.parse_args()
    {"add": cmd_add, "remove": cmd_remove, "list": cmd_list, "expire": cmd_expire}[args.command](args)


if __name__ == "__main__":
    main()
