#!/usr/bin/env python3
import argparse, json, os, sys
from datetime import datetime

def read_jsonl(path):
    if not os.path.exists(path):
        print(f"[ERR] Log file not found: {path}")
        return []
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                # skip bad line
                pass
    return out

def pretty_print(records):
    for i, rec in enumerate(records, 1):
        ts = rec.get("ts") or rec.get("time") or "-"
        dry = rec.get("dry_run")
        assigned = rec.get("assigned", 0)
        errors = rec.get("errors", 0)
        total = rec.get("issues_total", None)
        newrot = rec.get("new_rotation", None)
        print(f"\n=== RUN #{i} | {ts} | dry_run={dry} ===")
        if total is not None:
            print(f"issues_total: {total}")
        if newrot is not None:
            print(f"new_rotation: {newrot}")
        print(f"assigned: {assigned} | errors: {errors}")

        preview = rec.get("preview", [])
        if preview:
            print("preview:")
            for p in preview:
                key = p.get("key")
                to = p.get("to")
                mode = p.get("mode")
                pr = p.get("priority")
                summ = p.get("summary")
                print(f"  - {key} -> {to} [{mode}] | {pr} | {summ}")

        errs = rec.get("error_messages", [])
        if errs:
            print("errors/messages:")
            for e in errs:
                print(f"  - {e}")

def main():
    ap = argparse.ArgumentParser(description="View/export JSONL logs produced by round_robin_jira.py")
    ap.add_argument("--path", default=os.getenv("LOG_JSON_PATH", "assign_log.jsonl"),
                    help="Path to JSONL log file (default: assign_log.jsonl)")
    ap.add_argument("--last", type=int, default=10, help="Show last N runs (default: 10)")
    ap.add_argument("--export", help="Export shown runs to a JSON array file (e.g., out.json)")
    args = ap.parse_args()

    records = read_jsonl(args.path)
    if not records:
        print("[INFO] No records.")
        return

    shown = records[-args.last:] if args.last > 0 else records
    pretty_print(shown)

    if args.export:
        try:
            with open(args.export, "w", encoding="utf-8") as f:
                json.dump(shown, f, ensure_ascii=False, indent=2)
            print(f"\n[OK] Exported {len(shown)} runs to: {args.export}")
        except Exception as e:
            print(f"[ERR] Export failed: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
