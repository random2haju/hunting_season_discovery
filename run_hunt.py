"""
run_hunt.py — scheduled execution wrapper for consolidate.py

Skips runs on weekends and enforces a minimum interval of N calendar days
between runs (default 3). Designed to be called daily by Windows Task Scheduler;
the script self-gates so the actual hunt only runs on the right days.

Usage:
    python run_hunt.py                  # default: min 3 days, skip weekends
    python run_hunt.py --min-days 2     # run every 2nd day
    python run_hunt.py --force          # bypass schedule check (useful for ad-hoc runs)

Exit codes:
    0  — hunt ran (or --force used)
    2  — skipped (weekend or not enough days since last run)
    other — consolidate.py exited with that code

Windows Task Scheduler setup:
    1. Open Task Scheduler → Create Basic Task
    2. Trigger: Daily at your preferred time (e.g. 07:00)
    3. Action: Start a program
       Program:   python  (or full path: C:\\Python312\\python.exe)
       Arguments: C:\\path\\to\\anomali_detection\\run_hunt.py
    4. The script will skip Saturday/Sunday and non-interval days automatically.
"""

import argparse
import os
import subprocess
import sys
from datetime import date

SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
DEFAULT_STAMP = os.path.join(SCRIPT_DIR, "output", "last_run.txt")


def main():
    parser = argparse.ArgumentParser(description="Scheduled wrapper for consolidate.py")
    parser.add_argument("--min-days", type=int, default=3,
                        help="Minimum calendar days between runs (default 3)")
    parser.add_argument("--stamp", default=DEFAULT_STAMP,
                        help="Path to stamp file recording last run date")
    parser.add_argument("--force", action="store_true",
                        help="Run regardless of schedule or day-of-week")
    args = parser.parse_args()

    today = date.today()

    if not args.force:
        # Skip weekends (0=Mon … 4=Fri, 5=Sat, 6=Sun)
        if today.weekday() >= 5:
            print(f"[SKIP] {today.strftime('%A %Y-%m-%d')} is a weekend — no hunt today.")
            sys.exit(2)

        # Enforce minimum interval via stamp file
        if os.path.exists(args.stamp):
            try:
                with open(args.stamp) as f:
                    last_run = date.fromisoformat(f.read().strip())
                days_since = (today - last_run).days
                if days_since < args.min_days:
                    print(
                        f"[SKIP] Last run was {days_since} day(s) ago ({last_run}) — "
                        f"minimum interval is {args.min_days} day(s)."
                    )
                    sys.exit(2)
            except (ValueError, OSError):
                pass  # Corrupted or missing stamp — proceed with the run

    # Run consolidate.py
    hunt_script = os.path.join(SCRIPT_DIR, "consolidate.py")
    print(f"[RUN] Starting hunt — {today.strftime('%A %Y-%m-%d')}")
    result = subprocess.run([sys.executable, hunt_script], check=False)

    if result.returncode == 0:
        # Update stamp so the next scheduled call can gate correctly
        os.makedirs(os.path.dirname(args.stamp), exist_ok=True)
        with open(args.stamp, "w") as f:
            f.write(today.isoformat())
        print(f"[OK]  Hunt complete. Next earliest run: {args.min_days} day(s) from {today}.")
    else:
        print(f"[ERROR] consolidate.py exited with code {result.returncode}")
        sys.exit(result.returncode)


if __name__ == "__main__":
    main()
