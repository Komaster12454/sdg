#!/usr/bin/env python3
"""
continuous_runner.py

Runs cve_monitor's scan on a tight internal loop (default every 60s) so
scanning happens far more often than a plain cron trigger would allow.
This process itself doesn't need to live forever: the GitHub Actions
workflow re-triggers every 5 minutes via `schedule`, and with
`concurrency: cancel-in-progress: true`, each new trigger cancels whatever
instance of this job is still running and starts a fresh one — a rolling
restart, same pattern as a long-lived bot process kept alive by periodic
restarts. That means:

  - Scanning is effectively continuous (every SCAN_INTERVAL_SECONDS)
  - The job is automatically refreshed every ~5 minutes, so it never gets
    anywhere near GitHub's ~6h job limit, and a crashed/stuck loop
    self-heals on the next cron tick
  - No self re-dispatch API call and no Personal Access Token needed —
    GitHub's own scheduler + concurrency queue does all of it

State (state.json) is committed after every scan cycle that finds
something, so a mid-loop cancellation never loses already-found results.

Env vars (in addition to cve_monitor.py's):
  SCAN_INTERVAL_SECONDS  (optional) seconds between scans, default 60
  MAX_RUNTIME_SECONDS    (optional) safety cap in case cancellation ever
                          fails to fire, default 21000 (5h50m)
  GIT_COMMIT_STATE       (optional) "true"/"false", default "true"
"""

import os
import subprocess
import sys
import time

import cve_monitor as monitor


def get_env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def get_env_bool(name, default):
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True)


def commit_state_if_changed(state_file):
    add = git("add", state_file)
    if add.returncode != 0:
        print(f"WARNING: git add failed: {add.stderr}", file=sys.stderr)
        return False

    # Diff the staged change so a brand-new (previously untracked)
    # state.json is detected too, not just modifications to an existing one.
    diff = git("diff", "--cached", "--quiet", "--", state_file)
    if diff.returncode == 0:
        return False  # no changes

    commit = git("commit", "-m", "chore: update CVE scan state [skip ci]")
    if commit.returncode != 0:
        print(f"WARNING: git commit failed: {commit.stderr}", file=sys.stderr)
        return False

    push = git("push")
    if push.returncode != 0:
        print(f"WARNING: git push failed: {push.stderr}", file=sys.stderr)
        return False

    print("Committed and pushed updated state.json.")
    return True


def main():
    config = monitor.load_config()

    scan_interval = get_env_int("SCAN_INTERVAL_SECONDS", 60)
    max_runtime = get_env_int("MAX_RUNTIME_SECONDS", 21000)
    commit_state = get_env_bool("GIT_COMMIT_STATE", True)

    # Keep the lookback window a bit larger than the scan interval so
    # back-to-back scans never leave a gap.
    config["lookback_minutes"] = max(config["lookback_minutes"], (scan_interval // 60) + 2)

    print(f"Continuous runner starting: scanning every {scan_interval}s, "
          f"safety cap {max_runtime}s, lookback {config['lookback_minutes']}min. "
          f"(Normally this job gets restarted by the next cron trigger before the safety cap matters.)")

    start = time.monotonic()
    cycle = 0

    while True:
        elapsed = time.monotonic() - start
        remaining = max_runtime - elapsed
        if remaining <= 0:
            print("Safety cap reached; exiting so the next cron trigger can take over.")
            break

        cycle += 1
        print(f"\n=== Scan cycle {cycle} (elapsed {int(elapsed)}s) ===")
        try:
            monitor.run_once(config)
        except Exception as e:  # noqa: BLE001 - one bad cycle shouldn't kill the loop
            print(f"ERROR during scan cycle: {e}", file=sys.stderr)

        if commit_state:
            try:
                commit_state_if_changed(config["state_file"])
            except Exception as e:  # noqa: BLE001
                print(f"WARNING: state commit step failed: {e}", file=sys.stderr)

        elapsed = time.monotonic() - start
        remaining = max_runtime - elapsed
        if remaining <= 0:
            continue  # loop head will break

        sleep_for = min(scan_interval, remaining)
        print(f"Sleeping {int(sleep_for)}s until next scan...")
        time.sleep(sleep_for)


if __name__ == "__main__":
    main()
