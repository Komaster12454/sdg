#!/usr/bin/env python3
"""
continuous_runner.py

GitHub Actions jobs are capped at a few hours of runtime, so there's no way
to run a true always-on daemon on GitHub-hosted runners. This script gets
as close as the platform allows: it loops, running a CVE scan every
SCAN_INTERVAL_SECONDS, for up to MAX_RUNTIME_SECONDS (kept comfortably
under GitHub's ~6 hour job limit). After each scan it commits state.json
if it changed, so progress survives even if the job is later interrupted.

When this script's time budget runs out, it exits 0 and the workflow's
next step re-dispatches the workflow via the GitHub API, so a fresh job
picks up immediately where this one left off — a continuous chain of runs.
"One process at a time" is enforced by the workflow's `concurrency` group,
not by this script: GitHub Actions natively queues any additional triggered
runs (schedule, manual, or the self re-dispatch) behind the currently
running one instead of running them in parallel.

Env vars (in addition to cve_monitor.py's):
  SCAN_INTERVAL_SECONDS  (optional) seconds between scans, default 300 (5 min)
  MAX_RUNTIME_SECONDS    (optional) total loop budget, default 20400 (5h40m)
  GIT_COMMIT_STATE       (optional) "true"/"false", default "true" — commit+push
                          state.json after each scan that changes it
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

    # Diff the staged change so this also catches a brand-new (previously
    # untracked) state.json, not just modifications to an existing one.
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

    scan_interval = get_env_int("SCAN_INTERVAL_SECONDS", 300)
    max_runtime = get_env_int("MAX_RUNTIME_SECONDS", 20400)
    commit_state = get_env_bool("GIT_COMMIT_STATE", True)

    # Keep the lookback window slightly larger than the scan interval so
    # back-to-back scans never leave a gap, regardless of small jitter.
    config["lookback_minutes"] = max(config["lookback_minutes"], (scan_interval // 60) + 5)

    print(f"Continuous runner starting: scanning every {scan_interval}s, "
          f"budget {max_runtime}s, lookback {config['lookback_minutes']}min.")

    start = time.monotonic()
    cycle = 0

    while True:
        elapsed = time.monotonic() - start
        remaining = max_runtime - elapsed
        if remaining <= 0:
            print("Time budget exhausted for this job; handing off to the next run.")
            break

        cycle += 1
        print(f"\n=== Scan cycle {cycle} (elapsed {int(elapsed)}s / budget {max_runtime}s) ===")
        try:
            monitor.run_once(config)
        except Exception as e:  # noqa: BLE001 - a bad cycle should not kill the whole loop
            print(f"ERROR during scan cycle: {e}", file=sys.stderr)

        if commit_state:
            try:
                commit_state_if_changed(config["state_file"])
            except Exception as e:  # noqa: BLE001
                print(f"WARNING: state commit step failed: {e}", file=sys.stderr)

        elapsed = time.monotonic() - start
        remaining = max_runtime - elapsed
        if remaining <= 0:
            print("Time budget exhausted after this cycle; handing off to the next run.")
            break

        sleep_for = min(scan_interval, remaining)
        print(f"Sleeping {int(sleep_for)}s until next scan...")
        time.sleep(sleep_for)

    print("Continuous runner exiting cleanly (job time budget reached).")


if __name__ == "__main__":
    main()
