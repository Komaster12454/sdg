#!/usr/bin/env python3
"""
Run the vulnerability monitor repeatedly and persist its deduplication state.

In GitHub Actions, state is written with GitHub's contents API. The update is
based on the current remote blob SHA and retries conflicts after merging both
state documents. This avoids leaving the checkout permanently behind `main`
when another workflow or a person pushes while the long-running job is active.

Environment variables (in addition to cve_monitor.py's):
  SCAN_INTERVAL_SECONDS   seconds between scans, default 60
  MAX_RUNTIME_SECONDS     safety cap, default 21000 (5h50m)
  GIT_COMMIT_STATE        legacy state-persistence toggle, default true
  STATE_PERSISTENCE_MODE  auto, github, or git; default auto
  STATE_PERSIST_RETRIES   GitHub API conflict attempts, default 4
"""

import base64
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import time
from typing import Any
from urllib.parse import quote

import requests

import cve_monitor as monitor


STATE_COMMIT_MESSAGE = "chore: update CVE scan state [skip ci]"
GITHUB_API_VERSION = "2022-11-28"


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
    """Legacy local-git persistence for non-Actions environments."""
    add = git("add", state_file)
    if add.returncode != 0:
        print(f"WARNING: git add failed: {add.stderr}", file=sys.stderr)
        return False

    diff = git("diff", "--cached", "--quiet", "--", state_file)
    if diff.returncode == 0:
        return False

    commit = git("commit", "-m", STATE_COMMIT_MESSAGE)
    if commit.returncode != 0:
        print(f"WARNING: git commit failed: {commit.stderr}", file=sys.stderr)
        return False

    push = git("push")
    if push.returncode != 0:
        print(f"WARNING: git push failed: {push.stderr}", file=sys.stderr)
        return False

    print("Committed and pushed updated state.json.")
    return True


def _read_state_document(path: str) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot persist invalid state file {path}: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("records", {}), dict):
        raise ValueError(f"Cannot persist invalid state file {path}: records must be an object")
    payload.setdefault("records", {})
    return payload


def _state_time(entry: dict[str, Any]) -> float:
    for key in ("last_seen", "last_checked", "first_seen"):
        parsed = monitor.parse_time(entry.get(key))
        if parsed is not None:
            return parsed.timestamp()
    return float("-inf")


def merge_state_documents(
    remote: dict[str, Any],
    local: dict[str, Any],
    *,
    max_keep: int = 12000,
) -> dict[str, Any]:
    """Union concurrent state updates while preferring each newest record."""
    remote_records = remote.get("records", {}) if isinstance(remote, dict) else {}
    local_records = local.get("records", {}) if isinstance(local, dict) else {}
    if not isinstance(remote_records, dict) or not isinstance(local_records, dict):
        raise ValueError("State documents must contain a records object")

    merged: dict[str, dict[str, Any]] = {}
    for identifier in set(remote_records) | set(local_records):
        remote_entry = remote_records.get(identifier)
        local_entry = local_records.get(identifier)
        candidates = [entry for entry in (remote_entry, local_entry) if isinstance(entry, dict)]
        if not candidates:
            continue
        # Prefer local on a timestamp tie because it represents this cycle.
        winner = max(enumerate(candidates), key=lambda pair: (_state_time(pair[1]), pair[0]))[1]
        combined = dict(winner)

        first_seen_values = [
            entry.get("first_seen")
            for entry in candidates
            if monitor.parse_time(entry.get("first_seen")) is not None
        ]
        if first_seen_values:
            combined["first_seen"] = min(
                first_seen_values,
                key=lambda value: monitor.parse_time(value).timestamp(),
            )
        merged[identifier] = combined

    ordered = sorted(merged.items(), key=lambda pair: (_state_time(pair[1]), pair[0]))[-max_keep:]
    updated_candidates = [
        value
        for value in (remote.get("updated"), local.get("updated"))
        if monitor.parse_time(value) is not None
    ]
    updated = (
        max(updated_candidates, key=lambda value: monitor.parse_time(value).timestamp())
        if updated_candidates
        else monitor.utcnow().isoformat()
    )
    return {"records": dict(ordered), "updated": updated}


def _github_state_path(state_file: str) -> str:
    path = PurePosixPath(str(state_file).replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or str(path) in ("", "."):
        raise ValueError("STATE_FILE must be a repository-relative path for GitHub persistence")
    return str(path)


def _decode_remote_state(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("encoding") != "base64" or not isinstance(payload.get("content"), str):
        raise ValueError("GitHub returned an unsupported state.json content response")
    try:
        raw = base64.b64decode(payload["content"], validate=False).decode("utf-8")
        document = json.loads(raw)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("GitHub returned an invalid remote state.json") from exc
    if not isinstance(document, dict) or not isinstance(document.get("records", {}), dict):
        raise ValueError("Remote state.json must contain a records object")
    document.setdefault("records", {})
    return document


def _load_remote_state(
    client: requests.Session,
    contents_payload: dict[str, Any],
    *,
    repository: str,
    api_url: str,
    headers: dict[str, str],
) -> dict[str, Any]:
    """Decode inline content or fetch the blob used for files over 1 MiB."""
    if contents_payload.get("encoding") == "base64" and contents_payload.get("content"):
        return _decode_remote_state(contents_payload)

    sha = contents_payload.get("sha")
    if not isinstance(sha, str) or not sha:
        raise ValueError("GitHub state response did not include readable content or a blob SHA")
    blob_url = (
        f"{api_url.rstrip('/')}/repos/{quote(repository, safe='/')}/git/blobs/"
        f"{quote(sha, safe='')}"
    )
    blob_response = client.get(blob_url, headers=headers, timeout=30)
    blob_response.raise_for_status()
    return _decode_remote_state(blob_response.json())


def persist_state_to_github(
    state_file: str,
    *,
    repository: str,
    branch: str,
    token: str,
    api_url: str = "https://api.github.com",
    max_retries: int = 4,
    session: requests.Session | None = None,
) -> bool:
    """Create or update state through the contents API with conflict retries."""
    if not repository or "/" not in repository:
        raise ValueError("GITHUB_REPOSITORY must use owner/name format")
    if not branch:
        raise ValueError("GITHUB_REF_NAME is required for GitHub state persistence")
    if not token:
        raise ValueError("GITHUB_TOKEN is required for GitHub state persistence")

    local_document = _read_state_document(state_file)
    repository_path = _github_state_path(state_file)
    endpoint = (
        f"{api_url.rstrip('/')}/repos/{quote(repository, safe='/')}/contents/"
        f"{quote(repository_path, safe='/')}"
    )
    client = session or monitor.build_session()
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    contents_headers = {**headers, "Accept": "application/vnd.github.object+json"}

    for attempt in range(1, max(1, max_retries) + 1):
        response = client.get(
            endpoint,
            headers=contents_headers,
            params={"ref": branch},
            timeout=30,
        )
        if response.status_code == 404:
            remote_document: dict[str, Any] = {"records": {}}
            remote_sha = None
        else:
            response.raise_for_status()
            remote_payload = response.json()
            remote_sha = remote_payload.get("sha")
            if not isinstance(remote_sha, str) or not remote_sha:
                raise ValueError("GitHub state response did not include a blob SHA")
            remote_document = _load_remote_state(
                client,
                remote_payload,
                repository=repository,
                api_url=api_url,
                headers=headers,
            )

        merged = merge_state_documents(remote_document, local_document)
        content = json.dumps(merged, indent=2).encode("utf-8")
        body: dict[str, Any] = {
            "message": STATE_COMMIT_MESSAGE,
            "content": base64.b64encode(content).decode("ascii"),
            "branch": branch,
        }
        if remote_sha:
            body["sha"] = remote_sha

        update = client.put(endpoint, headers=headers, json=body, timeout=30)
        if update.status_code in (200, 201):
            Path(state_file).write_bytes(content)
            print(
                "Persisted state.json through the GitHub API "
                f"(attempt {attempt}, {len(merged['records'])} records)."
            )
            return True
        if update.status_code in (409, 422) and attempt < max_retries:
            local_document = merged
            print(
                f"State changed remotely; merging and retrying ({attempt}/{max_retries}).",
                file=sys.stderr,
            )
            continue
        update.raise_for_status()

    return False


def persist_state_if_changed(state_file: str) -> bool:
    mode = os.getenv("STATE_PERSISTENCE_MODE", "auto").strip().lower() or "auto"
    if mode not in {"auto", "github", "git"}:
        raise ValueError("STATE_PERSISTENCE_MODE must be auto, github, or git")

    use_github = mode == "github" or (
        mode == "auto"
        and get_env_bool("GITHUB_ACTIONS", False)
        and bool(os.getenv("GITHUB_TOKEN"))
    )
    if use_github:
        return persist_state_to_github(
            state_file,
            repository=os.getenv("GITHUB_REPOSITORY", ""),
            branch=os.getenv("GITHUB_REF_NAME", ""),
            token=os.getenv("GITHUB_TOKEN", ""),
            api_url=os.getenv("GITHUB_API_URL", "https://api.github.com"),
            max_retries=max(1, get_env_int("STATE_PERSIST_RETRIES", 4)),
        )
    if mode == "github":
        raise ValueError("GitHub state persistence is configured but its Actions context is incomplete")
    return commit_state_if_changed(state_file)


def main():
    config = monitor.load_config()

    scan_interval = get_env_int("SCAN_INTERVAL_SECONDS", 60)
    max_runtime = get_env_int("MAX_RUNTIME_SECONDS", 21000)
    commit_state = get_env_bool("GIT_COMMIT_STATE", True)

    config["lookback_minutes"] = max(config["lookback_minutes"], (scan_interval // 60) + 2)

    print(
        f"Continuous runner starting: scanning every {scan_interval}s, "
        f"safety cap {max_runtime}s, lookback {config['lookback_minutes']}min."
    )

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
        except Exception as exc:  # noqa: BLE001 - one bad cycle should not kill the loop
            print(f"ERROR during scan cycle: {exc}", file=sys.stderr)

        if commit_state:
            try:
                persist_state_if_changed(config["state_file"])
            except Exception as exc:  # noqa: BLE001
                print(f"WARNING: state persistence failed: {exc}", file=sys.stderr)

        elapsed = time.monotonic() - start
        remaining = max_runtime - elapsed
        if remaining <= 0:
            continue

        sleep_for = min(scan_interval, remaining)
        print(f"Sleeping {int(sleep_for)}s until next scan...")
        time.sleep(sleep_for)


if __name__ == "__main__":
    main()
