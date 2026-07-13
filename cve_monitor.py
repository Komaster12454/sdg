#!/usr/bin/env python3
"""
cve_monitor.py

Aggregates recent CVEs from multiple public sources and posts them to a
Discord channel as rich embeds, labeled Patched / Unpatched / Unknown:

  1. NVD CVE API 2.0        https://services.nvd.nist.gov/rest/json/cves/2.0
  2. GitHub Security Advisories (GHSA)   https://api.github.com/advisories
  3. GitHub repo search — finds newly-created repos whose name/description
     mentions a CVE ID. This is metadata only (repo name, URL, description,
     star count, created date) — no exploit/PoC code is fetched or
     reproduced. It exists purely as an early-warning signal: a public PoC
     repo appearing before NVD/GHSA list a fix is itself useful intel for
     "this is now more urgent."

Patch status is derived, in priority order:
  - GHSA per-package "patched_versions" data (most authoritative)
  - NVD reference entries tagged "Patch"
  - Otherwise: Unknown (with a note if only a GitHub PoC exists)

State (which CVE IDs have been posted, and their last known patch status)
is kept in state.json so re-runs don't spam duplicates, and so the script
can send a follow-up "patch released" notice when status flips from
Unpatched -> Patched. The GitHub Actions workflow commits this file back.

Env vars:
  DISCORD_WEBHOOK_URL   (required)  Discord webhook to post to
  NVD_API_KEY           (optional)  NVD API key, raises NVD rate limit
  GITHUB_TOKEN          (optional)  GitHub token, raises GH API rate limit
                                     (in Actions, pass ${{ secrets.GITHUB_TOKEN }})
  LOOKBACK_MINUTES      (optional)  How far back to search, default 70
  MIN_CVSS              (optional)  Only post CVEs with CVSS >= this, default 0
  STATE_FILE            (optional)  Path to dedupe state file, default state.json
"""

import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_API_URL = "https://api.github.com/advisories"
GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"

CVE_ID_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

SEVERITY_COLORS = {
    "CRITICAL": 0x992D22,  # dark red
    "HIGH": 0xE74C3C,      # red
    "MEDIUM": 0xE67E22,    # orange
    "LOW": 0xF1C40F,       # yellow
    "NONE": 0x95A5A6,      # gray
    "UNKNOWN": 0x7289DA,   # discord blurple
}

PATCH_LABELS = {
    "PATCHED": "✅ Patched",
    "UNPATCHED": "🔴 Unpatched",
    "UNKNOWN": "❓ Unknown",
}

DISCORD_EMBED_LIMIT = 10          # max embeds per Discord message
DISCORD_DESCRIPTION_LIMIT = 350   # truncate long descriptions
MAX_POC_REPOS_SHOWN = 3


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def get_env(name, default=None, required=False):
    val = os.environ.get(name, default)
    if required and not val:
        print(f"ERROR: required environment variable {name} is not set", file=sys.stderr)
        sys.exit(1)
    return val


def load_state(path):
    """Returns dict: { cve_id: {"posted": bool, "patch_status": str} }"""
    if os.path.exists(path):
        try:
            with open(path, "r") as f:
                data = json.load(f)
                records = data.get("records")
                if records is not None:
                    return records
                # Back-compat with the older seen_ids-only format
                return {cid: {"posted": True, "patch_status": "UNKNOWN"} for cid in data.get("seen_ids", [])}
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def save_state(path, records, max_keep=6000):
    if len(records) > max_keep:
        # Drop oldest-looking entries by simple insertion order trim
        keys = list(records.keys())[-max_keep:]
        records = {k: records[k] for k in keys}
    with open(path, "w") as f:
        json.dump(
            {"records": records, "updated": datetime.now(timezone.utc).isoformat()},
            f,
            indent=2,
        )


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


# --------------------------------------------------------------------------
# Source 1: NVD
# --------------------------------------------------------------------------

def fetch_nvd_cves(lookback_minutes, api_key=None):
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=lookback_minutes)

    params = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 200,
    }
    headers = {"User-Agent": "cve-discord-monitor/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    results = []
    start_index = 0
    while True:
        params["startIndex"] = start_index
        try:
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
        except requests.RequestException as e:
            print(f"WARNING: NVD request failed: {e}", file=sys.stderr)
            break
        if resp.status_code == 403:
            print("WARNING: NVD rate-limited the request (403). Consider setting NVD_API_KEY.", file=sys.stderr)
            break
        if not resp.ok:
            print(f"WARNING: NVD returned {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
            break
        data = resp.json()

        vulns = data.get("vulnerabilities", [])
        results.extend(vulns)

        total = data.get("totalResults", len(vulns))
        start_index += len(vulns)
        if start_index >= total or not vulns:
            break
        time.sleep(1.5 if not api_key else 0.6)

    return results


def extract_cvss(metrics):
    if not metrics:
        return None, "UNKNOWN"
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            entry = entries[0]
            cvss_data = entry.get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = entry.get("baseSeverity") or cvss_data.get("baseSeverity") or "UNKNOWN"
            return score, severity.upper() if severity else "UNKNOWN"
    return None, "UNKNOWN"


def get_english_description(descriptions):
    for d in descriptions or []:
        if d.get("lang") == "en":
            return d.get("value", "No description available.")
    return "No description available."


def normalize_nvd_item(item):
    cve = item.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        return None

    description = get_english_description(cve.get("descriptions"))
    score, severity = extract_cvss(cve.get("metrics", {}))
    references = cve.get("references", [])

    patch_status = "UNKNOWN"
    for ref in references:
        tags = [t.lower() for t in ref.get("tags", [])]
        if "patch" in tags:
            patch_status = "PATCHED"
            break

    weaknesses = cve.get("weaknesses", [])
    cwe_ids = []
    for w in weaknesses:
        for desc in w.get("description", []):
            if desc.get("value", "").startswith("CWE-"):
                cwe_ids.append(desc["value"])

    return {
        "cve_id": cve_id,
        "description": description,
        "score": score,
        "severity": severity,
        "published": cve.get("published"),
        "cwe": sorted(set(cwe_ids)),
        "references": [r.get("url") for r in references[:5] if r.get("url")],
        "patch_status": patch_status,
        "sources": {"NVD"},
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
    }


# --------------------------------------------------------------------------
# Source 2: GitHub Security Advisories (GHSA)
# --------------------------------------------------------------------------

def fetch_ghsa_advisories(lookback_minutes, token=None):
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=lookback_minutes)

    headers = {"Accept": "application/vnd.github+json", "User-Agent": "cve-discord-monitor/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    params = {
        "per_page": 100,
        "sort": "updated",
        "direction": "desc",
        "updated": f">{iso(start)}",
    }
    try:
        resp = requests.get(GHSA_API_URL, params=params, headers=headers, timeout=30)
    except requests.RequestException as e:
        print(f"WARNING: GHSA request failed: {e}", file=sys.stderr)
        return []
    if not resp.ok:
        print(f"WARNING: GHSA API returned {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
        return []

    return resp.json()


def normalize_ghsa_item(advisory):
    cve_id = advisory.get("cve_id")
    if not cve_id:
        return None  # some GHSAs don't have a CVE assigned yet; skip, NVD/CVE feed is our CVE-indexed source

    vulns = advisory.get("vulnerabilities", []) or []
    has_any_patch = False
    has_any_package = False
    for v in vulns:
        has_any_package = True
        if v.get("first_patched_version"):
            has_any_patch = True
            break
    if not has_any_package:
        patch_status = "UNKNOWN"
    else:
        patch_status = "PATCHED" if has_any_patch else "UNPATCHED"

    severity = (advisory.get("severity") or "unknown").upper()
    cwe_ids = advisory.get("cwe_ids") or []

    refs = [advisory.get("html_url")] if advisory.get("html_url") else []
    for r in advisory.get("references", []) or []:
        if isinstance(r, str):
            refs.append(r)
        elif isinstance(r, dict) and r.get("url"):
            refs.append(r["url"])

    return {
        "cve_id": cve_id,
        "description": advisory.get("summary") or advisory.get("description") or "No description available.",
        "score": (advisory.get("cvss") or {}).get("score"),
        "severity": severity,
        "published": advisory.get("published_at"),
        "cwe": cwe_ids,
        "references": refs[:5],
        "patch_status": patch_status,
        "sources": {"GHSA"},
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "ghsa_url": advisory.get("html_url"),
    }


# --------------------------------------------------------------------------
# Source 3: GitHub repo search for new CVE mentions / PoC activity
# --------------------------------------------------------------------------

def fetch_github_cve_repos(lookback_minutes, token=None):
    """
    Searches for repositories created recently whose name or description
    mentions a CVE ID. Used both to flag likely-unpatched CVEs that already
    have public PoC activity, and as an independent discovery source for
    brand-new CVEs GitHub users are already discussing.

    Only metadata is retrieved (name, url, description, stars, created_at) —
    repo contents/code are never fetched.
    """
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=lookback_minutes)
    # GitHub's repo search "created" qualifier has day granularity; we filter
    # precisely on created_at client-side after fetching that day's results.
    start_date = start.strftime("%Y-%m-%d")

    headers = {"Accept": "application/vnd.github+json", "User-Agent": "cve-discord-monitor/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    params = {
        "q": f"CVE in:name,description created:>={start_date}",
        "sort": "updated",
        "order": "desc",
        "per_page": 100,
    }
    try:
        resp = requests.get(GITHUB_SEARCH_URL, params=params, headers=headers, timeout=30)
    except requests.RequestException as e:
        print(f"WARNING: GitHub repo search failed: {e}", file=sys.stderr)
        return {}
    if resp.status_code == 403:
        print("WARNING: GitHub search rate-limited (403). Consider setting GITHUB_TOKEN.", file=sys.stderr)
        return {}
    if not resp.ok:
        print(f"WARNING: GitHub search returned {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
        return {}

    items = resp.json().get("items", [])

    cve_repo_map = {}
    for repo in items:
        created_at_str = repo.get("created_at")
        try:
            created_at = datetime.strptime(created_at_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            continue
        if created_at < start:
            continue  # outside our precise lookback window

        haystack = f"{repo.get('name', '')} {repo.get('description', '') or ''}"
        matches = set(m.upper() for m in CVE_ID_RE.findall(haystack))
        for cve_id in matches:
            cve_repo_map.setdefault(cve_id, []).append({
                "name": repo.get("full_name"),
                "url": repo.get("html_url"),
                "description": (repo.get("description") or "").strip(),
                "stars": repo.get("stargazers_count", 0),
                "created_at": created_at_str,
            })

    return cve_repo_map


# --------------------------------------------------------------------------
# Merge sources
# --------------------------------------------------------------------------

def merge_records(nvd_items, ghsa_items, github_repo_map):
    merged = {}

    # NVD first — richest description/CVSS/CWE data
    for raw in nvd_items:
        rec = normalize_nvd_item(raw)
        if rec:
            merged[rec["cve_id"]] = rec

    # GHSA — fill gaps, and GHSA's patch data is more authoritative when present
    for raw in ghsa_items:
        rec = normalize_ghsa_item(raw)
        if not rec:
            continue
        cid = rec["cve_id"]
        if cid in merged:
            existing = merged[cid]
            existing["sources"].add("GHSA")
            if rec["patch_status"] != "UNKNOWN":
                existing["patch_status"] = rec["patch_status"]  # GHSA patch data wins
            existing["ghsa_url"] = rec.get("ghsa_url")
            if not existing.get("score") and rec.get("score"):
                existing["score"] = rec["score"]
            existing["references"] = list(dict.fromkeys(existing["references"] + rec["references"]))[:6]
        else:
            merged[cid] = rec

    # GitHub PoC repos — attach as evidence, and seed brand-new CVEs
    # not yet present in NVD/GHSA (early discovery from GitHub itself).
    for cve_id, repos in github_repo_map.items():
        if cve_id in merged:
            merged[cve_id]["poc_repos"] = repos
            merged[cve_id]["sources"].add("GitHub")
        else:
            merged[cve_id] = {
                "cve_id": cve_id,
                "description": "No official NVD/GHSA record yet — discovered via GitHub repo activity. "
                                "Details may be preliminary.",
                "score": None,
                "severity": "UNKNOWN",
                "published": None,
                "cwe": [],
                "references": [],
                "patch_status": "UNKNOWN",
                "sources": {"GitHub"},
                "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "poc_repos": repos,
            }

    return merged


# --------------------------------------------------------------------------
# Discord embed construction
# --------------------------------------------------------------------------

def build_embed(rec, status_change=False):
    cve_id = rec["cve_id"]
    description = rec.get("description") or "No description available."
    if len(description) > DISCORD_DESCRIPTION_LIMIT:
        description = description[:DISCORD_DESCRIPTION_LIMIT].rsplit(" ", 1)[0] + "…"

    severity = rec.get("severity") or "UNKNOWN"
    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["UNKNOWN"])
    patch_status = rec.get("patch_status", "UNKNOWN")
    patch_label = PATCH_LABELS.get(patch_status, PATCH_LABELS["UNKNOWN"])

    score = rec.get("score")
    score_text = f"{score} ({severity})" if score is not None else severity

    poc_repos = rec.get("poc_repos") or []
    if poc_repos:
        lines = []
        for repo in poc_repos[:MAX_POC_REPOS_SHOWN]:
            lines.append(f"- [{repo['name']}]({repo['url']}) (★{repo.get('stars', 0)})")
        if len(poc_repos) > MAX_POC_REPOS_SHOWN:
            lines.append(f"...and {len(poc_repos) - MAX_POC_REPOS_SHOWN} more")
        poc_text = "\n".join(lines)
    else:
        poc_text = "None found"

    refs = rec.get("references") or []
    refs_text = "\n".join(f"- {r}" for r in refs[:3]) if refs else "None listed"

    sources_text = ", ".join(sorted(rec.get("sources", {"Unknown"})))

    title_prefix = "🔧 PATCH RELEASED — " if status_change else ""
    embed = {
        "title": f"{title_prefix}{cve_id}",
        "url": rec.get("ghsa_url") or rec.get("nvd_url"),
        "description": description,
        "color": color,
        "fields": [
            {"name": "Patch Status", "value": patch_label, "inline": True},
            {"name": "CVSS Score", "value": score_text, "inline": True},
            {"name": "Published", "value": rec.get("published") or "unknown", "inline": True},
            {"name": "CWE", "value": ", ".join(rec.get("cwe") or []) or "N/A", "inline": True},
            {"name": "GitHub PoC/Repo Activity", "value": poc_text, "inline": False},
            {"name": "References", "value": refs_text, "inline": False},
        ],
        "footer": {"text": f"Sources: {sources_text}"},
    }
    return embed


def send_to_discord(webhook_url, embeds, batch_note=None):
    for i in range(0, len(embeds), DISCORD_EMBED_LIMIT):
        batch = embeds[i:i + DISCORD_EMBED_LIMIT]
        payload = {"embeds": batch}
        if batch_note and i == 0:
            payload["content"] = batch_note
        print(f"Sending {len(batch)} embed(s) to Discord webhook...")
        resp = requests.post(webhook_url, json=payload, timeout=15)
        if resp.status_code == 429:
            try:
                retry_after = resp.json().get("retry_after", 2)
            except ValueError:
                retry_after = 2
            print(f"Rate limited by Discord, retrying after {retry_after}s", file=sys.stderr)
            time.sleep(float(retry_after) + 0.5)
            print(f"Sending {len(batch)} embed(s) to Discord webhook...")
        resp = requests.post(webhook_url, json=payload, timeout=15)
        print(f"Discord response: {resp.status_code}")
        if not resp.ok:
            print(f"ERROR posting to Discord: {resp.status_code} {resp.text}", file=sys.stderr)
        else:
            print("Discord webhook accepted the message.")
        time.sleep(1)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def load_config():
    return {
        "webhook_url": get_env("DISCORD_WEBHOOK_URL", required=True),
        "nvd_api_key": get_env("NVD_API_KEY", default=None),
        "github_token": get_env("GITHUB_TOKEN", default=None),
        "lookback_minutes": int(get_env("LOOKBACK_MINUTES", default="70")),
        "min_cvss": float(get_env("MIN_CVSS", default="0")),
        "state_file": get_env("STATE_FILE", default="state.json"),
    }


def run_once(config):
    """Runs a single scan-merge-post cycle. Returns the number of embeds posted."""
    webhook_url = config["webhook_url"]
    nvd_api_key = config["nvd_api_key"]
    github_token = config["github_token"]
    lookback_minutes = config["lookback_minutes"]
    min_cvss = config["min_cvss"]
    state_file = config["state_file"]

    print(f"Looking back {lookback_minutes} minutes across NVD, GHSA, and GitHub repo search...")

    nvd_items = fetch_nvd_cves(lookback_minutes, api_key=nvd_api_key)
    print(f"NVD: {len(nvd_items)} record(s).")

    ghsa_items = fetch_ghsa_advisories(lookback_minutes, token=github_token)
    print(f"GHSA: {len(ghsa_items)} record(s).")

    github_repo_map = fetch_github_cve_repos(lookback_minutes, token=github_token)
    print(f"GitHub repo search: {len(github_repo_map)} CVE ID(s) mentioned in new repos.")

    merged = merge_records(nvd_items, ghsa_items, github_repo_map)
    print(f"Merged total: {len(merged)} unique CVE(s) this run.")

    state = load_state(state_file)
    new_embeds = []
    update_embeds = []

    for cve_id, rec in merged.items():
        score = rec.get("score")
        if score is not None and score < min_cvss:
            continue

        prior = state.get(cve_id)

        if prior is None:
            # Brand new CVE we haven't posted before
            new_embeds.append(build_embed(rec))
            state[cve_id] = {"posted": True, "patch_status": rec["patch_status"]}
        else:
            prior_status = prior.get("patch_status", "UNKNOWN")
            new_status = rec["patch_status"]
            if prior_status == "UNPATCHED" and new_status == "PATCHED":
                update_embeds.append(build_embed(rec, status_change=True))
            state[cve_id]["patch_status"] = new_status

    all_embeds = new_embeds + update_embeds
    if all_embeds:
        note_parts = []
        if new_embeds:
            note_parts.append(f"{len(new_embeds)} new CVE(s)")
        if update_embeds:
            note_parts.append(f"{len(update_embeds)} patch update(s)")
        note = "🔔 **" + " / ".join(note_parts) + "**"
        print(f"Posting {len(all_embeds)} embed(s) to Discord...")
        send_to_discord(webhook_url, all_embeds, batch_note=note)
    else:
        print("Nothing new to post this run.")

    save_state(state_file, state)
    print("Scan cycle done.")
    return len(all_embeds)


def main():
    """Single-shot entry point (used by simple cron-only setups)."""
    config = load_config()
    run_once(config)


if __name__ == "__main__":
    main()

