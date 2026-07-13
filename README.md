# CVE → Discord Monitor

Scans multiple sources every 5 minutes for new/changed CVEs and posts them to Discord
as rich embeds labeled **Patched / Unpatched / Unknown**, running entirely on GitHub Actions.

## Sources

| Source | What it adds |
|---|---|
| [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | Description, CVSS score, CWE, "Patch"-tagged references |
| [GitHub Security Advisories](https://docs.github.com/en/rest/security-advisories) | Per-package patched-version data (most authoritative patch signal) |
| GitHub repo search | Newly-created repos whose name/description mentions a CVE ID — early signal of public PoC activity, sometimes before NVD/GHSA have a record. Metadata only (name, URL, description, stars, date) — no code is fetched. |

Patch status priority: GHSA patched-version data → NVD `Patch`-tagged reference →
`❓ Unknown`. If a CVE flips Unpatched → Patched between scans, a follow-up
**🔧 Patch released** message is posted.

## How it runs

`.github/workflows/cve-monitor.yml` triggers on `schedule: "*/5 * * * *"` — every 5
minutes, GitHub's minimum schedule interval — plus `workflow_dispatch` for manual runs.
Each trigger is a fresh, short-lived job: checkout → install deps → run `cve_monitor.py`
once → commit `state.json` if it changed. No long-running process, no self-relaunching.

**One process at a time** is enforced by the `concurrency` group (`cve-monitor`) with
`cancel-in-progress: false`. If a scan ever takes longer than 5 minutes and the next
cron trigger fires while it's still running, GitHub Actions queues the new run instead
of starting it in parallel — a real, built-in FIFO queue, not anything custom-built.

Note: GitHub's cron scheduler is best-effort — under platform load, a run can be
delayed by a few minutes. `LOOKBACK_MINUTES` is set a bit larger than the 5-minute
interval specifically to absorb that jitter without leaving gaps.

## Setup

1. **Discord webhook**: *Channel Settings → Integrations → Webhooks → New Webhook*.

2. **Repo secrets** (Settings → Secrets and variables → Actions):
   - `DISCORD_WEBHOOK_URL` — required.
   - `NVD_API_KEY` — optional, higher NVD rate limit (https://nvd.nist.gov/developers/request-an-api-key).
   - No PAT needed — `GITHUB_TOKEN` is provided automatically by Actions and is enough
     for the GHSA/repo-search calls and for committing `state.json`.

3. **Push this repo to GitHub.** The workflow starts running on its own once pushed
   (or trigger it immediately from the Actions tab via `workflow_dispatch`).

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `DISCORD_WEBHOOK_URL` | — | **Required.** |
| `NVD_API_KEY` | unset | Optional, higher NVD rate limit. |
| `GITHUB_TOKEN` | auto | Built-in, raises GHSA/search rate limits. Already wired in. |
| `LOOKBACK_MINUTES` | `10` | Search window per run; keep a bit larger than the cron interval. |
| `MIN_CVSS` | `0` | Only post CVEs with CVSS base score ≥ this value. |
| `STATE_FILE` | `state.json` | Dedupe/patch-status tracking file. |

## Run locally

```bash
pip install -r requirements.txt
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/xxxx/yyyy"
export GITHUB_TOKEN="ghp_xxx"   # optional but recommended, raises GH API rate limits
python cve_monitor.py
```

## Notes / limitations

- GitHub's repo-search "created" filter has day granularity; the script fetches that
  day's results and filters precisely by timestamp client-side.
- This surfaces metadata about PoC repo activity as a risk signal only — it never
  fetches or reproduces exploit code.
- `state.json` is trimmed to the most recent 6000 tracked CVEs so it won't grow unbounded.
- Want less frequent commits/noise? Raise the cron interval (e.g. `*/15 * * * *`) and
  bump `LOOKBACK_MINUTES` to match — same script, just a slower cadence.
