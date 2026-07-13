# CVE → Discord Monitor

Aggregates recent CVEs from **three sources** and posts them to a Discord channel as
rich embeds, labeled **Patched / Unpatched / Unknown**:

| Source | What it adds |
|---|---|
| [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | Description, CVSS score, CWE, "Patch"-tagged references |
| [GitHub Security Advisories](https://docs.github.com/en/rest/security-advisories) | Per-package patched-version data (most authoritative patch signal) |
| GitHub repo search | Flags newly-created repos whose name/description mentions a CVE ID — an early-warning signal that a public PoC exists, sometimes before NVD/GHSA even have a record. **Metadata only** (repo name, URL, description, stars, created date) — no code/exploit content is fetched or reproduced. |

Each embed includes a **Patch Status** field. Priority order for deciding it:

1. GHSA per-package patched-version data, if present
2. NVD reference tagged `Patch`
3. Otherwise `❓ Unknown` (GitHub PoC activity, if any, is still shown separately as a field so you can see "no official patch yet, but here's public exploit activity")

If a CVE was previously posted as Unpatched and later gets patched (per GHSA or NVD),
the bot posts a follow-up **🔧 Patch released** update instead of staying silent.

## Setup

1. **Create a Discord webhook**: *Channel Settings → Integrations → Webhooks → New Webhook*, copy the URL.

2. **Add repo secrets** (Settings → Secrets and variables → Actions):
   - `DISCORD_WEBHOOK_URL` — required.
   - `NVD_API_KEY` — optional. Without one, NVD allows ~5 requests/30s; with a free key
     (https://nvd.nist.gov/developers/request-an-api-key) it's ~50/30s.
   - `GITHUB_TOKEN` — **not something you need to create.** GitHub Actions provides this
     automatically as `secrets.GITHUB_TOKEN`, already wired into the workflow. It raises
     the GHSA and repo-search rate limits from unauthenticated levels to the standard
     authenticated ones.

3. **Push this repo to GitHub.** The workflow runs hourly (`cron: "0 * * * *"`) and can
   also be triggered manually from the Actions tab.

4. `permissions: contents: write` (already set) lets the workflow commit `state.json`
   back to the repo, which is how it remembers what's been posted and each CVE's last
   known patch status.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `DISCORD_WEBHOOK_URL` | — | **Required.** |
| `NVD_API_KEY` | unset | Optional, higher NVD rate limit. |
| `GITHUB_TOKEN` | unset | Optional, higher GHSA/search rate limit. Auto-provided in Actions. |
| `LOOKBACK_MINUTES` | `70` | Search window; keep it a bit larger than your cron interval to avoid gaps. |
| `MIN_CVSS` | `0` | Only post CVEs with CVSS base score ≥ this value. |
| `STATE_FILE` | `state.json` | Dedupe/patch-status tracking file. |

## Run locally

```bash
pip install -r requirements.txt
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/xxxx/yyyy"
export GITHUB_TOKEN="ghp_xxx"   # optional but recommended locally, unauthenticated GH search limit is low
python cve_monitor.py
```

## Notes / limitations

- GitHub's repo-search "created" filter has day granularity; the script fetches that
  day's results and then filters precisely by timestamp client-side, so short lookback
  windows still work correctly.
- This surfaces **metadata about** PoC repo activity as a risk signal — it does not
  pull in, summarize, or reproduce exploit code from those repos.
- If you want a tighter feed (e.g. only High/Critical), raise `MIN_CVSS` (e.g. `7.0`).
- `state.json` grows with each new CVE tracked; it's auto-trimmed to the most recent
  6000 records so it won't grow unbounded.
