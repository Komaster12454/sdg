# SDG Vulnerability Intelligence Monitor

SDG collects public vulnerability intelligence, correlates duplicate records, ranks risk, and sends Discord alerts. It also detects **pre-CVE and zero-day candidates** from passive public signals and authorized scanner output.

> A scraper cannot prove that a private, previously unknown vulnerability exists. SDG labels early signals as **candidates requiring validation**. It does not exploit targets, download exploit code, or actively scan systems.

## What changed

- NVD CVE API with pagination, retries, and CVSS/CWE/reference extraction
- GitHub Security Advisories, including optional unreviewed and pre-CVE GHSAs
- Official CVE List release feed for records that may appear before NVD enrichment
- CISA Known Exploited Vulnerabilities enrichment
- FIRST EPSS probability and percentile enrichment
- Configurable vuln.today REST API adapter
- GitHub public repository metadata signals
- Configurable watched-repository commit and issue metadata
- Configurable vendor RSS, Atom, and JSON advisory feeds
- SARIF ingestion for findings from authorized SAST/DAST/scanner workflows
- Custom JSON finding ingestion for responsible security research
- Zero-day candidate score, confidence score, risk priority, and evidence reasons
- GHSA-to-CVE alias correlation and state migration when a CVE is assigned later
- Separate Discord routing for Patched, Unpatched, Unknown, and Zero-day Candidate alerts
- Material-change fingerprints so updated findings can be re-alerted without duplicate spam
- Watchlist and CycloneDX/SPDX SBOM relevance boosts, suppression controls, source failure isolation, retries, and rate-limit handling
- Optional JSONL export for SIEM or later processing

## Sources

| Source | Information added |
|---|---|
| NVD CVE API 2.0 | CVE description, CVSS, CWE, references, patch/exploit tags |
| GitHub Global Security Advisories | Package/version data, fixes, reviewed and optional unreviewed advisories, pre-CVE GHSA IDs |
| Official CVE List releases | Early official CVE publication signal from `CVEProject/cvelistV5` |
| CISA KEV | Confirmed exploitation and ransomware campaign status |
| FIRST EPSS | Probability and percentile of exploitation in the next 30 days |
| GitHub repository metadata | Newly created public repositories that mention CVEs, GHSAs, zero-day, or 0day terms |
| Watched GitHub repositories | Security-relevant commit titles, issue titles, labels, and URLs; no code or issue bodies are downloaded |
| Vendor feeds | Configurable RSS, Atom, or JSON advisories |
| vuln.today | Optional enrichment from the configured REST API endpoint |
| SARIF/custom JSON | Findings produced by your own authorized testing workflows |

## Zero-day candidate model

A candidate can be created from:

1. A reviewed GHSA published before it has a CVE.
2. A trusted vendor advisory that describes a vulnerability but has no CVE or GHSA.
3. A security-relevant change in a repository you explicitly watch.
4. A security-labelled public issue in a repository you explicitly watch.
5. A high-confidence SARIF result from an authorized scanner.
6. A custom authorized-research finding.
7. Multiple lower-confidence public metadata signals that correlate to the same identifier.

Candidates receive:

- `zero_day_score`: strength and urgency of the pre-CVE evidence
- `confidence`: trust and diversity of sources
- `priority`: operational remediation priority using CVSS, EPSS, KEV, exploit signals, patch status, watchlist relevance, and candidate score
- `candidate_reasons`: human-readable reasons for the classification
- `evidence`: metadata links and scanner references

The default notification gate is:

```text
zero_day_score >= 60
confidence >= 35
```

A new public repository signal alone is intentionally below the default alert threshold. A reviewed pre-CVE GHSA, trusted vendor advisory, or serious SARIF finding normally exceeds it.

## Setup

### 1. Required Discord configuration

Set one fallback webhook:

```text
DISCORD_WEBHOOK_URL
```

Or use separate webhooks:

```text
DISCORD_WEBHOOK_PATCHED_URL
DISCORD_WEBHOOK_UNPATCHED_URL
DISCORD_WEBHOOK_UNKNOWN_URL
DISCORD_WEBHOOK_ZERO_DAY_URL
```

Unset category webhooks fall back to `DISCORD_WEBHOOK_URL`. Zero-day candidates also fall back to the Unknown webhook when one is configured.

Webhook values must be stored as GitHub Actions **secrets**, not repository variables. The monitor adds Discord's `wait=true` option and counts a message only when Discord returns the created message ID. A failed bucket is left out of deduplication state so it is retried on the next cycle. Look for `discord_messages_confirmed=N` in the run log; any delivery problem is also logged with its category and HTTP status without printing the webhook URL.

### 2. Optional API secrets

```text
NVD_API_KEY
VULN_TODAY_API_URL
VULN_TODAY_API_KEY
```

`GITHUB_TOKEN` is supplied automatically by GitHub Actions. The vuln.today endpoint is configurable because access and endpoint details can vary by account/API version.

### 3. Optional repository variables

```text
ZERO_DAY_WATCH_REPOS=owner/project,another/project
WATCH_TERMS=nginx,windows,fortinet,my-product
ADVISORY_FEEDS_JSON=[...]
```

Only add repositories you are authorized to monitor and whose security-fix metadata is useful to you.

## Configuration

| Variable | Default | Purpose |
|---|---:|---|
| `LOOKBACK_MINUTES` | `90` | Time window queried on each cycle |
| `MIN_CVSS` | `0` | Skip scored findings below this CVSS |
| `MIN_PRIORITY` | `0` | Skip ordinary findings below this priority |
| `MIN_ZERO_DAY_SCORE` | `60` | Minimum candidate score for a zero-day alert |
| `MIN_ZERO_DAY_CONFIDENCE` | `35` | Minimum candidate confidence for a zero-day alert |
| `MAX_NOTIFICATIONS_PER_RUN` | `60` | Flood-control cap per cycle |
| `GHSA_INCLUDE_UNREVIEWED` | `true` | Include GitHub unreviewed advisories |
| `NOTIFY_UPDATES` | `true` | Re-alert on material changes |
| `ZERO_DAY_WATCH_REPOS` | empty | Comma-separated GitHub repositories |
| `WATCH_TERMS` | empty | Products/vendors that receive a priority boost |
| `SUPPRESS_IDENTIFIERS` | empty | Comma-separated IDs to suppress |
| `ADVISORY_FEEDS_JSON` | `[]` | JSON array of vendor feed definitions |
| `SARIF_INPUT_GLOB` | empty | Comma-separated local SARIF glob patterns |
| `SBOM_INPUT_GLOB` | empty | CycloneDX/SPDX JSON files used for relevance matching |
| `CUSTOM_FINDINGS_JSON` | empty | Path to custom authorized-research JSON |
| `FINDINGS_JSONL` | empty | Optional output path for all normalized findings |
| `STATE_FILE` | `state.json` | Dedupe, aliases, and candidate tracking state |
| `STATE_PERSISTENCE_MODE` | `auto` | Use conflict-aware GitHub persistence in Actions or legacy local git elsewhere |
| `STATE_PERSIST_RETRIES` | `4` | Attempts after concurrent GitHub state updates |
| `DRY_RUN` | `false` | Print notification JSON instead of sending Discord messages |

## Vendor advisory feeds

`ADVISORY_FEEDS_JSON` is a JSON array. The `trusted` flag controls how strongly a feed contributes to candidate confidence.

```json
[
  {
    "name": "Vendor Security Advisories",
    "url": "https://vendor.example/security/advisories.atom",
    "type": "rss",
    "trusted": true
  },
  {
    "name": "Internal PSIRT Export",
    "url": "https://security.example/api/advisories",
    "type": "json",
    "trusted": true,
    "headers": {
      "X-API-Key": "use-a-secret-in-your-runtime-instead"
    }
  }
]
```

Do not commit real API keys to this file or to repository variables. Prefer repository secrets and a private proxy when a feed requires authentication.

The generic JSON adapter recognizes common containers such as `vulnerabilities`, `results`, `items`, `data`, `cves`, `advisories`, and `findings`.

## vuln.today

Set:

```text
VULN_TODAY_API_URL=https://your-account-endpoint
VULN_TODAY_API_KEY=your-key
```

The adapter sends both:

```text
Authorization: Bearer <key>
X-API-Key: <key>
```

It recognizes common fields including CVE/GHSA ID, title, description, severity, CVSS, references, patch status, exploit status, priority, and prevalence.

## Authorized SARIF ingestion

SDG does not run a scanner itself. It can ingest SARIF generated by CodeQL, Semgrep, SAST tools, DAST tools, or internal authorized scanners:

```text
SARIF_INPUT_GLOB=reports/**/*.sarif,artifacts/*.sarif
```

SARIF results are assigned stable `ZD-CAND-*` identifiers using the tool, rule, location, fingerprint, and message. They are candidates until manually verified.

## SBOM relevance

SDG can extract package names and package URLs from CycloneDX or SPDX JSON SBOMs and use them as watch terms:

```text
SBOM_INPUT_GLOB=sbom/**/*.json,artifacts/*-bom.json
```

A matching package receives a priority boost and appears in the Discord `Watchlist Matches` field. This is relevance ranking only; it does not replace version-aware SBOM vulnerability analysis.

## Custom authorized-research findings

Set:

```text
CUSTOM_FINDINGS_JSON=research-findings.json
```

Example:

```json
{
  "findings": [
    {
      "title": "Authentication boundary is not enforced",
      "description": "Observed during an authorized assessment of the staging environment.",
      "source": "Internal authorized assessment",
      "severity": "high",
      "zero_day_candidate": true,
      "zero_day_score": 78,
      "affected": ["example-service 4.2"],
      "url": "https://internal-tracker.example/SEC-123"
    }
  ]
}
```

Do not place exploit payloads, credentials, customer data, or sensitive reproduction steps into public Discord channels or a public repository.

## Local run

```bash
python -m pip install -r requirements.txt

export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
export GITHUB_TOKEN="ghp_..."                       # optional locally
export NVD_API_KEY="..."                           # optional
export LOOKBACK_MINUTES="90"
export MIN_ZERO_DAY_SCORE="60"
export ZERO_DAY_WATCH_REPOS="owner/project"

python cve_monitor.py
```

Dry run:

```bash
DRY_RUN=true FINDINGS_JSONL=findings.jsonl python cve_monitor.py
```

## Tests

```bash
python -m unittest discover -s tests -v
```

## Continuous GitHub Actions operation

`.github/workflows/cve-monitor.yml` starts every five minutes and runs `continuous_runner.py`. The runner scans at the configured interval and persists only `state.json`. In Actions it uses GitHub's contents API with the current blob SHA. If another workflow or person updates the branch concurrently, the runner fetches the new state, merges records by their newest observation time, and retries. It never builds up rejected local commits or force-pushes `main`.

GitHub scheduled workflows are best-effort and may be delayed. Keep `LOOKBACK_MINUTES` larger than the internal scan interval so delayed cycles do not create gaps.

## Responsible validation workflow

1. Treat all `ZD-CAND-*` and pre-CVE GHSA alerts as unverified.
2. Confirm scope and authorization before any testing.
3. Reproduce only in a controlled lab or explicitly authorized environment.
4. Preserve minimal evidence and avoid collecting unrelated data.
5. Check whether the vendor already has a private advisory or assigned CVE.
6. Report through the vendor PSIRT, CERT/CC, CNA, or coordinated disclosure channel.
7. Do not publish exploit details before a fix or coordinated disclosure date.
8. Suppress false positives with `SUPPRESS_IDENTIFIERS` and tune candidate thresholds.

## Limitations

- Passive monitoring can identify early public signals, but it cannot guarantee discovery before attackers.
- GitHub metadata can be misleading or intentionally noisy.
- Unreviewed GHSAs and generic feeds have higher false-positive rates.
- Vendor feeds vary widely in structure and timestamp quality.
- A candidate score is triage guidance, not proof of exploitability.
- EPSS and KEV apply only after a CVE exists.
- The monitor never downloads or executes proof-of-concept code.
