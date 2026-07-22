# Enhancement Summary

## Defensive zero-day candidate discovery

- Reviewed pre-CVE GHSA detection
- Optional unreviewed GHSA collection
- Trusted vendor RSS/Atom/JSON advisory ingestion
- Watched GitHub repository commit and issue metadata signals
- Authorized SARIF and custom research finding ingestion
- Stable `ZD-CAND-*` identifiers
- Candidate confidence and evidence scoring
- Separate zero-day Discord routing
- Candidate retention and suppression controls

## Vulnerability intelligence

- Official CVE List release feed
- NVD pagination and retry handling
- CISA KEV and ransomware enrichment
- FIRST EPSS enrichment with cache
- Configurable vuln.today API adapter
- CVE/GHSA alias correlation
- GHSA-to-CVE state migration
- Material-change fingerprints
- Watchlist and SBOM relevance boosts
- JSONL export

## Reliability

- Per-source failure isolation
- HTTP retry and backoff handling
- Discord rate-limit handling and character-aware batching
- Confirmed Discord delivery using returned message IDs
- Failed webhook buckets remain eligible for retry instead of being marked sent
- Conflict-aware `state.json` persistence through the GitHub API, including files over 1 MiB
- Flood-control cap
- Unit tests in GitHub Actions
- Fixed the previous `LOOKBACK_DAYS` override that ignored `LOOKBACK_MINUTES`
- Removed debug output and duplicate Discord retry parsing

## Validation

```text
Ran 41 tests
OK (skipped=4 live-source tests)
```

`cve_monitor.py`, `continuous_runner.py`, and the tests also pass Python bytecode compilation.
