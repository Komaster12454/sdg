# Migration

1. Replace the repository files with this package.
2. Keep the existing `state.json`; the loader remains compatible with the previous `records` format.
3. Add at least one Discord webhook secret.
4. Add `DISCORD_WEBHOOK_ZERO_DAY_URL` when candidates should use a separate channel.
5. Optionally add `VULN_TODAY_API_URL` and `VULN_TODAY_API_KEY` secrets.
6. Optionally configure `ZERO_DAY_WATCH_REPOS`, `WATCH_TERMS`, `ADVISORY_FEEDS_JSON`, and `SBOM_INPUT_GLOB` as repository variables.
7. Run the workflow manually once and inspect the first alert cycle.

The first cycle can generate updates for recently observed CVEs because the new state fingerprint contains additional intelligence fields. Older state entries outside the lookback window will not be re-posted.

For a conservative rollout, begin with:

```text
MIN_ZERO_DAY_SCORE=70
MIN_ZERO_DAY_CONFIDENCE=40
MAX_NOTIFICATIONS_PER_RUN=20
GHSA_INCLUDE_UNREVIEWED=false
```

Lower thresholds after reviewing false-positive rates.
