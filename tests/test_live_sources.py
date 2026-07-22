"""Opt-in live contract tests for public vulnerability sources.

Run with RUN_LIVE_SOURCE_TESTS=1. These tests intentionally remain out of the
normal deterministic suite because public services can be unavailable or rate
limited. A scheduled GitHub Actions workflow runs them separately.
"""

import json
import os
import unittest
from datetime import datetime, timedelta, timezone

import cve_monitor as monitor


RUN_LIVE = os.getenv("RUN_LIVE_SOURCE_TESTS", "").lower() in {"1", "true", "yes", "on"}


@unittest.skipUnless(RUN_LIVE, "set RUN_LIVE_SOURCE_TESTS=1 to call public APIs")
class LiveSourceContractTests(unittest.TestCase):
    def test_nvd_known_cve_contract(self):
        data = monitor.request_json(
            monitor.build_session(),
            monitor.NVD_API_URL,
            params={"cveId": "CVE-2021-44228"},
        )
        self.assertIsInstance(data.get("vulnerabilities"), list)
        self.assertTrue(
            any(row.get("cve", {}).get("id") == "CVE-2021-44228" for row in data["vulnerabilities"])
        )

    def test_cisa_kev_contract(self):
        data = monitor.request_json(monitor.build_session(), monitor.CISA_KEV_URL)
        self.assertIsInstance(data.get("vulnerabilities"), list)
        self.assertTrue(data["vulnerabilities"])
        self.assertIn("cveID", data["vulnerabilities"][0])

    def test_github_advisory_contract(self):
        headers = monitor.github_headers(os.getenv("GITHUB_TOKEN"))
        data = monitor.request_json(
            monitor.build_session(),
            monitor.GHSA_API_URL,
            params={"per_page": 1, "type": "reviewed"},
            headers=headers,
        )
        self.assertIsInstance(data, list)
        self.assertTrue(data)
        self.assertIn("ghsa_id", data[0])

    @unittest.skipUnless(
        monitor.env_bool("VULN_TODAY_ENABLED", False) and os.getenv("VULN_TODAY_API_URL"),
        "vuln.today integration not enabled/configured",
    )
    def test_vuln_today_configured_contract(self):
        url = os.environ["VULN_TODAY_API_URL"]
        default_method = "POST" if monitor.is_scan_endpoint(url) else "GET"
        method = os.getenv("VULN_TODAY_API_METHOD") or default_method
        payload = None
        if os.getenv("VULN_TODAY_REQUEST_JSON"):
            payload = json.loads(os.environ["VULN_TODAY_REQUEST_JSON"])
        findings = monitor.fetch_vuln_today(
            monitor.build_session(),
            url,
            os.getenv("VULN_TODAY_API_KEY"),
            datetime.now(timezone.utc) - timedelta(days=1),
            method=method,
            request_payload=payload,
            query_params=json.loads(os.environ["VULN_TODAY_QUERY_JSON"])
            if os.getenv("VULN_TODAY_QUERY_JSON")
            else None,
        )
        self.assertIsInstance(findings, list)


if __name__ == "__main__":
    unittest.main()
