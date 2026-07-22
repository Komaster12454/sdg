import json
import tempfile
import unittest
from pathlib import Path

import cve_monitor as monitor


class FakeResponse:
    def __init__(self, payload, links=None, status_code=200, headers=None):
        self._payload = payload
        self.links = links or {}
        self.status_code = status_code
        self.headers = headers or {"content-type": "application/json"}
        self.content = json.dumps(payload).encode()
        self.text = json.dumps(payload)
        self.ok = 200 <= status_code < 300

    def json(self):
        return self._payload

    def raise_for_status(self):
        if not self.ok:
            raise RuntimeError(self.status_code)


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)

    def get(self, *args, **kwargs):
        return self.responses.pop(0)


class MonitorTests(unittest.TestCase):
    def test_security_text_scoring(self):
        score, reasons = monitor.analyze_security_text(
            "security fix for authentication bypass leading to remote code execution"
        )
        self.assertGreaterEqual(score, 50)
        self.assertTrue(any("Remote code" in reason for reason in reasons))

    def test_pre_cve_ghsa_is_candidate(self):
        advisory = {
            "ghsa_id": "GHSA-2345-6789-cfgh",
            "cve_id": None,
            "summary": "Authentication bypass in example package",
            "severity": "high",
            "published_at": "2026-07-21T12:00:00Z",
            "updated_at": "2026-07-21T12:00:00Z",
            "html_url": "https://github.com/advisories/GHSA-2345-6789-cfgh",
            "vulnerabilities": [
                {
                    "package": {"ecosystem": "pip", "name": "example"},
                    "vulnerable_version_range": "< 2.0",
                    "first_patched_version": None,
                }
            ],
            "references": [],
            "cwe_ids": ["CWE-287"],
            "cvss": {"score": 8.1},
        }
        findings = monitor.fetch_ghsa(
            FakeSession([FakeResponse([advisory])]),
            monitor.parse_time("2026-07-21T00:00:00Z"),
            None,
            False,
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertTrue(finding.zero_day_candidate)
        self.assertEqual(finding.patch_status, "UNPATCHED")
        self.assertGreaterEqual(finding.zero_day_score, 70)
        finding.calculate_scores([])
        self.assertGreaterEqual(finding.confidence, 35)

    def test_vuln_today_preserves_explicit_unpatched_false(self):
        findings = monitor.normalize_vuln_today_item(
            {
                "cve_id": "CVE-2026-12345",
                "title": "Example issue",
                "patched": False,
                "score": 8.0,
            }
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].patch_status, "UNPATCHED")

    def test_cve_canonicalizes_ghsa_alias(self):
        cve = monitor.Finding(
            identifier="CVE-2026-12345",
            aliases=["GHSA-2345-6789-cfgh"],
            description="Official CVE",
            sources={"NVD"},
            source_weights=[30],
        )
        ghsa = monitor.Finding(
            identifier="GHSA-2345-6789-cfgh",
            description="Pre-CVE advisory",
            sources={"GHSA"},
            source_weights=[30],
            zero_day_candidate=True,
            zero_day_score=80,
        )
        merged = monitor.merge_findings([[ghsa], [cve]], {})
        self.assertEqual(set(merged), {"CVE-2026-12345"})
        self.assertIn("GHSA-2345-6789-cfgh", merged["CVE-2026-12345"].aliases)
        self.assertEqual(merged["CVE-2026-12345"].sources, {"NVD", "GHSA"})

    def test_state_alias_migration_lookup(self):
        state = {
            "GHSA-2345-6789-cfgh": {
                "fingerprint": "old",
                "first_seen": "2026-07-20T00:00:00+00:00",
            }
        }
        finding = monitor.Finding(
            identifier="CVE-2026-12345",
            aliases=["GHSA-2345-6789-cfgh"],
        )
        key, record = monitor.find_previous_state(state, finding)
        self.assertEqual(key, "GHSA-2345-6789-cfgh")
        self.assertEqual(record["fingerprint"], "old")

    def test_sarif_becomes_candidate(self):
        sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Example SAST", "rules": []}},
                    "results": [
                        {
                            "ruleId": "AUTH-001",
                            "level": "error",
                            "message": {"text": "Potential authentication bypass"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/auth.py"},
                                        "region": {"startLine": 42},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "result.sarif"
            path.write_text(json.dumps(sarif), encoding="utf-8")
            findings = monitor.fetch_sarif_findings(str(path))
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].zero_day_candidate)
        self.assertGreaterEqual(findings[0].zero_day_score, 65)
        self.assertIn("src/auth.py:42", findings[0].affected)



    def test_atom_feed_parser(self):
        atom = b"""<?xml version='1.0'?>
        <feed xmlns='http://www.w3.org/2005/Atom'>
          <entry>
            <title>CVE-2026-12345 published</title>
            <updated>2026-07-21T12:00:00Z</updated>
            <link href='https://example.com/advisory' rel='alternate'/>
            <content type='html'>&lt;p&gt;Security advisory&lt;/p&gt;</content>
          </entry>
        </feed>"""
        entries = monitor.parse_xml_feed(atom)
        self.assertEqual(len(entries), 1)
        self.assertIn("CVE-2026-12345", entries[0]["title"])
        self.assertEqual(entries[0]["link"], "https://example.com/advisory")

    def test_trusted_advisory_without_id_is_candidate(self):
        findings = monitor.normalize_advisory_entry(
            source_name="Example PSIRT",
            title="Security advisory: authentication bypass",
            description="Remote code execution may be possible before a patch is available.",
            link="https://example.com/security/1",
            published="2026-07-21T12:00:00Z",
            trusted=True,
        )
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        finding.calculate_scores([])
        self.assertTrue(finding.zero_day_candidate)
        self.assertGreaterEqual(finding.zero_day_score, 60)
        self.assertGreaterEqual(finding.confidence, 35)

    def test_cyclonedx_sbom_terms(self):
        sbom = {
            "bomFormat": "CycloneDX",
            "components": [
                {
                    "type": "library",
                    "group": "org.example",
                    "name": "auth-lib",
                    "version": "1.2.3",
                    "purl": "pkg:pypi/auth-lib@1.2.3",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bom.json"
            path.write_text(json.dumps(sbom), encoding="utf-8")
            terms = monitor.load_sbom_terms(str(path))
        self.assertIn("auth-lib", terms)
        self.assertIn("org.example/auth-lib", terms)

    def test_embed_is_within_discord_budget(self):
        finding = monitor.Finding(
            identifier="ZD-CAND-ABCDEF123456",
            description="x " * 1000,
            sources={"Authorized research"},
            source_weights=[25],
            zero_day_candidate=True,
            zero_day_score=90,
            candidate_reasons=["reason " * 100] * 8,
            references=["https://example.com/" + "x" * 500] * 6,
        )
        finding.calculate_scores([])
        embed = monitor.build_embed(finding)
        self.assertLessEqual(monitor.embed_char_count(embed), monitor.DISCORD_TOTAL_CHAR_LIMIT)


if __name__ == "__main__":
    unittest.main()
