import json
import re
import tempfile
import unittest
from pathlib import Path

import cve_monitor as monitor


class MonitorBehaviorTests(unittest.TestCase):
    def test_security_scoring_separates_exploit_signal_from_documentation_noise(self):
        exploit_score, exploit_reasons = monitor.analyze_security_text(
            "Unauthenticated remote code execution caused by an authentication bypass"
        )
        noise_score, noise_reasons = monitor.analyze_security_text(
            "Security fix documentation example and README formatting cleanup"
        )

        self.assertGreater(exploit_score, noise_score)
        self.assertIn("Remote code execution signal", exploit_reasons)
        self.assertIn("Low-signal documentation/test wording", noise_reasons)
        self.assertLess(noise_score, 14)  # below the trusted-advisory candidate gate

    def test_candidate_ids_are_deterministic_and_source_scoped(self):
        first = monitor.stable_candidate_id("Vendor PSIRT", "https://vendor.test/advisory/1")
        second = monitor.stable_candidate_id("Vendor PSIRT", "https://vendor.test/advisory/1")
        different_source = monitor.stable_candidate_id("Other PSIRT", "https://vendor.test/advisory/1")
        different_advisory = monitor.stable_candidate_id("Vendor PSIRT", "https://vendor.test/advisory/2")

        self.assertEqual(first, second)
        self.assertNotEqual(first, different_source)
        self.assertNotEqual(first, different_advisory)
        self.assertRegex(first, r"^ZD-CAND-[A-F0-9]{12}$")

    def test_advisory_gate_rejects_low_signal_noise(self):
        findings = monitor.normalize_advisory_entry(
            source_name="Example PSIRT",
            title="Documentation refresh",
            description="README formatting and translation cleanup only.",
            link="https://example.test/docs/1",
            published="2026-07-21T12:00:00Z",
            trusted=True,
        )
        self.assertEqual(findings, [])

    def test_trusted_high_signal_advisory_without_identifier_becomes_candidate(self):
        findings = monitor.normalize_advisory_entry(
            source_name="Example PSIRT",
            title="Authentication bypass security advisory",
            description="Unauthenticated attackers may achieve remote code execution.",
            link="https://example.test/security/1",
            published="2026-07-21T12:00:00Z",
            trusted=True,
            extra={"patched": False, "affected": ["example-product < 2.0"]},
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertTrue(finding.zero_day_candidate)
        self.assertTrue(finding.provisional)
        self.assertEqual(finding.patch_status, "UNPATCHED")
        self.assertEqual(finding.affected, ["example-product < 2.0"])
        self.assertTrue(any("without a CVE/GHSA" in reason for reason in finding.candidate_reasons))

    def test_named_cve_is_not_mislabeled_as_zero_day_candidate(self):
        findings = monitor.normalize_advisory_entry(
            source_name="Vendor PSIRT",
            title="CVE-2026-12345 authentication bypass",
            description="Vendor advisory for the assigned CVE.",
            link="https://vendor.test/CVE-2026-12345",
            published="2026-07-21T12:00:00Z",
            trusted=True,
            extra={"patched": True, "score": 8.4},
        )

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.identifier, "CVE-2026-12345")
        self.assertFalse(finding.zero_day_candidate)
        self.assertFalse(finding.provisional)
        self.assertEqual(finding.patch_status, "PATCHED")

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

    def test_merge_is_order_independent_and_preserves_richest_evidence(self):
        cve = monitor.Finding(
            identifier="CVE-2026-12345",
            aliases=["GHSA-2345-6789-cfgh"],
            description="Official CVE List record.",
            score=7.5,
            severity="HIGH",
            published="2026-07-21T12:00:00Z",
            modified="2026-07-21T13:00:00Z",
            references=["https://cve.test/record"],
            sources={"CVE List"},
            source_weights=[35],
            patch_status="UNKNOWN",
        )
        ghsa = monitor.Finding(
            identifier="GHSA-2345-6789-cfgh",
            description="Detailed authentication bypass affecting example-lib before 2.0.",
            score=8.1,
            severity="HIGH",
            published="2026-07-20T12:00:00Z",
            modified="2026-07-22T13:00:00Z",
            cwes=["CWE-287"],
            references=["https://github.test/advisory"],
            affected=["example-lib < 2.0"],
            sources={"GHSA"},
            source_weights=[30],
            patch_status="UNPATCHED",
            zero_day_candidate=True,
            zero_day_score=80,
        )

        merged_a = monitor.merge_findings([[ghsa], [cve]], {})
        merged_b = monitor.merge_findings([[cve], [ghsa]], {})

        self.assertEqual(set(merged_a), {"CVE-2026-12345"})
        self.assertEqual(merged_a["CVE-2026-12345"].to_json(), merged_b["CVE-2026-12345"].to_json())
        result = merged_a["CVE-2026-12345"]
        self.assertEqual(result.description, ghsa.description)
        self.assertEqual(result.score, 8.1)
        self.assertEqual(result.patch_status, "UNPATCHED")
        self.assertEqual(result.published, "2026-07-20T12:00:00Z")
        self.assertEqual(result.modified, "2026-07-22T13:00:00Z")
        self.assertEqual(result.sources, {"CVE List", "GHSA"})
        self.assertCountEqual(result.references, ["https://cve.test/record", "https://github.test/advisory"])
        self.assertIn("GHSA-2345-6789-cfgh", result.aliases)
        self.assertEqual(result.affected, ["example-lib < 2.0"])

    def test_unpatched_evidence_wins_over_patched_evidence_in_either_order(self):
        unpatched_first = monitor.Finding(identifier="CVE-2026-12345", patch_status="UNPATCHED")
        patched_second = monitor.Finding(identifier="CVE-2026-12345", patch_status="PATCHED")
        unpatched_first.merge(patched_second)

        patched_first = monitor.Finding(identifier="CVE-2026-12345", patch_status="PATCHED")
        unpatched_second = monitor.Finding(identifier="CVE-2026-12345", patch_status="UNPATCHED")
        patched_first.merge(unpatched_second)

        self.assertEqual(unpatched_first.patch_status, "UNPATCHED")
        self.assertEqual(patched_first.patch_status, "UNPATCHED")

    def test_unpatched_candidate_receives_more_urgency_than_patched_candidate(self):
        patched = monitor.Finding(
            identifier="GHSA-2345-6789-cfgh",
            sources={"GHSA unreviewed"},
            source_weights=[24],
            severity="HIGH",
            patch_status="PATCHED",
            provisional=True,
            zero_day_candidate=True,
            zero_day_score=58,
        )
        unpatched = monitor.Finding(
            identifier="GHSA-3456-789c-fghj",
            sources={"GHSA unreviewed"},
            source_weights=[24],
            severity="HIGH",
            patch_status="UNPATCHED",
            provisional=True,
            zero_day_candidate=True,
            zero_day_score=58,
        )

        patched.calculate_scores()
        unpatched.calculate_scores()

        self.assertGreater(unpatched.zero_day_score, patched.zero_day_score)
        self.assertGreater(unpatched.priority, patched.priority)

    def test_state_alias_lookup_supports_ghsa_to_cve_migration(self):
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

    def test_fingerprint_is_order_stable_but_changes_for_material_risk(self):
        first = monitor.Finding(
            identifier="CVE-2026-12345",
            aliases=["GHSA-BBBB-CCCC-DDDD", "GHSA-AAAA-BBBB-CCCC"],
            sources={"NVD", "GHSA"},
            source_weights=[30, 35],
            patch_status="UNKNOWN",
        )
        second = monitor.Finding(
            identifier="CVE-2026-12345",
            aliases=["GHSA-AAAA-BBBB-CCCC", "GHSA-BBBB-CCCC-DDDD"],
            sources={"GHSA", "NVD"},
            source_weights=[35, 30],
            patch_status="UNKNOWN",
        )
        self.assertEqual(monitor.finding_fingerprint(first), monitor.finding_fingerprint(second))

        second.known_exploited = True
        self.assertNotEqual(monitor.finding_fingerprint(first), monitor.finding_fingerprint(second))

    def test_sarif_candidate_id_is_stable_and_duplicate_results_correlate(self):
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
                            "partialFingerprints": {"primary": "abc123"},
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
            first_path = Path(tmp) / "first.sarif"
            second_path = Path(tmp) / "second.sarif"
            first_path.write_text(json.dumps(sarif), encoding="utf-8")
            second_path.write_text(json.dumps(sarif), encoding="utf-8")
            first = monitor.fetch_sarif_findings(str(first_path))
            second = monitor.fetch_sarif_findings(str(second_path))

        self.assertEqual(first[0].identifier, second[0].identifier)
        merged = monitor.merge_findings([first, second], {})
        self.assertEqual(len(merged), 1)
        result = next(iter(merged.values()))
        self.assertTrue(result.zero_day_candidate)
        self.assertEqual(result.affected, ["src/auth.py:42"])

    def test_xml_parser_handles_atom_and_rss(self):
        atom = b"""<?xml version='1.0'?>
        <feed xmlns='http://www.w3.org/2005/Atom'>
          <entry>
            <title>CVE-2026-12345 published</title>
            <updated>2026-07-21T12:00:00Z</updated>
            <link href='https://example.test/advisory' rel='alternate'/>
            <content type='html'>&lt;p&gt;Security advisory&lt;/p&gt;</content>
          </entry>
        </feed>"""
        rss = b"""<?xml version='1.0'?>
        <rss version='2.0'><channel><item>
          <title>Security advisory</title>
          <pubDate>Tue, 21 Jul 2026 12:00:00 GMT</pubDate>
          <link>https://example.test/rss-advisory</link>
          <description>Authentication bypass</description>
        </item></channel></rss>"""

        atom_entries = monitor.parse_xml_feed(atom)
        rss_entries = monitor.parse_xml_feed(rss)

        self.assertEqual(atom_entries[0]["link"], "https://example.test/advisory")
        self.assertIn("CVE-2026-12345", atom_entries[0]["title"])
        self.assertEqual(rss_entries[0]["link"], "https://example.test/rss-advisory")
        self.assertIn("Authentication bypass", rss_entries[0]["summary"])

    def test_sbom_terms_support_cyclonedx_nested_components_and_spdx(self):
        cyclonedx = {
            "bomFormat": "CycloneDX",
            "components": [
                {
                    "type": "application",
                    "name": "parent-app",
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
            ],
        }
        spdx = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "openssl",
                    "externalRefs": [
                        {"referenceLocator": "pkg:generic/openssl@3.0.0"}
                    ],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "cyclonedx.json").write_text(json.dumps(cyclonedx), encoding="utf-8")
            Path(tmp, "spdx.json").write_text(json.dumps(spdx), encoding="utf-8")
            terms = monitor.load_sbom_terms(str(Path(tmp, "*.json")))

        self.assertIn("parent-app", terms)
        self.assertIn("auth-lib", terms)
        self.assertIn("org.example/auth-lib", terms)
        self.assertIn("pkg:pypi/auth-lib@1.2.3", terms)
        self.assertIn("openssl", terms)
        self.assertIn("pkg:generic/openssl@3.0.0", terms)

    def test_extract_items_handles_nested_api_envelopes_without_accepting_scalars(self):
        payload = {"data": {"results": [{"id": "one"}, "bad", {"id": "two"}]}}
        self.assertEqual(monitor._extract_items(payload), [{"id": "one"}, {"id": "two"}])
        self.assertEqual(monitor._extract_items("not-json-object"), [])

    def test_embed_obeys_discord_total_and_per_field_limits(self):
        finding = monitor.Finding(
            identifier="ZD-CAND-ABCDEF123456",
            description="x " * 5000,
            sources={f"Very-Long-Source-{index}-" + "s" * 100 for index in range(80)},
            source_weights=[25],
            zero_day_candidate=True,
            zero_day_score=90,
            candidate_reasons=["reason " * 300] * 8,
            references=["https://example.test/" + "x" * 1500] * 6,
            affected=["product-" + "a" * 1500],
            watch_matches=["watch-" + "w" * 300] * 20,
        )
        finding.calculate_scores([])
        embed = monitor.build_embed(finding)

        self.assertLessEqual(monitor.embed_char_count(embed), monitor.DISCORD_TOTAL_CHAR_LIMIT)
        self.assertLessEqual(len(embed.get("title", "")), 256)
        self.assertLessEqual(len(embed.get("description", "")), 4096)
        self.assertLessEqual(len(embed.get("fields", [])), 25)
        self.assertLessEqual(len((embed.get("footer") or {}).get("text", "")), 2048)
        for field in embed.get("fields", []):
            self.assertLessEqual(len(field.get("name", "")), 256)
            self.assertLessEqual(len(field.get("value", "")), 1024)

    def test_save_state_keeps_newest_records_by_last_seen(self):
        records = {
            "old": {"last_seen": "2026-07-01T00:00:00+00:00"},
            "middle": {"last_seen": "2026-07-10T00:00:00+00:00"},
            "new": {"last_seen": "2026-07-20T00:00:00+00:00"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            monitor.save_state(str(path), records, max_keep=2)
            saved = json.loads(path.read_text(encoding="utf-8"))["records"]

        self.assertEqual(set(saved), {"middle", "new"})


if __name__ == "__main__":
    unittest.main()
