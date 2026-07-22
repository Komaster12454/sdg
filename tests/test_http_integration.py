import base64
import json
import os
import threading
import unittest
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import requests

import cve_monitor as monitor
import continuous_runner as runner


@contextmanager
def local_json_server(dispatch):
    requests_seen = []

    class Handler(BaseHTTPRequestHandler):
        def _handle(self):
            parsed = urlparse(self.path)
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length) if length else b""
            try:
                json_body = json.loads(raw_body) if raw_body else None
            except json.JSONDecodeError:
                json_body = None
            record = {
                "method": self.command,
                "path": parsed.path,
                "query": parse_qs(parsed.query),
                "headers": dict(self.headers.items()),
                "json": json_body,
                "raw_body": raw_body,
            }
            requests_seen.append(record)
            status, headers, payload = dispatch(record)
            body = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", headers.pop("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(body)))
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        do_GET = _handle
        do_POST = _handle
        do_PUT = _handle

        def log_message(self, format, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"
    try:
        yield base_url, requests_seen
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def nvd_row(identifier):
    return {
        "cve": {
            "id": identifier,
            "published": "2026-07-21T12:00:00.000",
            "lastModified": "2026-07-21T12:00:00.000",
            "descriptions": [{"lang": "en", "value": f"Description for {identifier}"}],
            "metrics": {},
            "references": [],
            "weaknesses": [],
        }
    }


def ghsa_row(identifier, cve_id=None):
    return {
        "ghsa_id": identifier,
        "cve_id": cve_id,
        "summary": f"Advisory {identifier}",
        "severity": "high",
        "published_at": "2026-07-21T12:00:00Z",
        "updated_at": "2026-07-21T12:00:00Z",
        "html_url": f"https://github.com/advisories/{identifier}",
        "vulnerabilities": [],
        "references": [],
        "cwe_ids": [],
        "cvss": {"score": 8.0},
    }


class HttpIntegrationTests(unittest.TestCase):
    def test_discord_delivery_waits_for_and_validates_created_message(self):
        def dispatch(record):
            self.assertEqual(record["method"], "POST")
            self.assertEqual(record["query"], {"thread_id": ["42"], "wait": ["true"]})
            self.assertEqual(record["json"]["content"], "delivery test")
            return 200, {}, {"id": "123456789", "channel_id": "987654321"}

        with local_json_server(dispatch) as (base_url, seen), patch.object(
            monitor, "build_session", return_value=requests.Session()
        ):
            sent = monitor.send_to_discord(
                f"{base_url}/webhook?thread_id=42",
                [{"title": "test"}],
                label="UNKNOWN",
                batch_note="delivery test",
            )

        self.assertEqual(sent, 1)
        self.assertEqual(len(seen), 1)

    def test_discord_success_without_message_id_is_not_counted_as_delivery(self):
        def dispatch(record):
            return 204, {}, b""

        with local_json_server(dispatch) as (base_url, _), patch.object(
            monitor, "build_session", return_value=requests.Session()
        ):
            with self.assertRaisesRegex(RuntimeError, "without a message confirmation"):
                monitor.send_to_discord(
                    f"{base_url}/webhook",
                    [{"title": "test"}],
                    label="UNKNOWN",
                )

    def test_discord_rate_limit_retries_are_bounded(self):
        def dispatch(record):
            return 429, {}, {"retry_after": 0.01}

        with local_json_server(dispatch) as (base_url, seen), patch.object(
            monitor, "build_session", return_value=requests.Session()
        ), patch.object(monitor.time, "sleep", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "remained rate limited"):
                monitor.send_to_discord(
                    f"{base_url}/webhook",
                    [{"title": "test"}],
                    label="UNKNOWN",
                )

        self.assertEqual(len(seen), monitor.DISCORD_MAX_RETRIES + 1)

    def test_github_state_persistence_merges_after_a_concurrent_update(self):
        local_document = {
            "records": {
                "CVE-LOCAL": {
                    "first_seen": "2026-07-22T01:00:00+00:00",
                    "last_seen": "2026-07-22T03:00:00+00:00",
                    "fingerprint": "local",
                },
                "CVE-SHARED": {
                    "first_seen": "2026-07-22T01:00:00+00:00",
                    "last_seen": "2026-07-22T03:00:00+00:00",
                    "fingerprint": "local-shared",
                },
            },
            "updated": "2026-07-22T03:00:00+00:00",
        }
        first_remote = {
            "records": {
                "CVE-REMOTE": {
                    "first_seen": "2026-07-22T00:30:00+00:00",
                    "last_seen": "2026-07-22T02:00:00+00:00",
                    "fingerprint": "remote",
                }
            },
            "updated": "2026-07-22T02:00:00+00:00",
        }
        concurrent_remote = {
            "records": {
                **first_remote["records"],
                "CVE-SHARED": {
                    "first_seen": "2026-07-21T23:00:00+00:00",
                    "last_seen": "2026-07-22T04:00:00+00:00",
                    "fingerprint": "concurrent-wins",
                },
                "CVE-CONCURRENT": {
                    "first_seen": "2026-07-22T04:00:00+00:00",
                    "last_seen": "2026-07-22T04:00:00+00:00",
                    "fingerprint": "concurrent",
                },
            },
            "updated": "2026-07-22T04:00:00+00:00",
        }
        get_count = 0
        put_count = 0
        final_body = {}

        def github_content(document, sha):
            content = base64.b64encode(json.dumps(document).encode()).decode()
            return {"encoding": "base64", "content": content, "sha": sha}

        def dispatch(record):
            nonlocal get_count, put_count, final_body
            self.assertEqual(record["path"], "/repos/owner/repo/contents/state.json")
            self.assertEqual(record["headers"].get("Authorization"), "Bearer test-token")
            if record["method"] == "GET":
                get_count += 1
                self.assertEqual(record["query"], {"ref": ["main"]})
                document = first_remote if get_count == 1 else concurrent_remote
                return 200, {}, github_content(document, f"sha-{get_count}")
            put_count += 1
            if put_count == 1:
                return 409, {}, {"message": "sha changed"}
            final_body = record["json"]
            return 200, {}, {"commit": {"sha": "commit-sha"}}

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp, local_json_server(dispatch) as (base_url, seen):
            state_path = Path(tmp) / "state.json"
            state_path.write_text(json.dumps(local_document), encoding="utf-8")
            with patch.object(runner, "_github_state_path", return_value="state.json"):
                persisted = runner.persist_state_to_github(
                    str(state_path),
                    repository="owner/repo",
                    branch="main",
                    token="test-token",
                    api_url=base_url,
                    session=requests.Session(),
                )
            saved = json.loads(state_path.read_text(encoding="utf-8"))

        self.assertTrue(persisted)
        self.assertEqual([request["method"] for request in seen], ["GET", "PUT", "GET", "PUT"])
        self.assertEqual(final_body["sha"], "sha-2")
        uploaded = json.loads(base64.b64decode(final_body["content"]))
        self.assertEqual(set(uploaded["records"]), {
            "CVE-LOCAL", "CVE-REMOTE", "CVE-SHARED", "CVE-CONCURRENT"
        })
        self.assertEqual(uploaded["records"]["CVE-SHARED"]["fingerprint"], "concurrent-wins")
        self.assertEqual(uploaded["records"]["CVE-SHARED"]["first_seen"], "2026-07-21T23:00:00+00:00")
        self.assertEqual(saved, uploaded)

    def test_github_state_persistence_fetches_large_state_through_blob_api(self):
        document = {
            "records": {
                "CVE-2026-10000": {
                    "first_seen": "2026-07-22T01:00:00+00:00",
                    "last_seen": "2026-07-22T02:00:00+00:00",
                }
            },
            "updated": "2026-07-22T02:00:00+00:00",
        }
        encoded = base64.b64encode(json.dumps(document).encode()).decode()

        def dispatch(record):
            if record["method"] == "GET" and record["path"].endswith("/contents/state.json"):
                return 200, {}, {"encoding": "none", "content": "", "sha": "large-blob-sha"}
            if record["method"] == "GET" and record["path"].endswith("/git/blobs/large-blob-sha"):
                return 200, {}, {"encoding": "base64", "content": encoded, "sha": "large-blob-sha"}
            if record["method"] == "PUT":
                self.assertEqual(record["json"]["sha"], "large-blob-sha")
                return 200, {}, {"commit": {"sha": "commit-sha"}}
            return 404, {}, {"message": "not found"}

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp, local_json_server(dispatch) as (base_url, seen):
            state_path = Path(tmp) / "state.json"
            state_path.write_text(json.dumps(document), encoding="utf-8")
            with patch.object(runner, "_github_state_path", return_value="state.json"):
                runner.persist_state_to_github(
                    str(state_path),
                    repository="owner/repo",
                    branch="main",
                    token="test-token",
                    api_url=base_url,
                    session=requests.Session(),
                )

        self.assertEqual(
            [request["method"] for request in seen],
            ["GET", "GET", "PUT"],
        )

    def test_nvd_pagination_uses_real_http_query_parameters(self):
        def dispatch(record):
            self.assertEqual(record["method"], "GET")
            start = record["query"].get("startIndex", ["0"])[0]
            if start == "0":
                return 200, {}, {"totalResults": 2, "vulnerabilities": [nvd_row("CVE-2026-10001")]}
            if start == "1":
                return 200, {}, {"totalResults": 2, "vulnerabilities": [nvd_row("CVE-2026-10002")]}
            return 400, {}, {"error": f"unexpected startIndex {start}"}

        with local_json_server(dispatch) as (base_url, seen), patch.object(
            monitor, "NVD_API_URL", f"{base_url}/nvd"
        ), patch.object(monitor.time, "sleep", return_value=None):
            findings = monitor.fetch_nvd(
                monitor.build_session(),
                datetime(2026, 7, 21, tzinfo=timezone.utc),
                None,
            )

        self.assertEqual([finding.identifier for finding in findings], ["CVE-2026-10001", "CVE-2026-10002"])
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0]["query"]["startIndex"], ["0"])
        self.assertEqual(seen[1]["query"]["startIndex"], ["1"])
        self.assertIn("lastModStartDate", seen[0]["query"])

    def test_ghsa_follows_link_pagination_and_sends_authentication(self):
        base_holder = {}

        def dispatch(record):
            page = record["query"].get("page", ["1"])[0]
            if page == "1":
                return 200, {
                    "Link": f'<{base_holder["url"]}/advisories?page=2>; rel="next"'
                }, [ghsa_row("GHSA-2345-6789-cfgh")]
            return 200, {}, [ghsa_row("GHSA-3456-789c-fghj", "CVE-2026-10003")]

        with local_json_server(dispatch) as (base_url, seen):
            base_holder["url"] = base_url
            with patch.object(monitor, "GHSA_API_URL", f"{base_url}/advisories"):
                findings = monitor.fetch_ghsa(
                    monitor.build_session(),
                    datetime(2026, 7, 21, tzinfo=timezone.utc),
                    "test-token",
                    False,
                )

        self.assertEqual(len(findings), 2)
        self.assertEqual(seen[0]["query"]["type"], ["reviewed"])
        self.assertEqual(seen[1]["query"], {"page": ["2"]})
        self.assertEqual(seen[0]["headers"].get("Authorization"), "Bearer test-token")
        self.assertEqual(seen[1]["headers"].get("Authorization"), "Bearer test-token")

    def test_vuln_today_post_sends_exact_configured_payload(self):
        payload = {
            "manifest": {
                "type": "requirements.txt",
                "content": "requests==2.31.0\n",
            }
        }

        def dispatch(record):
            self.assertEqual(record["path"], "/api/v1/scan")
            return 200, {}, {
                "results": [
                    {
                        "cve_id": "CVE-2026-10004",
                        "title": "Affected dependency",
                        "patched": False,
                    }
                ]
            }

        with local_json_server(dispatch) as (base_url, seen):
            findings = monitor.fetch_vuln_today(
                monitor.build_session(),
                f"{base_url}/api/v1/scan",
                "secret-key",
                datetime(2026, 7, 21, tzinfo=timezone.utc),
                method="POST",
                request_payload=payload,
            )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].identifier, "CVE-2026-10004")
        self.assertEqual(seen[0]["method"], "POST")
        self.assertEqual(seen[0]["query"], {})
        self.assertEqual(seen[0]["json"], payload)
        self.assertEqual(seen[0]["headers"].get("Authorization"), "Bearer secret-key")
        self.assertEqual(seen[0]["headers"].get("X-API-Key"), "secret-key")

    def test_vuln_today_post_fails_closed_without_payload(self):
        with self.assertRaisesRegex(ValueError, "requires VULN_TODAY_REQUEST_JSON"):
            monitor.fetch_vuln_today(
                requests.Session(),
                "https://vuln.today/api/v1/scan",
                None,
                datetime(2026, 7, 21, tzinfo=timezone.utc),
                method="POST",
                request_payload=None,
            )

    def test_scan_url_defaults_to_post_but_requires_explicit_request_body(self):
        env = {
            "DRY_RUN": "true",
            "VULN_TODAY_ENABLED": "true",
            "VULN_TODAY_API_URL": "https://vuln.today/api/v1/scan",
            "VULN_TODAY_REQUEST_JSON": '{"packages":[{"name":"example","version":"1.0"}]}',
        }
        with patch.dict(os.environ, env, clear=True):
            config = monitor.load_config()
        self.assertEqual(config["vuln_today_api_method"], "POST")
        self.assertEqual(
            config["vuln_today_request_payload"],
            {"packages": [{"name": "example", "version": "1.0"}]},
        )


    def test_empty_method_environment_does_not_override_scan_post_default(self):
        env = {
            "DRY_RUN": "true",
            "VULN_TODAY_ENABLED": "true",
            "VULN_TODAY_API_URL": "https://vuln.today/api/v1/scan",
            "VULN_TODAY_API_METHOD": "",
            "VULN_TODAY_REQUEST_JSON": '{"packages":[{"name":"example","version":"1.0"}]}',
        }
        with patch.dict(os.environ, env, clear=True):
            config = monitor.load_config()
        self.assertEqual(config["vuln_today_api_method"], "POST")

    def test_vuln_today_toggle_defaults_disabled_and_ignores_stale_configuration(self):
        env = {
            "DRY_RUN": "true",
            "VULN_TODAY_API_URL": "https://vuln.today/api/v1/scan",
            "VULN_TODAY_REQUEST_JSON": "not-valid-json",
        }
        with patch.dict(os.environ, env, clear=True):
            config = monitor.load_config()

        self.assertFalse(config["vuln_today_enabled"])
        self.assertIsNone(config["vuln_today_api_method"])
        self.assertIsNone(config["vuln_today_request_payload"])
        self.assertIsNone(config["vuln_today_query_params"])

    def test_vuln_today_toggle_accepts_common_true_and_false_values(self):
        for value in ("1", "true", "yes", "on", "TRUE"):
            with self.subTest(value=value), patch.dict(
                os.environ,
                {
                    "DRY_RUN": "true",
                    "VULN_TODAY_ENABLED": value,
                    "VULN_TODAY_API_URL": "https://example.test/api/v1/feed",
                },
                clear=True,
            ):
                self.assertTrue(monitor.load_config()["vuln_today_enabled"])

        for value in ("0", "false", "no", "off", "", "unexpected"):
            with self.subTest(value=value), patch.dict(
                os.environ,
                {"DRY_RUN": "true", "VULN_TODAY_ENABLED": value},
                clear=True,
            ):
                self.assertFalse(monitor.load_config()["vuln_today_enabled"])

    def test_disabled_vuln_today_source_is_not_scheduled(self):
        import tempfile
        from pathlib import Path

        config = {
            "webhooks": {},
            "dry_run": True,
            "nvd_api_key": None,
            "github_token": None,
            "vuln_today_enabled": False,
            "vuln_today_api_url": "https://vuln.today/api/v1/scan",
            "vuln_today_api_method": "POST",
            "vuln_today_request_payload": None,
            "vuln_today_query_params": None,
            "lookback_minutes": 10,
            "min_cvss": 0.0,
            "min_priority": 0,
            "min_zero_day_score": 60,
            "min_zero_day_confidence": 35,
            "max_notifications": 10,
            "include_unreviewed": False,
            "notify_updates": True,
            "jsonl_output": None,
            "sarif_glob": "",
            "sbom_glob": "",
            "custom_findings_path": None,
            "watch_repositories": [],
            "watch_terms": [],
            "suppressed_identifiers": set(),
            "advisory_feeds": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            config["state_file"] = str(Path(tmp) / "state.json")
            with patch.object(monitor, "fetch_nvd", return_value=[]), \
                patch.object(monitor, "fetch_ghsa", return_value=[]), \
                patch.object(monitor, "fetch_cve_list_release_feed", return_value=[]), \
                patch.object(monitor, "fetch_github_repository_signals", return_value=[]), \
                patch.object(monitor, "fetch_cisa_kev", return_value={}), \
                patch.object(monitor, "enrich_epss"), \
                patch.object(monitor, "fetch_vuln_today") as vuln_today, \
                patch.object(monitor, "_log"):
                monitor.run_once(config)

        vuln_today.assert_not_called()

    def test_enabled_vuln_today_source_is_scheduled(self):
        import tempfile
        from pathlib import Path

        config = {
            "webhooks": {},
            "dry_run": True,
            "nvd_api_key": None,
            "github_token": None,
            "vuln_today_enabled": True,
            "vuln_today_api_url": "https://vuln.today/api/v1/feed",
            "vuln_today_api_key": None,
            "vuln_today_api_method": "GET",
            "vuln_today_request_payload": None,
            "vuln_today_query_params": {},
            "lookback_minutes": 10,
            "min_cvss": 0.0,
            "min_priority": 0,
            "min_zero_day_score": 60,
            "min_zero_day_confidence": 35,
            "max_notifications": 10,
            "include_unreviewed": False,
            "notify_updates": True,
            "jsonl_output": None,
            "sarif_glob": "",
            "sbom_glob": "",
            "custom_findings_path": None,
            "watch_repositories": [],
            "watch_terms": [],
            "suppressed_identifiers": set(),
            "advisory_feeds": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            config["state_file"] = str(Path(tmp) / "state.json")
            with patch.object(monitor, "fetch_nvd", return_value=[]), \
                patch.object(monitor, "fetch_ghsa", return_value=[]), \
                patch.object(monitor, "fetch_cve_list_release_feed", return_value=[]), \
                patch.object(monitor, "fetch_github_repository_signals", return_value=[]), \
                patch.object(monitor, "fetch_cisa_kev", return_value={}), \
                patch.object(monitor, "enrich_epss"), \
                patch.object(monitor, "fetch_vuln_today", return_value=[]) as vuln_today, \
                patch.object(monitor, "_log"):
                monitor.run_once(config)

        vuln_today.assert_called_once()

    def test_scan_endpoint_rejects_get_before_network_access(self):
        with self.assertRaisesRegex(ValueError, "/scan endpoint requires POST"):
            monitor.fetch_vuln_today(
                requests.Session(),
                "https://vuln.today/api/v1/scan",
                None,
                datetime(2026, 7, 21, tzinfo=timezone.utc),
                method="GET",
            )

    def test_vuln_today_get_uses_only_explicit_query_parameters(self):
        def dispatch(record):
            return 200, {}, {"results": []}

        with local_json_server(dispatch) as (base_url, seen):
            monitor.fetch_vuln_today(
                monitor.build_session(),
                f"{base_url}/api/v1/feed",
                None,
                datetime(2026, 7, 21, tzinfo=timezone.utc),
                method="GET",
                query_params={"cursor": "abc", "page_size": 25},
            )

        self.assertEqual(seen[0]["method"], "GET")
        self.assertEqual(seen[0]["query"], {"cursor": ["abc"], "page_size": ["25"]})
        self.assertNotIn("since", seen[0]["query"])
        self.assertNotIn("limit", seen[0]["query"])

    def test_http_errors_are_not_treated_as_empty_success(self):
        def dispatch(record):
            return 503, {}, {"error": "temporary failure"}

        with local_json_server(dispatch) as (base_url, seen):
            with self.assertRaises(requests.HTTPError):
                monitor.request_json(requests.Session(), f"{base_url}/broken")
        self.assertEqual(len(seen), 1)

    def test_unsupported_http_method_fails_before_network_access(self):
        with self.assertRaisesRegex(ValueError, "Unsupported JSON request method"):
            monitor.request_json(requests.Session(), "https://example.invalid", method="DELETE")

    def test_failed_discord_delivery_does_not_consume_notification_state(self):
        finding = monitor.Finding(
            identifier="CVE-2026-19999",
            description="Authentication bypass in example service",
            sources={"NVD"},
            source_weights=[20],
            patch_status="UNKNOWN",
        )

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "state.json"
            config = {
                "webhooks": {"UNKNOWN": "https://discord.invalid/webhook"},
                "dry_run": False,
                "nvd_api_key": None,
                "github_token": None,
                "vuln_today_enabled": False,
                "vuln_today_api_url": None,
                "lookback_minutes": 10,
                "min_cvss": 0.0,
                "min_priority": 0,
                "min_zero_day_score": 60,
                "min_zero_day_confidence": 35,
                "max_notifications": 10,
                "include_unreviewed": False,
                "notify_updates": True,
                "state_file": str(state_path),
                "jsonl_output": None,
                "sarif_glob": "",
                "sbom_glob": "",
                "custom_findings_path": None,
                "watch_repositories": [],
                "watch_terms": [],
                "suppressed_identifiers": set(),
                "advisory_feeds": [],
            }
            with patch.object(monitor, "fetch_nvd", return_value=[finding]), \
                patch.object(monitor, "fetch_ghsa", return_value=[]), \
                patch.object(monitor, "fetch_cve_list_release_feed", return_value=[]), \
                patch.object(monitor, "fetch_github_repository_signals", return_value=[]), \
                patch.object(monitor, "fetch_cisa_kev", return_value={}), \
                patch.object(monitor, "enrich_epss", return_value=None), \
                patch.object(monitor, "send_to_discord", side_effect=[RuntimeError("down"), 1]) as send, \
                patch.object(monitor, "_log"):
                self.assertEqual(monitor.run_once(config), 0)
                failed_state = json.loads(state_path.read_text(encoding="utf-8"))["records"]
                self.assertNotIn(finding.identifier, failed_state)

                self.assertEqual(monitor.run_once(config), 1)
                delivered_state = json.loads(state_path.read_text(encoding="utf-8"))["records"]

        self.assertEqual(send.call_count, 2)
        self.assertIn(finding.identifier, delivered_state)

    def test_full_dry_run_pipeline_correlates_sources_and_writes_state(self):
        cve_id = "CVE-2026-10005"

        def dispatch(record):
            if record["path"] == "/nvd":
                return 200, {}, {"totalResults": 1, "vulnerabilities": [nvd_row(cve_id)]}
            if record["path"] == "/advisories":
                advisory = ghsa_row("GHSA-4567-89cf-ghjm", cve_id)
                advisory["vulnerabilities"] = [
                    {
                        "package": {"ecosystem": "pip", "name": "example"},
                        "vulnerable_version_range": "< 2.0",
                        "first_patched_version": {"identifier": "2.0"},
                    }
                ]
                return 200, {}, [advisory]
            if record["path"] == "/releases.atom":
                return 200, {"Content-Type": "application/atom+xml"}, b"<?xml version='1.0'?><feed xmlns='http://www.w3.org/2005/Atom'></feed>"
            if record["path"] == "/search/repositories":
                return 200, {}, {"items": []}
            if record["path"] == "/kev":
                return 200, {}, {"vulnerabilities": []}
            if record["path"] == "/epss":
                return 200, {}, {
                    "data": [{"cve": cve_id, "epss": "0.91", "percentile": "0.99"}]
                }
            return 404, {}, {"error": record["path"]}

        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp, local_json_server(dispatch) as (base_url, seen), \
            patch.object(monitor, "NVD_API_URL", f"{base_url}/nvd"), \
            patch.object(monitor, "GHSA_API_URL", f"{base_url}/advisories"), \
            patch.object(monitor, "CVE_LIST_RELEASE_FEED", f"{base_url}/releases.atom"), \
            patch.object(monitor, "GITHUB_SEARCH_URL", f"{base_url}/search/repositories"), \
            patch.object(monitor, "CISA_KEV_URL", f"{base_url}/kev"), \
            patch.object(monitor, "EPSS_API_URL", f"{base_url}/epss"):
            monitor._SOURCE_CACHE.clear()
            state_path = Path(tmp) / "state.json"
            jsonl_path = Path(tmp) / "findings.jsonl"
            config = {
                "webhooks": {},
                "dry_run": True,
                "nvd_api_key": None,
                "github_token": "token",
                "vuln_today_api_url": None,
                "lookback_minutes": 90,
                "min_cvss": 0.0,
                "min_priority": 0,
                "min_zero_day_score": 60,
                "min_zero_day_confidence": 35,
                "max_notifications": 10,
                "include_unreviewed": False,
                "notify_updates": True,
                "state_file": str(state_path),
                "jsonl_output": str(jsonl_path),
                "sarif_glob": "",
                "sbom_glob": "",
                "custom_findings_path": None,
                "watch_repositories": [],
                "watch_terms": ["example"],
                "suppressed_identifiers": set(),
                "advisory_feeds": [],
            }
            with patch.object(monitor, "_log"):
                monitor.run_once(config)

            state = json.loads(state_path.read_text(encoding="utf-8"))["records"]
            exported = [json.loads(line) for line in jsonl_path.read_text(encoding="utf-8").splitlines()]

        self.assertIn(cve_id, state)
        self.assertEqual(len(exported), 1)
        self.assertEqual(exported[0]["identifier"], cve_id)
        self.assertEqual(set(exported[0]["sources"]), {"GHSA", "NVD"})
        self.assertEqual(exported[0]["patch_status"], "PATCHED")
        self.assertAlmostEqual(exported[0]["epss"], 0.91)
        self.assertTrue(any(request["path"] == "/epss" for request in seen))


if __name__ == "__main__":
    unittest.main()
