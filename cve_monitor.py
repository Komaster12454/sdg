#!/usr/bin/env python3
"""Defensive vulnerability intelligence and pre-CVE signal monitor.

The monitor correlates public vulnerability records and passive early-warning
signals. It does not exploit targets, download exploit code, or actively probe
systems. "Zero-day" output is deliberately labelled as a *candidate* that
requires manual validation and responsible disclosure.

Sources:
  - NVD CVE API 2.0
  - GitHub Global Security Advisories (reviewed and optional unreviewed)
  - Official CVE List release feed (CVEProject/cvelistV5)
  - CISA Known Exploited Vulnerabilities
  - FIRST EPSS
  - GitHub repository metadata and configured repository commit/issue metadata
  - Configurable RSS/Atom/JSON vendor advisory feeds
  - Optional vuln.today REST API
  - Optional local SARIF and custom JSON findings from authorized testing
"""

from __future__ import annotations

import collections
import glob
import html
import hashlib
import json
import os
import re
import sys
import threading
import xml.etree.ElementTree as ET
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Callable, Iterable

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_API_URL = "https://api.github.com/advisories"
GITHUB_API_URL = "https://api.github.com"
GITHUB_SEARCH_URL = f"{GITHUB_API_URL}/search/repositories"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_API_URL = "https://api.first.org/data/v1/epss"
CVE_LIST_RELEASE_FEED = "https://github.com/CVEProject/cvelistV5/releases.atom"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
GHSA_RE = re.compile(
    r"GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}",
    re.IGNORECASE,
)
CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)

PATCH_LABELS = {
    "PATCHED": "✅ Patched",
    "UNPATCHED": "🔴 Unpatched",
    "UNKNOWN": "❓ Unknown",
}
SEVERITY_COLORS = {
    "CRITICAL": 0x992D22,
    "HIGH": 0xE74C3C,
    "MEDIUM": 0xE67E22,
    "LOW": 0xF1C40F,
    "NONE": 0x95A5A6,
    "UNKNOWN": 0x7289DA,
}
ZERO_DAY_COLOR = 0x9B59B6

DISCORD_EMBED_LIMIT = 10
DISCORD_TOTAL_CHAR_LIMIT = 5500
DISCORD_DESCRIPTION_LIMIT = 400
DISCORD_MAX_RETRIES = 3
DISCORD_SEND_DELAY = 1.0

_PRINT_LOCK = threading.Lock()
_CACHE_LOCK = threading.Lock()
_SOURCE_CACHE: dict[str, tuple[float, Any]] = {}

SECURITY_PATTERNS: tuple[tuple[re.Pattern[str], int, str], ...] = (
    (re.compile(r"\b(?:zero[ -]?day|0day)\b", re.I), 28, "Explicit zero-day wording"),
    (re.compile(r"\bremote code execution\b|\bRCE\b", re.I), 25, "Remote code execution signal"),
    (re.compile(r"\bauth(?:entication|orization)? bypass\b", re.I), 23, "Authentication/authorization bypass signal"),
    (re.compile(r"\bprivilege escalation\b|\bLPE\b", re.I), 21, "Privilege escalation signal"),
    (re.compile(r"\barbitrary (?:code|command) execution\b", re.I), 22, "Arbitrary execution signal"),
    (re.compile(r"\buse[- ]after[- ]free\b", re.I), 20, "Use-after-free signal"),
    (re.compile(r"\bmemory corruption\b|\bheap corruption\b", re.I), 19, "Memory corruption signal"),
    (re.compile(r"\bbuffer (?:overflow|overrun)\b|\bout[- ]of[- ]bounds\b", re.I), 18, "Memory safety signal"),
    (re.compile(r"\bSQL injection\b|\bSQLi\b", re.I), 17, "SQL injection signal"),
    (re.compile(r"\bserver[- ]side request forgery\b|\bSSRF\b", re.I), 16, "SSRF signal"),
    (re.compile(r"\bpath traversal\b|\bdirectory traversal\b", re.I), 15, "Path traversal signal"),
    (re.compile(r"\bdeseriali[sz]ation\b", re.I), 15, "Unsafe deserialization signal"),
    (re.compile(r"\binformation disclosure\b|\bdata exposure\b", re.I), 12, "Information disclosure signal"),
    (re.compile(r"\bsecurity (?:fix|patch|advisory|issue)\b", re.I), 16, "Explicit security-fix wording"),
    (re.compile(r"\bvulnerabilit(?:y|ies)\b", re.I), 10, "Vulnerability wording"),
    (re.compile(r"\bexploit(?:ed|ation|able)?\b", re.I), 10, "Exploit wording"),
    (re.compile(r"\bCWE-\d+\b", re.I), 8, "CWE reference"),
    (re.compile(r"\b(?:panic|crash)\b", re.I), 3, "Crash/panic signal"),
)

LOW_SIGNAL_PATTERNS = (
    re.compile(r"\b(?:docs?|documentation|readme|typo|formatting|translation)\b", re.I),
    re.compile(r"\b(?:test only|tests? cleanup|example)\b", re.I),
)


def _log(message: str, *, file: Any = sys.stdout) -> None:
    with _PRINT_LOCK:
        print(message, file=file)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def parse_time(value: Any) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        text = str(value).strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)




def parse_feed_time(value: Any) -> datetime | None:
    parsed = parse_time(value)
    if parsed is not None:
        return parsed
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(str(value))
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_xml_feed(content: bytes | str) -> list[dict[str, str]]:
    """Parse the small Atom/RSS subset needed by advisory feeds."""
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"invalid XML feed: {exc}") from exc

    def local_name(tag: str) -> str:
        return tag.rsplit("}", 1)[-1].lower()

    def text_of(element: ET.Element, names: set[str]) -> str:
        for child in element.iter():
            if local_name(child.tag) in names and child.text:
                return html.unescape("".join(child.itertext()).strip())
        return ""

    entries = [element for element in root.iter() if local_name(element.tag) in {"entry", "item"}]
    results: list[dict[str, str]] = []
    for entry in entries:
        link = ""
        for child in entry.iter():
            if local_name(child.tag) != "link":
                continue
            href = child.attrib.get("href")
            rel = child.attrib.get("rel", "alternate")
            if href and rel in {"alternate", ""}:
                link = href
                break
            if child.text and not link:
                link = child.text.strip()
        results.append(
            {
                "title": text_of(entry, {"title"}),
                "summary": text_of(entry, {"summary", "description", "content"}),
                "published": text_of(entry, {"published", "pubdate", "updated", "date"}),
                "link": link,
            }
        )
    return results

def safe_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def as_list(value: Any) -> list[Any]:
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def unique(values: Iterable[Any], limit: int | None = None) -> list[Any]:
    result: list[Any] = []
    seen: set[str] = set()
    for value in values:
        if value in (None, ""):
            continue
        key = json.dumps(value, sort_keys=True, default=str) if isinstance(value, (dict, list)) else str(value)
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
        if limit is not None and len(result) >= limit:
            break
    return result


def truncate(text: str, limit: int) -> str:
    text = str(text or "")
    if len(text) <= limit:
        return text
    shortened = text[:limit].rsplit(" ", 1)[0]
    return (shortened or text[: limit - 1]) + "…"


def severity_from_score(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def stable_candidate_id(source: str, value: str) -> str:
    digest = hashlib.sha256(f"{source}\0{value}".encode("utf-8", "replace")).hexdigest()[:12].upper()
    return f"ZD-CAND-{digest}"


def extract_identifiers(text: str) -> list[str]:
    return unique(
        [*(match.upper() for match in CVE_RE.findall(text or "")), *(match.upper() for match in GHSA_RE.findall(text or ""))]
    )


def analyze_security_text(text: str, labels: Iterable[str] = ()) -> tuple[int, list[str]]:
    text = text or ""
    score = 0
    reasons: list[str] = []
    for pattern, points, reason in SECURITY_PATTERNS:
        if pattern.search(text):
            score += points
            reasons.append(reason)
    normalized_labels = {str(label).strip().lower() for label in labels}
    if normalized_labels & {"security", "vulnerability", "cve", "critical", "high severity"}:
        score += 22
        reasons.append("Security-related label")
    if any(pattern.search(text) for pattern in LOW_SIGNAL_PATTERNS):
        score -= 12
        reasons.append("Low-signal documentation/test wording")
    return max(0, min(70, score)), unique(reasons, 8)


def parse_json_env(name: str, default: Any) -> Any:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        _log(f"WARNING: {name} is not valid JSON: {exc}", file=sys.stderr)
        return default


def build_session() -> requests.Session:
    retry = Retry(
        total=4,
        connect=4,
        read=4,
        status=4,
        backoff_factor=0.8,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET", "POST"}),
        respect_retry_after_header=True,
    )
    session = requests.Session()
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    session.headers.update(
        {
            "User-Agent": "sdg-vulnerability-intel/3.0",
            "Accept": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
    )
    return session


def request_json(
    session: requests.Session,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
) -> Any:
    response = session.get(url, params=params, headers=headers, timeout=timeout)
    response.raise_for_status()
    return response.json()


def cached_json(
    cache_key: str,
    ttl_seconds: int,
    loader: Callable[[], Any],
) -> Any:
    now = time.monotonic()
    with _CACHE_LOCK:
        cached = _SOURCE_CACHE.get(cache_key)
        if cached and now - cached[0] < ttl_seconds:
            return cached[1]
    value = loader()
    with _CACHE_LOCK:
        _SOURCE_CACHE[cache_key] = (now, value)
    return value


@dataclass
class Finding:
    identifier: str
    description: str = "No description available."
    score: float | None = None
    severity: str = "UNKNOWN"
    published: str | None = None
    modified: str | None = None
    cwes: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    source_weights: list[int] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    patch_status: str = "UNKNOWN"
    affected: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    poc_repos: list[dict[str, Any]] = field(default_factory=list)
    known_exploited: bool = False
    ransomware_use: bool = False
    public_exploit: bool = False
    epss: float | None = None
    epss_percentile: float | None = None
    provisional: bool = False
    zero_day_candidate: bool = False
    zero_day_score: int = 0
    candidate_reasons: list[str] = field(default_factory=list)
    confidence: int = 0
    priority: int = 0
    watch_matches: list[str] = field(default_factory=list)
    url: str | None = None

    def merge(self, other: "Finding") -> None:
        if other.identifier != self.identifier:
            self.aliases = unique([*self.aliases, other.identifier])
        self.aliases = unique([*self.aliases, *other.aliases], 20)
        self.sources |= other.sources
        self.source_weights = unique([*self.source_weights, *other.source_weights], 20)

        current_is_placeholder = self.description.startswith(("No description", "Preliminary", "Official CVE List"))
        other_is_placeholder = other.description.startswith(("No description", "Preliminary", "Official CVE List"))
        if current_is_placeholder and not other_is_placeholder:
            self.description = other.description
        elif len(other.description or "") > len(self.description or "") and not other_is_placeholder:
            self.description = other.description

        if self.score is None or (other.score is not None and other.score > self.score):
            self.score = other.score
            self.severity = other.severity or severity_from_score(other.score)
        if self.severity == "UNKNOWN" and other.severity != "UNKNOWN":
            self.severity = other.severity

        published_times = [(parse_time(value), value) for value in (self.published, other.published) if value]
        if published_times:
            self.published = min(published_times, key=lambda pair: pair[0] or utcnow())[1]
        modified_times = [(parse_time(value), value) for value in (self.modified, other.modified) if value]
        if modified_times:
            self.modified = max(modified_times, key=lambda pair: pair[0] or datetime.min.replace(tzinfo=timezone.utc))[1]

        self.cwes = unique([*self.cwes, *other.cwes], 16)
        self.references = unique([*self.references, *other.references], 16)
        self.affected = unique([*self.affected, *other.affected], 20)
        self.evidence = unique([*self.evidence, *other.evidence], 20)
        self.poc_repos = unique([*self.poc_repos, *other.poc_repos], 10)
        self.candidate_reasons = unique([*self.candidate_reasons, *other.candidate_reasons], 12)
        self.watch_matches = unique([*self.watch_matches, *other.watch_matches], 12)
        self.known_exploited = self.known_exploited or other.known_exploited
        self.ransomware_use = self.ransomware_use or other.ransomware_use
        self.public_exploit = self.public_exploit or other.public_exploit
        self.epss = max((value for value in (self.epss, other.epss) if value is not None), default=None)
        self.epss_percentile = max(
            (value for value in (self.epss_percentile, other.epss_percentile) if value is not None), default=None
        )
        self.zero_day_candidate = self.zero_day_candidate or other.zero_day_candidate
        self.zero_day_score = max(self.zero_day_score, other.zero_day_score)
        self.provisional = self.provisional and other.provisional
        self.url = self.url or other.url
        if other.patch_status == "PATCHED":
            self.patch_status = "PATCHED"
        elif other.patch_status == "UNPATCHED" and self.patch_status == "UNKNOWN":
            self.patch_status = "UNPATCHED"

    def calculate_scores(self, watch_terms: Iterable[str] = ()) -> None:
        searchable = " ".join(
            [self.identifier, self.description, " ".join(self.affected), " ".join(self.candidate_reasons)]
        ).lower()
        self.watch_matches = unique(
            [term for term in watch_terms if term and term.lower() in searchable],
            12,
        )

        confidence = 8 + sum(self.source_weights)
        if len(self.sources) > 1:
            confidence += min(20, (len(self.sources) - 1) * 7)
        if self.identifier.startswith("CVE-"):
            confidence += 10
        if self.provisional and len(self.sources) == 1:
            confidence -= 8
        self.confidence = max(5, min(100, confidence))

        zero_day = self.zero_day_score
        zero_day += min(15, max(0, len(self.sources) - 1) * 5)
        zero_day += 10 if self.severity in {"HIGH", "CRITICAL"} else 0
        zero_day += 8 if self.public_exploit else 0
        zero_day += 5 if self.patch_status == "UNKNOWN" else 0
        zero_day -= 12 if self.identifier.startswith("CVE-") and not self.provisional else 0
        self.zero_day_score = max(0, min(100, zero_day))

        priority = int((self.score or 0) * 4)
        priority += 38 if self.known_exploited else 0
        priority += 18 if self.public_exploit else 0
        priority += int((self.epss or 0) * 25)
        priority += 15 if self.ransomware_use else 0
        priority += 10 if self.patch_status == "UNPATCHED" else 0
        priority += min(15, len(self.poc_repos) * 5)
        priority += int(self.zero_day_score * 0.25) if self.zero_day_candidate else 0
        priority += 12 if self.watch_matches else 0
        self.priority = max(0, min(100, priority))

    def to_json(self) -> dict[str, Any]:
        return {
            "identifier": self.identifier,
            "aliases": self.aliases,
            "description": self.description,
            "score": self.score,
            "severity": self.severity,
            "published": self.published,
            "modified": self.modified,
            "cwes": self.cwes,
            "references": self.references,
            "sources": sorted(self.sources),
            "patch_status": self.patch_status,
            "affected": self.affected,
            "known_exploited": self.known_exploited,
            "ransomware_use": self.ransomware_use,
            "public_exploit": self.public_exploit,
            "epss": self.epss,
            "epss_percentile": self.epss_percentile,
            "provisional": self.provisional,
            "zero_day_candidate": self.zero_day_candidate,
            "zero_day_score": self.zero_day_score,
            "candidate_reasons": self.candidate_reasons,
            "confidence": self.confidence,
            "priority": self.priority,
            "watch_matches": self.watch_matches,
            "evidence": self.evidence,
            "poc_repos": self.poc_repos,
            "url": self.url,
        }


# ---------------------------------------------------------------------------
# Official vulnerability sources
# ---------------------------------------------------------------------------


def fetch_nvd(session: requests.Session, since: datetime, api_key: str | None) -> list[Finding]:
    params: dict[str, Any] = {
        "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": utcnow().strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    headers = {"apiKey": api_key} if api_key else None
    findings: list[Finding] = []
    while True:
        data = request_json(session, NVD_API_URL, params=params, headers=headers)
        rows = data.get("vulnerabilities", [])
        for row in rows:
            cve = row.get("cve", {})
            identifier = str(cve.get("id") or "").upper()
            if not CVE_RE.fullmatch(identifier):
                continue
            description = next(
                (entry.get("value") for entry in cve.get("descriptions", []) if entry.get("lang") == "en"),
                "No description available.",
            )
            score = None
            severity = "UNKNOWN"
            for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                entries = cve.get("metrics", {}).get(key) or []
                if entries:
                    metric = entries[0]
                    cvss = metric.get("cvssData", {})
                    score = safe_float(cvss.get("baseScore"))
                    severity = str(metric.get("baseSeverity") or cvss.get("baseSeverity") or "UNKNOWN").upper()
                    break
            references = cve.get("references", [])
            patched = any(
                "patch" in {str(tag).lower() for tag in reference.get("tags", [])}
                for reference in references
            )
            public_exploit = any(
                {"exploit", "proof of concept"} & {str(tag).lower() for tag in reference.get("tags", [])}
                for reference in references
            )
            cwes = [
                description_entry.get("value")
                for weakness in cve.get("weaknesses", [])
                for description_entry in weakness.get("description", [])
                if str(description_entry.get("value", "")).upper().startswith("CWE-")
            ]
            findings.append(
                Finding(
                    identifier=identifier,
                    description=description,
                    score=score,
                    severity=severity,
                    published=cve.get("published"),
                    modified=cve.get("lastModified"),
                    cwes=unique(cwes),
                    references=unique([reference.get("url") for reference in references], 12),
                    sources={"NVD"},
                    source_weights=[30],
                    patch_status="PATCHED" if patched else "UNKNOWN",
                    public_exploit=public_exploit,
                    url=f"https://nvd.nist.gov/vuln/detail/{identifier}",
                )
            )
        params["startIndex"] += len(rows)
        if not rows or params["startIndex"] >= data.get("totalResults", len(rows)):
            break
        time.sleep(0.6 if api_key else 1.5)
    return findings


def fetch_ghsa(
    session: requests.Session,
    since: datetime,
    token: str | None,
    include_unreviewed: bool,
) -> list[Finding]:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    findings: list[Finding] = []
    advisory_types = ["reviewed"] + (["unreviewed"] if include_unreviewed else [])

    for advisory_type in advisory_types:
        url: str | None = GHSA_API_URL
        params: dict[str, Any] | None = {
            "per_page": 100,
            "sort": "updated",
            "direction": "desc",
            "modified": f">{since.strftime('%Y-%m-%dT%H:%M:%S')}",
            "type": advisory_type,
        }
        pages = 0
        while url and pages < 10:
            response = session.get(url, params=params, headers=headers, timeout=30)
            response.raise_for_status()
            rows = response.json()
            for advisory in rows:
                if advisory.get("withdrawn_at"):
                    continue
                cve_id = str(advisory.get("cve_id") or "").upper()
                ghsa_id = str(advisory.get("ghsa_id") or "").upper()
                identifier = cve_id if CVE_RE.fullmatch(cve_id) else ghsa_id
                if not identifier:
                    continue
                packages = advisory.get("vulnerabilities") or []
                has_package = bool(packages)
                has_patch = any(vulnerability.get("first_patched_version") for vulnerability in packages)
                affected: list[str] = []
                for vulnerability in packages:
                    package = vulnerability.get("package") or {}
                    name = package.get("name")
                    ecosystem = package.get("ecosystem")
                    vulnerable_range = vulnerability.get("vulnerable_version_range")
                    if name:
                        text = f"{ecosystem or 'package'}:{name}"
                        if vulnerable_range:
                            text += f" {vulnerable_range}"
                        affected.append(text)
                references = [advisory.get("html_url")]
                references.extend(
                    reference if isinstance(reference, str) else reference.get("url")
                    for reference in advisory.get("references", []) or []
                )
                score = safe_float((advisory.get("cvss") or {}).get("score"))
                epss = advisory.get("epss") or {}
                provisional = not identifier.startswith("CVE-")
                zero_day_reasons = ["GitHub advisory published before CVE assignment"] if provisional else []
                findings.append(
                    Finding(
                        identifier=identifier,
                        aliases=unique([ghsa_id] if ghsa_id and ghsa_id != identifier else []),
                        description=advisory.get("summary")
                        or advisory.get("description")
                        or "No description available.",
                        score=score,
                        severity=str(advisory.get("severity") or severity_from_score(score)).upper(),
                        published=advisory.get("published_at"),
                        modified=advisory.get("updated_at"),
                        cwes=unique(advisory.get("cwe_ids") or []),
                        references=unique(references, 12),
                        sources={"GHSA" if advisory_type == "reviewed" else "GHSA unreviewed"},
                        source_weights=[40 if advisory_type == "reviewed" else 24],
                        patch_status=("PATCHED" if has_patch else "UNPATCHED") if has_package else "UNKNOWN",
                        affected=unique(affected, 16),
                        epss=safe_float(epss.get("percentage")),
                        epss_percentile=safe_float(epss.get("percentile")),
                        provisional=provisional,
                        zero_day_candidate=provisional,
                        zero_day_score=78 if advisory_type == "reviewed" else 58,
                        candidate_reasons=zero_day_reasons,
                        url=advisory.get("html_url"),
                    )
                )
            pages += 1
            next_url = response.links.get("next", {}).get("url")
            url = next_url
            params = None
    return findings


def fetch_cve_list_release_feed(session: requests.Session, since: datetime) -> list[Finding]:
    response = session.get(CVE_LIST_RELEASE_FEED, headers={"Accept": "application/atom+xml"}, timeout=30)
    response.raise_for_status()
    entries = parse_xml_feed(response.content)
    findings: dict[str, Finding] = {}
    for entry in entries:
        published = parse_feed_time(entry.get("published"))
        if published and published < since:
            continue
        text = f"{entry.get('title', '')} {entry.get('summary', '')}"
        link = entry.get("link")
        for identifier in {match.upper() for match in CVE_RE.findall(text)}:
            findings[identifier] = Finding(
                identifier=identifier,
                description="Official CVE List release signal; detailed enrichment may arrive from NVD or the CNA later.",
                published=(published.isoformat() if published else entry.get("published")),
                references=unique([link]),
                sources={"CVE.org"},
                source_weights=[30],
                provisional=False,
                url=f"https://www.cve.org/CVERecord?id={identifier}",
            )
    return list(findings.values())


def fetch_cisa_kev(session: requests.Session) -> dict[str, dict[str, Any]]:
    return cached_json(
        "cisa-kev",
        6 * 60 * 60,
        lambda: {
            row["cveID"].upper(): row
            for row in request_json(session, CISA_KEV_URL).get("vulnerabilities", [])
            if row.get("cveID")
        },
    )


def enrich_epss(session: requests.Session, findings: dict[str, Finding]) -> None:
    identifiers = [identifier for identifier in findings if identifier.startswith("CVE-")]
    for offset in range(0, len(identifiers), 100):
        batch = identifiers[offset : offset + 100]
        if not batch:
            continue
        cache_key = "epss:" + hashlib.sha1(",".join(sorted(batch)).encode()).hexdigest()
        data = cached_json(
            cache_key,
            12 * 60 * 60,
            lambda batch=batch: request_json(session, EPSS_API_URL, params={"cve": ",".join(batch)}),
        )
        for row in data.get("data", []):
            finding = findings.get(str(row.get("cve") or "").upper())
            if finding:
                finding.epss = safe_float(row.get("epss"))
                finding.epss_percentile = safe_float(row.get("percentile"))


# ---------------------------------------------------------------------------
# Passive early-warning and candidate sources
# ---------------------------------------------------------------------------


def github_headers(token: str | None) -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_github_repository_signals(
    session: requests.Session,
    since: datetime,
    token: str | None,
) -> list[Finding]:
    queries = [
        f"CVE in:name,description created:>={since:%Y-%m-%d}",
        f'"zero-day" in:name,description created:>={since:%Y-%m-%d}',
        f'0day in:name,description created:>={since:%Y-%m-%d}',
    ]
    findings: dict[str, Finding] = {}
    seen_repositories: set[str] = set()
    for query in queries:
        data = request_json(
            session,
            GITHUB_SEARCH_URL,
            params={"q": query, "sort": "updated", "order": "desc", "per_page": 100},
            headers=github_headers(token),
        )
        for repository in data.get("items", []):
            html_url = repository.get("html_url")
            if not html_url or html_url in seen_repositories:
                continue
            seen_repositories.add(html_url)
            created = parse_time(repository.get("created_at"))
            if created and created < since:
                continue
            text = f"{repository.get('name', '')} {repository.get('description') or ''}"
            identifiers = extract_identifiers(text)
            repo_evidence = {
                "kind": "github_repository",
                "name": repository.get("full_name"),
                "url": html_url,
                "stars": repository.get("stargazers_count", 0),
                "created_at": repository.get("created_at"),
            }
            if identifiers:
                for identifier in identifiers:
                    finding = findings.setdefault(
                        identifier,
                        Finding(
                            identifier=identifier,
                            description="Preliminary public repository metadata signal detected before or alongside official enrichment.",
                            sources={"GitHub repository signal"},
                            source_weights=[8],
                            provisional=True,
                            zero_day_candidate=not identifier.startswith("CVE-"),
                            zero_day_score=25,
                            candidate_reasons=["New public repository metadata mentions a vulnerability identifier"],
                            url=(
                                f"https://nvd.nist.gov/vuln/detail/{identifier}"
                                if identifier.startswith("CVE-")
                                else html_url
                            ),
                        ),
                    )
                    finding.poc_repos.append(repo_evidence)
                    finding.public_exploit = finding.public_exploit or bool(
                        re.search(r"\b(?:poc|proof.of.concept|exploit)\b", text, re.I)
                    )
            else:
                text_score, reasons = analyze_security_text(text)
                if text_score < 25:
                    continue
                identifier = stable_candidate_id("github-repository", html_url)
                findings[identifier] = Finding(
                    identifier=identifier,
                    description=repository.get("description") or repository.get("name") or "Public repository signal",
                    published=repository.get("created_at"),
                    references=[html_url],
                    sources={"GitHub repository signal"},
                    source_weights=[6],
                    evidence=[repo_evidence],
                    poc_repos=[repo_evidence],
                    provisional=True,
                    zero_day_candidate=True,
                    zero_day_score=min(45, 12 + text_score),
                    candidate_reasons=reasons,
                    public_exploit=bool(re.search(r"\b(?:poc|proof.of.concept|exploit)\b", text, re.I)),
                    url=html_url,
                )
    return list(findings.values())


def fetch_watched_repository_signals(
    session: requests.Session,
    since: datetime,
    token: str | None,
    repositories: Iterable[str],
) -> list[Finding]:
    findings: list[Finding] = []
    headers = github_headers(token)
    for repository in unique([repo.strip() for repo in repositories if repo.strip()], 50):
        if not re.fullmatch(r"[^/\s]+/[^/\s]+", repository):
            _log(f"WARNING: ignoring invalid ZERO_DAY_WATCH_REPOS entry: {repository}", file=sys.stderr)
            continue
        commits_url = f"{GITHUB_API_URL}/repos/{repository}/commits"
        try:
            commits = request_json(
                session,
                commits_url,
                params={"since": since.isoformat(), "per_page": 100},
                headers=headers,
            )
        except requests.RequestException as exc:
            _log(f"WARNING: watched-repo commits failed for {repository}: {exc}", file=sys.stderr)
            commits = []
        for commit in commits:
            message = str((commit.get("commit") or {}).get("message") or "").splitlines()[0]
            url = commit.get("html_url")
            identifiers = extract_identifiers(message)
            signal_score, reasons = analyze_security_text(message)
            if not identifiers and signal_score < 18:
                continue
            evidence = {
                "kind": "commit_metadata",
                "repository": repository,
                "sha": commit.get("sha"),
                "title": truncate(message, 240),
                "url": url,
            }
            target_ids = identifiers or [stable_candidate_id("github-commit", url or f"{repository}:{commit.get('sha')}")]
            for identifier in target_ids:
                candidate = not identifier.startswith("CVE-")
                findings.append(
                    Finding(
                        identifier=identifier,
                        description=f"Security-relevant commit metadata in watched repository {repository}: {message}",
                        published=(commit.get("commit") or {}).get("author", {}).get("date"),
                        modified=(commit.get("commit") or {}).get("committer", {}).get("date"),
                        references=unique([url]),
                        sources={"GitHub watched commit"},
                        source_weights=[16],
                        evidence=[evidence],
                        provisional=candidate,
                        zero_day_candidate=candidate,
                        zero_day_score=min(80, 30 + signal_score) if candidate else 20,
                        candidate_reasons=unique(["Security-relevant change in a configured watched repository", *reasons], 10),
                        url=url,
                    )
                )

        issues_url = f"{GITHUB_API_URL}/repos/{repository}/issues"
        try:
            issues = request_json(
                session,
                issues_url,
                params={"since": since.isoformat(), "state": "all", "sort": "updated", "per_page": 100},
                headers=headers,
            )
        except requests.RequestException as exc:
            _log(f"WARNING: watched-repo issues failed for {repository}: {exc}", file=sys.stderr)
            issues = []
        for issue in issues:
            if issue.get("pull_request"):
                continue
            title = str(issue.get("title") or "")
            labels = [label.get("name") for label in issue.get("labels", []) if isinstance(label, dict)]
            identifiers = extract_identifiers(title)
            signal_score, reasons = analyze_security_text(title, labels)
            if not identifiers and signal_score < 22:
                continue
            url = issue.get("html_url")
            evidence = {
                "kind": "issue_metadata",
                "repository": repository,
                "number": issue.get("number"),
                "title": truncate(title, 240),
                "labels": labels,
                "url": url,
            }
            target_ids = identifiers or [stable_candidate_id("github-issue", url or f"{repository}:{issue.get('number')}")]
            for identifier in target_ids:
                candidate = not identifier.startswith("CVE-")
                findings.append(
                    Finding(
                        identifier=identifier,
                        description=f"Security-relevant public issue metadata in watched repository {repository}: {title}",
                        published=issue.get("created_at"),
                        modified=issue.get("updated_at"),
                        references=unique([url]),
                        sources={"GitHub watched issue"},
                        source_weights=[14],
                        evidence=[evidence],
                        provisional=candidate,
                        zero_day_candidate=candidate,
                        zero_day_score=min(75, 25 + signal_score) if candidate else 18,
                        candidate_reasons=unique(["Security-relevant issue in a configured watched repository", *reasons], 10),
                        url=url,
                    )
                )
    return findings


def _extract_items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("vulnerabilities", "results", "items", "data", "cves", "advisories", "findings"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = _extract_items(value)
            if nested:
                return nested
    return [payload]


def normalize_advisory_entry(
    *,
    source_name: str,
    title: str,
    description: str,
    link: str | None,
    published: str | None,
    trusted: bool,
    extra: dict[str, Any] | None = None,
) -> list[Finding]:
    extra = extra or {}
    text = f"{title}\n{description}"
    identifiers = extract_identifiers(text + " " + str(extra))
    score = safe_float(extra.get("score") or extra.get("cvss_score"))
    severity = str(extra.get("severity") or severity_from_score(score)).upper()
    references = extra.get("references") or []
    if isinstance(references, str):
        references = [references]
    references = [reference.get("url") if isinstance(reference, dict) else reference for reference in references]
    references = unique([link, *references], 12)
    cwes = unique(CWE_RE.findall(text) + as_list(extra.get("cwes") or extra.get("cwe")), 12)
    fixed = next((extra[key] for key in ("fixed", "patched", "patch_available") if key in extra), None)
    patch_status = str(extra.get("patch_status") or "").upper()
    if patch_status not in PATCH_LABELS:
        patch_status = "PATCHED" if fixed is True else "UNPATCHED" if fixed is False else "UNKNOWN"
    public_exploit = bool(
        extra.get("public_exploit")
        or extra.get("exploit_available")
        or re.search(r"\b(?:public exploit|proof.of.concept|PoC available)\b", text, re.I)
    )
    signal_score, reasons = analyze_security_text(text)
    source_weight = 38 if trusted else 14

    if identifiers:
        results = []
        for identifier in identifiers:
            provisional = not identifier.startswith("CVE-")
            results.append(
                Finding(
                    identifier=identifier,
                    description=description or title or "No description available.",
                    score=score,
                    severity=severity,
                    published=published,
                    modified=extra.get("modified") or extra.get("updated_at"),
                    cwes=cwes,
                    references=references,
                    sources={source_name},
                    source_weights=[source_weight],
                    patch_status=patch_status,
                    affected=unique(as_list(extra.get("affected") or extra.get("products")), 16),
                    public_exploit=public_exploit,
                    provisional=provisional,
                    zero_day_candidate=provisional,
                    zero_day_score=(65 if trusted else 42) + min(15, signal_score // 3) if provisional else 12,
                    candidate_reasons=(
                        unique([f"{source_name} advisory has no CVE assignment", *reasons], 10) if provisional else reasons
                    ),
                    url=link,
                )
            )
        return results

    if signal_score < (14 if trusted else 28):
        return []
    identifier = stable_candidate_id(source_name, link or f"{title}|{published}")
    return [
        Finding(
            identifier=identifier,
            description=description or title or "Potential vulnerability advisory signal.",
            score=score,
            severity=severity,
            published=published,
            modified=extra.get("modified") or extra.get("updated_at"),
            cwes=cwes,
            references=references,
            sources={source_name},
            source_weights=[source_weight],
            patch_status=patch_status,
            affected=unique(as_list(extra.get("affected") or extra.get("products")), 16),
            public_exploit=public_exploit,
            provisional=True,
            zero_day_candidate=True,
            zero_day_score=min(90, (58 if trusted else 30) + signal_score // 2),
            candidate_reasons=unique([f"Security advisory signal without a CVE/GHSA identifier from {source_name}", *reasons], 10),
            url=link,
        )
    ]


def fetch_advisory_feeds(
    session: requests.Session,
    since: datetime,
    feed_specs: Iterable[dict[str, Any]],
) -> list[Finding]:
    findings: list[Finding] = []
    for spec in feed_specs:
        name = str(spec.get("name") or spec.get("url") or "Advisory feed")
        url = str(spec.get("url") or "")
        if not url.startswith(("https://", "http://")):
            _log(f"WARNING: ignoring invalid advisory feed URL for {name}", file=sys.stderr)
            continue
        feed_type = str(spec.get("type") or "auto").lower()
        trusted = bool(spec.get("trusted", False))
        headers = {str(key): str(value) for key, value in (spec.get("headers") or {}).items()}
        try:
            response = session.get(url, headers=headers, timeout=30)
            response.raise_for_status()
        except requests.RequestException as exc:
            _log(f"WARNING: advisory feed failed for {name}: {exc}", file=sys.stderr)
            continue

        content_type = response.headers.get("content-type", "").lower()
        is_json = feed_type == "json" or (feed_type == "auto" and "json" in content_type)
        if is_json:
            try:
                rows = _extract_items(response.json())
            except (ValueError, json.JSONDecodeError) as exc:
                _log(f"WARNING: advisory feed JSON failed for {name}: {exc}", file=sys.stderr)
                continue
            for row in rows:
                published = row.get("published") or row.get("published_at") or row.get("date")
                parsed = parse_time(published)
                if parsed and parsed < since:
                    continue
                findings.extend(
                    normalize_advisory_entry(
                        source_name=name,
                        title=str(row.get("title") or row.get("name") or row.get("id") or ""),
                        description=str(row.get("description") or row.get("summary") or ""),
                        link=row.get("url") or row.get("link"),
                        published=published,
                        trusted=trusted,
                        extra=row,
                    )
                )
            continue

        try:
            entries = parse_xml_feed(response.content)
        except ValueError as exc:
            _log(f"WARNING: advisory XML feed failed for {name}: {exc}", file=sys.stderr)
            continue
        for entry in entries:
            published = entry.get("published")
            parsed = parse_feed_time(published)
            if parsed and parsed < since:
                continue
            findings.extend(
                normalize_advisory_entry(
                    source_name=name,
                    title=str(entry.get("title") or ""),
                    description=str(entry.get("summary") or ""),
                    link=entry.get("link"),
                    published=(parsed.isoformat() if parsed else published),
                    trusted=trusted,
                )
            )
    return findings


def normalize_vuln_today_item(item: dict[str, Any]) -> list[Finding]:
    title = str(item.get("title") or item.get("name") or item.get("id") or "")
    description = str(item.get("description") or item.get("summary") or "")
    identifier_text = str(
        item.get("cve_id") or item.get("cve") or item.get("ghsa_id") or item.get("id") or ""
    )
    identifiers = extract_identifiers(identifier_text + " " + title + " " + description)
    normalized = normalize_advisory_entry(
        source_name="vuln.today",
        title=title,
        description=description,
        link=item.get("url") or item.get("link"),
        published=item.get("published") or item.get("published_at") or item.get("date"),
        trusted=True,
        extra=item,
    )
    for finding in normalized:
        if identifiers and finding.identifier not in identifiers:
            finding.aliases = unique([*finding.aliases, *identifiers])
        finding.source_weights = [36]
        finding.known_exploited = bool(item.get("known_exploited") or item.get("exploited"))
        prevalence = safe_float(item.get("prevalence") or item.get("prevalence_score"))
        priority = safe_float(item.get("priority") or item.get("priority_score"))
        if prevalence is not None and prevalence >= 0.75:
            finding.candidate_reasons = unique([*finding.candidate_reasons, "vuln.today marks affected software as widespread"])
            finding.zero_day_score = min(100, finding.zero_day_score + 5)
        if priority is not None:
            finding.priority = min(100, int(priority if priority <= 100 else priority / 2.35))
    return normalized


def fetch_vuln_today(
    session: requests.Session,
    api_url: str | None,
    api_key: str | None,
    since: datetime,
) -> list[Finding]:
    if not api_url:
        return []
    headers = {"Accept": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
        headers["X-API-Key"] = api_key
    data = request_json(
        session,
        api_url,
        params={"since": since.isoformat(), "limit": 500},
        headers=headers,
    )
    findings: list[Finding] = []
    for item in _extract_items(data):
        findings.extend(normalize_vuln_today_item(item))
    return findings


# ---------------------------------------------------------------------------
# Local authorized-research ingestion
# ---------------------------------------------------------------------------


def fetch_sarif_findings(patterns: str) -> list[Finding]:
    findings: list[Finding] = []
    paths: list[str] = []
    for pattern in [part.strip() for part in patterns.split(",") if part.strip()]:
        paths.extend(glob.glob(pattern, recursive=True))
    for path in unique(paths, 200):
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            _log(f"WARNING: SARIF read failed for {path}: {exc}", file=sys.stderr)
            continue
        for run in payload.get("runs", []):
            driver = ((run.get("tool") or {}).get("driver") or {})
            tool_name = driver.get("name") or "SARIF scanner"
            rules = {rule.get("id"): rule for rule in driver.get("rules", []) if rule.get("id")}
            for result in run.get("results", []):
                rule_id = str(result.get("ruleId") or "unknown-rule")
                message = str((result.get("message") or {}).get("text") or "Potential security finding")
                locations: list[str] = []
                for location in result.get("locations", []):
                    physical = location.get("physicalLocation") or {}
                    uri = ((physical.get("artifactLocation") or {}).get("uri"))
                    region = physical.get("region") or {}
                    if uri:
                        suffix = f":{region.get('startLine')}" if region.get("startLine") else ""
                        locations.append(f"{uri}{suffix}")
                fingerprint_values = list((result.get("partialFingerprints") or {}).values())
                seed = "|".join([tool_name, rule_id, *locations, *map(str, fingerprint_values), message])
                identifier = stable_candidate_id("sarif", seed)
                level = str(result.get("level") or "warning").lower()
                base_score = {"error": 65, "warning": 52, "note": 35, "none": 30}.get(level, 45)
                signal_score, reasons = analyze_security_text(
                    " ".join([rule_id, message, json.dumps(rules.get(rule_id, {}), default=str)])
                )
                findings.append(
                    Finding(
                        identifier=identifier,
                        aliases=extract_identifiers(message),
                        description=message,
                        severity={"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}.get(level, "UNKNOWN"),
                        published=datetime.fromtimestamp(Path(path).stat().st_mtime, tz=timezone.utc).isoformat(),
                        references=[],
                        sources={f"SARIF:{tool_name}"},
                        source_weights=[38],
                        affected=unique(locations, 12),
                        evidence=[
                            {
                                "kind": "sarif",
                                "file": path,
                                "tool": tool_name,
                                "rule_id": rule_id,
                                "locations": locations,
                            }
                        ],
                        provisional=True,
                        zero_day_candidate=True,
                        zero_day_score=min(95, base_score + signal_score // 3),
                        candidate_reasons=unique(
                            ["Candidate imported from an authorized scanner SARIF result", *reasons], 10
                        ),
                    )
                )
    return findings




def load_sbom_terms(patterns: str) -> list[str]:
    """Extract package/product terms from CycloneDX or SPDX JSON SBOM files."""
    paths: list[str] = []
    for pattern in [part.strip() for part in patterns.split(",") if part.strip()]:
        paths.extend(glob.glob(pattern, recursive=True))
    terms: list[str] = []

    def walk_components(components: Iterable[dict[str, Any]]) -> None:
        for component in components:
            if not isinstance(component, dict):
                continue
            name = component.get("name")
            group = component.get("group")
            purl = component.get("purl")
            if name:
                terms.append(str(name))
            if group and name:
                terms.append(f"{group}/{name}")
            if purl:
                # Retain the full purl and the package name portion for matching.
                terms.append(str(purl))
                purl_name = str(purl).split("@", 1)[0].rsplit("/", 1)[-1]
                if purl_name:
                    terms.append(purl_name)
            walk_components(component.get("components") or [])

    for path in unique(paths, 100):
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            _log(f"WARNING: SBOM read failed for {path}: {exc}", file=sys.stderr)
            continue
        walk_components(payload.get("components") or [])
        for package in payload.get("packages") or []:
            if not isinstance(package, dict):
                continue
            name = package.get("name") or package.get("PackageName")
            if name:
                terms.append(str(name))
            for reference in package.get("externalRefs") or package.get("ExternalRefs") or []:
                if not isinstance(reference, dict):
                    continue
                locator = reference.get("referenceLocator") or reference.get("ReferenceLocator")
                if locator:
                    terms.append(str(locator))
    return unique([term.strip() for term in terms if len(term.strip()) >= 2], 5000)

def fetch_custom_findings(path: str | None) -> list[Finding]:
    if not path:
        return []
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        _log(f"WARNING: custom findings read failed for {path}: {exc}", file=sys.stderr)
        return []
    findings: list[Finding] = []
    for row in _extract_items(payload):
        title = str(row.get("title") or row.get("name") or row.get("id") or "Authorized research finding")
        description = str(row.get("description") or row.get("summary") or title)
        source = str(row.get("source") or "Authorized research")
        normalized = normalize_advisory_entry(
            source_name=source,
            title=title,
            description=description,
            link=row.get("url") or row.get("link"),
            published=row.get("published") or row.get("date"),
            trusted=True,
            extra=row,
        )
        for finding in normalized:
            finding.source_weights = [38]
            finding.zero_day_candidate = bool(row.get("zero_day_candidate", True))
            finding.zero_day_score = max(finding.zero_day_score, safe_int(row.get("zero_day_score"), 60))
            finding.candidate_reasons = unique(
                ["Candidate imported from an authorized research finding", *finding.candidate_reasons], 10
            )
        findings.extend(normalized)
    return findings


# ---------------------------------------------------------------------------
# Correlation, state, notifications
# ---------------------------------------------------------------------------


def merge_findings(groups: Iterable[Iterable[Finding]], kev: dict[str, dict[str, Any]]) -> dict[str, Finding]:
    all_findings = [finding for group in groups for finding in group]
    all_findings.sort(key=lambda finding: (0 if finding.identifier.startswith("CVE-") else 1, finding.identifier))

    merged: dict[str, Finding] = {}
    alias_to_key: dict[str, str] = {}
    for finding in all_findings:
        identifiers = unique([finding.identifier, *finding.aliases])
        existing_key = next((alias_to_key[value] for value in identifiers if value in alias_to_key), None)
        if existing_key:
            merged[existing_key].merge(finding)
            target = merged[existing_key]
        else:
            merged[finding.identifier] = finding
            existing_key = finding.identifier
            target = finding
        for value in unique([target.identifier, *target.aliases, *identifiers]):
            alias_to_key[value] = existing_key

    for identifier, finding in merged.items():
        kev_row = kev.get(identifier)
        if kev_row:
            finding.sources.add("CISA KEV")
            finding.source_weights = unique([*finding.source_weights, 35])
            finding.known_exploited = True
            finding.ransomware_use = str(kev_row.get("knownRansomwareCampaignUse", "")).lower() == "known"
            finding.references = unique(
                [*finding.references, "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"], 16
            )
            action = kev_row.get("requiredAction")
            if action:
                finding.candidate_reasons = unique([*finding.candidate_reasons, f"CISA action: {action}"], 12)
    return merged


def finding_fingerprint(finding: Finding) -> str:
    payload = {
        "aliases": sorted(finding.aliases),
        "patch": finding.patch_status,
        "score": finding.score,
        "severity": finding.severity,
        "kev": finding.known_exploited,
        "exploit": finding.public_exploit,
        "epss": round(finding.epss or 0, 4),
        "sources": sorted(finding.sources),
        "poc": len(finding.poc_repos),
        "zero_day_score": finding.zero_day_score,
        "watch": sorted(finding.watch_matches),
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:20]


def load_state(path: str) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        records = payload.get("records", {})
        if isinstance(records, dict):
            return records
        return {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(path: str, records: dict[str, Any], max_keep: int = 12000) -> None:
    ordered = sorted(records.items(), key=lambda pair: pair[1].get("last_seen", ""))[-max_keep:]
    Path(path).write_text(
        json.dumps({"records": dict(ordered), "updated": utcnow().isoformat()}, indent=2),
        encoding="utf-8",
    )


def find_previous_state(state: dict[str, Any], finding: Finding) -> tuple[str | None, dict[str, Any] | None]:
    for key in unique([finding.identifier, *finding.aliases]):
        if key in state:
            return key, state[key]
    return None, None


def embed_char_count(embed: dict[str, Any]) -> int:
    total = len(embed.get("title") or "") + len(embed.get("description") or "")
    total += len((embed.get("footer") or {}).get("text") or "")
    for field_value in embed.get("fields") or []:
        total += len(field_value.get("name") or "") + len(field_value.get("value") or "")
    return total


def build_embed(
    finding: Finding,
    *,
    update: bool = False,
    identifier_assigned: bool = False,
) -> dict[str, Any]:
    if identifier_assigned:
        prefix = "🆔 IDENTIFIER ASSIGNED — "
    elif update:
        prefix = "🔄 UPDATED — "
    elif finding.zero_day_candidate:
        prefix = "🕵️ ZERO-DAY CANDIDATE — "
    else:
        prefix = ""

    exploit_text = "CISA KEV" if finding.known_exploited else "No confirmed KEV listing"
    if finding.public_exploit:
        exploit_text += " · public exploit signal"
    if finding.ransomware_use:
        exploit_text += " · ransomware campaigns"
    epss = (
        f"{finding.epss:.1%} (percentile {finding.epss_percentile:.1%})"
        if finding.epss is not None and finding.epss_percentile is not None
        else "Unavailable"
    )
    evidence_lines = []
    for evidence in finding.evidence[:4]:
        label = evidence.get("title") or evidence.get("name") or evidence.get("kind") or "Evidence"
        url = evidence.get("url")
        evidence_lines.append(f"- [{truncate(label, 100)}]({url})" if url else f"- {truncate(label, 120)}")
    evidence_text = "\n".join(evidence_lines) or "No additional evidence metadata"
    repository_lines = [
        f"- [{repository.get('name')}]({repository.get('url')}) (★{repository.get('stars', 0)})"
        for repository in finding.poc_repos[:3]
        if repository.get("url")
    ]
    repository_text = "\n".join(repository_lines) or "None detected"
    references = "\n".join(f"- {reference}" for reference in finding.references[:3]) or "None listed"
    candidate_reasons = "\n".join(f"- {reason}" for reason in finding.candidate_reasons[:5]) or "N/A"
    aliases = ", ".join(finding.aliases[:5]) or "None"

    fields = [
        {"name": "Patch", "value": PATCH_LABELS.get(finding.patch_status, PATCH_LABELS["UNKNOWN"]), "inline": True},
        {
            "name": "CVSS",
            "value": f"{finding.score if finding.score is not None else 'N/A'} ({finding.severity})",
            "inline": True,
        },
        {"name": "Priority", "value": f"{finding.priority}/100", "inline": True},
        {"name": "Confidence", "value": f"{finding.confidence}/100", "inline": True},
        {"name": "EPSS", "value": epss, "inline": True},
        {"name": "Exploitation", "value": exploit_text, "inline": True},
    ]
    if finding.zero_day_candidate:
        fields.extend(
            [
                {"name": "Candidate Score", "value": f"{finding.zero_day_score}/100", "inline": True},
                {"name": "Candidate Evidence", "value": truncate(candidate_reasons, 700), "inline": False},
            ]
        )
    fields.extend(
        [
            {"name": "Aliases", "value": truncate(aliases, 500), "inline": False},
            {"name": "Affected", "value": truncate(", ".join(finding.affected) or "Unknown", 600), "inline": False},
            {"name": "Evidence Metadata", "value": truncate(evidence_text, 700), "inline": False},
            {"name": "Public Repository Signals", "value": truncate(repository_text, 700), "inline": False},
            {"name": "References", "value": truncate(references, 700), "inline": False},
        ]
    )
    if finding.watch_matches:
        fields.append({"name": "Watchlist Matches", "value": ", ".join(finding.watch_matches), "inline": False})

    embed = {
        "title": f"{prefix}{finding.identifier}",
        "description": truncate(finding.description, DISCORD_DESCRIPTION_LIMIT),
        "color": ZERO_DAY_COLOR
        if finding.zero_day_candidate
        else SEVERITY_COLORS.get(finding.severity, SEVERITY_COLORS["UNKNOWN"]),
        "fields": fields,
        "footer": {
            "text": "Sources: "
            + ", ".join(sorted(finding.sources))
            + (" · candidate requires validation" if finding.zero_day_candidate else "")
        },
    }
    embed_url = finding.url or (
        f"https://nvd.nist.gov/vuln/detail/{finding.identifier}"
        if finding.identifier.startswith("CVE-")
        else None
    )
    if embed_url:
        embed["url"] = embed_url
    while embed_char_count(embed) > DISCORD_TOTAL_CHAR_LIMIT and len(embed["fields"]) > 6:
        embed["fields"].pop(-2)
    if embed_char_count(embed) > DISCORD_TOTAL_CHAR_LIMIT:
        embed["description"] = truncate(embed.get("description", ""), 160)
    return embed


def chunk_embeds(embeds: list[dict[str, Any]]) -> Iterable[list[dict[str, Any]]]:
    batch: list[dict[str, Any]] = []
    chars = 0
    for embed in embeds:
        size = embed_char_count(embed)
        if batch and (len(batch) >= DISCORD_EMBED_LIMIT or chars + size > DISCORD_TOTAL_CHAR_LIMIT):
            yield batch
            batch = []
            chars = 0
        batch.append(embed)
        chars += size
    if batch:
        yield batch


def send_to_discord(
    webhook_url: str,
    embeds: list[dict[str, Any]],
    *,
    label: str,
    batch_note: str | None = None,
) -> int:
    if not embeds:
        return 0
    session = build_session()
    queue = collections.deque(
        {"embeds": batch, "attempt": 0, "note": batch_note if index == 0 else None}
        for index, batch in enumerate(chunk_embeds(embeds))
    )
    sent = 0
    while queue:
        item = queue.popleft()
        payload: dict[str, Any] = {"embeds": item["embeds"]}
        if item["note"]:
            payload["content"] = item["note"]
        try:
            response = session.post(webhook_url, json=payload, timeout=20)
        except requests.RequestException as exc:
            item["attempt"] += 1
            if item["attempt"] <= DISCORD_MAX_RETRIES:
                time.sleep(2 ** item["attempt"])
                queue.appendleft(item)
            else:
                _log(f"[{label}] ERROR: Discord request failed permanently: {exc}", file=sys.stderr)
            continue
        if response.status_code == 429:
            try:
                retry_after = float(response.json().get("retry_after", 2))
            except (ValueError, TypeError):
                retry_after = 2.0
            time.sleep(retry_after + 0.25)
            queue.appendleft(item)
            continue
        if not response.ok:
            item["attempt"] += 1
            if response.status_code >= 500 and item["attempt"] <= DISCORD_MAX_RETRIES:
                time.sleep(2 ** item["attempt"])
                queue.appendleft(item)
            else:
                _log(
                    f"[{label}] ERROR: Discord returned {response.status_code}: {response.text[:300]}",
                    file=sys.stderr,
                )
            continue
        sent += 1
        if queue:
            time.sleep(DISCORD_SEND_DELAY)
    return sent


def export_jsonl(path: str | None, findings: Iterable[Finding]) -> None:
    if not path:
        return
    with Path(path).open("w", encoding="utf-8") as handle:
        for finding in findings:
            handle.write(json.dumps(finding.to_json(), sort_keys=True) + "\n")


def load_config() -> dict[str, Any]:
    fallback = os.getenv("DISCORD_WEBHOOK_URL")
    webhooks = {
        "PATCHED": os.getenv("DISCORD_WEBHOOK_PATCHED_URL") or fallback,
        "UNPATCHED": os.getenv("DISCORD_WEBHOOK_UNPATCHED_URL") or fallback,
        "UNKNOWN": os.getenv("DISCORD_WEBHOOK_UNKNOWN_URL") or fallback,
        "ZERO_DAY": os.getenv("DISCORD_WEBHOOK_ZERO_DAY_URL") or os.getenv("DISCORD_WEBHOOK_UNKNOWN_URL") or fallback,
    }
    dry_run = env_bool("DRY_RUN", False)
    if not dry_run and not any(webhooks.values()):
        raise RuntimeError("No Discord webhook configured. Set DISCORD_WEBHOOK_URL or a category webhook.")

    watch_repositories = [
        value.strip() for value in os.getenv("ZERO_DAY_WATCH_REPOS", "").split(",") if value.strip()
    ]
    watch_terms = [value.strip() for value in os.getenv("WATCH_TERMS", "").split(",") if value.strip()]
    advisory_feeds = parse_json_env("ADVISORY_FEEDS_JSON", [])
    if not isinstance(advisory_feeds, list):
        advisory_feeds = []

    return {
        "webhooks": webhooks,
        "dry_run": dry_run,
        "nvd_api_key": os.getenv("NVD_API_KEY"),
        "github_token": os.getenv("GITHUB_TOKEN"),
        "vuln_today_api_url": os.getenv("VULN_TODAY_API_URL"),
        "vuln_today_api_key": os.getenv("VULN_TODAY_API_KEY"),
        "lookback_minutes": safe_int(os.getenv("LOOKBACK_MINUTES"), 90),
        "min_cvss": safe_float(os.getenv("MIN_CVSS")) or 0.0,
        "min_priority": safe_int(os.getenv("MIN_PRIORITY"), 0),
        "min_zero_day_score": safe_int(os.getenv("MIN_ZERO_DAY_SCORE"), 60),
        "min_zero_day_confidence": safe_int(os.getenv("MIN_ZERO_DAY_CONFIDENCE"), 35),
        "max_notifications": safe_int(os.getenv("MAX_NOTIFICATIONS_PER_RUN"), 60),
        "include_unreviewed": env_bool("GHSA_INCLUDE_UNREVIEWED", True),
        "notify_updates": env_bool("NOTIFY_UPDATES", True),
        "state_file": os.getenv("STATE_FILE", "state.json"),
        "jsonl_output": os.getenv("FINDINGS_JSONL"),
        "sarif_glob": os.getenv("SARIF_INPUT_GLOB", ""),
        "sbom_glob": os.getenv("SBOM_INPUT_GLOB", ""),
        "custom_findings_path": os.getenv("CUSTOM_FINDINGS_JSON"),
        "watch_repositories": watch_repositories,
        "watch_terms": watch_terms,
        "suppressed_identifiers": {
            value.strip().upper()
            for value in os.getenv("SUPPRESS_IDENTIFIERS", "").split(",")
            if value.strip()
        },
        "advisory_feeds": advisory_feeds,
    }


def run_once(config: dict[str, Any]) -> int:
    lookback_minutes = max(1, safe_int(config.get("lookback_minutes"), 90))
    since = utcnow() - timedelta(minutes=lookback_minutes)
    _log(f"Scanning passive vulnerability intelligence from the last {lookback_minutes} minute(s)...")

    source_jobs: list[tuple[str, Callable[[], list[Finding]]]] = [
        (
            "NVD",
            lambda: fetch_nvd(build_session(), since, config.get("nvd_api_key")),
        ),
        (
            "GHSA",
            lambda: fetch_ghsa(
                build_session(),
                since,
                config.get("github_token"),
                bool(config.get("include_unreviewed", True)),
            ),
        ),
        (
            "CVE.org release feed",
            lambda: fetch_cve_list_release_feed(build_session(), since),
        ),
        (
            "GitHub repository signals",
            lambda: fetch_github_repository_signals(build_session(), since, config.get("github_token")),
        ),
    ]
    if config.get("watch_repositories"):
        source_jobs.append(
            (
                "GitHub watched repositories",
                lambda: fetch_watched_repository_signals(
                    build_session(),
                    since,
                    config.get("github_token"),
                    config.get("watch_repositories", []),
                ),
            )
        )
    if config.get("advisory_feeds"):
        source_jobs.append(
            (
                "Advisory feeds",
                lambda: fetch_advisory_feeds(
                    build_session(), since, config.get("advisory_feeds", [])
                ),
            )
        )
    if config.get("vuln_today_api_url"):
        source_jobs.append(
            (
                "vuln.today",
                lambda: fetch_vuln_today(
                    build_session(),
                    config.get("vuln_today_api_url"),
                    config.get("vuln_today_api_key"),
                    since,
                ),
            )
        )

    groups: list[list[Finding]] = []
    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=min(8, len(source_jobs))) as executor:
        future_to_name = {executor.submit(callback): name for name, callback in source_jobs}
        for future in as_completed(future_to_name):
            name = future_to_name[future]
            try:
                result = future.result()
                groups.append(result)
                _log(f"{name}: {len(result)} signal(s)")
            except Exception as exc:  # noqa: BLE001 - one source must not kill the cycle
                errors.append(f"{name}: {exc}")

    if config.get("sarif_glob"):
        sarif_findings = fetch_sarif_findings(config["sarif_glob"])
        groups.append(sarif_findings)
        _log(f"SARIF: {len(sarif_findings)} candidate(s)")
    if config.get("custom_findings_path"):
        custom_findings = fetch_custom_findings(config["custom_findings_path"])
        groups.append(custom_findings)
        _log(f"Custom findings: {len(custom_findings)} candidate(s)")

    try:
        kev = fetch_cisa_kev(build_session())
    except requests.RequestException as exc:
        kev = {}
        errors.append(f"CISA KEV: {exc}")

    merged = merge_findings(groups, kev)
    try:
        enrich_epss(build_session(), merged)
    except requests.RequestException as exc:
        errors.append(f"EPSS: {exc}")

    watch_terms = list(config.get("watch_terms", []))
    if config.get("sbom_glob"):
        sbom_terms = load_sbom_terms(config["sbom_glob"])
        watch_terms = unique([*watch_terms, *sbom_terms], 5000)
        _log(f"SBOM relevance terms: {len(sbom_terms)}")

    for finding in merged.values():
        finding.calculate_scores(watch_terms)

    export_jsonl(
        config.get("jsonl_output"),
        sorted(merged.values(), key=lambda finding: finding.priority, reverse=True),
    )

    state_file = str(config.get("state_file") or "state.json")
    state = load_state(state_file)
    now = utcnow().isoformat()
    buckets: dict[str, list[dict[str, Any]]] = {
        "PATCHED": [],
        "UNPATCHED": [],
        "UNKNOWN": [],
        "ZERO_DAY": [],
    }
    max_notifications = max(1, safe_int(config.get("max_notifications"), 60))
    notification_count = 0

    ordered_findings = sorted(
        merged.values(),
        key=lambda finding: (
            finding.zero_day_candidate and finding.zero_day_score >= config.get("min_zero_day_score", 60),
            finding.priority,
            finding.confidence,
        ),
        reverse=True,
    )
    for finding in ordered_findings:
        if finding.identifier.upper() in config.get("suppressed_identifiers", set()):
            continue
        if finding.score is not None and finding.score < config.get("min_cvss", 0):
            continue
        candidate_alert = (
            finding.zero_day_candidate
            and finding.zero_day_score >= config.get("min_zero_day_score", 60)
            and finding.confidence >= config.get("min_zero_day_confidence", 35)
        )
        if not candidate_alert and finding.priority < config.get("min_priority", 0):
            continue

        fingerprint = finding_fingerprint(finding)
        previous_key, previous = find_previous_state(state, finding)
        identifier_assigned = bool(
            previous_key
            and previous_key != finding.identifier
            and finding.identifier.startswith("CVE-")
        )
        changed = bool(previous and previous.get("fingerprint") != fingerprint)
        should_notify = previous is None or identifier_assigned or (changed and config.get("notify_updates", True))

        if should_notify and notification_count < max_notifications:
            bucket = "ZERO_DAY" if candidate_alert else finding.patch_status
            buckets[bucket].append(
                build_embed(
                    finding,
                    update=changed and not identifier_assigned,
                    identifier_assigned=identifier_assigned,
                )
            )
            notification_count += 1

        if previous_key and previous_key != finding.identifier:
            del state[previous_key]
        state[finding.identifier] = {
            "fingerprint": fingerprint,
            "first_seen": previous.get("first_seen", now) if previous else now,
            "last_seen": now,
            "patch_status": finding.patch_status,
            "priority": finding.priority,
            "zero_day_score": finding.zero_day_score,
            "aliases": finding.aliases,
            "candidate": finding.zero_day_candidate,
        }

    # Retain unresolved candidates for 30 days and ordinary records for state dedupe.
    candidate_cutoff = utcnow() - timedelta(days=30)
    for identifier, entry in list(state.items()):
        if not entry.get("candidate"):
            continue
        last_seen = parse_time(entry.get("last_seen"))
        if last_seen and last_seen < candidate_cutoff:
            del state[identifier]

    total_sent = 0
    if config.get("dry_run"):
        for bucket, embeds in buckets.items():
            for embed in embeds:
                _log(json.dumps({"bucket": bucket, "embed": embed}, default=str))
    else:
        jobs = []
        for bucket, embeds in buckets.items():
            if not embeds:
                continue
            webhook = config.get("webhooks", {}).get(bucket)
            if not webhook:
                errors.append(f"No webhook configured for {bucket}; skipped {len(embeds)} notification(s)")
                continue
            note = (
                f"🕵️ **Zero-day candidates requiring validation** — {len(embeds)} signal(s)"
                if bucket == "ZERO_DAY"
                else f"🔔 **{PATCH_LABELS[bucket]}** — {len(embeds)} notification(s)"
            )
            jobs.append((bucket, webhook, embeds, note))
        if jobs:
            with ThreadPoolExecutor(max_workers=len(jobs)) as executor:
                futures = {
                    executor.submit(
                        send_to_discord,
                        webhook,
                        embeds,
                        label=bucket,
                        batch_note=note,
                    ): bucket
                    for bucket, webhook, embeds, note in jobs
                }
                for future in as_completed(futures):
                    bucket = futures[future]
                    try:
                        total_sent += future.result()
                    except Exception as exc:  # noqa: BLE001
                        errors.append(f"Discord {bucket}: {exc}")

    save_state(state_file, state)
    candidate_count = sum(1 for finding in merged.values() if finding.zero_day_candidate)
    _log(
        f"findings={len(merged)} candidates={candidate_count} "
        f"notifications={notification_count} messages={total_sent}"
    )
    for error in errors:
        _log(f"WARNING: {error}", file=sys.stderr)
    return total_sent


def main() -> int:
    try:
        config = load_config()
        run_once(config)
    except (RuntimeError, ValueError) as exc:
        _log(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
