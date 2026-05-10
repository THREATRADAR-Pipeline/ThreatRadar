#!/usr/bin/env python3
"""
Cortex Scorer: query Cortex for intelligence on IOCs and produce risk scores.
© 2026 THREATRADAR Team
"""
from __future__ import annotations

import argparse
import os
import sys
sys.path.insert(0, "/vx")
from common import TARGET_INDICES
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed
from elasticsearch import Elasticsearch, helpers


import threading
_CACHE: dict[tuple[str, str], dict | None] = {}
_CACHE_LOCK = threading.Lock()

def _cache_get(ioc_value: str, analyzer: str) -> tuple[bool, dict | None]:
    key = (ioc_value, analyzer)
    with _CACHE_LOCK:
        if key in _CACHE:
            return True, _CACHE[key]
    return False, None

def _cache_set(ioc_value: str, analyzer: str, report: dict | None) -> None:
    with _CACHE_LOCK:
        _CACHE[(ioc_value, analyzer)] = report

def cache_stats() -> str:
    with _CACHE_LOCK:
        return f"cache={len(_CACHE)} entries"


_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip())


ELASTIC_HOST     = os.environ.get("ELASTIC_HOST",     "http://elasticsearch:9200")
ELASTIC_USER     = os.environ.get("ELASTIC_USER",     "elastic")
ELASTIC_PASSWORD = os.environ.get("ELASTIC_PASSWORD", "")
CORTEX_URL       = os.environ.get("CORTEX_URL",       "http://cortex:9001")
CORTEX_API_KEY   = os.environ.get("CORTEX_API_KEY",   "")

POLL_INTERVAL    = int(os.environ.get("SCORER_POLL_INTERVAL", "60"))
BATCH_SIZE       = int(os.environ.get("SCORER_BATCH_SIZE",    "50"))
IOC_WORKERS      = int(os.environ.get("SCORER_IOC_WORKERS",   "10"))
SCROLL_TIMEOUT   = "5m"

JOB_POLL_INTERVAL = float(os.environ.get("CORTEX_JOB_POLL",    "3.0"))
JOB_MAX_WAIT      = int(os.environ.get("CORTEX_JOB_MAX_WAIT",  "120"))

ANALYZER_IDS: dict[str, str] = {
    "VirusTotal":     "4e0c593591c2d943509e6e3ccb359d23",
    "AbuseIPDB":      "316d8e2f7e446ecae6cbb3e77280584f",
    "Maltiverse":     "1f79ad8a0af87006bb6f094a27a87561",
    "IPinfo":         "050365fe333a9c7c5fb0a1928bb8f25b",
    "Urlscan":        "3eaf513a6e1abf7bf21fe1fae5bbd503",
    "HybridAnalysis": "ffc2eaee2d7c9a507e42752e81593103",
}

ANALYZERS_BY_TYPE: dict[str, list[str]] = {
    "ip":         ["VirusTotal", "AbuseIPDB", "Maltiverse", "IPinfo"],
    "url":        ["VirusTotal", "Urlscan", "Maltiverse", "HybridAnalysis"],
    "hash":       ["VirusTotal", "Maltiverse", "Urlscan"],
    "domain":     ["VirusTotal", "Maltiverse", "HybridAnalysis", "Urlscan"],
    "cve":        [],
    "ransomware": [],
    "wallet":     [],
}

THRESHOLDS = [
    (75, "CRITICAL", "auto_block"),
    (50, "HIGH",     "alert_soc"),
    (25, "MEDIUM",   "watchlist"),
    (5,  "LOW",      "log_review"),
    (0,  "UNKNOWN",  "manual_triage"),
]

NO_AUTO_BLOCK_TYPES = {"ransomware", "wallet","cve"}


from dataclasses import dataclass as _dc, field as _field
from collections import defaultdict as _defaultdict

@_dc
class PassStats:
    pass_num:    int  = 0
    total_polled: int = 0
    scored:      int  = 0
    skipped:     int  = 0
    failed:      int  = 0
    by_type:     dict = _field(default_factory=lambda: _defaultdict(int))
    by_severity: dict = _field(default_factory=lambda: _defaultdict(int))
    ransomware_rows: list = _field(default_factory=list)
    wallet_rows:     list = _field(default_factory=list)
    cumulative_scored: int = 0

    def record(self, result: "ScoreResult") -> None:
        self.scored += 1
        self.by_type[result.ioc_type] += 1
        self.by_severity[result.severity] += 1
        if result.ioc_type == "ransomware":
            bd = result.breakdown.get("analyzer_detail") or {}
            self.ransomware_rows.append({
                "group":   bd.get("group_name") or result.ioc_value[:40],
                "score":   result.final_score,
                "severity": result.severity,
                "boost":   result.context_boost,
                "pre":     result.pre_score,
                "sector":  bd.get("activity_sector") or "",
                "country": bd.get("country") or "",
            })
        elif result.ioc_type == "wallet":
            bd = result.breakdown.get("analyzer_detail") or {}
            self.wallet_rows.append({
                "address":  result.ioc_value[:50],
                "family":   bd.get("malware_family") or "",
                "crypto":   bd.get("wallet_type") or "",
                "score":    result.final_score,
                "severity": result.severity,
                "boost":    result.context_boost,
                "pre":      result.pre_score,
                "verified": bd.get("blockchain_verified", False),
            })

    def log_summary(self) -> None:
        print("=" * 70)
        print(
            f"PASS #{self.pass_num} SUMMARY  polled={self.total_polled}  scored={self.scored}  "
            f"skipped={self.skipped}  failed={self.failed}  cumulative={self.cumulative_scored}"
        )
        if self.by_type:
            type_line = "  ".join(
                f"{t}={n}" for t, n in sorted(self.by_type.items())
            )
            print(f"  By type    : {type_line}")
        sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        sev_parts = [
            f"{s}={self.by_severity.get(s, 0)}" for s in sev_order
            if self.by_severity.get(s, 0) > 0
        ]
        if sev_parts:
            print(f"  Severity   : {'  '.join(sev_parts)}")
        if self.ransomware_rows:
            print(f"  -- Ransomware Actor Scores ({len(self.ransomware_rows)} records) --")
            for r in sorted(self.ransomware_rows, key=lambda x: x["score"], reverse=True):
                print(
                    f"    [{r['severity']}] {r['group']}  score={r['score']}  pre={r['pre']:.1f}  "
                    f"boost={r['boost']}  sector={r['sector'] or 'unknown'}  country={r['country'] or '?'}"
                )
        if self.wallet_rows:
            print(f"  -- Wallet Scores ({len(self.wallet_rows)} records) --")
            for w in sorted(self.wallet_rows, key=lambda x: x["score"], reverse=True):
                verified_tag = "blockchain-verified" if w["verified"] else "RSS-extracted"
                print(
                    f"    [{w['severity']}] {w['address']}  {w['crypto']}  "
                    f"family={w['family'] or 'unknown'}  score={w['score']}  "
                    f"pre={w['pre']:.2f}  boost={w['boost']}  [{verified_tag}]"
                )
        print("=" * 70)


@dataclass
class ScoreResult:
    ioc_value:         str
    ioc_type:          str
    cortex_score:      float
    context_boost:     int
    pre_score:         float
    source_confidence: float
    final_score:       int
    severity:          str
    action:            str
    analyzer_hits:     dict[str, Any] = field(default_factory=dict)
    breakdown:         dict[str, Any] = field(default_factory=dict)
    analyzers_run:     list[str]      = field(default_factory=list)
    error:             str            = ""

    @property
    def is_threat_actor(self) -> bool:
        return self.ioc_type in ("ransomware", "wallet")

def _make_session(retries: int = 3, backoff: float = 1.0) -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total            = retries,
        backoff_factor   = backoff,
        status_forcelist = {429, 502, 503, 504},
        allowed_methods  = {"GET", "POST"},
        raise_on_status  = False,
    )
    adapter = HTTPAdapter(
        max_retries       = retry,
        pool_connections  = IOC_WORKERS + 2,
        pool_maxsize      = IOC_WORKERS * 4,
    )
    session.mount("http://",  adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "Content-Type": "application/json",
        "User-Agent":   "THREATRADAR-CortexScorer/3.0",
    })
    if CORTEX_API_KEY:
        session.headers["Authorization"] = f"Bearer {CORTEX_API_KEY}"
    return session


_SESSION: requests.Session | None = None
_SESSION_LOCK = threading.Lock()

def _get_session() -> requests.Session:
    global _SESSION
    if _SESSION is None:
        with _SESSION_LOCK:
            if _SESSION is None:
                _SESSION = _make_session()
    return _SESSION


def _http(
    url:     str,
    method:  str         = "GET",
    payload: dict | None = None,
    headers: dict | None = None,
    timeout: int         = 30,
    retries: int         = 3,
) -> dict | None:
    session = _get_session()
    extra_headers = headers or {}
    try:
        resp = session.request(
            method  = method,
            url     = url,
            json    = payload,
            headers = extra_headers,
            timeout = timeout,
        )
        if resp.status_code >= 400:
            print(f"[ERROR] HTTP {resp.status_code} for {url}: {resp.text[:200]}")
            return None
        return resp.json()
    except requests.exceptions.Timeout:
        print(f"[WARNING] Timeout ({timeout}s) for {url}")
        return None
    except requests.exceptions.ConnectionError as exc:
        print(f"[WARNING] Connection error for {url}: {exc}")
        return None
    except Exception as exc:
        print(f"[ERROR] Request error for {url}: {exc}")
        return None


class CortexClient:

    def __init__(self, base_url: str, api_key: str):
        self.base = base_url.rstrip("/")
        self.key  = api_key

    def _url(self, path: str) -> str:
        return f"{self.base}/api{path}"

    def run_analyzer(self, analyzer_id: str, ioc_type: str, ioc_value: str, tlp: int = 2) -> dict | None:
        data_type_map = {
            "ip": "ip", "url": "url", "hash": "hash",
            "domain": "domain", "cve": "other", "wallet": "other",
        }
        payload = {
            "data":       ioc_value,
            "dataType":   data_type_map.get(ioc_type, "other"),
            "tlp":        tlp,
            "pap":        tlp,
            "message":    f"THREATRADAR analysis {ioc_type} {ioc_value[:16]}",
            "parameters": {},
        }
        return _http(self._url(f"/analyzer/{analyzer_id}/run"), method="POST", payload=payload)

    def get_job(self, job_id: str) -> dict | None:
        return _http(self._url(f"/job/{job_id}"))

    def get_job_report(self, job_id: str) -> dict | None:
        return _http(self._url(f"/job/{job_id}/report"))

    def wait_for_job(self, job_id: str) -> dict | None:
        deadline  = time.time() + JOB_MAX_WAIT
        poll_wait = 1.0
        POLL_CAP  = 5.0
        while time.time() < deadline:
            job = self.get_job(job_id)
            if not job:
                return None
            status = job.get("status", "")
            if status == "Success":
                return self.get_job_report(job_id)
            if status in ("Failure", "Deleted"):
                print(f"[DEBUG]   Job {job_id} -> {status}")
                return None
            time.sleep(poll_wait)
            poll_wait = min(poll_wait * 2, POLL_CAP)
        print(f"[WARNING]   Job {job_id} timed out after {JOB_MAX_WAIT}s")
        return None

    def analyze(self, analyzer_name: str, ioc_type: str, ioc_value: str) -> dict | None:
        analyzer_id = ANALYZER_IDS.get(analyzer_name)
        if not analyzer_id:
            print(f"[WARNING]   Unknown analyzer alias: {analyzer_name}")
            return None

        hit, cached = _cache_get(ioc_value, analyzer_name)
        if hit:
            print(f"[DEBUG]   Cache HIT: {analyzer_name} on [{ioc_value[:32]}]")
            return cached

        job = self.run_analyzer(analyzer_id, ioc_type, ioc_value)
        if not job:
            _cache_set(ioc_value, analyzer_name, None)
            return None

        job_id = job.get("id")
        if not job_id:
            print(f"[WARNING]   No job ID returned for {analyzer_name}")
            _cache_set(ioc_value, analyzer_name, None)
            return None

        report = self.wait_for_job(job_id)
        if not report:
            _cache_set(ioc_value, analyzer_name, None)
            return None

        inner = report.get("report") or report
        if isinstance(inner, dict):
            summary = inner.get("summary") or {}
            full    = inner.get("full")    or {}
            merged  = {}
            if isinstance(full,    dict): merged.update(full)
            if isinstance(summary, dict): merged.update(summary)
            result = merged if merged else inner
        else:
            result = inner

        _cache_set(ioc_value, analyzer_name, result)
        return result


def _score_virustotal(report: dict, ioc_type: str) -> int:
    if not report:
        return 0
    vt_max = 40 if ioc_type == "domain" else 50
    stats = (report.get("attributes") or {}).get("last_analysis_stats") or {}
    mal = int(stats.get("malicious") or 0)
    if mal >= 5: return vt_max
    if mal >= 1: return vt_max // 2
    if stats: return 0
    for tax in (report.get("taxonomies") or []):
        val = str(tax.get("value") or "")
        if "/" in val:
            try:
                mal = int(val.split("/")[0])
                if mal >= 5: return vt_max
                if mal >= 1: return vt_max // 2
                return 0
            except ValueError: pass
    mal = report.get("malicious") or report.get("positives") or 0
    if isinstance(mal, bool): return vt_max if mal else 0
    mal = int(mal) if mal else 0
    if mal >= 5: return vt_max
    if mal >= 1: return vt_max // 2
    return 0


def _score_abuseipdb(report: dict) -> int:
    if not report:
        return 0
    for tax in (report.get("taxonomies") or []):
        if "abuse confidence" in str(tax.get("predicate") or "").lower():
            try:
                s = int(tax.get("value") or 0)
                if s >= 75: return 25
                if s >= 30: return 12
                return 0
            except (ValueError, TypeError): pass
    for entry in (report.get("values") or []):
        s = (entry.get("data") or {}).get("abuseConfidenceScore")
        if s is not None:
            s = int(s)
            if s >= 75: return 25
            if s >= 30: return 12
            return 0
    s = int(report.get("abuseConfidenceScore") or 0)
    if s >= 75: return 25
    if s >= 30: return 12
    return 0


def _score_maltiverse(report: dict, ioc_type: str) -> int:
    if not report:
        return 0
    m_max = 25 if ioc_type == "hash" else (20 if ioc_type == "domain" else 15)
    for tax in (report.get("taxonomies") or []):
        level = str(tax.get("level") or "").lower()
        val   = str(tax.get("value") or "").lower()
        c = val if val not in ("", "info") else level
        if c == "malicious":               return m_max
        if c in ("suspicious", "neutral"): return m_max // 2
    c = (report.get("classification") or report.get("verdict") or report.get("type") or "clean").lower()
    if c == "malicious":               return m_max
    if c in ("suspicious", "neutral"): return m_max // 2
    return 0


def _score_ipinfo(report: dict) -> int:
    if not report:
        return 3
    infra_kw = {"hosting", "vpn", "datacenter", "proxy", "cloud", "tor",
                "data center", "web hosting", "transit", "colocation"}
    for tax in (report.get("taxonomies") or []):
        val = str(tax.get("value") or "").lower()
        if any(kw in val for kw in infra_kw):
            return 10
    org   = (report.get("org") or report.get("company") or "").lower()
    usage = report.get("privacy") or {}
    if (any(kw in org for kw in infra_kw)
            or (isinstance(usage, dict) and
                (usage.get("hosting") or usage.get("vpn") or
                 usage.get("proxy")   or usage.get("tor")))):
        return 10
    return 3


def _score_urlscan(report: dict, ioc_type: str) -> int:
    if not report:
        return 0
    u_max = 30 if ioc_type == "url" else 25
    for tax in (report.get("taxonomies") or []):
        level = str(tax.get("level") or "").lower()
        val   = str(tax.get("value") or "").lower()
        if "0 result" in val or "no result" in val:
            return 0
        if level == "malicious":  return u_max
        if level == "suspicious": return u_max // 2
    for result in ((report.get("indicator") or {}).get("results") or []):
        if (result.get("verdicts") or {}).get("overall", {}).get("malicious"):
            return u_max
    verdict = (report.get("verdict") or report.get("overall_verdict") or report.get("malicious") or "clean")
    if isinstance(verdict, bool): return u_max if verdict else 0
    verdict = str(verdict).lower()
    if verdict == "malicious":                             return u_max
    if verdict in ("suspicious", "potentially malicious"): return u_max // 2
    return 0


def _score_hybridanalysis(report: dict, ioc_type: str) -> int:
    if not report:
        return 0
    h_max = 15 if ioc_type == "domain" else 5
    for tax in (report.get("taxonomies") or []):
        level = str(tax.get("level") or "").lower()
        if level == "malicious":  return h_max
        if level == "suspicious": return h_max // 2
    verdict = (report.get("verdict") or report.get("threat_level_human")
               or report.get("classification") or "clean").lower()
    if verdict in ("malicious", "confirmed_threat"):  return h_max
    if verdict in ("suspicious", "likely_malicious"): return h_max // 2
    return 0


def aggregate_cortex_score(
    analyzer_reports: dict[str, dict | None],
    ioc_type: str,
) -> tuple[int, dict]:
    score     = 0
    breakdown = {}

    if "VirusTotal" in analyzer_reports:
        pts = _score_virustotal(analyzer_reports["VirusTotal"], ioc_type)
        score += pts
        breakdown["virustotal"] = pts

    if "AbuseIPDB" in analyzer_reports and ioc_type == "ip":
        pts = _score_abuseipdb(analyzer_reports["AbuseIPDB"])
        score += pts
        breakdown["abuseipdb"] = pts

    if "Maltiverse" in analyzer_reports:
        pts = _score_maltiverse(analyzer_reports["Maltiverse"], ioc_type)
        score += pts
        breakdown["maltiverse"] = pts

    if "IPinfo" in analyzer_reports and ioc_type == "ip":
        pts = _score_ipinfo(analyzer_reports["IPinfo"])
        score += pts
        breakdown["ipinfo"] = pts

    if "Urlscan" in analyzer_reports and ioc_type != "ip":
        pts = _score_urlscan(analyzer_reports["Urlscan"], ioc_type)
        score += pts
        breakdown["urlscan"] = pts

    if "HybridAnalysis" in analyzer_reports and ioc_type in ("url", "domain"):
        pts = _score_hybridanalysis(analyzer_reports["HybridAnalysis"], ioc_type)
        score += pts
        breakdown["hybridanalysis"] = pts

    if score == 0:
        score = 5
        breakdown["fallback_min"] = 5

    return score, breakdown


def score_cve(doc: dict) -> tuple[int, dict]:
    in_kev = (doc.get("source_name") or "") == "cisa_kev"
    cvss   = float(doc.get("cvss_score") or 0)

    if in_kev:
        if cvss >= 9.0:
            score = 95
        elif cvss >= 7.0:
            score = 85
        elif cvss >= 4.0:
            score = 70
        else:
            score = 60
    else:
        if cvss >= 9.0:
            score = 75
        elif cvss >= 7.0:
            score = 60
        elif cvss >= 4.0:
            score = 40
        elif cvss > 0:
            score = 15
        else:
            score = 5

    return score, {"cisa_kev": in_kev, "cvss_score": cvss, "matrix_score": score}


def _extract_threat_actor_signals(score_fields: dict) -> dict:
    return {
        "critical_sector":      score_fields.get("critical_sector", False),
        "group_active_days":    score_fields.get("group_active_days", -1),
        "monthly_victim_count": score_fields.get("monthly_victim_count", 0),
        "technique_count":      score_fields.get("technique_count", 0),
        "ransomware_matched":   score_fields.get("ransomware_matched", False),
        "ransomware_group":     score_fields.get("ransomware_group", ""),
        "corroboration_bonus":  score_fields.get("corroboration_bonus", 0),
    }


def apply_formula(
    cortex_score:      float,
    context_boost:     int,
    source_confidence: float,
    ioc_type:          str,
) -> tuple[int, str, str]:
    FALLBACK_MIN = 5

    if ioc_type in ("ransomware", "wallet", "cve"):
        raw = cortex_score + context_boost
    else:
        boost_scale = 1.0 if cortex_score > FALLBACK_MIN else source_confidence
        raw = (cortex_score + context_boost * boost_scale) * source_confidence

    final = min(int(round(raw)), 100)

    severity = "UNKNOWN"
    action   = "manual_triage"
    for threshold, sev, act in THRESHOLDS:
        if final >= threshold:
            severity = sev
            action   = act
            break

    if ioc_type in NO_AUTO_BLOCK_TYPES and action == "auto_block":
        action = "alert_soc"

    return final, severity, action


def score_doc(doc: dict, cortex: CortexClient) -> ScoreResult | None:
    ioc_type = (doc.get("ioc_type") or "").lower()
    ioc_value = (
        doc.get("ioc_value")
        or (doc.get("group_name") if ioc_type == "ransomware" else None)
        or ""
    )
    _raw_conf = doc.get("source_confidence")
    src_conf  = float(_raw_conf) if _raw_conf is not None else 0.50
    weight = float(doc.get("ioc_type_weight") or 50)

    score_fields  = (doc.get("enriched") or {}).get("score") or {}
    pre_score     = float(score_fields.get("pre_score") or round(weight * src_conf, 2))
    context_boost = int(score_fields.get("context_boost") or 0)

    if not score_fields and ioc_type not in ("cve",):
        print(
            f"[WARNING]   SKIP [{ioc_type}] {ioc_value[:50] or '?'} -- "
            f"enriched.score.* absent. Run enricher.py first. "
            f"context_boost would be 0, producing an incorrect score."
        )
        return None

    analyzer_reports: dict[str, dict | None] = {}
    cortex_score  = 0.0
    vt_breakdown: dict = {}
    analyzers_run: list[str] = []

    if ioc_type == "cve":
        cortex_score, vt_breakdown = score_cve(doc)

    elif ioc_type == "ransomware":
        cortex_score = pre_score
        vt_breakdown = {
            "note":            "Threat Actor Intelligence , no Cortex analyzers",
            "intel_class":     "threat_actor_activity",
            "score_type":      "actor_danger_rating",
            "pre_score":       pre_score,
            "group_name":      doc.get("group_name", ""),
            "activity_sector": doc.get("activity", ""),
            "first_seen":      str(doc.get("first_seen", ""))[:10],
            "country":         doc.get("country", ""),
            **_extract_threat_actor_signals(score_fields),
        }

    elif ioc_type == "wallet":
        source_names      = doc.get("source_names") or []
        primary_source    = source_names[0] if source_names else (doc.get("source_name") or "")
        blockchain_verified = "ransomwhere" in str(primary_source).lower()
        cortex_score = pre_score
        vt_breakdown = {
            "note":                "Wallet IOC -- no Cortex analyzers",
            "ioc_class":           "financial_indicator",
            "wallet_type":         doc.get("wallet_type") or "",
            "malware_family":      doc.get("malware") or "",
            "pre_score":           pre_score,
            "source_name":         primary_source,
            "blockchain_verified": blockchain_verified,
            "ransomwhere_score":   f"{92*0.92:.2f}" if blockchain_verified else "n/a",
            **_extract_threat_actor_signals(score_fields),
        }

    else:
        aliases = list(ANALYZERS_BY_TYPE.get(ioc_type, []))
        analyzers_run = list(aliases)

        def _run_one(alias: str) -> tuple[str, dict | None]:
            print(f"[DEBUG]     -> Cortex: {alias} on [{ioc_value}]")
            return alias, cortex.analyze(alias, ioc_type, ioc_value)

        with ThreadPoolExecutor(max_workers=max(len(aliases), 1)) as pool:
            futures = {pool.submit(_run_one, a): a for a in aliases}
            for future in as_completed(futures):
                try:
                    alias, report = future.result()
                    analyzer_reports[alias] = report
                except Exception as exc:
                    print(f"[WARNING]     Analyzer {futures[future]} error: {exc}")

        cortex_score, vt_breakdown = aggregate_cortex_score(analyzer_reports, ioc_type)

    final, severity, action = apply_formula(cortex_score, context_boost, src_conf, ioc_type)

    breakdown = {
        "cortex_score_raw":    cortex_score,
        "context_boost":       context_boost,
        "source_confidence":   src_conf,
        "pre_multiplied":      round(cortex_score + context_boost, 2),
        "final_capped":        final,
        "analyzer_detail":     vt_breakdown,
        "ransomware_group":    score_fields.get("ransomware_group", ""),
        "corroboration_bonus": score_fields.get("corroboration_bonus", 0),
    }

    return ScoreResult(
        ioc_value          = ioc_value,
        ioc_type           = ioc_type,
        cortex_score       = cortex_score,
        context_boost      = context_boost,
        pre_score          = pre_score,
        source_confidence  = src_conf,
        final_score        = final,
        severity           = severity,
        action             = action,
        analyzer_hits      = analyzer_reports,
        breakdown          = breakdown,
        analyzers_run      = analyzers_run,
    )


def _analyzer_verdict(alias: str, report: dict, ioc_type: str) -> tuple[str, int]:
    if not report:
        return "unknown", 0

    CONF = {"malicious": 90, "suspicious": 50, "clean": 5, "not_found": 0, "unknown": 0}

    if alias == "VirusTotal":
        stats = (report.get("attributes") or {}).get("last_analysis_stats") or {}
        mal = int(stats.get("malicious") or 0)
        if stats:
            v = "malicious" if mal >= 5 else ("suspicious" if mal >= 1 else "clean")
            return v, CONF[v]
        for tax in (report.get("taxonomies") or []):
            val = str(tax.get("value") or "")
            if "/" in val:
                try:
                    mal = int(val.split("/")[0])
                    v = "malicious" if mal >= 5 else ("suspicious" if mal >= 1 else "clean")
                    return v, CONF[v]
                except ValueError:
                    pass
        mal = report.get("malicious") or report.get("positives") or 0
        if isinstance(mal, bool):
            v = "malicious" if mal else "clean"
        else:
            mal = int(mal) if mal else 0
            v = "malicious" if mal >= 5 else ("suspicious" if mal >= 1 else "clean")
        return v, CONF[v]

    if alias == "AbuseIPDB":
        score = None
        for tax in (report.get("taxonomies") or []):
            if "abuse confidence" in str(tax.get("predicate") or "").lower():
                try:
                    score = int(tax.get("value") or 0)
                    break
                except (ValueError, TypeError):
                    pass
        if score is None:
            for entry in (report.get("values") or []):
                s = (entry.get("data") or {}).get("abuseConfidenceScore")
                if s is not None:
                    score = int(s)
                    break
        if score is None:
            score = int(report.get("abuseConfidenceScore") or 0)
        v = "malicious" if score >= 75 else ("suspicious" if score >= 30 else "clean")
        return v, CONF[v]

    if alias == "Maltiverse":
        for tax in (report.get("taxonomies") or []):
            level = str(tax.get("level") or "").lower()
            val   = str(tax.get("value") or "").lower()
            c = val if val not in ("", "info") else level
            if c == "malicious":                return "malicious",  CONF["malicious"]
            if c in ("suspicious", "neutral"):  return "suspicious", CONF["suspicious"]
        c = (report.get("classification") or report.get("verdict")
             or report.get("type") or "clean").lower()
        if c == "malicious":               return "malicious",  CONF["malicious"]
        if c in ("suspicious", "neutral"): return "suspicious", CONF["suspicious"]
        return "clean", CONF["clean"]

    if alias == "IPinfo":
        infra_kw = {"hosting", "vpn", "datacenter", "proxy", "cloud", "tor",
                    "data center", "web hosting", "transit", "colocation"}
        for tax in (report.get("taxonomies") or []):
            if any(kw in str(tax.get("value") or "").lower() for kw in infra_kw):
                return "malicious", CONF["malicious"]
        org = (report.get("org") or report.get("company") or "").lower()
        usage = report.get("privacy") or {}
        if (any(kw in org for kw in infra_kw) or
                (isinstance(usage, dict) and
                 (usage.get("hosting") or usage.get("vpn") or
                  usage.get("proxy")   or usage.get("tor")))):
            return "malicious", CONF["malicious"]
        return "clean", CONF["clean"]

    if alias == "Urlscan":
        for tax in (report.get("taxonomies") or []):
            level = str(tax.get("level") or "").lower()
            val   = str(tax.get("value") or "").lower()
            if "0 result" in val or "no result" in val:
                return "not_found", CONF["not_found"]
            if level == "malicious":  return "malicious",  CONF["malicious"]
            if level == "suspicious": return "suspicious", CONF["suspicious"]
        for r in ((report.get("indicator") or {}).get("results") or []):
            if (r.get("verdicts") or {}).get("overall", {}).get("malicious"):
                return "malicious", CONF["malicious"]
        v = (report.get("verdict") or report.get("overall_verdict")
             or report.get("malicious") or "clean")
        if isinstance(v, bool):
            return ("malicious" if v else "clean"), CONF["malicious" if v else "clean"]
        v = str(v).lower()
        if v == "malicious":                             return "malicious",  CONF["malicious"]
        if v in ("suspicious", "potentially malicious"): return "suspicious", CONF["suspicious"]
        return "clean", CONF["clean"]

    if alias == "HybridAnalysis":
        for tax in (report.get("taxonomies") or []):
            level = str(tax.get("level") or "").lower()
            if level == "malicious":  return "malicious",  CONF["malicious"]
            if level == "suspicious": return "suspicious", CONF["suspicious"]
        v = (report.get("verdict") or report.get("threat_level_human")
             or report.get("classification") or "clean").lower()
        if v in ("malicious", "confirmed_threat"):  return "malicious",  CONF["malicious"]
        if v in ("suspicious", "likely_malicious"): return "suspicious", CONF["suspicious"]
        return "clean", CONF["clean"]

    for tax in (report.get("taxonomies") or []):
        level = str(tax.get("level") or "").lower()
        if level == "malicious":  return "malicious",  CONF["malicious"]
        if level == "suspicious": return "suspicious", CONF["suspicious"]
        if level in ("safe", "info"): return "clean",  CONF["clean"]
    v = (report.get("verdict") or report.get("classification")
         or report.get("malicious") or "unknown")
    if isinstance(v, bool):
        return ("malicious" if v else "clean"), CONF["malicious" if v else "clean"]
    v = str(v).lower()
    if v in ("malicious", "confirmed_threat"):  return "malicious",  CONF["malicious"]
    if v in ("suspicious", "likely_malicious"): return "suspicious", CONF["suspicious"]
    if v in ("clean", "safe", "harmless"):      return "clean",      CONF["clean"]
    return "unknown", 0


def _build_cortex_analyzers_list(result: ScoreResult) -> list[dict]:
    if not result.analyzers_run:
        return []
    entries = []
    for alias in result.analyzers_run:
        report = result.analyzer_hits.get(alias) or {}
        verdict, conf_int = _analyzer_verdict(alias, report, result.ioc_type)
        entries.append({"name": alias, "result": verdict, "confidence": conf_int})
    return entries


def build_es_update(result: ScoreResult) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    analyzers_list = _build_cortex_analyzers_list(result)

    if result.ioc_type == "ransomware":
        return {
            "cortex_analyzed":    True,
            "cortex_analyzed_at": now,
            "scoring_timestamp":  now,
            "actor_danger_score": result.final_score,
            "actor_threat_level": result.severity,
            "intel_class":        "threat_actor_activity",
            "intel_type":         "threat_actor_activity",
            "score_type":         "actor_danger_rating",
            "score_meaning":      "actor_danger_rating",
            "action":             "alert_soc",
            "cortex_action":      "alert_soc",
            "cortex_score":       result.cortex_score,
            "source_confidence":  result.source_confidence,
            "cortex_final_score": result.final_score,
            "cortex_severity":    result.severity,
            "severity":           result.severity,
            "final_score":        result.final_score,
            "verdict":            result.severity,
            "cortex_verdict":     result.severity,
            "score_breakdown":    result.breakdown,
            "cortex_analyzers":   [],
            "has_score":          True,
        }

    if result.ioc_type == "wallet":
        return {
            "cortex_analyzed":    True,
            "cortex_analyzed_at": now,
            "scoring_timestamp":  now,
            "cortex_score":       result.cortex_score,
            "cortex_final_score": result.final_score,
            "cortex_severity":    result.severity,
            "cortex_action":      "alert_soc",
            "action":             "alert_soc",
            "source_confidence":  result.source_confidence,
            "score_breakdown":    result.breakdown,
            "severity":           result.severity,
            "final_score":        result.final_score,
            "verdict":            result.severity,
            "cortex_verdict":     result.severity,
            "cortex_analyzers":   [],
            "has_score":          True,
        }

    return {
        "cortex_analyzed":    True,
        "cortex_analyzed_at": now,
        "scoring_timestamp":  now,
        "cortex_score":       result.cortex_score,
        "cortex_final_score": result.final_score,
        "cortex_severity":    result.severity,
        "cortex_action":      result.action,
        "source_confidence":  result.source_confidence,
        "score_breakdown":    result.breakdown,
        "severity":           result.severity,
        "action":             result.action,
        "final_score":        result.final_score,
        "verdict":            result.severity,
        "cortex_verdict":     result.severity,
        "cortex_analyzers":   analyzers_list,
        "has_score":          True,
    }



_PRINT_LOCK = threading.Lock()


def _build_signal_flags(bd: dict) -> list[str]:
    flags = []
    if bd.get("ransomware_matched"):
        flags.append("group matched +20")
    if bd.get("critical_sector"):
        flags.append("critical sector +15")
    days = bd.get("group_active_days", -1)
    if 0 <= days < 30:
        flags.append(f"active {days}d ago +10")
    mvc = bd.get("monthly_victim_count", 0)
    if mvc >= 5:
        flags.append(f"{mvc} victims/30d +10")
    tc = bd.get("technique_count", 0)
    if tc >= 5:
        flags.append(f"{tc} MITRE techniques +10")
    corrob = bd.get("corroboration_bonus", 0)
    if corrob > 0:
        flags.append(f"corroboration +{corrob}")
    return flags


def print_score_card(result: ScoreResult, doc_index: str) -> None:
    with _PRINT_LOCK:
        sep = "-" * 70
        bd  = result.breakdown.get("analyzer_detail") or {}

        print(f"\n{sep}")

        if result.ioc_type == "ransomware":
            print(f"  THREAT ACTOR INTEL  {bd.get('group_name', result.ioc_value)[:60]}")
            print(f"  Index    : {doc_index}")
            print(f"  Sector   : {bd.get('activity_sector', 'unknown')}  |  "
                  f"Country: {bd.get('country', '?')}  |  "
                  f"First seen: {bd.get('first_seen', '?')[:10]}")
            flags = _build_signal_flags(bd)
            if flags:
                print(f"  Signals  : {' . '.join(flags)}")
            print(
                f"  Rating   : "
                f"pre={result.pre_score:.1f} + boost={result.context_boost} "
                f"x conf={result.source_confidence:.2f} "
                f"-> {result.final_score}/100"
            )
            print(f"  Verdict  : [{result.severity}]  ALERT_SOC  "
                  f"(actor_danger_rating -- never auto_block)")
            print(f"  ES fields: actor_danger_score={result.final_score}  "
                  f"actor_threat_level={result.severity}")

        elif result.ioc_type == "wallet":
            bc_tag = "blockchain-verified" if bd.get("blockchain_verified", False) else "RSS-extracted"
            print(f"  WALLET  {result.ioc_value[:50]}  "
                  f"{bd.get('wallet_type') or ''}  [{bc_tag}]")
            if bd.get("malware_family"):
                print(f"  Family   : {bd.get('malware_family')}")
            print(f"  Index    : {doc_index}")
            flags = _build_signal_flags(bd)
            if flags:
                print(f"  Signals  : {' . '.join(flags)}")
            print(
                f"  Score    : "
                f"pre={result.pre_score:.2f} + boost={result.context_boost} "
                f"x conf={result.source_confidence:.2f} "
                f"-> {result.final_score}/100"
            )
            print(f"  Verdict  : [{result.severity}]  ALERT_SOC  "
                  f"(financial IOC -- law enforcement coordination required)")
            print(f"  ES fields: cortex_final_score={result.final_score}  "
                  f"cortex_severity={result.severity}")

        else:
            print(f"  {result.ioc_type.upper()}  {result.ioc_value[:60]}")
            print(f"  Index    : {doc_index}")
            parts = []
            for k, v in bd.items():
                if k in ("note", "pre_score", "cisa_kev", "cvss_score",
                         "matrix_score", "fallback_min"):
                    continue
                if isinstance(v, int) and v > 0:
                    parts.append(f"{k}=+{v}")
            if parts:
                print(f"  Analyzers: {'  '.join(parts)}")
            if result.ioc_type == "cve":
                kev_tag = "CISA KEV" if bd.get("cisa_kev") else "no KEV"
                cvss = bd.get("cvss_score", 0)
                print(f"  CVE data : {kev_tag}  CVSS={cvss}  matrix={bd.get('matrix_score','?')}")
            flags = []
            rg = result.breakdown.get("ransomware_group") or ""
            if rg:
                flags.append(f"group={rg} +20")
            corrob = result.breakdown.get("corroboration_bonus", 0)
            if corrob > 0:
                flags.append(f"corroboration +{corrob}")
            if flags:
                print(f"  Boost    : {' . '.join(flags)}")
            print(
                f"  Score    : "
                f"(cortex={result.cortex_score:.0f} + boost={result.context_boost}) "
                f"x conf={result.source_confidence:.2f} "
                f"-> {result.final_score}/100"
            )
            print(f"  Verdict  : [{result.severity}]  {result.action.upper()}")
            print(f"  ES fields: cortex_final_score={result.final_score}  "
                  f"cortex_severity={result.severity}  cortex_action={result.action}")

        print(sep)


def poll_unscored(
    es:       Elasticsearch,
    ioc_type: str | None,
    limit:    int,
) -> list[tuple[str, str, dict]]:
    if ioc_type:
        index_target = f"ti_{ioc_type}"
    else:
        existing = []
        for idx in TARGET_INDICES:
            try:
                if es.indices.exists(index=idx):
                    existing.append(idx)
            except Exception:
                pass
        if not existing:
            return []
        index_target = ",".join(existing)

    base_filter: list[dict] = [{"term": {"cortex_analyzed": False}}]
    if not ioc_type:
        base_filter.append({"terms": {"ioc_type": [
            "ip", "url", "hash", "domain", "cve", "ransomware", "wallet",
        ]}})

    query: dict = {
        "size": limit,
        "query": {"bool": {"filter": base_filter}},
        "_source": True,
    }

    try:
        resp = es.search(index=index_target, body=query)
    except Exception as e:
        print(f"[WARNING]   Poll failed: {e}")
        return []

    return [(hit["_index"], hit["_id"], hit["_source"]) for hit in resp["hits"]["hits"]]


def write_results_bulk(
    es:      Elasticsearch,
    updates: list[tuple[str, str, dict]],
) -> tuple[int, int]:
    if not updates:
        return 0, 0

    actions = [
        {
            "_op_type": "update",
            "_index":   index,
            "_id":      doc_id,
            "doc":      update_body,
        }
        for index, doc_id, update_body in updates
    ]

    success = 0
    failed  = 0
    try:
        ok, errors = helpers.bulk(
            es, actions,
            raise_on_error    = False,
            raise_on_exception = False,
        )
        success = ok
        failed  = len(errors) if errors else 0
        if errors:
            for err in errors[:3]:
                print(f"[ERROR]   Bulk write error: {err}")
    except Exception as exc:
        print(f"[ERROR]   Bulk write failed entirely: {exc}")
        failed = len(actions)

    return success, failed


def run_pass(
    es:     Elasticsearch,
    cortex: CortexClient,
    args:   argparse.Namespace,
    pass_num: int = 0,
    cumulative_scored: int = 0,
) -> int:
    stats = PassStats(
        pass_num          = pass_num,
        cumulative_scored = cumulative_scored,
    )

    batch = poll_unscored(es, args.ioc_type, args.limit)
    stats.total_polled = len(batch)
    if not batch:
        print("[INFO]   No unscored IOCs found -- sleeping.")
        return 0

    print(f"[INFO]   Scoring {len(batch)} IOCs (workers={IOC_WORKERS}, {cache_stats()}) ...")

    scored_results: list[tuple[str, str, ScoreResult]] = []

    def _score_one(item: tuple[str, str, dict]) -> tuple[str, str, ScoreResult | None]:
        index, doc_id, src = item
        try:
            result = score_doc(src, cortex)
            return index, doc_id, result
        except Exception as exc:
            print(f"[ERROR]   Score error for {doc_id}: {exc}")
            return index, doc_id, None

    with ThreadPoolExecutor(max_workers=IOC_WORKERS) as pool:
        futures = {pool.submit(_score_one, item): item for item in batch}
        for future in as_completed(futures):
            index, doc_id, result = future.result()
            if result is None:
                stats.skipped += 1
            else:
                scored_results.append((index, doc_id, result))
                stats.record(result)
                print_score_card(result, index)

    stats.failed = 0

    ok_count = 0
    if not args.dry_run and scored_results:
        bulk_updates = [
            (index, doc_id, build_es_update(result))
            for index, doc_id, result in scored_results
        ]
        ok_count, fail_count = write_results_bulk(es, bulk_updates)
        stats.failed += fail_count
        print(
            f"[INFO]   Bulk write: {ok_count} ok, {fail_count} failed "
            f"({len(bulk_updates)} docs in 1 request)"
        )
    elif args.dry_run:
        ok_count = len(scored_results)

    print(
        f"[INFO]   Pass complete -- scored: {ok_count}  "
        f"skipped: {stats.skipped}  failed: {stats.failed}"
        + ("  [DRY RUN -- no writes]" if args.dry_run else "")
        + f"  {cache_stats()}"
    )
    if stats.skipped > 0:
        print(
            f"[WARNING]   {stats.skipped} docs skipped (enriched.score.* absent or score error). "
            f"Run enricher.py before cortex_scorer.py."
        )

    stats.scored = ok_count
    stats.cumulative_scored = cumulative_scored + ok_count
    stats.log_summary()

    return ok_count


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog            = "cortex_scorer.py",
        description     = "THREATRADAR Cortex Scorer v3.0",
        formatter_class = argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--loop", action="store_true",
        help="Run continuously, polling every SCORER_POLL_INTERVAL seconds")
    p.add_argument("--dry-run", action="store_true",
        help="Score but do not write results to Elasticsearch")
    p.add_argument("--ioc-type",
        choices=["ip", "url", "hash", "domain", "cve", "ransomware", "wallet"],
        default=None,
        help="Restrict scoring to a single IOC type (default: all types)")
    p.add_argument("--limit", type=int, default=BATCH_SIZE,
        help="Maximum IOCs to score per pass")
    p.add_argument("--workers", type=int, default=IOC_WORKERS,
        help="Parallel IOC scoring threads (overrides SCORER_IOC_WORKERS env var)")
    p.add_argument("--interval", type=int, default=POLL_INTERVAL,
        help="Seconds between polls in --loop mode")
    p.add_argument("--cortex-url", default=CORTEX_URL,
        help="Cortex base URL (overrides CORTEX_URL env var)")
    p.add_argument("--cortex-key", default=CORTEX_API_KEY,
        help="Cortex API key (overrides CORTEX_API_KEY env var)")
    p.add_argument("--elastic-host", default=ELASTIC_HOST,
        help="Elasticsearch host (overrides ELASTIC_HOST env var)")
    p.add_argument("--debug", action="store_true",
        help="Enable debug logging (shows Cortex API calls)")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    global IOC_WORKERS, _SESSION
    IOC_WORKERS = args.workers

    with _SESSION_LOCK:
        _SESSION = _make_session()

    print(" © 2026 THREATRADAR Team - Cortex Scorer")
    print(f"[INFO] Connecting to Elasticsearch at {args.elastic_host} ...")
    es = Elasticsearch(args.elastic_host, basic_auth=(ELASTIC_USER, ELASTIC_PASSWORD))
    if not es.ping():
        print("[ERROR] Cannot reach Elasticsearch. Check ELASTIC_HOST / credentials.")
        sys.exit(1)
    print("[INFO] Elasticsearch OK")

    cortex = CortexClient(args.cortex_url, args.cortex_key)
    if not args.cortex_key:
        print(
            "[WARNING] CORTEX_API_KEY is not set. "
            "CVE/Ransomware/Wallet scoring will still work (matrix-only), "
            "but Cortex analyzer calls will fail for IP/URL/Hash/Domain."
        )

    if args.dry_run:
        print("[INFO] DRY RUN mode -- Elasticsearch writes are disabled.")

    if args.loop:
        print(
            f"[INFO] Loop mode -- polling every {args.interval}s "
            f"(batch={args.limit}, type={args.ioc_type or 'all'})"
        )
        pass_num          = 0
        cumulative_scored = 0
        while True:
            pass_num += 1
            print(f"{'_'*50}")
            print(f"[INFO] Poll #{pass_num}  [{datetime.now(timezone.utc).strftime('%H:%M:%S UTC')}]")
            try:
                scored = run_pass(
                    es, cortex, args,
                    pass_num=pass_num,
                    cumulative_scored=cumulative_scored,
                )
                cumulative_scored += scored
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                print(f"[ERROR] Pass #{pass_num} error: {exc}")
            time.sleep(args.interval)
    else:
        run_pass(es, cortex, args, pass_num=1, cumulative_scored=0)

    print("[INFO] Scorer done.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted -- scorer stopped.")
        sys.exit(0)
