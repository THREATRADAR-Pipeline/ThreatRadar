#!/usr/bin/env python3
"""
THREATRADAR Enricher takes raw IOCs from Elasticsearch and attaches structured context.
© 2026 THREATRADAR Team
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta
from typing import Any
from elasticsearch import Elasticsearch, helpers

sys.path.insert(0, "/vx")
from common import _DOWNSTREAM_RESET, TARGET_INDICES

_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(_env_path):
    with open(_env_path) as _env_file:
        for _line in _env_file:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip())

ELASTIC_HOST     = os.environ.get("ELASTIC_HOST", "http://elasticsearch:9200")
ELASTIC_USER     = os.environ.get("ELASTIC_USER", "elastic")
ELASTIC_PASSWORD = os.environ.get("ELASTIC_PASSWORD")
SCROLL_SIZE    = 500
SCROLL_TIMEOUT = "5m"

NVD_API_KEY  = os.environ.get("NVD_API_KEY", "")
NVD_API_URL  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_SLEEP    = 0.025 if NVD_API_KEY else 0.6
NVD_RETRY_DAYS = 7

ATTACK_FILE    = "enterprise-attack.json"
ATTACK_MIN_MB  = 35
ATTACK_MIN_VER = 18
ATTACK_URL = (
    "https://github.com/mitre/cti/releases/download/"
    "ATT%26CK-v18.1/enterprise-attack.json"
)

OWASP_VERSION      = "2021"
OWASP_VERSION_NOTE = (
    "OWASP Top 10 2021 (https://owasp.org/Top10/). "
    "OWASP Top 10 2025 RC released — key changes: "
    "A02=Security Misconfiguration, A03=Supply Chain Failures (NEW), "
    "A10=Mishandling Exceptional Conditions (NEW, SSRF absorbed into A01). "
    "Will be adopted once official CWE mappings are published."
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("enricher")

SOURCE_TIER_MULTIPLIER: dict[str, float] = {
    "tier1": 1.00,
    "tier2": 0.85,
    "tier3": 0.60,
}
_KNOWN_TIERS = frozenset(SOURCE_TIER_MULTIPLIER.keys())

def _get_tier_multiplier(tier: str, doc_id: str = "") -> float:
    if tier in _KNOWN_TIERS:
        return SOURCE_TIER_MULTIPLIER[tier]
    log.warning(
        f"  Unknown source_tier={tier!r} on doc {doc_id or '?'} — "
        f"falling back to tier3 (0.60). Check ti_processor.py tier assignment."
    )
    return SOURCE_TIER_MULTIPLIER["tier3"]

def http_get(url, headers=None, timeout=60, retries=3, backoff=2.0):
    req_headers = {"User-Agent": "OTIC-Enricher/1.0"}
    if headers:
        req_headers.update(headers)
    req      = urllib.request.Request(url, headers=req_headers)
    last_err = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429 or e.code >= 500:
                wait = backoff ** attempt
                log.debug(f"HTTP {e.code} for {url} — retry in {wait:.0f}s")
                time.sleep(wait)
                continue
            log.warning(f"HTTP {e.code} for {url}: {e.reason}")
            return None
        except Exception as e:
            last_err = e
            wait = backoff ** attempt
            log.warning(f"Request error for {url}: {e} — retry in {wait:.0f}s")
            time.sleep(wait)
    log.warning(f"All {retries} attempts failed for {url}: {last_err}")
    return None


def _parse_cwes(cve_item):
    return list(dict.fromkeys(
        desc["value"]
        for weakness in cve_item.get("cve", {}).get("weaknesses", [])
        for desc in weakness.get("description", [])
        if desc.get("value", "").startswith("CWE-")
           and desc["value"] not in ("CWE-noinfo", "CWE-Other")
    ))


def _parse_cvss(cve_item):
    metrics = cve_item.get("cve", {}).get("metrics", {})
    for key, version_label in [
        ("cvssMetricV31", "3.1"),
        ("cvssMetricV30", "3.0"),
        ("cvssMetricV2",  "2.0"),
    ]:
        entries = metrics.get(key, [])
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data  = entry.get("cvssData", {})
        score = data.get("baseScore")
        if score is None:
            continue
        return {
            "cvss_score":          float(score),
            "cvss_severity":       data.get("baseSeverity", entry.get("baseSeverity", "UNKNOWN")).upper(),
            "cvss_vector":         data.get("vectorString", ""),
            "cvss_version":        version_label,
            "cvss_exploitability": entry.get("exploitabilityScore"),
            "cvss_impact":         entry.get("impactScore"),
        }
    return None


def _nvd_fetch_single(cve_id: str) -> dict | None:
    url  = f"{NVD_API_URL}?cveId={urllib.parse.quote(cve_id)}"
    hdrs = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    data = http_get(url, headers=hdrs, timeout=30)
    if not data:
        return None
    try:
        body  = json.loads(data)
        vulns = body.get("vulnerabilities", [])
        return vulns[0] if vulns else None
    except (json.JSONDecodeError, KeyError):
        return None


def _bulk_update(es, index, docs):
    if not docs:
        return

    def _actions():
        for doc in docs:
            doc    = doc.copy()
            doc_id = doc.pop("_id", None)
            action = {"_op_type": "update", "_index": index, "doc": doc}
            if doc_id:
                action["_id"] = doc_id
            yield action

    success, errors = helpers.bulk(es, _actions(), raise_on_error=False, chunk_size=500)
    log.info(f"  -> Updated {success} docs in {index}" +
             (f" | {len(errors)} errors" if errors else ""))
    for err in errors[:3]:
        log.warning(f"    Error: {err}")


def enrich_cves_with_nvd(es):
    log.info("=" * 55)
    log.info("PART 1: NIST NVD — Enriching ti_cve with CWEs + CVSS")
    log.info("=" * 55)

    if NVD_API_KEY:
        log.info("  NVD_API_KEY loaded")
    else:
        log.warning("  NVD_API_KEY not set — rate limited to 5 req/sec (0.6s sleep).")
        log.warning("  Register free key at https://nvd.nist.gov/developers/request-an-api-key")

    nvd_query = {
        "bool": {
            "should": [
                {"bool": {"must_not": {"exists": {"field": "nvd_fetched_at"}}}},
                {"bool": {"must": [
                    {"term":  {"nvd_enriched": False}},
                    {"range": {"nvd_fetched_at": {"lte": f"now-{NVD_RETRY_DAYS}d"}}},
                ]}},
            ],
            "minimum_should_match": 1,
        }
    }

    cve_to_doc_id: dict[str, str] = {}
    search_after = None

    while True:
        kwargs: dict = {
            "size":    500,
            "source":  ["ioc_value"],
            "query":   nvd_query,
            "sort":    [{"ioc_value": "asc"}],
        }
        if search_after:
            kwargs["search_after"] = search_after

        try:
            resp = es.search(index="ti_cve", **kwargs)
        except Exception as e:
            log.warning(f"  ti_cve query failed: {e}")
            return

        hits = resp["hits"]["hits"]
        if not hits:
            break

        if search_after is None:
            total = resp["hits"]["total"]["value"]
            if total == 0:
                log.info("  All CVEs already enriched or retried recently — skipping NVD fetch ")
                return
            log.info(f"  CVEs to process: {total} "
                     f"(new + retries after {NVD_RETRY_DAYS}d)")

        for hit in hits:
            cve_id = hit["_source"].get("ioc_value", "").upper()
            if cve_id.startswith("CVE-"):
                cve_to_doc_id[cve_id] = hit["_id"]

        search_after = hits[-1]["sort"]
        if len(hits) < 500:
            break

    if not cve_to_doc_id:
        log.info("  Nothing to enrich.")
        return

    log.info(f"  Fetching {len(cve_to_doc_id)} CVEs individually from NVD ...")

    updates:          list[dict] = []
    total_cves        = len(cve_to_doc_id)
    total_enriched    = 0
    total_no_data     = 0
    total_api_failure = 0
    now_ts            = datetime.now(timezone.utc).isoformat()

    for i, (cve_id, doc_id) in enumerate(cve_to_doc_id.items(), 1):
        item = _nvd_fetch_single(cve_id)

        if item is None:
            total_api_failure += 1
        else:
            cwes = _parse_cwes(item)
            cvss = _parse_cvss(item)

            if cwes or cvss:
                total_enriched += 1
                update: dict = {
                    "_id":            doc_id,
                    "nvd_enriched":   True,
                    "nvd_fetched_at": now_ts,
                }
                if cwes:
                    update["cwes"] = cwes
                if cvss:
                    update.update(cvss)
                updates.append(update)
            else:
                total_no_data += 1
                updates.append({
                    "_id":            doc_id,
                    "nvd_enriched":   False,
                    "nvd_fetched_at": now_ts,
                })

        if len(updates) >= 100:
            _bulk_update(es, "ti_cve", updates)
            updates = []

        if i % 100 == 0 or i == total_cves:
            log.info(f"  Progress: {i}/{total_cves} | "
                     f"enriched: {total_enriched} | "
                     f"no data (retry in {NVD_RETRY_DAYS}d): {total_no_data} | "
                     f"api failures (retry next run): {total_api_failure}")

        time.sleep(NVD_SLEEP)

    if updates:
        _bulk_update(es, "ti_cve", updates)

    log.info(f"  Done: {total_enriched} enriched | "
             f"{total_no_data} pending NVD data | "
             f"{total_api_failure} API failures ")

# OWASP TOP 10 version: 2021
_OWASP_CATEGORIES = {
    "A01": {"id": "A01", "name": "Broken Access Control",              "risk": "Critical"},
    "A02": {"id": "A02", "name": "Cryptographic Failures",             "risk": "High"},
    "A03": {"id": "A03", "name": "Injection",                          "risk": "Critical"},
    "A04": {"id": "A04", "name": "Insecure Design",                    "risk": "High"},
    "A05": {"id": "A05", "name": "Security Misconfiguration",          "risk": "High"},
    "A06": {"id": "A06", "name": "Vulnerable and Outdated Components", "risk": "High"},
    "A07": {"id": "A07", "name": "Auth Failures",                      "risk": "Critical"},
    "A08": {"id": "A08", "name": "Software Integrity Failures",        "risk": "High"},
    "A09": {"id": "A09", "name": "Logging and Monitoring Failures",    "risk": "Medium"},
    "A10": {"id": "A10", "name": "Server-Side Request Forgery",        "risk": "Critical"},
}

_CWE_GROUPS = {
    "A01": [22, 59, 200, 201, 276, 284, 285, 352, 359, 377, 402, 425, 441, 497, 538, 540, 548, 552, 566, 601, 639, 651, 668, 706],
    "A02": [261, 296, 310, 311, 312, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 347, 523, 720, 757, 759, 760, 780, 818, 916],
    "A03": [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 116, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917],
    "A04": [73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 362, 440, 489, 657, 840, 841],
    "A05": [2, 11, 13, 15, 16, 260, 315, 520, 526, 537, 541, 547, 611, 614, 756, 776, 942, 1021, 1173],
    "A06": [1035, 1104],
    "A07": [255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 303, 304, 305, 306, 307, 308, 309, 340, 549, 592, 603, 620, 640, 798, 940, 1216],
    "A08": [345, 353, 426, 494, 502, 565, 784, 829, 830, 915],
    "A09": [117, 223, 532, 778],
    "A10": [918],
}

CWE_TO_OWASP = {
    f"CWE-{cwe}": _OWASP_CATEGORIES[cat]
    for cat, cwes in _CWE_GROUPS.items()
    for cwe in cwes
}

_URL_MITRE_PATTERNS = [
    (re.compile(r"(union\s+select|select\s+\*|drop\s+table|insert\s+into)", re.I),
     {"id": "A03", "name": "Injection",                   "risk": "Critical", "pattern": "SQL Injection"}),
    (re.compile(r"(<script|javascript:|onerror=|onload=|alert\()", re.I),
     {"id": "A03", "name": "Injection",                   "risk": "Critical", "pattern": "XSS"}),
    (re.compile(r"(eval\(|exec\(|system\(|passthru\(|shell_exec)", re.I),
     {"id": "A03", "name": "Injection",                   "risk": "Critical", "pattern": "Command Injection"}),
    (re.compile(r"(\.\./|\.\.\\|%2e%2e)", re.I),
     {"id": "A01", "name": "Broken Access Control",       "risk": "Critical", "pattern": "Path Traversal"}),
    (re.compile(r"(/etc/passwd|/etc/shadow|/proc/self|/var/log)", re.I),
     {"id": "A01", "name": "Broken Access Control",       "risk": "Critical", "pattern": "LFI"}),
    (re.compile(r"(file=https?://|url=https?://[^/]|path=https?://|ssrf|gopher://|dict://)", re.I),
     {"id": "A10", "name": "Server-Side Request Forgery", "risk": "Critical", "pattern": "SSRF"}),
    (re.compile(r"(phish|login|signin|account|verify|secure|update).*\.(tk|ml|ga|cf|gq)", re.I),
     {"id": "A05", "name": "Security Misconfiguration",   "risk": "High",     "pattern": "Phishing Domain"}),
    (re.compile(r"(admin|wp-admin|administrator|manager|console)", re.I),
     {"id": "A05", "name": "Security Misconfiguration",   "risk": "High",     "pattern": "Admin Panel Exposure"}),
    (re.compile(r"(\.git/|\.env|\.htaccess|web\.config|dockerfile)", re.I),
     {"id": "A05", "name": "Security Misconfiguration",   "risk": "High",     "pattern": "Sensitive File Exposure"}),
    (re.compile(r"(deseria|pickle|ysoserial|java\.lang\.runtime)", re.I),
     {"id": "A08", "name": "Software Integrity Failures", "risk": "High",     "pattern": "Deserialization"}),
    (re.compile(r"(password|passwd|credential|token|api.key|apikey)", re.I),
     {"id": "A07", "name": "Auth Failures",               "risk": "Critical", "pattern": "Credential Harvesting"}),
    (re.compile(r"(npm|pypi|package\.json|requirements\.txt|dependency|update\.json)", re.I),
     {"id": "A08", "name": "Software Integrity Failures", "risk": "High",     "pattern": "Supply Chain"}),
    (re.compile(r"(miner|stratum\+|coinhive|cryptonight|xmrig)", re.I),
     {"id": "A08", "name": "Software Integrity Failures", "risk": "High",     "pattern": "Cryptomining"}),
]

_URL_PATTERN_TO_MITRE: dict[str, dict] = {
    "SQL Injection":        {"id": "T1190", "name": "Exploit Public-Facing Application",
                             "tactic": ["Initial Access"],
                             "url": "https://attack.mitre.org/techniques/T1190"},
    "XSS":                  {"id": "T1059", "name": "Command and Scripting Interpreter",
                             "tactic": ["Execution"],
                             "url": "https://attack.mitre.org/techniques/T1059"},
    "Command Injection":    {"id": "T1059", "name": "Command and Scripting Interpreter",
                             "tactic": ["Execution"],
                             "url": "https://attack.mitre.org/techniques/T1059"},
    "Path Traversal":       {"id": "T1083", "name": "File and Directory Discovery",
                             "tactic": ["Discovery"],
                             "url": "https://attack.mitre.org/techniques/T1083"},
    "LFI":                  {"id": "T1005", "name": "Data from Local System",
                             "tactic": ["Collection"],
                             "url": "https://attack.mitre.org/techniques/T1005"},
    "SSRF":                 {"id": "T1190", "name": "Exploit Public-Facing Application",
                             "tactic": ["Initial Access"],
                             "url": "https://attack.mitre.org/techniques/T1190"},
    "Credential Harvesting":{"id": "T1078", "name": "Valid Accounts",
                             "tactic": ["Defense Evasion", "Persistence"],
                             "url": "https://attack.mitre.org/techniques/T1078"},
    "Deserialization":      {"id": "T1211", "name": "Exploitation for Defense Evasion",
                             "tactic": ["Defense Evasion"],
                             "url": "https://attack.mitre.org/techniques/T1211"},
    "Supply Chain":         {"id": "T1195", "name": "Supply Chain Compromise",
                             "tactic": ["Initial Access"],
                             "url": "https://attack.mitre.org/techniques/T1195"},
    "Cryptomining":         {"id": "T1496", "name": "Resource Hijacking",
                             "tactic": ["Impact"],
                             "url": "https://attack.mitre.org/techniques/T1496"},
    "Admin Panel Exposure": {"id": "T1078", "name": "Valid Accounts",
                             "tactic": ["Defense Evasion"],
                             "url": "https://attack.mitre.org/techniques/T1078"},
}

# OWASP Top 10 enrichment

def enrich_owasp(src: dict) -> dict | None:
    if src.get("ioc_type") != "cve":
        return None

    raw_cwes = src.get("cwes", [])
    if isinstance(raw_cwes, str):
        raw_cwes = [raw_cwes]

    cat_matches: dict[str, dict] = {}

    for cwe in raw_cwes:
        cwe_id = str(cwe).strip().upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"
        if cwe_id not in CWE_TO_OWASP:
            continue
        cat = CWE_TO_OWASP[cwe_id]
        cat_id = cat["id"]
        if cat_id not in cat_matches:
            cat_matches[cat_id] = {**cat, "matched_cwes": []}
        cat_matches[cat_id]["matched_cwes"].append(cwe_id)

    if not cat_matches:
        return None

    matches      = list(cat_matches.values())
    risk_order   = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    highest_risk = max(matches, key=lambda m: risk_order.get(m.get("risk", "Low"), 0))

    return {
        "categories":     matches,
        "highest_risk":   highest_risk["risk"],
        "category_ids":   [m["id"] for m in matches],
        "category_names": [m["name"] for m in matches],
    }
# MITRE ATT&CK
DEFAULT_TECHNIQUES: dict[str, dict] = {
    "ip":         {"id": "T1071", "name": "Application Layer Protocol",
                   "tactic": ["Command And Control"],
                   "url": "https://attack.mitre.org/techniques/T1071",
                   "is_default": True},
    "url":        {"id": "T1189", "name": "Drive-by Compromise",
                   "tactic": ["Initial Access"],
                   "url": "https://attack.mitre.org/techniques/T1189",
                   "is_default": True},
    "hash":       {"id": "T1204", "name": "User Execution",
                   "tactic": ["Execution"],
                   "url": "https://attack.mitre.org/techniques/T1204",
                   "is_default": True},
    "domain":     {"id": "T1566", "name": "Phishing",
                   "tactic": ["Initial Access"],
                   "url": "https://attack.mitre.org/techniques/T1566",
                   "is_default": True},
    "cve":        {"id": "T1190", "name": "Exploit Public-Facing Application",
                   "tactic": ["Initial Access"],
                   "url": "https://attack.mitre.org/techniques/T1190",
                   "is_default": True},
    "ransomware": {"id": "T1486", "name": "Data Encrypted for Impact",
                   "tactic": ["Impact"],
                   "url": "https://attack.mitre.org/techniques/T1486",
                   "is_default": True},
    "wallet":     {"id": "T1657", "name": "Financial Theft",
                   "tactic": ["Impact"],
                   "url": "https://attack.mitre.org/techniques/T1657",
                   "is_default": True},
}

_SKIP_CANDIDATES = frozenset([
    "compromised", "botnet-c2", "attacker", "emerging-threats",
    "ssl-blacklist", "malware", "unknown malware", "unknown",
    "threat", "forwarded", "news", "indicator", "c&c", "c2",
])

_MALWARE_SUFFIXES = (
    " c&c", " c2", " rat", " stealer", " loader",
    " downloader", " backdoor", " trojan", " botnet",
    " ransomware", " worm", " rootkit", " apt",
)

_ALIAS_GROUPS: dict[str, list[str]] = {
    "cobalt strike":    ["cobaltstrike", "cobalt strike c&c"],
    "doublepulsar":     ["double pulsar"],
    "gootloader":       ["gootkit", "gootkit c&c"],
    "orcus":            ["orcusrat", "orcus rat"],
    "zeus panda":       ["pandazeus", "panda zeus"],
    "qakbot":           ["quakbot", "quakbot c&c"],
    "torrentlocker":    ["torrent locker"],
    "dcrat":            ["dcrat c&c"],
    "netsupportmanager":["net support manager", "netsupportmanager rat"],
    "lumma stealer":    ["lummastealer", "lumma stealer c&c", "lummac2", "lummac"],
    "icedid":           ["iced id"],
    "rhadamanthys":     [],
    "bitrat":           ["bit rat"],
    "xworm":            [],
    "havoc":            [],
    "connectwise rav":  ["connectwise", "connectwise c&c"],
    "meterpreter":      [],
    "sliver":           [],
    "remcos":           ["remcos rat"],
    "asyncrat":         ["async rat", "asyncrat c&c"],
    "bashlite":         ["gafgyt", "lizkebab", "qbot", "torlus", "bashlite c&c"],
    "xtremrat":         ["xtreme rat", "xtrem rat"],
    "hook":             ["hook android", "hook rat"],
    "lockbit":          [],
    "blackcat":         ["alphv", "noberus"],
    "clop":             ["cl0p", "ta505"],
    "royal":            [],
    "black basta":      ["blackbasta"],
    "akira":            [],
    "play":             ["playcrypt"],
    "rhysida":          [],
    "hunters international": ["hunters int", "hunters"],
    "8base":            [],
    "meow":             ["meowleaks"],
    "incransom":        ["inc ransom"],
    "medusa":           ["medusalocker"],
    "ransomhub":        ["ransom hub"],
    "dragonforce":      ["dragon force"],
    "fog":              [],
    "qilin":            ["agenda"],
    "cactus":           [],
    "darkside":         ["dark side"],
    "revil":            ["sodinokibi", "sodin"],
    "conti":            ["wizard spider"],
    "hive":             [],
    "vice society":     ["vicesociety"],
    "cuba":             ["fidel"],
    "avoslocker":       ["avos locker"],
    "lorenz":           [],
    "nokoyawa":         [],
    "bianlian":         ["bian lian"],
    "maze":             ["maze team"],
    "egregor":          [],
    "netwalker":        ["mailto"],
    "doppelpaymer":     ["doppel paymer", "doppel mafia"],
    "pysa":             ["mespinoza"],
    "grief":            [],
    "mount locker":     ["mountlocker"],
}
_ATTACK_ALIASES: dict[str, str] = {
    variant: canonical
    for canonical, variants in _ALIAS_GROUPS.items()
    for variant in ([canonical] + variants)
}

_VERSION_RE = re.compile(r'\s+[\d]+[\d.]*$')
_SLASH_RE   = re.compile(r'[/\\]')
_CAMEL_RE   = re.compile(r'([a-z])([A-Z])')


def normalize_tactic(t: str) -> str:
    return t.replace("-", " ").title()


def _try_add(name: str, candidates: list[str], seen: set[str]) -> None:
    if not name or len(name) < 3 or name in seen:
        return
    seen.add(name)
    candidates.append(name)
    alias = _ATTACK_ALIASES.get(name)
    if alias and alias not in seen:
        seen.add(alias)
        candidates.append(alias)


def _normalize_malware_name(raw: str) -> list[str]:
    if not raw:
        return []
    base = raw.strip().lower()
    if base in _SKIP_CANDIDATES:
        return []

    candidates: list[str] = []
    seen:       set[str]  = set()

    seen.add(base)
    candidates.append(base)
    alias = _ATTACK_ALIASES.get(base)
    if alias and alias not in seen:
        seen.add(alias)
        candidates.append(alias)

    # Strip known malware-type suffixes
    for suffix in _MALWARE_SUFFIXES:
        if base.endswith(suffix):
            _try_add(base[:-len(suffix)].strip(), candidates, seen)
            break

    stripped = _VERSION_RE.sub("", base).strip()
    if stripped != base:
        _try_add(stripped, candidates, seen)

    if _SLASH_RE.search(base):
        for part in _SLASH_RE.split(base):
            _try_add(part.strip(), candidates, seen)

    spaced = _CAMEL_RE.sub(r'\1 \2', raw).strip().lower()
    if spaced != base:
        _try_add(spaced, candidates, seen)
        for suffix in _MALWARE_SUFFIXES:
            if spaced.endswith(suffix):
                _try_add(spaced[:-len(suffix)].strip(), candidates, seen)
                break

    return candidates


def _check_bundle_version() -> tuple[bool, str]:
    if not os.path.exists(ATTACK_FILE):
        return False, "missing"

    size_mb = os.path.getsize(ATTACK_FILE) / 1_048_576
    if size_mb < ATTACK_MIN_MB:
        log.warning(f"  Bundle too small ({size_mb:.1f} MB < {ATTACK_MIN_MB} MB) — re-downloading")
        return False, "too small"

    try:
        with open(ATTACK_FILE, "r", encoding="utf-8") as f:
            objects = json.load(f).get("objects", [])

        versions: set[str] = set()
        for o in objects:
            if o.get("type") == "x-mitre-collection":
                ver   = o.get("x_mitre_version", "0")
                major = int(str(ver).split(".")[0])
                if major < ATTACK_MIN_VER:
                    log.warning(f"  Bundle is ATT&CK v{ver} — v{ATTACK_MIN_VER}+ required.")
                    return False, f"v{ver}"
                log.info(f"  ATT&CK bundle v{ver} already present — skipping download ")
                return True, f"v{ver}"
            v = o.get("x_mitre_version")
            if v:
                versions.add(str(v))

        if versions:
            ver = sorted(versions, reverse=True)[0]
            log.info(f"  ATT&CK bundle present (inferred v{ver}) — skipping download ")
            return True, f"v{ver}"

        log.warning(f"  ATT&CK bundle present ({size_mb:.1f} MB) — trusting file ")
        return True, "unknown"

    except Exception as e:
        log.warning(f"  Could not parse bundle for version check: {e}")
        if size_mb >= ATTACK_MIN_MB:
            return True, "unknown"
        return False, "parse error"


def download_attack_data() -> str:
    ok, ver = _check_bundle_version()
    if ok:
        return ver

    if os.path.exists(ATTACK_FILE):
        log.warning(f"  Removing bundle ({ver}): {ATTACK_FILE}")
        os.remove(ATTACK_FILE)

    log.info("Downloading MITRE ATT&CK v18.1 data")
    try:
        urllib.request.urlretrieve(ATTACK_URL, ATTACK_FILE)
        size_mb = os.path.getsize(ATTACK_FILE) / 1_048_576
        log.info(f"  Downloaded -> {ATTACK_FILE} ({size_mb:.1f} MB) ")
        _, ver = _check_bundle_version()
        return ver
    except Exception as e:
        log.error(f"  Failed to download ATT&CK bundle: {e}")
        raise

def parse_attack_bundle() -> tuple[dict, dict]:
    log.info("Parsing ATT&CK bundle ...")
    with open(ATTACK_FILE, "r", encoding="utf-8") as f:
        objects = json.load(f).get("objects", [])

    techniques_by_id: dict[str, dict] = {}
    software_by_id:   dict[str, str]  = {}
    groups_by_id:     dict[str, str]  = {}

    bundle_aliases: dict[str, str] = {}

    for o in objects:
        otype = o.get("type")
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        if otype == "attack-pattern":
            refs    = o.get("external_references", [])
            tech_id = next((r.get("external_id", "") for r in refs if r.get("source_name") == "mitre-attack"), "")
            url     = next((r.get("url", "")         for r in refs if r.get("source_name") == "mitre-attack"), "")
            tactics = [normalize_tactic(p.get("phase_name", ""))
                       for p in o.get("kill_chain_phases", [])
                       if p.get("kill_chain_name") == "mitre-attack"]
            techniques_by_id[o["id"]] = {"id": tech_id, "name": o.get("name", ""), "tactic": tactics, "url": url}
        elif otype in ("malware", "tool"):
            name      = o.get("name", "")
            canonical = name.strip().lower()
            software_by_id[o["id"]] = name

            for alias in o.get("x_mitre_aliases", []):
                variant = alias.strip().lower()
                if variant and variant != canonical and variant not in _ATTACK_ALIASES and variant not in bundle_aliases:
                    bundle_aliases[variant] = canonical
        elif otype == "intrusion-set":
            name      = o.get("name", "")
            canonical = name.strip().lower()
            groups_by_id[o["id"]] = name

            for alias in o.get("x_mitre_aliases", []):
                variant = alias.strip().lower()
                if variant and variant != canonical and variant not in _ATTACK_ALIASES and variant not in bundle_aliases:
                    bundle_aliases[variant] = canonical

    sw_to_tech:    dict[str, list] = {}
    sw_to_groups:  dict[str, list] = {}
    group_tech_map: dict[str, list] = {}

    for o in objects:
        if o.get("type") != "relationship" or o.get("revoked"):
            continue
        src_ref = o.get("source_ref", "")
        tgt_ref = o.get("target_ref", "")
        if o.get("relationship_type") != "uses":
            continue

        if src_ref in software_by_id and tgt_ref in techniques_by_id:
            sw_to_tech.setdefault(src_ref, []).append(techniques_by_id[tgt_ref])

        if src_ref in groups_by_id and tgt_ref in software_by_id:
            sw_to_groups.setdefault(tgt_ref, []).append(groups_by_id[src_ref])

        if src_ref in groups_by_id and tgt_ref in techniques_by_id:
            gname = groups_by_id[src_ref].lower().strip()
            group_tech_map.setdefault(gname, []).append(techniques_by_id[tgt_ref])

    malware_map: dict[str, list] = {}
    group_map:   dict[str, list] = {}
    for sw_id, sw_name in software_by_id.items():
        key = sw_name.lower().strip()
        if sw_to_tech.get(sw_id):   malware_map[key] = sw_to_tech[sw_id]
        if sw_to_groups.get(sw_id): group_map[key]   = sw_to_groups[sw_id]

    for gname, techs in group_tech_map.items():
        if gname not in malware_map:
            malware_map[gname] = techs
        if gname not in group_map:
            display_name = next(
                (v for v in groups_by_id.values() if v.lower().strip() == gname),
                gname.title(),
            )
            group_map[gname] = [display_name]

    _ATTACK_ALIASES.update(bundle_aliases)

    log.info(
        f"  Malware->technique: {len(malware_map)} | "
        f"Malware->groups: {len(group_map)} | "
        f"Bundle aliases loaded: {len(bundle_aliases)}"
    )
    return malware_map, group_map

def enrich_mitre(
    src: dict,
    malware_map: dict,
    group_map: dict,
) -> dict | None:
    ioc_type   = src.get("ioc_type", "")
    raw_values: list[str] = []

    if ioc_type == "ransomware":
        val = src.get("group_name", "")
        if val and isinstance(val, str):
            raw_values.append(val.strip())

    if ioc_type == "wallet":
        for field in ("group_name",):
            val = src.get(field, "")
            if val and isinstance(val, str):
                raw_values.append(val.strip())
        for source in src.get("sources", []):
            val = source.get("group_name", "")
            if val and isinstance(val, str):
                raw_values.append(val.strip())

    for field in ("malware", "threat_type", "malware_printable", "signature"):
        val = src.get(field, "")
        if val and isinstance(val, str):
            raw_values.append(val.strip())

    for source in src.get("sources", []):
        for field in ("malware", "threat"):
            val = source.get(field, "")
            if val and isinstance(val, str):
                raw_values.append(val.strip())

    candidates: list[str] = []
    seen:       set[str]  = set()
    for raw in raw_values:
        for c in _normalize_malware_name(raw):
            if c and c not in seen:
                seen.add(c)
                candidates.append(c)

    techniques:      list[dict] = []
    groups:          list[str]  = []
    matched_malware: str | None = None

    for c in candidates:
        if c in malware_map:
            techniques      = malware_map[c]
            groups          = group_map.get(c, [])
            matched_malware = c
            break

    if not techniques and ioc_type == "url":
        ioc_val    = src.get("ioc_value", "")
        seen_ids:  set[str]   = set()
        url_techs: list[dict] = []
        for pattern, cat in _URL_MITRE_PATTERNS:
            if pattern.search(ioc_val):
                pname = cat.get("pattern", "")
                if pname in _URL_PATTERN_TO_MITRE:
                    tech = _URL_PATTERN_TO_MITRE[pname]
                    if tech["id"] not in seen_ids:
                        seen_ids.add(tech["id"])
                        url_techs.append(tech)
        if url_techs:
            techniques      = url_techs
            matched_malware = f"url-pattern:{','.join(seen_ids)}"

    if not techniques and ioc_type in DEFAULT_TECHNIQUES:
        techniques = [DEFAULT_TECHNIQUES[ioc_type]]

    if not techniques:
        return None

    seen_ids_final: set[str]   = set()
    unique_tech:    list[dict] = []
    for t in techniques:
        tid = t.get("id", "")
        if tid and tid not in seen_ids_final:
            seen_ids_final.add(tid)
            unique_tech.append(t)
    unique_tech = unique_tech[:10]

    tactics = list({
        tac
        for t in unique_tech
        for tac in (t["tactic"] if isinstance(t["tactic"], list) else [t["tactic"]])
        if tac
    })

    all_default = all(t.get("is_default", False) for t in unique_tech)

    return {
        "techniques":      unique_tech,
        "tactics":         tactics,
        "groups":          list(dict.fromkeys(groups))[:10],
        "matched_malware": matched_malware,
        "technique_count": len(unique_tech),
        "tactic_count":    len(tactics),
        "is_default":      all_default,
    }

# SCORE CONTEXT PRE-COMPUTATION
CRITICAL_SECTORS: frozenset[str] = frozenset([
    "healthcare", "health", "energy", "finance",
    "financial", "hospital", "government",
])

def _scroll_ransomware(es) -> list:
    hits_all  = []
    scroll_id = None
    try:
        resp = es.search(
            index="ti_ransomware",
            query={"match_all": {}},
            size=SCROLL_SIZE,
            scroll=SCROLL_TIMEOUT,
        )
        scroll_id = resp["_scroll_id"]
        hits      = resp["hits"]["hits"]
        while hits:
            hits_all.extend(hits)
            resp      = es.scroll(scroll_id=scroll_id, scroll=SCROLL_TIMEOUT)
            scroll_id = resp["_scroll_id"]
            hits      = resp["hits"]["hits"]
    except Exception as e:
        log.warning(f"  Could not scroll ti_ransomware: {e}")
    finally:
        if scroll_id:
            try:
                es.clear_scroll(scroll_id=scroll_id)
            except Exception:
                pass
    return hits_all

def _parse_date_flexible(value: str) -> datetime | None:
    if not value:
        return None
    value = value.strip().replace("Z", "+00:00")
    for fmt in (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None

def build_ransomware_context_map(es) -> dict:
    log.info("=" * 55)
    log.info("PART 4: Building ransomware context map from ti_ransomware ...")
    log.info("=" * 55)

    now      = datetime.now(timezone.utc)
    cutoff   = now - timedelta(days=30)
    raw_hits = _scroll_ransomware(es)
    log.info(f"  Scrolled {len(raw_hits)} ti_ransomware docs")

    groups: dict[str, dict] = {}
    for hit in raw_hits:
        src   = hit.get("_source", {})
        gname = (src.get("group_name") or "").strip().lower()
        if not gname:
            continue
        gname = _ATTACK_ALIASES.get(gname, gname)
        sector   = (src.get("activity") or "").strip().lower()
        seen_raw = src.get("first_seen")

        if gname not in groups:
            groups[gname] = {"critical_sector": False, "latest_seen": None, "monthly_count": 0}
        g = groups[gname]

        if sector and any(s in sector for s in CRITICAL_SECTORS):
            g["critical_sector"] = True

        dt = _parse_date_flexible(str(seen_raw)) if seen_raw else None
        if dt is not None:
            if g["latest_seen"] is None or dt > g["latest_seen"]:
                g["latest_seen"] = dt
            if dt >= cutoff:
                g["monthly_count"] += 1

    for g in groups.values():
        g["active_days"] = (now - g["latest_seen"]).days if g["latest_seen"] else -1

    log.info(f"  Loaded {len(groups)} distinct ransomware groups")
    return groups

def compute_score_fields(src: dict, group_context_map: dict, doc_id: str = "") -> dict:
    ioc_type     = src.get("ioc_type", "")
    weight       = src.get("ioc_type_weight", 50)
    confidence   = src.get("source_confidence", 0.50)
    source_count = src.get("source_count", 1)

    tier      = src.get("source_tier", "tier3")
    tier_mult = _get_tier_multiplier(tier, doc_id)
    pre_score = round(weight * confidence * tier_mult, 2)

    enriched_mitre = (src.get("enriched") or {}).get("mitre") or {}
    mitre_groups   = enriched_mitre.get("groups") or []
    tech_count     = enriched_mitre.get("technique_count") or 0

    corrob_bonus = min((source_count - 1) * 5, 15)

    matched_group   = ""
    ransomware_hit  = False
    critical_sector = False
    active_days     = -1
    monthly_count   = 0

    for g in mitre_groups:
        key       = g.strip().lower()
        alias_key = _ATTACK_ALIASES.get(key, key)
        lookups = [alias_key] if alias_key == key else [alias_key, key]
        for lookup in lookups:
            if lookup in group_context_map:
                gdata           = group_context_map[lookup]
                matched_group   = g
                ransomware_hit  = True
                critical_sector = gdata["critical_sector"]
                active_days     = gdata["active_days"]
                monthly_count   = gdata["monthly_count"]
                break
        if ransomware_hit:
            break

    boost = corrob_bonus
    if ransomware_hit:        boost += 20
    if critical_sector:       boost += 15
    if 0 <= active_days < 30: boost += 10
    if monthly_count >= 5:    boost += 10
    if tech_count >= 5:       boost += 10

    if ioc_type == "ransomware" and not ransomware_hit and not group_context_map:
        sector          = (src.get("activity") or "").lower()
        critical_sector = any(s in sector for s in CRITICAL_SECTORS)
        matched_group   = src.get("group_name", "")
        ransomware_hit  = bool(matched_group)
        if ransomware_hit:  boost += 20
        if critical_sector: boost += 15
        if tech_count >= 5: boost += 10

    enriched_score = round(min(pre_score + boost, 100), 2)

    return {
        "pre_score":            pre_score,
        "tier_multiplier":      tier_mult,
        "corroboration_bonus":  corrob_bonus,
        "ransomware_matched":   ransomware_hit,
        "ransomware_group":     matched_group,
        "critical_sector":      critical_sector,
        "group_active_days":    active_days,
        "monthly_victim_count": monthly_count,
        "technique_count":      tech_count,
        "context_boost":        boost,
        "enriched_score":       enriched_score,
        "scored_at":            datetime.now(timezone.utc).isoformat(),
        "has_score":            True,
    }

# ENRICH INDICES
def enrich_index(
    es,
    index:             str,
    malware_map:       dict,
    group_map:         dict,
    group_context_map: dict,
    attack_ver:        str = "unknown",
) -> None:
    log.info(f"{'='*55}")
    log.info(f"Enriching: {index.upper()}")
    log.info(f"{'='*55}")

    scroll_id        = None
    total_read       = 0
    total_enr_real    = 0
    total_enr_default = 0
    enriched_at      = datetime.now(timezone.utc).isoformat()

    enrich_query = {
        "bool": {
            "must_not": {"exists": {"field": "enriched.score.pre_score"}}
        }
    }

    try:
        resp = es.search(
            index=index,
            size=SCROLL_SIZE,
            query=enrich_query,
            scroll=SCROLL_TIMEOUT,
        )
    except Exception as e:
        log.warning(f"  Could not query {index}: {e}")
        return

    scroll_id = resp["_scroll_id"]
    hits      = resp["hits"]["hits"]

    try:
        while hits:
            actions = []
            for hit in hits:
                total_read += 1
                doc_id = hit["_id"]
                src    = hit["_source"]
                mitre  = enrich_mitre(src, malware_map, group_map)
                owasp  = enrich_owasp(src)

                src_with_mitre = dict(src)
                if mitre is not None:
                    src_with_mitre["enriched"] = {"mitre": mitre}
                score = compute_score_fields(src_with_mitre, group_context_map, doc_id)

                if mitre or owasp:
                    mitre_is_default = mitre.get("is_default", False) if mitre else True
                    if not mitre_is_default or owasp is not None:
                        total_enr_real += 1
                    else:
                        total_enr_default += 1

                flat_techniques    = []
                flat_mitre_tactics = []
                flat_owasp_risk    = None

                if mitre:
                    flat_techniques = [
                        {"id": t.get("id", ""), "name": t.get("name", ""),
                         "is_default": t.get("is_default", False)}
                        for t in mitre.get("techniques", [])
                        if t.get("id")
                    ]
                    flat_mitre_tactics = mitre.get("tactics", [])

                if owasp:
                    flat_owasp_risk = owasp.get("highest_risk")

                _enriched_sub: dict[str, Any] = {
                    "mitre":          mitre,
                    "score":          score,
                    "enriched_at":    enriched_at,
                    "attack_version": attack_ver,
                    "has_mitre":      mitre is not None,
                    "has_owasp":      owasp is not None,
                    "has_score":      True,
                }
                if owasp is not None:
                    _enriched_sub["owasp"]              = owasp
                    _enriched_sub["owasp_version"]      = OWASP_VERSION
                    _enriched_sub["owasp_version_note"] = OWASP_VERSION_NOTE

                doc_update: dict[str, Any] = {
                    "enriched": _enriched_sub,
                    # The two fields below are flat top-level copies written for Kibana dashboards and external consumers only.
                    "techniques": flat_techniques,
                    "mitre": {
                        "tactics":    flat_mitre_tactics,
                        "is_default": mitre.get("is_default", True) if mitre else True,
                    },
                    **_DOWNSTREAM_RESET,
                }

                if flat_owasp_risk:
                    doc_update["owasp"] = {"highest_risk": flat_owasp_risk}

                actions.append({
                    "_op_type": "update",
                    "_index":   index,
                    "_id":      doc_id,
                    "doc":      doc_update,
                })

            if actions:
                success, errors = helpers.bulk(es, actions, raise_on_error=False, chunk_size=500)
                for err in errors[:3]:
                    log.warning(f"  Bulk error: {err}")

            resp      = es.scroll(scroll_id=scroll_id, scroll=SCROLL_TIMEOUT)
            scroll_id = resp["_scroll_id"]
            hits      = resp["hits"]["hits"]

    finally:
        if scroll_id:
            try:
                es.clear_scroll(scroll_id=scroll_id)
            except Exception:
                pass

    total_enr = total_enr_real + total_enr_default
    log.info(f"  Read:              {total_read}")
    log.info(f"  Updated (total):   {total_read} — every doc receives score + enriched_at + downstream reset")
    log.info(f"  MITRE/OWASP real:  {total_enr_real} "
             f"({100 * total_enr_real  // max(total_read, 1)}%) — real ATT&CK signal")
    log.info(f"  MITRE/OWASP dflt:  {total_enr_default} "
             f"({100 * total_enr_default // max(total_read, 1)}%) — default/fallback only")
    log.info(f"  Score-only:        {total_read - total_enr} — no MITRE/OWASP match; score fields only")
    if total_enr_default > 0 and total_enr > 0:
        dflt_pct = 100 * total_enr_default // total_enr
        if dflt_pct >= 80:
            log.warning(
                f"   {dflt_pct}% of enriched docs on {index} are default-only — "
                f"check malware field extraction in ti_processor.py"
            )
    log.info(f" {index} enrichment complete")


def main() -> None:
    start = time.time()

    log.info(f"Connecting to Elasticsearch at {ELASTIC_HOST} ...")
    es = Elasticsearch(ELASTIC_HOST, basic_auth=(ELASTIC_USER, ELASTIC_PASSWORD))
    if not es.ping():
        log.error("Cannot connect to Elasticsearch. Exiting.")
        sys.exit(1)
    log.info("Elasticsearch is up ")

    try:
        enrich_cves_with_nvd(es)
    except Exception as e:
        log.error(f"NVD enrichment failed: {e}", exc_info=True)

    attack_ver = download_attack_data()
    log.info(f"  ATT&CK bundle version: {attack_ver}")
    malware_map, group_map = parse_attack_bundle()

    log.info("Pre-enriching ti_ransomware for context map accuracy ...")
    try:
        enrich_index(es, "ti_ransomware", malware_map, group_map, {}, attack_ver)
    except Exception as e:
        log.error(f"ti_ransomware pre-enrichment failed: {e}", exc_info=True)

    try:
        group_context_map = build_ransomware_context_map(es)
    except Exception as e:
        log.error(f"Ransomware context map build failed: {e}", exc_info=True)
        group_context_map = {}

    for index in TARGET_INDICES:
        if index == "ti_ransomware":
            continue
        try:
            enrich_index(es, index, malware_map, group_map, group_context_map, attack_ver)
        except Exception as e:
            log.error(f"Failed {index}: {e}", exc_info=True)

    log.info(f"{'='*55}")
    log.info(f"Enrichment complete in {time.time()-start:.1f}s")
    log.info(f"{'='*55}")

if __name__ == "__main__":
    main()
