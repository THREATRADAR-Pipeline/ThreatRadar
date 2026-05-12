#!/usr/bin/env python3
"""
THREATRADAR TI Processor
Reads raw threat intelligence feeds from Elasticsearch, deduplicates and
normalises them into clean IOC documents, then upserts the results into
the output indices.
© 2026 THREATRADAR Team
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import re
import hashlib
import time
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Generator, Iterator

from elasticsearch import Elasticsearch, helpers
import os
import sys

sys.path.insert(0, "/vx")
from common import _DOWNSTREAM_RESET, OUTPUT_INDICES, TARGET_INDICES

ELASTIC_HOST     = os.environ.get("ELASTIC_HOST", "http://elasticsearch:9200")
ELASTIC_USER     = os.environ.get("ELASTIC_USER", "elastic")
ELASTIC_PASSWORD = os.environ.get("ELASTIC_PASSWORD")
SCROLL_SIZE    = 1000
SCROLL_TIMEOUT = "5m"
RUN_INTERVAL   = 300

RAW_INDICES: dict[str, list[str]] = {
    "ip":         ["ti_feodo-*", "ti_otx-*", "ti_threatfox-*",
                   "ti_et_compromised-*", "ti_et_botnet-*",
                   "ti_ioc_extracted_from_news-*"],
    "url":        ["ti_abuseurl-*", "ti_otx-*", "ti_threatfox-*",
                   "ti_openphish-*",
                   "ti_ioc_extracted_from_news-*"],
    "hash":       ["ti_abusemalware-*", "ti_otx-*", "ti_threatfox-*",
                   "ti_sslbl-*",
                   "ti_ioc_extracted_from_news-*"],
    "domain":     ["ti_otx-*", "ti_threatfox-*",
                   "ti_certpl-*",
                   "ti_ioc_extracted_from_news-*"],
    "cve":        ["ti_cisa-*",
                   "ti_ioc_extracted_from_news-*"],
    "ransomware": ["ti_ransomware-*"],
    "wallet":     ["ti_ransomwhere-*",
                   "ti_ioc_extracted_from_news-*"],
}

SENTINEL_UNSCORED = "UNSCORED"
SENTINEL_ACTION   = "PENDING"
SENTINEL_KEYWORD  = "UNKNOWN"

SENTINEL_SEVERITY = SENTINEL_UNSCORED
SENTINEL_VERDICT  = SENTINEL_UNSCORED


_ENRICHED_SCORE_RESET: dict = {
    "pre_score":            None,
    "tier_multiplier":      None,
    "corroboration_bonus":  0,
    "ransomware_matched":   False,
    "ransomware_group":     None,
    "critical_sector":      False,
    "group_active_days":    -1,
    "monthly_victim_count": 0,
    "technique_count":      0,
    "context_boost":        0,
    "enriched_score":       None,
    "scored_at":            None,
    "has_score":            False,
}


INTEL_CLASS: dict[str, str] = {
    "ip":         "network_indicator",
    "url":        "network_indicator",
    "hash":       "network_indicator",
    "domain":     "network_indicator",
    "cve":        "vulnerability",
    "ransomware": "threat_actor_activity",
    "wallet":     "financial_indicator",
}


_NULL_TS_SENTINELS: frozenset[str] = frozenset([
    "", "null", "none", "n/a", "na", "unknown", "-", "undefined",
])


def stamp_intel_class(doc: dict, ioc_type: str) -> dict:
    doc["intel_class"] = INTEL_CLASS.get(ioc_type, "network_indicator")
    return doc



SOURCE_CONFIDENCE: dict[str, dict] = {
    "feodo_tracker":    {"confidence": 0.95, "tier": "tier1"},
    "cisa_kev":         {"confidence": 0.95, "tier": "tier1"},
    "ransomwhere":      {"confidence": 0.92, "tier": "tier1"},
    "urlhaus_payloads": {"confidence": 0.90, "tier": "tier1"},
    "openphish":        {"confidence": 0.88, "tier": "tier1"},
    "certpl":           {"confidence": 0.88, "tier": "tier1"},
    "et_botnet":        {"confidence": 0.85, "tier": "tier1"},
    "sslbl":            {"confidence": 0.82, "tier": "tier2"},
    "ransomware_live":  {"confidence": 0.80, "tier": "tier2"},
    "et_compromised":   {"confidence": 0.78, "tier": "tier2"},
    "threatfox":        {"confidence": 0.75, "tier": "tier2"},
    "otx":              {"confidence": 0.60, "tier": "tier2"},
    "rss_extracted":    {"confidence": 0.40, "tier": "tier3"},
}

IOC_TYPE_WEIGHT: dict[str, int] = {
    "ti_wallet":                  92,
    "ti_cisa":                    90,
    "ti_ransomware":              88,
    "ti_feodo":                   85,
    "ti_openphish":               82,
    "ti_certpl":                  82,
    "ti_abuseurl":                80,
    "ti_abusemalware":            80,
    "ti_et_botnet":               78,
    "ti_sslbl":                   72,
    "ti_ip":                      68,
    "ti_url":                     68,
    "ti_hash":                    68,
    "ti_domain":                  68,
    "ti_threatfox":               65,
    "ti_otx":                     62,
    "ti_et_compromised":          60,
    "ti_ioc_extracted_from_news": 45,
}

_DATASET_TO_SOURCE_NAME: dict[str, str] = {
    "ti_feodo":                   "feodo_tracker",
    "ti_cisa":                    "cisa_kev",
    "ti_ransomwhere":             "ransomwhere",
    "ti_abusemalware":            "urlhaus_payloads",
    "ti_openphish":               "openphish",
    "ti_certpl":                  "certpl",
    "ti_et":                      "et_botnet",
    "ti_et_botnet":               "et_botnet",
    "ti_et_compromised":          "et_compromised",
    "ti_sslbl":                   "sslbl",
    "ti_ransomware":              "ransomware_live",
    "ti_threatfox":               "threatfox",
    "ti_otx":                     "otx",
    "ti_abuseurl":                "urlhaus_payloads",
    "ti_ioc_extracted_from_news": "rss_extracted",
}


def resolve_source_name(dataset: str, feed_name: str) -> str:
    if dataset in _DATASET_TO_SOURCE_NAME:
        return _DATASET_TO_SOURCE_NAME[dataset]
    if feed_name and feed_name.lower() in SOURCE_CONFIDENCE:
        return feed_name.lower()
    return "rss_extracted"


def stamp_source_fields(
    doc: dict,
    dataset: str,
    feed_name: str,
    output_index: str,
    source_key: str | None = None,
) -> dict:
    sname    = source_key or resolve_source_name(dataset, feed_name)
    src_meta = SOURCE_CONFIDENCE.get(sname, {"confidence": 0.50, "tier": "tier3"})

    weight_key = dataset
    if weight_key not in IOC_TYPE_WEIGHT:
        weight_key = dataset.split("-")[0] if "-" in dataset else dataset

    doc["source_name"]       = sname
    doc["source_confidence"] = src_meta["confidence"]
    doc["source_tier"]       = src_meta["tier"]
    doc["ioc_type_weight"]   = IOC_TYPE_WEIGHT.get(weight_key, 50)
    return doc


def _safe_ts(feed_ts: Any) -> str | None:
    if feed_ts is None:
        return None
    ts_str = str(feed_ts).strip()
    if ts_str.lower() in _NULL_TS_SENTINELS:
        return None
    return ts_str

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("ti_processor")


NULL_HASHES: frozenset[str] = frozenset([
    "d41d8cd98f00b204e9800998ecf8427e",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "0" * 32, "0" * 40, "0" * 64,
    "f" * 32, "f" * 40, "f" * 64,
])

NOISE_DOMAIN_EXACT: frozenset[str] = frozenset([
    "localhost", "localdomain", "local", "internal",
    "example.com", "example.org", "example.net",
    "test.com", "invalid", "arpa",
])

NOISE_DOMAIN_SUFFIXES: tuple[str, ...] = tuple("." + d for d in NOISE_DOMAIN_EXACT)
KNOWN_CDN_SUFFIXES: tuple[str, ...] = (
    ".cloudflare.com", ".akamai.com", ".fastly.com",
    ".cdn.jsdelivr.net", ".ajax.googleapis.com",
)
NOISE_URL_SCHEMES: tuple[str, ...] = ("ftp://", "file://", "data:")

_RE_DOMAIN = re.compile(r'^[a-z0-9]([a-z0-9\-\.]{0,251}[a-z0-9])?$')
_RE_HASH   = re.compile(r'^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$')
_RE_CVE    = re.compile(r'^CVE-\d{4}-\d{4,}$')
_RE_URL_IP = re.compile(r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

_PRIVATE_NETS: tuple = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("255.255.255.0/24"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
)

def is_noise_ip(value: str) -> tuple[bool, str]:
    try:
        ip = ipaddress.ip_address(value.strip())
        if ip.is_loopback:    return True, "loopback"
        if ip.is_multicast:   return True, "multicast"
        if ip.is_unspecified: return True, "unspecified"
        if ip.is_link_local:  return True, "link-local"
        if ip.is_private:     return True, "private"
        for net in _PRIVATE_NETS:
            if ip in net:
                return True, f"reserved ({net})"
    except ValueError:
        return True, "invalid IP format"
    return False, ""


def is_noise_domain(value: str) -> tuple[bool, str]:
    value = value.strip().lower()
    if len(value) < 4:                        return True, "too short"
    if value in NOISE_DOMAIN_EXACT:           return True, "noise domain"
    if value.endswith(NOISE_DOMAIN_SUFFIXES): return True, "noise domain suffix"
    if value.endswith(KNOWN_CDN_SUFFIXES):    return True, "known CDN"
    if "." not in value:                      return True, "no TLD"
    if not _RE_DOMAIN.match(value):           return True, "invalid domain format"
    return False, ""

def is_noise_url(value: str) -> tuple[bool, str]:
    value = value.strip().lower()
    if not value:                           return True, "empty URL"
    if value.startswith(NOISE_URL_SCHEMES): return True, "non-http scheme"
    if not value.startswith("http"):        return True, "missing http scheme"
    m = _RE_URL_IP.match(value)
    if m:
        noisy, reason = is_noise_ip(m.group(1))
        if noisy:
            return True, f"URL points to private IP ({reason})"
    return False, ""

def is_noise_hash(value: str) -> tuple[bool, str]:
    value = value.strip().lower()
    if not value:                 return True, "empty hash"
    if value in NULL_HASHES:      return True, "null/empty hash"
    if not _RE_HASH.match(value): return True, "invalid hash format"
    return False, ""


def is_noise_cve(value: str) -> tuple[bool, str]:
    if not _RE_CVE.match(value.strip().upper()): return True, "invalid CVE format"
    return False, ""


def is_noise_ransomware(value: str) -> tuple[bool, str]:
    value = value.strip()
    if not value:      return True, "empty value"
    if len(value) < 3: return True, "too short"
    return False, ""


def is_noise_wallet(value: str) -> tuple[bool, str]:
    if not value or not value.strip(): return True, "empty wallet"
    return False, ""

_NOISE_FILTERS: dict[str, Any] = {
    "ip":         is_noise_ip,
    "url":        is_noise_url,
    "hash":       is_noise_hash,
    "domain":     is_noise_domain,
    "cve":        is_noise_cve,
    "ransomware": is_noise_ransomware,
    "wallet":     is_noise_wallet,
}


def is_noise(ioc_type: str, ioc_value: str) -> tuple[bool, str]:
    if not ioc_value or not ioc_type:
        return True, "missing ioc_value or ioc_type"
    fn = _NOISE_FILTERS.get(ioc_type)
    if fn is None:
        return True, f"unknown ioc_type: {ioc_type}"
    return fn(ioc_value)


@lru_cache(maxsize=4096)
def parse_message(raw: str) -> dict:
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return {}


def _parse_message_from_src(src: dict) -> dict:
    return parse_message(src.get("message") or "")


def normalize_tags(raw: Any, *extras: str) -> list[str]:
    if isinstance(raw, list):
        tags = [str(t).strip() for t in raw if t]
    elif isinstance(raw, str):
        tags = [t.strip() for t in raw.split(",") if t.strip()]
    else:
        tags = []
    for e in extras:
        if e and e not in tags:
            tags.append(e)
    return tags


def _get_dataset(src: dict) -> str:
    dataset = src.get("event", {}).get("dataset", "")
    if dataset:
        return dataset
    return src.get("fields", {}).get("event", {}).get("dataset", "")


def _get_feed_name(src: dict) -> str:
    name = src.get("threat", {}).get("feed", {}).get("name", "")
    if name:
        return name
    return src.get("fields", {}).get("threat", {}).get("feed", {}).get("name", "Unknown")


def extract_feodo(msg: dict, requested: str) -> list:
    if requested != "ip":
        return []
    malware = msg.get("malware")
    return [(msg.get("ip_address", ""), "ip", {
        "ioc_port":   str(msg["port"]) if msg.get("port") else None,
        "malware":    malware,
        "first_seen": msg.get("first_seen"),
        "tags":       [malware] if malware else [],
    })]


def extract_abuseurl(msg: dict, requested: str) -> list:
    if requested != "url":
        return []
    return [(msg.get("url", ""), "url", {
        "first_seen": msg.get("date_added"),
        "tags":       normalize_tags(msg.get("tags")),
        "threat":     msg.get("threat"),
    })]


def extract_abusemalware(msg: dict, requested: str) -> list:
    if requested != "hash":
        return []
    sha256 = msg.get("sha256_hash", "")
    md5    = msg.get("md5_hash", "")
    val    = sha256 or md5
    return [(val, "hash", {
        "hash_type":  "sha256" if sha256 else "md5",
        "first_seen": msg.get("firstseen"),
        "tags":       [],
    })]


def extract_threatfox(msg: dict, requested: str) -> list:
    if "query_status" in msg:
        return []
    raw_ioc  = msg.get("ioc", "")
    ioc_type = msg.get("ioc_type", "").lower()
    malware  = msg.get("malware_printable") or msg.get("malware")
    tags     = normalize_tags(msg.get("tags"), malware or "")
    extra = {
        "malware":    malware,
        "confidence": msg.get("confidence_level"),
        "first_seen": msg.get("first_seen"),
        "tags":       tags,
    }
    if ioc_type == "ip:port":
        if requested != "ip":
            return []
        if ":" in raw_ioc:
            raw_ioc, port = raw_ioc.rsplit(":", 1)
            extra["ioc_port"] = port
        return [(raw_ioc, "ip", extra)]
    _TYPE_MAP = {
        "domain":      ("domain", None),
        "url":         ("url",    None),
        "md5_hash":    ("hash",   "md5"),
        "sha256_hash": ("hash",   "sha256"),
    }
    mapping = _TYPE_MAP.get(ioc_type)
    if not mapping:
        return []
    target, hash_type = mapping
    if target != requested:
        return []
    if hash_type:
        extra["hash_type"] = hash_type
    return [(raw_ioc, target, extra)]


_OTX_TYPE_MAP: dict[str, str] = {
    "IPv4":            "ip",
    "IPv6":            "ip",
    "domain":          "domain",
    "hostname":        "domain",
    "URL":             "url",
    "FileHash-MD5":    "hash",
    "FileHash-SHA256": "hash",
    "FileHash-SHA1":   "hash",
}
_OTX_HASH_TYPES: dict[str, str] = {
    "FileHash-SHA256": "sha256",
    "FileHash-SHA1":   "sha1",
    "FileHash-MD5":    "md5",
}

def extract_otx(msg: dict, requested: str) -> list:
    msg_type = msg.get("type", "")
    target   = _OTX_TYPE_MAP.get(msg_type)
    if not target or target != requested:
        return []
    extra: dict[str, Any] = {"tags": [], "first_seen": None}
    if target == "hash":
        extra["hash_type"] = _OTX_HASH_TYPES.get(msg_type, "md5")
    return [(msg.get("indicator", ""), target, extra)]

def extract_cisa(msg: dict, requested: str) -> list:
    if requested != "cve":
        return []
    return [(msg.get("cveID", ""), "cve", {
        "vuln_name":       msg.get("vulnerabilityName"),
        "product":         msg.get("product"),
        "vendor":          msg.get("vendorProject"),
        "required_action": msg.get("requiredAction"),
        "due_date":        msg.get("dueDate"),
        "first_seen":      msg.get("dateAdded"),
        "tags":            [],
    })]

def extract_ransomware(msg: dict, requested: str) -> list:
    if requested != "ransomware":
        return []

    if isinstance(msg, list):
        out = []
        for item in msg:
            if isinstance(item, dict):
                out.extend(extract_ransomware(item, requested))
        return out

    val   = (msg.get("website") or msg.get("post_url")
             or msg.get("victim") or msg.get("url") or "")
    group = (msg.get("group_name") or msg.get("group") or "").strip()
    if not group:
        return []
    if not val:
        victim = (msg.get("victim") or msg.get("post_title") or "unknown").strip()
        val = f"{group}::{victim}"
    return [(val, "ransomware", {
        "group_name":  group,
        "post_url":    msg.get("post_url"),
        "post_title":  msg.get("post_title"),
        "country":     msg.get("country"),
        "activity":    msg.get("activity") or msg.get("sector") or "",
        "description": msg.get("description"),
        "first_seen":  (msg.get("discovered") or msg.get("published")
                        or msg.get("date") or msg.get("first_seen")),
        "tags":        [group],
    })]

def extract_et(msg: dict, requested: str) -> list:
    if requested != "ip":
        return []
    category = msg.get("et_category", "emerging-threats")
    return [(msg.get("ip_address", ""), "ip", {
        "first_seen": msg.get("first_seen"),
        "malware":    category,
        "tags":       [category, "emerging-threats"],
    })]

def extract_sslbl(msg: dict, requested: str) -> list:
    if requested != "hash":
        return []
    reason = msg.get("listing_reason", "")
    return [(msg.get("sha1_hash", ""), "hash", {
        "hash_type":  "sha1",
        "first_seen": msg.get("first_seen") or msg.get("listing_date"),
        "malware":    reason,
        "tags":       normalize_tags(None, "ssl-blacklist", reason),
    })]

def extract_ransomwhere(msg: dict, requested: str) -> list:
    if requested != "wallet":
        return []

    if "result" in msg and not msg.get("address"):
        result_list = msg.get("result")
        if isinstance(result_list, list):
            out = []
            for item in result_list:
                if isinstance(item, dict):
                    out.extend(extract_ransomwhere(item, requested))
            return out
        log.warning(
            "[ransomwhere] 'result' key found but value is not a list: %s",
            type(result_list).__name__,
        )
        return []

    address = msg.get("address", "").strip()
    family  = msg.get("family", "").strip()
    crypto  = (msg.get("blockchain") or msg.get("cryptocurrency") or "BTC").strip()
    if not address:
        log.debug(
            "[ransomwhere] Skipping record with empty address. Keys present: %s",
            list(msg.keys())[:10],
        )
        return []
    return [(address, "wallet", {
        "wallet_type": crypto,
        "malware":     family,
        "group_name":  family,
        "first_seen":  msg.get("createdAt") or msg.get("created_at"),
        "tags":        normalize_tags(None, family, "ransomware", "ransomwhere") if family
                       else normalize_tags(None, "ransomware", "ransomwhere"),
    })]

def extract_openphish(msg: dict, requested: str) -> list:
    if requested != "url":
        return []
    url = msg.get("url", "").strip()
    if not url:
        return []
    return [(url, "url", {
        "threat":     msg.get("threat_type", "phishing"),
        "first_seen": msg.get("first_seen"),
        "tags":       normalize_tags(None, "phishing", "openphish"),
    })]

def extract_certpl(msg: dict, requested: str) -> list:
    if requested != "domain":
        return []
    domain = msg.get("domain", "").strip().lower()
    if not domain:
        return []
    return [(domain, "domain", {
        "threat":     msg.get("threat_type", "phishing"),
        "first_seen": msg.get("first_seen"),
        "tags":       normalize_tags(None, "phishing", "cert-pl"),
    })]

def extract_rss_ioc(src: dict, requested: str) -> list:
    ioc_type  = src.get("ioc_type", "").lower()
    ioc_value = src.get("ioc_value", "").strip()
    if not ioc_value or ioc_type != requested:
        return []
    extra: dict[str, Any] = {
        "first_seen": src.get("first_seen"),
        "tags":       ["rss-extracted", "osint"],
    }
    if ioc_type == "hash"   and src.get("hash_type"):
        extra["hash_type"]   = src["hash_type"]
    if ioc_type == "wallet" and src.get("wallet_type"):
        extra["wallet_type"] = src["wallet_type"]
    return [(ioc_value, ioc_type, extra)]


_DATASET_EXTRACTORS: dict[str, Any] = {
    "ti_feodo":                   extract_feodo,
    "ti_abuseurl":                extract_abuseurl,
    "ti_abusemalware":            extract_abusemalware,
    "ti_threatfox":               extract_threatfox,
    "ti_otx":                     extract_otx,
    "ti_cisa":                    extract_cisa,
    "ti_ransomware":              extract_ransomware,
    "ti_et":                      extract_et,
    "ti_et_botnet":               extract_et,
    "ti_et_compromised":          extract_et,
    "ti_sslbl":                   extract_sslbl,
    "ti_ransomwhere":             extract_ransomwhere,
    "ti_openphish":               extract_openphish,
    "ti_certpl":                  extract_certpl,
    "ti_ioc_extracted_from_news": None,
}

_FLAT_DATASETS: frozenset[str] = frozenset({"ti_ransomware", "ti_feodo"})

def extract_iocs_from_hit(hit: dict, requested_type: str) -> list:
    src     = hit["_source"]
    dataset = _get_dataset(src)

    if dataset == "ti_ioc_extracted_from_news":
        return extract_rss_ioc(src, requested_type)

    extractor = _DATASET_EXTRACTORS.get(dataset)
    if extractor is None:
        return []

    msg = _parse_message_from_src(src)

    if dataset in _FLAT_DATASETS:
        return extractor(msg if msg else src, requested_type)

    if not msg:
        return []
    return extractor(msg, requested_type)

_BASE_PROPERTIES: dict = {

    "ioc_value":           {"type": "keyword"},
    "ioc_type":            {"type": "keyword"},
    "tags":                {"type": "keyword"},
    "malware":             {"type": "keyword"},
    "confidence":          {"type": "integer"},
    "feed_dataset":        {"type": "keyword"},
    "threat_type":         {"type": "keyword"},

    "source_count":        {"type": "integer"},
    "source_names":        {"type": "keyword"},
    "source_name":         {"type": "keyword"},
    "source_confidence":   {"type": "float"},
    "source_tier":         {"type": "keyword"},
    "ioc_type_weight":     {"type": "integer"},

    "first_seen":          {"type": "date", "ignore_malformed": True},
    "last_seen":           {"type": "date", "ignore_malformed": True},
    "processed_at":        {"type": "date"},

    "sources": {
        "type": "nested",
        "properties": {
            "feed_name":       {"type": "keyword"},
            "feed_reputation": {"type": "float"},
            "dataset":         {"type": "keyword"},
            "raw_index":       {"type": "keyword"},
            "first_seen":      {"type": "date", "ignore_malformed": True},
            "tags":            {"type": "keyword"},
            "malware":         {"type": "keyword"},
            "threat":          {"type": "keyword"},
        }
    },

    "intel_class":         {"type": "keyword"},

    "cortex_analyzed":     {"type": "boolean"},
    "cortex_analyzed_at":  {"type": "date"},
    "scoring_timestamp":   {"type": "date"},
    "cortex_verdict":      {"type": "keyword"},
    "cortex_score":        {"type": "float"},
    "cortex_final_score":  {"type": "float"},
    "cortex_severity":     {"type": "keyword"},
    "cortex_action":       {"type": "keyword"},
    "cortex_analyzers": {
        "type": "nested",
        "properties": {
            "name":       {"type": "keyword"},
            "result":     {"type": "keyword"},
            "confidence": {"type": "integer"},
        }
    },

    "final_score":         {"type": "float"},
    "verdict":             {"type": "keyword"},
    "severity":            {"type": "keyword"},
    "action":              {"type": "keyword"},
    "has_score":           {"type": "boolean"},
    "actor_danger_score":  {"type": "float"},
    "actor_threat_level":  {"type": "keyword"},
    "intel_type":          {"type": "keyword"},
    "score_type":          {"type": "keyword"},
    "score_meaning":       {"type": "keyword"},
    "score_breakdown": {
        "properties": {
            "cortex_score_raw":    {"type": "float"},
            "context_boost":       {"type": "integer"},
            "source_confidence":   {"type": "float"},
            "pre_multiplied":      {"type": "float"},
            "final_capped":        {"type": "float"},
            "ransomware_group":    {"type": "keyword"},
            "corroboration_bonus": {"type": "integer"},
            "analyzer_detail":     {"type": "object", "enabled": False},
        }
    },

    "ml_score":                 {"type": "float"},
    "poisoning_flagged":        {"type": "boolean"},
    "infrastructure_age_days":  {"type": "integer"},
    "ml_tier":                  {"type": "keyword"},
    "llm_confidence":           {"type": "integer"},
    "llm_verdict":              {"type": "keyword"},
    "llm_contradiction_class":  {"type": "keyword"},
    "llm_poison_score":         {"type": "float"},
    "llm_contradictions_found": {"type": "object",  "enabled": False},
    "llm_coherence_reasoning":  {"type": "text",    "index": False},
    "llm_red_flags":            {"type": "keyword"},
    "llm_analyst_challenge":    {"type": "text",    "index": False},
    "llm_raw_response":         {"type": "text",    "index": False},
    "contradictions_count":     {"type": "integer"},
    "composite_poison_score":   {"type": "float"},
    "final_action":             {"type": "keyword"},
    "final_likelihood":         {"type": "keyword"},
    "fusion_confidence":        {"type": "float"},
    "fusion_reasoning":         {"type": "text"},
    "analysis_ts":              {"type": "date"},

    "pushed_to_misp":           {"type": "boolean"},
    "misp_push_timestamp":      {"type": "date"},
    "misp_event_id":            {"type": "keyword"},
    "misp_push_failed":         {"type": "boolean"},
    "misp_push_error":          {"type": "keyword"},
    "misp_push_fail_count":     {"type": "integer"},
    "misp_push_fail_at":        {"type": "date"},
    "analyst_confirmed":        {"type": "boolean"},
    "misp_sightings":           {"type": "integer"},
    "sighting_updated_at":      {"type": "date"},
    "enriched_at":              {"type": "date"},
    "owasp": {
        "properties": {
            "highest_risk": {"type": "keyword"},
        }
    },
    "techniques": {
        "properties": {
            "id":         {"type": "keyword"},
            "name":       {"type": "keyword"},
            "is_default": {"type": "boolean"},
        }
    },
    "mitre": {
        "properties": {
            "tactics": {"type": "keyword"},
        }
    },

    "enriched": {
        "properties": {
            "has_mitre":          {"type": "boolean"},
            "has_owasp":          {"type": "boolean"},
            "has_score":          {"type": "boolean"},
            "enriched_at":        {"type": "date"},
            "attack_version": {
                "type": "text",
                "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}
            },
            "mitre": {
                "properties": {
                    "matched_malware": {"type": "keyword"},
                    "tactics":         {"type": "keyword"},
                    "groups":          {"type": "keyword"},
                    "technique_count": {"type": "integer"},
                    "tactic_count":    {"type": "integer"},
                    "is_default":      {"type": "boolean"},
                    "techniques": {
                        "type": "nested",
                        "properties": {
                            "id":         {"type": "keyword"},
                            "name":       {"type": "text"},
                            "tactic":     {"type": "keyword"},
                            "url":        {"type": "keyword"},
                            "is_default": {"type": "boolean"},
                        }
                    },
                }
            },
            "score": {
                "properties": {
                    "pre_score":            {"type": "float"},
                    "tier_multiplier":      {"type": "float"},
                    "corroboration_bonus":  {"type": "integer"},
                    "ransomware_matched":   {"type": "boolean"},
                    "ransomware_group":     {"type": "keyword"},
                    "critical_sector":      {"type": "boolean"},
                    "group_active_days":    {"type": "integer"},
                    "monthly_victim_count": {"type": "integer"},
                    "technique_count":      {"type": "integer"},
                    "context_boost":        {"type": "integer"},
                    "enriched_score":       {"type": "float"},
                    "scored_at":            {"type": "date"},
                    "has_score":            {"type": "boolean"},
                }
            },
        }
    },
}


_IP_EXTRA: dict = {
    "ioc_port":     {"type": "keyword"},
    "ioc_port_int": {"type": "integer"},
    "country":      {"type": "keyword"},
}

_URL_EXTRA: dict = {
    "ioc_port":     {"type": "keyword"},
    "ioc_port_int": {"type": "integer"},
}

_HASH_EXTRA: dict = {
    "hash_type": {"type": "keyword"},
}

_DOMAIN_EXTRA: dict = {

    "country": {"type": "keyword"},
}

_CVE_EXTRA: dict = {
    "nvd_enriched":        {"type": "boolean"},
    "nvd_fetched_at":      {"type": "date"},
    "cvss_score":          {"type": "float"},
    "cvss_severity":       {"type": "keyword"},
    "cvss_vector":         {"type": "keyword"},
    "cvss_version":        {"type": "keyword"},
    "cvss_exploitability": {"type": "float"},
    "cvss_impact":         {"type": "float"},
    "cwes":                {"type": "keyword"},
    "vuln_name":           {"type": "text"},
    "product":             {"type": "keyword"},
    "vendor":              {"type": "keyword"},
    "due_date":            {"type": "keyword"},
    "required_action":     {"type": "text"},

    "owasp": {
        "properties": {
            "highest_risk": {"type": "keyword"},
        }
    },
}

_RANSOMWARE_EXTRA: dict = {
    "group_name":       {"type": "keyword"},
    "ransomware_group": {"type": "keyword"},
    "ransomware_title": {"type": "text"},
    "post_url":         {"type": "keyword"},
    "post_title":       {"type": "text"},
    "country":          {"type": "keyword"},
    "activity":         {"type": "keyword"},
    "description":      {"type": "text"},
}

_WALLET_EXTRA: dict = {
    "wallet_type":      {"type": "keyword"},
    "group_name":       {"type": "keyword"},
    "ransomware_group": {"type": "keyword"},
    "ransomware_title": {"type": "text"},
}

_CVE_ENRICHED_EXTRA: dict = {
    "owasp_version":      {"type": "keyword"},
    "owasp_version_note": {"type": "text"},
    "owasp": {
        "properties": {
            "highest_risk":   {"type": "keyword"},
            "category_ids":   {"type": "keyword"},
            "category_names": {"type": "keyword"},
            "categories": {
                "type": "nested",
                "properties": {
                    "id":           {"type": "keyword"},
                    "name":         {"type": "keyword"},
                    "risk":         {"type": "keyword"},
                    "pattern":      {"type": "keyword"},
                    "matched_cwes": {"type": "keyword"},
                }
            },
        }
    },
}

def _make_mapping(*extras: dict, enriched_extra: dict | None = None) -> dict:
    props = {**_BASE_PROPERTIES}
    for extra in extras:
        props.update(extra)
    if enriched_extra:
        enriched_props = {**props["enriched"]["properties"]}
        enriched_props.update(enriched_extra)
        props["enriched"] = {"properties": enriched_props}
    return {"mappings": {"properties": props}}


_INDEX_MAPPINGS: dict[str, dict] = {
    "ti_ip":         _make_mapping(_IP_EXTRA),
    "ti_url":        _make_mapping(_URL_EXTRA),
    "ti_hash":       _make_mapping(_HASH_EXTRA),
    "ti_domain":     _make_mapping(_DOMAIN_EXTRA),
    "ti_cve":        _make_mapping(_CVE_EXTRA, enriched_extra=_CVE_ENRICHED_EXTRA),
    "ti_ransomware": _make_mapping(_RANSOMWARE_EXTRA),
    "ti_wallet":     _make_mapping(_WALLET_EXTRA),
}


def _type_specific_fields(ioc_type: str, extra: dict, port_int: int | None) -> dict:
    if ioc_type == "ip":
        return {
            "ioc_port":     extra.get("ioc_port"),
            "ioc_port_int": port_int,
            "country":      extra.get("country"),
        }
    if ioc_type == "url":
        return {
            "ioc_port":     extra.get("ioc_port"),
            "ioc_port_int": port_int,
        }
    if ioc_type == "hash":
        return {
            "hash_type": extra.get("hash_type"),
        }
    if ioc_type == "domain":
        return {
            "country": extra.get("country"),
        }
    if ioc_type == "cve":
        return {
            "nvd_enriched":        False,
            "nvd_fetched_at":      None,
            "cvss_score":          None,
            "cvss_severity":       None,
            "cvss_vector":         None,
            "cvss_version":        None,
            "cvss_exploitability": None,
            "cvss_impact":         None,
            "cwes":                [],
            "vuln_name":           extra.get("vuln_name"),
            "product":             extra.get("product"),
            "vendor":              extra.get("vendor"),
            "due_date":            extra.get("due_date"),
            "required_action":     extra.get("required_action"),
        }
    if ioc_type == "ransomware":
        return {
            "group_name":       extra.get("group_name"),
            "ransomware_group": extra.get("group_name"),
            "ransomware_title": extra.get("post_title"),
            "post_url":         extra.get("post_url"),
            "post_title":       extra.get("post_title"),
            "country":          extra.get("country"),
            "activity":         extra.get("activity", ""),
            "description":      extra.get("description"),
        }
    if ioc_type == "wallet":
        return {
            "wallet_type":      extra.get("wallet_type"),
            "group_name":       extra.get("group_name"),
            "ransomware_group": extra.get("group_name"),
            "ransomware_title": extra.get("post_title"),
        }
    return {}


_STORED_SCRIPT_ID   = "ti_processor_upsert"
_STORED_SCRIPT_BODY = """
    String _toIso(String s) {
        if (s == null) { return null; }
        s = s.trim();
        if (s.length() == 0 || s.equals('null') || s.equals('N/A') ||
            s.equals('n/a')  || s.equals('-')   || s.equals('unknown') ||
            s.equals('none') || s.equals('undefined')) {
            return null;
        }
        if (s.endsWith(' UTC') || s.endsWith(' GMT')) {
            s = s.substring(0, s.length() - 4).trim();
        }
        if (s.contains('T')) {
            boolean hasOffset = s.endsWith('Z') || s.contains('+') ||
                (s.length() > 19 && s.substring(19, 20).equals('-') && s.lastIndexOf('-') > 7);
            if (!hasOffset) { s = s + 'Z'; }
            return s;
        }
        s = s.replace('/', '-');
        if (s.contains(' ') && s.contains('.')) {
            int dotIdx   = s.lastIndexOf('.');
            int spaceIdx = s.indexOf(' ');
            if (dotIdx > spaceIdx) { s = s.substring(0, dotIdx); }
        }
        if (s.length() >= 19 && s.substring(4, 5).equals('-') && s.contains(' ')) {
            return s.replace(' ', 'T') + 'Z';
        }
        if (s.length() == 10) {
            if (s.substring(4, 5).equals('-')) { return s + 'T00:00:00Z'; }
            if (s.substring(2, 3).equals('-')) {
                String d = s.substring(6,10) + '-' + s.substring(3,5) + '-' + s.substring(0,2);
                return d + 'T00:00:00Z';
            }
        }
        if (s.length() >= 10 && s.substring(4, 5).equals('-')) {
            return s.substring(0, 10) + 'T00:00:00Z';
        }
        return null;
    }

    if (ctx._source.sources == null) { ctx._source.sources = []; }
    boolean found = false;
    for (s in ctx._source.sources) {
        if (s.feed_name == params.source.feed_name) { found = true; break; }
    }
    if (!found) {
        ctx._source.sources.add(params.source);
        ctx._source.source_count = ctx._source.sources.length;

        if (ctx._source.source_names == null) { ctx._source.source_names = []; }
        if (!ctx._source.source_names.contains(params.source.feed_name)) {
            ctx._source.source_names.add(params.source.feed_name);
        }

        if (params.source_key != null && params.source_key.length() > 0) {
            if (!ctx._source.source_names.contains(params.source_key)) {
                ctx._source.source_names.add(params.source_key);
            }
        }

        if (ctx._source.tags == null) { ctx._source.tags = []; }
        if (params.source.tags != null) {
            for (t in params.source.tags) {
                if (t != null && t.length() > 0 && !ctx._source.tags.contains(t)) {
                    ctx._source.tags.add(t);
                }
            }
        }

        if (params.source.feed_reputation != null) {
            if (ctx._source.source_confidence == null ||
                params.source.feed_reputation > ctx._source.source_confidence) {
                ctx._source.source_confidence = params.source.feed_reputation;
            }
        }

        if (params.ioc_type_weight != null) {
            if (ctx._source.ioc_type_weight == null ||
                params.ioc_type_weight > ctx._source.ioc_type_weight) {
                ctx._source.ioc_type_weight = params.ioc_type_weight;
            }
        }
    }

    if (ctx._source.last_seen == null) {
        ctx._source.last_seen = params.last_seen;
    } else if (params.last_seen != null && !params.last_seen.equals('')) {
        String existIso = _toIso(ctx._source.last_seen);
        String incomIso = _toIso(params.last_seen);
        if (existIso != null && incomIso != null) {
            try {
                ZonedDateTime existing = ZonedDateTime.parse(existIso);
                ZonedDateTime incoming = ZonedDateTime.parse(incomIso);
                if (incoming.toInstant().toEpochMilli() > existing.toInstant().toEpochMilli()) {
                    ctx._source.last_seen = params.last_seen;
                }
            } catch (Exception e) { }
        }
    }
"""

def register_stored_script(es: Elasticsearch) -> None:
    es.put_script(
        id=_STORED_SCRIPT_ID,
        script={
            "lang":   "painless",
            "source": _STORED_SCRIPT_BODY,
        },
    )
    log.info(f"Stored Painless script registered: {_STORED_SCRIPT_ID}")

def scroll_index(es: Elasticsearch, index_pattern: str) -> Generator:
    scroll_id = None
    try:
        resp = es.search(
            index=index_pattern,
            query={"match_all": {}},
            size=SCROLL_SIZE,
            scroll=SCROLL_TIMEOUT,
        )
        scroll_id = resp["_scroll_id"]
        hits      = resp["hits"]["hits"]
        while hits:
            yield from hits
            resp      = es.scroll(scroll_id=scroll_id, scroll=SCROLL_TIMEOUT)
            scroll_id = resp["_scroll_id"]
            hits      = resp["hits"]["hits"]
    except Exception as e:
        log.warning(f"Could not query {index_pattern}: {e}")
    finally:
        if scroll_id:
            try:
                es.clear_scroll(scroll_id=scroll_id)
            except Exception:
                pass

def register_index_template(es: Elasticsearch) -> None:
    errors_seen = []

    for index, mapping in _INDEX_MAPPINGS.items():
        component_name = f"ti_clean_{index}"
        try:
            es.cluster.put_component_template(
                name=component_name,
                template={"mappings": mapping["mappings"]},
            )
            log.info(f"  Component template registered: {component_name}")
        except Exception as e:
            log.warning(f"  Could not register component template {component_name}: {e}")
            errors_seen.append(component_name)

    for index in _INDEX_MAPPINGS:
        it_name   = f"ti_clean_it_{index}"
        component = f"ti_clean_{index}"
        try:
            es.indices.put_index_template(
                name=it_name,
                index_patterns=[index],
                composed_of=[component],
                priority=200,
            )
            log.info(f"  Index template registered: {it_name} -> {component}")
        except Exception as e:
            log.warning(f"  Could not register index template {it_name}: {e}")
            errors_seen.append(it_name)

    if not errors_seen:
        log.info("All index templates registered successfully ")
    else:
        log.warning(f"Template registration had errors for: {errors_seen}")

def create_index_if_missing(es: Elasticsearch, index: str) -> None:
    if es.indices.exists(index=index):
        return
    mapping = _INDEX_MAPPINGS.get(index, {"mappings": {"properties": _BASE_PROPERTIES}})
    es.indices.create(index=index, mappings=mapping["mappings"])
    log.info(f"Created index: {index}")

def bulk_upsert(es: Elasticsearch, index: str, clean_docs: dict) -> None:
    if not clean_docs:
        return

    def _actions() -> Iterator[dict]:
        for doc in clean_docs.values():
            src        = doc["_source"]
            source_rec = src["sources"][0] if src.get("sources") else {}
            source_key = resolve_source_name(
                source_rec.get("dataset", ""),
                source_rec.get("feed_name", ""),
            )
            yield {
                "_op_type": "update",
                "_index":   index,
                "_id":      doc["_id"],
                "script": {
                    "id":     _STORED_SCRIPT_ID,
                    "params": {
                        "source":          source_rec,
                        "source_key":      source_key,
                        "last_seen":       src.get("processed_at", ""),
                        "raw_index":       source_rec.get("raw_index", ""),
                        "ioc_type_weight": src.get("ioc_type_weight"),
                    },
                },
                "upsert": src,
            }

    success, errors = helpers.bulk(
        es, _actions(), raise_on_error=False, chunk_size=500,
    )
    log.info(f"  -> Upserted {success} docs into {index}" +
             (f" | {len(errors)} errors" if errors else ""))
    for err in errors[:3]:
        log.warning(f"    Bulk error: {err}")

def _make_doc_id(ioc_type: str, ioc_value: str) -> str:
    raw = f"{ioc_type}_{ioc_value}"
    if len(raw.encode()) > 512:
        digest = hashlib.sha256(raw.encode()).hexdigest()
        return f"{ioc_type}_{digest}"
    return raw

def _parse_port_int(raw_port: Any) -> int | None:
    if raw_port is None:
        return None
    try:
        return int(str(raw_port).strip())
    except (ValueError, TypeError):
        return None

def _build_enriched_skeleton(include_owasp: bool = False) -> dict:
    skeleton: dict = {
        "has_mitre":          False,
        "has_owasp":          False,
        "has_score":          False,
        "enriched_at":        None,
        "mitre": {
            "matched_malware": None,
            "tactics":         [],
            "groups":          [],
            "technique_count": 0,
            "tactic_count":    0,
            "is_default":      True,
            "techniques":      [],
        },
        "score": {
            "has_score":            False,
            "pre_score":            None,
            "tier_multiplier":      None,
            "context_boost":        0,
            "corroboration_bonus":  0,
            "ransomware_matched":   False,
            "ransomware_group":     None,
            "critical_sector":      False,
            "group_active_days":    -1,
            "monthly_victim_count": 0,
            "technique_count":      0,
            "enriched_score":       None,
            "scored_at":            None,
        },
    }
    if include_owasp:
        skeleton["owasp_version"]      = None
        skeleton["owasp_version_note"] = None
        skeleton["owasp"] = {
            "highest_risk":   SENTINEL_KEYWORD,
            "category_ids":   [],
            "category_names": [],
            "categories":     [],
        }
    return skeleton

def build_clean_docs(es: Elasticsearch, ioc_type: str) -> dict:
    clean:        dict[str, dict] = {}
    seen_feeds:   dict[str, set[str]] = {}

    total_read  = 0
    total_noval = 0
    total_noise = 0
    total_dupes = 0

    processed_at     = datetime.now(timezone.utc).isoformat()
    output_index     = OUTPUT_INDICES[ioc_type]
    combined_pattern = ",".join(RAW_INDICES[ioc_type])
    log.info(f"  Querying: {combined_pattern}")

    for hit in scroll_index(es, combined_pattern):
        total_read += 1
        src       = hit["_source"]
        feed_name = _get_feed_name(src)
        dataset   = _get_dataset(src)
        raw_index = hit["_index"]

        extracted = extract_iocs_from_hit(hit, ioc_type)
        if not extracted:
            total_noval += 1
            continue

        for (ioc_value, actual_type, extra) in extracted:
            ioc_value = str(ioc_value).strip()
            if actual_type != "wallet":
                ioc_value = ioc_value.lower()

            if not ioc_value:
                total_noval += 1
                continue

            noisy, reason = is_noise(actual_type, ioc_value)
            if noisy:
                total_noise += 1
                log.debug(f"  NOISE [{actual_type}] {ioc_value} — {reason}")
                continue

            _feed_ts = extra.get("first_seen")
            if not _feed_ts:
                _ingest_ts = src.get("@timestamp")
                if _ingest_ts:
                    log.debug(
                        f"  first_seen absent for [{actual_type}] {ioc_value!r} — "
                        f"falling back to @timestamp ({_ingest_ts})."
                    )
                _feed_ts = _ingest_ts
            first_seen = _safe_ts(_feed_ts)

            tags = extra.get("tags") or []
            if not isinstance(tags, list):
                tags = [str(tags)]

            source_key = resolve_source_name(dataset, feed_name)
            initial_source_names = list(
                {feed_name, source_key} - {""}
            )

            raw_port = extra.get("ioc_port")
            port_int = _parse_port_int(raw_port)

            if ioc_value not in clean:
                doc_source: dict[str, Any] = {
                    "ioc_value":       ioc_value,
                    "ioc_type":        actual_type,
                    "tags":            list(tags),
                    "source_count":    1,
                    "source_names":    initial_source_names,
                    "first_seen":      first_seen,
                    "last_seen":       processed_at,
                    "processed_at":    processed_at,
                    "sources": [{
                        "feed_name":       feed_name,
                        "feed_reputation": SOURCE_CONFIDENCE.get(
                            source_key, {"confidence": 0.50}
                        )["confidence"],
                        "dataset":         dataset,
                        "raw_index":       raw_index,
                        "first_seen":      first_seen,
                        "tags":            tags,
                        "malware":         extra.get("malware"),
                        "threat":          extra.get("threat"),
                    }],
                    "feed_dataset":    dataset,
                    **{k: ([] if isinstance(v, list) else v)
                       for k, v in _DOWNSTREAM_RESET.items()},
                    "pushed_to_misp":      False,
                    "misp_push_timestamp": None,
                    "analyst_confirmed":   False,
                    "misp_sightings":      0,
                    "sighting_updated_at": None,
                    "enriched_at":         None,
                    "enriched":            _build_enriched_skeleton(
                        include_owasp=(actual_type == "cve")
                    ),
                    **_type_specific_fields(actual_type, extra, port_int),
                }

                if extra.get("threat"):
                    doc_source["threat_type"] = extra["threat"]

                for field in ("malware", "confidence"):
                    val = extra.get(field)
                    if val is not None:
                        doc_source[field] = val

                stamp_source_fields(doc_source, dataset, feed_name, output_index, source_key=source_key)
                stamp_intel_class(doc_source, actual_type)

                clean[ioc_value] = {
                    "_id":     _make_doc_id(actual_type, ioc_value),
                    "_source": doc_source,
                }
                seen_feeds[ioc_value] = {feed_name}

            else:
                total_dupes += 1
                doc = clean[ioc_value]["_source"]

                if feed_name not in seen_feeds[ioc_value]:
                    seen_feeds[ioc_value].add(feed_name)
                    doc["sources"].append({
                        "feed_name":       feed_name,
                        "feed_reputation": SOURCE_CONFIDENCE.get(
                            resolve_source_name(dataset, feed_name),
                            {"confidence": 0.50},
                        )["confidence"],
                        "dataset":         dataset,
                        "raw_index":       raw_index,
                        "first_seen":      first_seen,
                        "tags":            tags,
                        "malware":         extra.get("malware"),
                        "threat":          extra.get("threat"),
                    })
                    doc["source_count"] = len(doc["sources"])

                    for name in (feed_name, source_key):
                        if name and name not in doc["source_names"]:
                            doc["source_names"].append(name)

                    existing_tags = doc.get("tags", [])
                    for t in tags:
                        if t and t not in existing_tags:
                            existing_tags.append(t)
                    doc["tags"] = existing_tags

                    if actual_type == "ransomware":
                        if extra.get("group_name") and not doc.get("group_name"):
                            doc["group_name"]       = extra["group_name"]
                            doc["ransomware_group"] = extra["group_name"]
                        if extra.get("post_title") and not doc.get("ransomware_title"):
                            doc["ransomware_title"] = extra["post_title"]
                    elif actual_type == "wallet":
                        if extra.get("group_name") and not doc.get("group_name"):
                            doc["group_name"]       = extra["group_name"]
                            doc["ransomware_group"] = extra["group_name"]

                    if extra.get("threat") and not doc.get("threat_type"):
                        doc["threat_type"] = extra["threat"]

                    doc.update({
                        k: ([] if isinstance(v, list) else v)
                        for k, v in _DOWNSTREAM_RESET.items()
                    })

                    if doc.get("enriched") and doc["enriched"].get("score"):
                        doc["enriched"]["score"].update(_ENRICHED_SCORE_RESET)

                if processed_at > doc["last_seen"]:
                    doc["last_seen"] = processed_at

    log.info(f"  Read:          {total_read:,}")
    log.info(f"  No value:      {total_noval:,}")
    log.info(f"  Noise removed: {total_noise:,}")
    log.info(f"  Duplicates:    {total_dupes:,}")
    log.info(f"  Unique IOCs:   {len(clean):,}")
    return clean

def process_ioc_type(es: Elasticsearch, ioc_type: str) -> None:
    log.info(f"{'='*55}")
    log.info(f"Processing: {ioc_type.upper()}")
    log.info(f"{'='*55}")

    clean_docs = build_clean_docs(es, ioc_type)
    if not clean_docs:
        log.info(f"  No clean IOCs for {ioc_type}")
        return

    output_index = OUTPUT_INDICES[ioc_type]
    create_index_if_missing(es, output_index)
    bulk_upsert(es, output_index, clean_docs)
    log.info(f"  {len(clean_docs):,} unique IOCs -> {output_index}")

def run_once(es: Elasticsearch) -> None:
    start = time.time()
    log.info("Starting TI processing run ...")
    for ioc_type in OUTPUT_INDICES:
        try:
            process_ioc_type(es, ioc_type)
        except Exception as e:
            log.error(f"Failed processing {ioc_type}: {e}", exc_info=True)
    log.info(f"Run complete in {time.time() - start:.1f}s")

def _connect(es: Elasticsearch) -> bool:
    for attempt in range(10):
        try:
            if es.ping():
                log.info("Elasticsearch is up")
                register_index_template(es)
                register_stored_script(es)
                return True
        except Exception:
            pass
        log.warning(f"Waiting for Elasticsearch ... ({attempt + 1}/10)")
        time.sleep(10)
    log.error("Could not connect to Elasticsearch. Exiting.")
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TI Processor — deduplicate and normalize threat intelligence feeds",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        default=False,
        help=f"Run continuously every {RUN_INTERVAL}s daemon mode. "
             f"Default: run once and exit pipeline mode.",
    )
    args = parser.parse_args()

    log.info(f"Connecting to Elasticsearch at {ELASTIC_HOST} ...")
    es = Elasticsearch(ELASTIC_HOST, basic_auth=(ELASTIC_USER, ELASTIC_PASSWORD))

    if not _connect(es):
        return

    if args.loop:
        log.info(f"Daemon mode — running every {RUN_INTERVAL}s. Press Ctrl+C to stop.")
        while True:
            try:
                run_once(es)
            except KeyboardInterrupt:
                log.info("Stopped by user.")
                break
            except Exception as e:
                log.error(f"Unexpected error: {e}", exc_info=True)
            log.info(f"Sleeping {RUN_INTERVAL}s ...")
            time.sleep(RUN_INTERVAL)
    else:
        log.info("Pipeline mode — running once then exiting.")
        try:
            run_once(es)
        except KeyboardInterrupt:
            log.info("Stopped by user.")
        log.info("Done")

if __name__ == "__main__":
    main()
