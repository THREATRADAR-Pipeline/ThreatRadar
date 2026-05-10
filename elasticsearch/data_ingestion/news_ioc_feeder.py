#!/usr/bin/env python3
"""
THREATRADAR news ioc feeder — extracts IOCs from raw news articles and stages them for ti_processor.
© 2026 THREATRADAR Team
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from elasticsearch import Elasticsearch, helpers

ELASTIC_HOST     = os.environ.get("ELASTIC_HOST", "http://elasticsearch:9200")
ELASTIC_USER     = os.environ.get("ELASTIC_USER", "elastic")
ELASTIC_PASSWORD = os.environ.get("ELASTIC_PASSWORD")
SCROLL_SIZE    = 500
SCROLL_TIMEOUT = "5m"

NEWS_SITE_DOMAINS = frozenset([
    "bleepingcomputer.com",
    "thehackernews.com",
    "feedburner.com",
    "talosintelligence.com",
    "paloaltonetworks.com",
    "securelist.com",
    "emergingthreats.net",
    "abuse.ch",
    "openphish.com",
    "cert.pl",
])


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("news_ioc_feeder")


_RE_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_RE_DOMAIN = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){1,}'
    r'(?:com|net|org|io|ru|cn|info|biz|xyz|top|tk|ml|ga|cf|onion|gov|edu|co)\b',
    re.IGNORECASE,
)
_RE_SHA256 = re.compile(r'\b[a-f0-9]{64}\b', re.IGNORECASE)
_RE_SHA1   = re.compile(r'\b[a-f0-9]{40}\b', re.IGNORECASE)
_RE_MD5    = re.compile(r'\b[a-f0-9]{32}\b', re.IGNORECASE)
_RE_CVE    = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)
_RE_URL    = re.compile(r'https?://[^\s<>"\']{10,2048}')
_RE_BTC = re.compile(r'\b(?:bc1[a-z0-9]{25,87}|[13][a-zA-Z0-9]{24,33})\b')
_RE_ETH = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
_RE_XMR = re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b')

def extract_iocs(title: str, summary: str) -> dict[str, list[dict]]:
    text = f"{title} {summary}"
    out: dict[str, list[dict]] = {
        "ip": [], "domain": [], "hash": [],
        "url": [], "cve": [], "wallet": [],
    }

    seen: set[str] = set()
    for v in _RE_IPV4.findall(text):
        if v not in seen:
            seen.add(v)
            out["ip"].append({"value": v})

    seen = set()
    for v in _RE_DOMAIN.findall(text.lower()):
        if v in seen:
            continue
        seen.add(v)
        if len(v) < 4:
            continue
        if any(v == n or v.endswith("." + n) for n in NEWS_SITE_DOMAINS):
            continue
        out["domain"].append({"value": v})

    masked = text 
    s256: set[str] = set()
    for m in _RE_SHA256.finditer(masked):
        h = m.group().lower()
        s256.add(h)
        masked = masked[:m.start()] + " " * (m.end() - m.start()) + masked[m.end():]
    s1: set[str] = set()
    for m in _RE_SHA1.finditer(masked):
        h = m.group().lower()
        s1.add(h)
        masked = masked[:m.start()] + " " * (m.end() - m.start()) + masked[m.end():]
    md5: set[str] = set()
    for m in _RE_MD5.finditer(masked):
        h = m.group().lower()
        md5.add(h)
    for h in s256: out["hash"].append({"value": h, "hash_type": "sha256"})
    for h in s1:   out["hash"].append({"value": h, "hash_type": "sha1"})
    for h in md5:  out["hash"].append({"value": h, "hash_type": "md5"})

    seen = set()
    for v in _RE_URL.findall(text):
        if v not in seen:
            seen.add(v)
            try:
                url_host = urllib.parse.urlparse(v).netloc.lower().split(":")[0]
            except Exception:
                url_host = ""
            if url_host and not any(
                url_host == n or url_host.endswith("." + n)
                for n in NEWS_SITE_DOMAINS
            ):
                out["url"].append({"value": v})

    seen = set()
    for v in _RE_CVE.findall(text):
        vu = v.upper()
        if vu not in seen:
            seen.add(vu)
            out["cve"].append({"value": vu})

    seen = set()
    for v in _RE_BTC.findall(text):
        if v not in seen:
            seen.add(v)
            out["wallet"].append({"value": v, "wallet_type": "bitcoin"})
    for v in _RE_ETH.findall(text):
        if v not in seen:
            seen.add(v)
            out["wallet"].append({"value": v, "wallet_type": "ethereum"})
    for v in _RE_XMR.findall(text):
        if v not in seen:
            seen.add(v)
            out["wallet"].append({"value": v, "wallet_type": "monero"})

    return out


def _merge_extracted_iocs(iocs: dict[str, list[dict]], stored: dict) -> None:
    existing: dict[str, set[str]] = {
        t: {i["value"] for i in lst} for t, lst in iocs.items()
    }

    field_map = {
        "ip":     ("ips",     {}),
        "domain": ("domains", {}),
        "url":    ("urls",    {}),
        "cve":    ("cves",    {}),
    }
    for ioc_type, (field, extra) in field_map.items():
        for v in stored.get(field, []):
            v = str(v).strip()
            if ioc_type != "url":
                v = v.lower()
            if not v or v in existing[ioc_type]:
                continue
            if ioc_type == "domain" and any(
                v == n or v.endswith("." + n) for n in NEWS_SITE_DOMAINS
            ):
                continue
            if ioc_type == "url":
                try:
                    url_host = urllib.parse.urlparse(v).netloc.lower().split(":")[0]
                except Exception:
                    url_host = ""
                if url_host and any(
                    url_host == n or url_host.endswith("." + n)
                    for n in NEWS_SITE_DOMAINS
                ):
                    continue
            existing[ioc_type].add(v)
            iocs[ioc_type].append({"value": v, **extra})

    _HEX_RE = re.compile(r'^[a-f0-9]+$')
    for h in stored.get("hashes", []):
        h = str(h).strip().lower()
        if not h or h in existing["hash"]:
            continue
        if not _HEX_RE.fullmatch(h):
            continue
        existing["hash"].add(h)
        if len(h) == 64:
            iocs["hash"].append({"value": h, "hash_type": "sha256"})
        elif len(h) == 40:
            iocs["hash"].append({"value": h, "hash_type": "sha1"})
        elif len(h) == 32:
            iocs["hash"].append({"value": h, "hash_type": "md5"})

    for w in stored.get("wallets", []):
        w = str(w).strip()
        if not w or w in existing["wallet"]:
            continue
        existing["wallet"].add(w)
        if w.startswith(("bc1", "1", "3")):
            wtype = "bitcoin"
        elif w.startswith("0x"):
            wtype = "ethereum"
        elif w.startswith("4"):
            wtype = "monero"
        else:
            log.warning(f"  _merge_extracted_iocs: unrecognised wallet prefix, skipping: {w[:12]}…")
            continue
        iocs["wallet"].append({"value": w, "wallet_type": wtype})


_STAGING_INDEX_MAPPING: dict = {
    "mappings": {
        "properties": {
            "@timestamp":      {"type": "date"},
            "message":         {"type": "text"},
            "event": {
                "properties": {
                    "dataset":  {"type": "keyword"},
                    "category": {"type": "keyword"},
                    "type":     {"type": "keyword"},
                }
            },
            "threat": {
                "properties": {
                    "feed": {
                        "properties": {
                            "name": {"type": "keyword"},
                        }
                    }
                }
            },
            "tags":            {"type": "keyword"},
            "input": {
                "properties": {
                    "type":    {"type": "keyword"},
                }
            },
            "ioc_value":       {"type": "keyword"},
            "ioc_type":        {"type": "keyword"},
            "hash_type":       {"type": "keyword"},
            "wallet_type":     {"type": "keyword"}, 
            "article_title":   {"type": "text"},
            "article_url":     {"type": "keyword"},
            "article_source":  {"type": "keyword"},
            "first_seen":      {"type": "date"},
        }
    }
}

def _ensure_index(es: Elasticsearch, index: str, mapping: dict) -> None:
    if not es.indices.exists(index=index):
        es.indices.create(index=index, mappings=mapping["mappings"])
        log.info(f"  Created index: {index}")


def _bulk_index_staging(es: Elasticsearch, index: str, docs: list[dict]) -> None:
    if not docs:
        return

    def _actions():
        for doc in docs:
            yield {"_op_type": "index", "_index": index, "_source": doc}

    success, errors = helpers.bulk(es, _actions(), raise_on_error=False, chunk_size=500)
    log.info(f"  Indexed {success} docs into {index}" +
             (f" | {len(errors)} errors" if errors else ""))
    for err in errors[:3]:
        log.warning(f"    Error: {err}")


def scroll_index(es: Elasticsearch, index_pattern: str):
    scroll_id = None
    try:
        resp = es.search(
            index=index_pattern,
            query={"match_all": {}},
            scroll=SCROLL_TIMEOUT,
            size=SCROLL_SIZE,
        )
        scroll_id = resp["_scroll_id"]
        hits      = resp["hits"]["hits"]
        while hits:
            yield from hits
            resp      = es.scroll(scroll_id=scroll_id, scroll=SCROLL_TIMEOUT)
            scroll_id = resp["_scroll_id"]
            hits      = resp["hits"]["hits"]
    except Exception as e:
        from elasticsearch import NotFoundError
        if isinstance(e, NotFoundError):
            log.warning(f"Index not found, skipping: {index_pattern}")
        else:
            log.error(f"Scroll failed on {index_pattern}: {e}")
            raise
    finally:
        if scroll_id:
            try:
                es.clear_scroll(scroll_id=scroll_id)
            except Exception:
                pass


def _build_staging_doc(
    now_ts:    str,
    feed_name: str,
    ioc_type:  str,
    ioc:       dict,
    title:     str,
    link:      str,
    feed:      str,
) -> dict:
    value = ioc["value"].strip()
    if ioc_type not in ("wallet", "url"):
        value = value.lower()

    payload: dict[str, Any] = {
        "ioc_value":       value,
        "ioc_type":        ioc_type,
        "article_title":   title[:200],
        "article_url":     link,
        "article_source":  feed,
        "first_seen":      now_ts,
    }

    if ioc_type == "hash"   and ioc.get("hash_type"):
        payload["hash_type"]    = ioc["hash_type"]
    if ioc_type == "wallet" and ioc.get("wallet_type"):
        payload["wallet_type"]  = ioc["wallet_type"]

    return {
        "@timestamp": now_ts,
        "message":    json.dumps(payload),
        "event":      {
            "dataset":  "ti_ioc_extracted_from_news",
            "category": "threat",
            "type":     "indicator",
        },
        "threat":     {"feed": {"name": feed_name}},
        "tags":       ["rss-extracted", "osint", "staging"],
        "input":      {"type": "python-ingestor"},
        **payload,
    }


def process(es: Elasticsearch) -> None:
    log.info("=" * 60)
    log.info("NEWS IOC FEEDER — ti_news-*")
    log.info("=" * 60)
    log.info("  All IOC types (ip/domain/hash/url/cve/wallet) staged uniformly.")
    log.info("")

    now_dt      = datetime.now(timezone.utc)
    now_ts      = now_dt.isoformat()
    today       = now_dt.strftime("%Y.%m.%d")
    staging_idx = f"ti_ioc_extracted_from_news-{today}"

    _ensure_index(es, staging_idx, _STAGING_INDEX_MAPPING)

    staging_docs: list[dict] = []
    stats = {
        "articles": 0, "skipped": 0,
        "ip": 0, "domain": 0, "hash": 0,
        "url": 0, "cve": 0, "wallet": 0,
    }

    log.info("  Scrolling ti_news-* ...")

    for hit in scroll_index(es, "ti_news-*"):
        src     = hit["_source"]
        article = src.get("article", {})
        title   = article.get("title",   "")
        summary = article.get("summary", "")
        link    = article.get("link",    "")
        feed    = src.get("threat", {}).get("feed", {}).get("name", "RSS")

        if not title and not summary:
            stats["skipped"] += 1
            continue

        stats["articles"] += 1
        feed_name = f"RSS:{feed}"
        now_ts = datetime.now(timezone.utc).isoformat()

        stored = src.get("extracted_iocs", {})
        if stored:
            iocs: dict[str, list[dict]] = {t: [] for t in ("ip", "domain", "hash", "url", "cve", "wallet")}
            _merge_extracted_iocs(iocs, stored)
        else:
            iocs = extract_iocs(title, summary)

        for ioc_type in ("ip", "domain", "hash", "url", "cve", "wallet"):
            for ioc in iocs[ioc_type]:
                if not ioc.get("value", "").strip():
                    continue
                staging_docs.append(
                    _build_staging_doc(
                        now_ts, feed_name, ioc_type, ioc, title, link, feed
                    )
                )
                stats[ioc_type] += 1

                if len(staging_docs) >= 1000:
                    _bulk_index_staging(es, staging_idx, staging_docs)
                    staging_docs = []

    if staging_docs:
        _bulk_index_staging(es, staging_idx, staging_docs)

    total_iocs = sum(
        stats[t] for t in ("ip", "domain", "hash", "url", "cve", "wallet")
    )

    log.info("")
    log.info("=" * 60)
    log.info(f"  Articles processed : {stats['articles']:,}")
    log.info(f"  Articles skipped   : {stats['skipped']:,}")
    log.info(f"  Total IOCs staged  : {total_iocs:,}  ->  {staging_idx}")
    log.info("")
    log.info("  Breakdown:")
    for t in ("ip", "domain", "hash", "url", "cve", "wallet"):
        if stats[t]:
            log.info(f"    {t:<8} : {stats[t]:,}")
    log.info("=" * 60)
    log.info("  news feeder complete")


def main() -> None:
    start = time.time()
    log.info(f"Connecting to Elasticsearch at {ELASTIC_HOST} ...")
    es = Elasticsearch(ELASTIC_HOST, basic_auth=(ELASTIC_USER, ELASTIC_PASSWORD))
    if not es.ping():
        log.error("Cannot connect to Elasticsearch. Exiting.")
        sys.exit(1)
    log.info("Elasticsearch is up")
    process(es)
    log.info(f"\nComplete in {time.time() - start:.1f}s")

if __name__ == "__main__":
    main()
