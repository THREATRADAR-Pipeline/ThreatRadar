#!/usr/bin/env python3
"""
Additional TI Feed Ingestor for feeds that don't fit the filebeat parsers well
© 2026 THREATRADAR Team
"""
from __future__ import annotations

import csv
import gzip
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from datetime import datetime, timezone
from typing import Any

from elasticsearch import Elasticsearch, helpers

ELASTIC_HOST     = os.environ.get("ELASTIC_HOST", "http://elasticsearch:9200")
ELASTIC_USER     = os.environ.get("ELASTIC_USER", "elastic")
ELASTIC_PASSWORD = os.environ.get("ELASTIC_PASSWORD")
ET_FEEDS: list[dict[str, str]] = [
    {
        "url":  "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "name": "ET Compromised IPs",
        "tag":  "compromised",
    },
    {
        "url":  "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "name": "ET Botnet C2",
        "tag":  "botnet-c2",
    },
]

SSLBL_URL: str = "https://sslbl.abuse.ch/blacklist/sslblacklist.csv"

NEWS_FEEDS: list[dict[str, str]] = [
    {"url": "https://feeds.feedburner.com/TheHackersNews",  "name": "TheHackersNews",      "tag": "news-thn"},
    {"url": "https://www.bleepingcomputer.com/feed/",       "name": "BleepingComputer",    "tag": "news-bc"},
    {"url": "https://blog.talosintelligence.com/rss/",      "name": "CiscoTalos",          "tag": "news-talos"},
    {"url": "https://unit42.paloaltonetworks.com/feed/",    "name": "PaloAltoUnit42",      "tag": "news-unit42"},
    {"url": "https://securelist.com/feed/",                 "name": "KasperskySecureList", "tag": "news-kaspersky"},
]


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("new_feeds")

# IOC REGEX PATTERNS
_RE_IPV4   = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b')
_RE_DOMAIN = re.compile(
    # Require at least two labels (one dot) before the TLD
    r'\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){1,}'
    r'(?:com|net|org|io|ru|cn|info|biz|xyz|top|tk|ml|ga|cf|onion|gov|edu|co)\b',
    re.IGNORECASE,
)
_RE_SHA256 = re.compile(r'\b[a-f0-9]{64}\b', re.IGNORECASE)
_RE_SHA1   = re.compile(r'\b[a-f0-9]{40}\b', re.IGNORECASE)
_RE_MD5    = re.compile(r'\b[a-f0-9]{32}\b', re.IGNORECASE)
_RE_CVE    = re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE)
_RE_URL    = re.compile(r'https?://[^\s<>"\']{10,2048}')

_RE_BTC    = re.compile(r'\b(?:bc1[a-z0-9]{25,87}|[13][a-zA-Z0-9]{24,33})\b')
_RE_ETH    = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
_RE_XMR    = re.compile(r'\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b')

_RE_NEWS_ITEM  = re.compile(r'<(?:item|entry)>(.*?)</(?:item|entry)>', re.DOTALL | re.IGNORECASE)
_RE_LINK_HREF = re.compile(r'<link[^>]+href=["\']([^"\']+)["\']', re.IGNORECASE)
_RE_STRIP_TAG = re.compile(r'<[^>]+>')


def _decompress(data: bytes, encoding: str) -> bytes:
    enc = (encoding or "").lower()
    if enc == "gzip" or (len(data) >= 2 and data[:2] == b'\x1f\x8b'):
        try:
            return gzip.decompress(data)
        except Exception:
            pass
    if enc == "deflate":
        try:
            return zlib.decompress(data)
        except Exception:
            pass
    return data


def http_get(
    url: str,
    headers: dict[str, str] | None = None,
    timeout: int = 30,
    retries: int = 3,
    backoff: float = 2.0,
) -> bytes | None:
    req_headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent":      "OTIC-TI-Ingestor/1.0",
    }
    if headers:
        req_headers.update(headers)

    req      = urllib.request.Request(url, headers=req_headers)
    last_err: Exception | None = None

    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return _decompress(resp.read(), resp.headers.get("Content-Encoding", ""))
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code == 429 or e.code >= 500:
                wait = backoff ** attempt
                log.warning(f"HTTP {e.code} for {url} — retry in {wait:.0f}s ({attempt+1}/{retries})")
                time.sleep(wait)
                continue
            log.warning(f"HTTP {e.code} for {url}: {e.reason}")
            return None
        except urllib.error.URLError as e:
            last_err = e
            wait = backoff ** attempt
            log.warning(f"URL error for {url}: {e.reason} — retry in {wait:.0f}s")
            time.sleep(wait)
        except Exception as e:
            last_err = e
            log.warning(f"Request failed for {url}: {e}")
            return None

    log.warning(f"All {retries} attempts failed for {url}: {last_err}")
    return None


def extract_iocs_from_text(text: str) -> dict[str, list[str]]:
    # Extract hashes longest-first with span-masking so shorter regexes cannot
    # match substrings of already-claimed hex runs (e.g. MD5 inside SHA256).
    masked = text
    sha256_set: set[str] = set()
    for m in _RE_SHA256.finditer(masked):
        h = m.group().lower()
        sha256_set.add(h)
        masked = masked[:m.start()] + " " * (m.end() - m.start()) + masked[m.end():]
    sha1_set: set[str] = set()
    for m in _RE_SHA1.finditer(masked):
        h = m.group().lower()
        sha1_set.add(h)
        masked = masked[:m.start()] + " " * (m.end() - m.start()) + masked[m.end():]
    md5_set: set[str] = set()
    for m in _RE_MD5.finditer(masked):
        md5_set.add(m.group().lower())
    hashes = list(sha256_set) + list(sha1_set) + list(md5_set)

    wallets: list[str] = []
    seen_w: set[str] = set()
    for v in _RE_BTC.findall(text):
        if v not in seen_w:
            seen_w.add(v); wallets.append(v)
    for v in _RE_ETH.findall(text):
        if v not in seen_w:
            seen_w.add(v); wallets.append(v)
    for v in _RE_XMR.findall(text):
        if v not in seen_w:
            seen_w.add(v); wallets.append(v)

    domains = list(dict.fromkeys(
        v for v in _RE_DOMAIN.findall(text.lower()) if len(v) >= 4
    ))

    return {
        "ip":     list(dict.fromkeys(_RE_IPV4.findall(text))),
        "domain": domains,
        "hash":   list(dict.fromkeys(hashes)),
        "cve":    list(dict.fromkeys(c.upper() for c in _RE_CVE.findall(text))),
        "url":    list(dict.fromkeys(_RE_URL.findall(text))),
        "wallet": wallets,
    }


_RAW_INDEX_MAPPING: dict = {
    "mappings": {
        "properties": {
            "@timestamp":       {"type": "date"},
            "message":          {"type": "text"},
            "event.dataset":    {"type": "keyword"},
            "threat.feed.name": {"type": "keyword"},
            "tags":             {"type": "keyword"},
        }
    }
}

_NEWS_INDEX_MAPPING: dict = {
    "mappings": {
        "properties": {
            "@timestamp":       {"type": "date"},
            "message":          {"type": "text"},
            "event.dataset":    {"type": "keyword"},
            "threat.feed.name": {"type": "keyword"},
            "tags":             {"type": "keyword"},
            "article": {
                "properties": {
                    "title":    {"type": "text"},
                    "link":     {"type": "keyword"},
                    "summary":  {"type": "text"},
                    "pub_date": {"type": "keyword"},
                    "source":   {"type": "keyword"},
                }
            },
            "extracted_iocs": {
                "properties": {
                    "ips":     {"type": "keyword"},
                    "domains": {"type": "keyword"},
                    "hashes":  {"type": "keyword"},
                    "cves":    {"type": "keyword"},
                    "urls":    {"type": "keyword"},
                    "wallets": {"type": "keyword"},
                }
            },
            "has_iocs":  {"type": "boolean"},
            "ioc_count": {"type": "integer"},
        }
    }
}

def _ensure_index(es: Elasticsearch, index: str, mapping: dict) -> None:
    if not es.indices.exists(index=index):
        es.indices.create(index=index, mappings=mapping["mappings"])
        log.info(f"  Created index: {index}")


def _bulk_write(es: Elasticsearch, index: str, docs: list[dict], op_type: str = "index") -> None:
    if not docs:
        return

    def _actions():
        for doc in docs:
            action: dict[str, Any] = {"_op_type": op_type, "_index": index}
            if "_id" in doc:
                action["_id"] = doc.pop("_id")
            action["doc" if op_type == "update" else "_source"] = doc
            yield action

    success, errors = helpers.bulk(es, _actions(), raise_on_error=False, chunk_size=500)
    log.info(f"  → {op_type.capitalize()}d {success} docs into {index}" +
             (f" | {len(errors)} errors" if errors else ""))
    for err in errors[:3]:
        log.warning(f"    Error: {err}")


def _bulk_index(es: Elasticsearch, index: str, docs: list[dict]) -> None:
    if docs:
        _bulk_write(es, index, docs, op_type="index")


def _make_raw_doc(dataset: str, feed_name: str, tag: str, payload: dict) -> dict:
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "message":    json.dumps(payload),
        "event":      {"dataset": dataset, "category": "threat", "type": "indicator"},
        "threat":     {"feed": {"name": feed_name}},
        "tags":       [tag, "forwarded"],
        "input":      {"type": "python-ingestor"},
    }


ET_INDEX_NAMES: dict[str, str] = {
    "compromised": "ti_et_compromised",
    "botnet-c2":   "ti_et_botnet",
}


ET_DATASET_NAMES: dict[str, str] = {
    "compromised": "ti_et_compromised",
    "botnet-c2":   "ti_et_botnet",
}

def fetch_emerging_threats(es: Elasticsearch) -> None:
    log.info("=" * 55)
    log.info("SOURCE 1: Emerging Threats — IP Blocklists")
    log.info("=" * 55)

    today = datetime.now(timezone.utc).strftime("%Y.%m.%d")

    for feed in ET_FEEDS:
        log.info(f"  Fetching: {feed['name']} ...")
        data = http_get(feed["url"])
        if not data:
            log.warning(f"  Failed to fetch {feed['name']}")
            continue

        index_base = ET_INDEX_NAMES.get(feed["tag"], f"ti_et_{feed['tag']}")
        index      = f"{index_base}-{today}"
        _ensure_index(es, index, _RAW_INDEX_MAPPING)

        docs:  list[dict] = []
        count = 0
        now   = datetime.now(timezone.utc).isoformat()

        for line in data.decode("utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            ip = line.split()[0]
            docs.append(_make_raw_doc(
                dataset   = ET_DATASET_NAMES.get(feed["tag"], "ti_et"),
                feed_name = feed["name"],
                tag       = f"threatintel-et-{feed['tag']}",
                payload   = {"ip_address": ip, "et_category": feed["tag"], "first_seen": now},
            ))
            count += 1
            if len(docs) >= 1000:
                _bulk_index(es, index, docs)
                docs = []

        if docs:
            _bulk_index(es, index, docs)
        log.info(f"  {feed['name']}: {count} IPs → {index}")




def fetch_ssl_blacklist(es: Elasticsearch) -> None:
    log.info("=" * 55)
    log.info("SOURCE 2: Abuse.ch SSL Blacklist")
    log.info("=" * 55)

    index = f"ti_sslbl-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"
    _ensure_index(es, index, _RAW_INDEX_MAPPING)

    data = http_get(SSLBL_URL)
    if not data:
        log.warning("  Failed to fetch SSL Blacklist")
        return

    text   = data.decode("utf-8", errors="ignore").replace("\x00", "")
    reader = csv.reader(
        line for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    )

    docs:  list[dict] = []
    count = 0

    for row in reader:
        if len(row) < 3:
            continue
        listing_date = row[0].strip()
        sha1         = row[1].strip().lower()
        reason       = row[2].strip()
        docs.append(_make_raw_doc(
            dataset   = "ti_sslbl",
            feed_name = "Abuse.ch SSL Blacklist",
            tag       = "threatintel-sslbl",
            payload   = {"sha1_hash": sha1, "listing_date": listing_date,
                         "listing_reason": reason, "first_seen": listing_date},
        ))
        count += 1
        if len(docs) >= 1000:
            _bulk_index(es, index, docs)
            docs = []

    if docs:
        _bulk_index(es, index, docs)

    log.info(f"  SSL certs indexed: {count} → {index}")
    log.info(" Abuse.ch SSL Blacklist complete")

# SOURCE 3 — NEWS FEEDS

def _decode_html_entities(text: str) -> str:
    return (text
        .replace("&amp;",  "&").replace("&lt;",   "<").replace("&gt;",   ">")
        .replace("&quot;", '"').replace("&#39;",  "'").replace("&apos;", "'")
        .replace("&nbsp;", " ")
    )


def _NEWS_tag(item_text: str, tag: str) -> str:
    for pat in [
        rf'<(?:[\w]+:)?{tag}[^>]*><!\[CDATA\[(.*?)\]\]></(?:[\w]+:)?{tag}>',
        rf'<(?:[\w]+:)?{tag}[^>]*>(.*?)</(?:[\w]+:)?{tag}>',
    ]:
        m = re.search(pat, item_text, re.DOTALL | re.IGNORECASE)
        if m:
            return _decode_html_entities(_RE_STRIP_TAG.sub(' ', m.group(1)).strip())
    return ""


def parse_NEWS(xml_text: str) -> list[dict[str, str]]:
    xml_text = re.sub(r'\s+xmlns(?::\w+)?="[^"]*"', '', xml_text)
    items = []
    for match in _RE_NEWS_ITEM.finditer(xml_text):
        item_text = match.group(1)
        title    = _NEWS_tag(item_text, "title")
        desc     = (_NEWS_tag(item_text, "description") or _NEWS_tag(item_text, "summary")
                    or _NEWS_tag(item_text, "encoded")   or _NEWS_tag(item_text, "content"))
        pub_date = (_NEWS_tag(item_text, "pubDate") or _NEWS_tag(item_text, "published")
                    or _NEWS_tag(item_text, "updated")   or _NEWS_tag(item_text, "date"))
        link_m   = _RE_LINK_HREF.search(item_text)
        link     = link_m.group(1).strip() if link_m else _NEWS_tag(item_text, "link")
        if title or desc:
            items.append({"title": title, "link": link,
                          "summary": desc[:2000] if desc else "", "pub_date": pub_date})
    return items


def fetch_NEWS_feeds(es: Elasticsearch) -> None:
    log.info("=" * 55)
    log.info("SOURCE 3: NEWS Feeds — Threat Intel News")
    log.info("=" * 55)

    index  = f"ti_news-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"
    _ensure_index(es, index, _NEWS_INDEX_MAPPING)

    total_articles  = 0
    total_with_iocs = 0
    now_ts          = datetime.now(timezone.utc).isoformat()

    for feed in NEWS_FEEDS:
        log.info(f"  Fetching: {feed['name']} ...")
        data = http_get(feed["url"], timeout=20)
        if not data:
            log.warning(f"  Failed to fetch {feed['name']}")
            continue

        xml_text = data.decode("utf-8", errors="ignore")
        articles = parse_NEWS(xml_text)
        if not articles:
            log.warning(f"  {feed['name']}: 0 articles — response preview: {xml_text[:300]!r}")
            continue

        docs: list[dict] = []
        for article in articles:
            iocs      = extract_iocs_from_text(f"{article['title']} {article['summary']}")
            ioc_count = sum(len(v) for v in iocs.values())
            has_iocs  = ioc_count > 0
            if has_iocs:
                total_with_iocs += 1

            docs.append({
                "@timestamp": now_ts,
                "message":    json.dumps({
                    "title":   article["title"],
                    "link":    article["link"],
                    "summary": article["summary"],
                    "source":  feed["name"],
                }),
                "event":   {"dataset": "ti_news", "category": "threat", "type": "indicator"},
                "threat":  {"feed": {"name": feed["name"]}},
                "tags":    [feed["tag"], "news", "forwarded"],
                "input":   {"type": "python-ingestor"},
                "article": {
                    "title":    article["title"],
                    "link":     article["link"],
                    "summary":  article["summary"][:2000],
                    "pub_date": article["pub_date"],
                    "source":   feed["name"],
                },
                "extracted_iocs": {
                    "ips":     iocs["ip"],
                    "domains": iocs["domain"],
                    "hashes":  iocs["hash"],
                    "cves":    iocs["cve"],
                    "urls":    iocs["url"],
                    "wallets": iocs["wallet"],
                },
                "has_iocs":  has_iocs,
                "ioc_count": ioc_count,
            })

        _bulk_index(es, index, docs)
        total_articles += len(docs)
        log.info(f"  {feed['name']}: {len(docs)} articles, "
                 f"{sum(1 for d in docs if d['has_iocs'])} with IOCs")

    log.info(f"  Total: {total_articles} articles | {total_with_iocs} with IOCs → {index}")
    log.info(" NEWS feeds complete")



OPENPHISH_URL: str = "https://openphish.com/feed.txt"

def fetch_openphish(es: Elasticsearch) -> None:
    log.info("=" * 55)
    log.info("SOURCE 4: OpenPhish — Phishing URL Feed")
    log.info("=" * 55)

    index = f"ti_openphish-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"
    _ensure_index(es, index, _RAW_INDEX_MAPPING)

    data = http_get(OPENPHISH_URL, timeout=30)
    if not data:
        log.warning("  Failed to fetch OpenPhish feed")
        return

    lines = [
        l.strip() for l in data.decode("utf-8", errors="ignore").splitlines()
        if l.strip() and l.strip().startswith("http")
    ]
    if not lines:
        log.warning("  OpenPhish returned no valid URLs — feed may be temporarily unavailable")
        return

    docs:  list[dict] = []
    count = 0
    now   = datetime.now(timezone.utc).isoformat()

    for url in lines:
        try:
            parsed_domain = urllib.parse.urlparse(url).netloc
        except Exception:
            parsed_domain = ""

        docs.append(_make_raw_doc(
            dataset   = "ti_openphish",
            feed_name = "OpenPhish",
            tag       = "threatintel-openphish",
            payload   = {
                "url":            url,
                "domain":         parsed_domain,
                "indicator_type": "url",
                "threat_type":    "phishing",
                "first_seen":     now,
            },
        ))
        count += 1
        if len(docs) >= 1000:
            _bulk_index(es, index, docs)
            docs = []

    if docs:
        _bulk_index(es, index, docs)

    log.info(f"  OpenPhish: {count} phishing URLs → {index}")
    log.info(" OpenPhish complete")


CERTPL_URL: str = "https://hole.cert.pl/domains/domains.txt"


def fetch_certpl(es: Elasticsearch) -> None:
    log.info("=" * 55)
    log.info("SOURCE 5: CERT.pl — Phishing Domain Feed")
    log.info("=" * 55)

    index = f"ti_certpl-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"
    _ensure_index(es, index, _RAW_INDEX_MAPPING)

    data = http_get(CERTPL_URL, timeout=30)
    if not data:
        log.warning("  Failed to fetch CERT.pl feed")
        return

    docs:  list[dict] = []
    count = 0
    now   = datetime.now(timezone.utc).isoformat()

    for line in data.decode("utf-8", errors="ignore").splitlines():
        domain = line.strip().lower()
        if not domain or domain.startswith("#") or "." not in domain:
            continue

        docs.append(_make_raw_doc(
            dataset   = "ti_certpl",
            feed_name = "CERT.pl",
            tag       = "threatintel-certpl",
            payload   = {
                "domain":         domain,
                "indicator_type": "domain-name",
                "threat_type":    "phishing",
                "source_cert":    "CERT Polska",
                "first_seen":     now,
            },
        ))
        count += 1
        if len(docs) >= 1000:
            _bulk_index(es, index, docs)
            docs = []

    if docs:
        _bulk_index(es, index, docs)

    log.info(f"  CERT.pl: {count:,} phishing domains → {index}")
    log.info(" CERT.pl complete")

def main() -> None:
    start = time.time()
    log.info(f"Connecting to Elasticsearch at {ELASTIC_HOST} ...")
    es = Elasticsearch(ELASTIC_HOST, basic_auth=(ELASTIC_USER, ELASTIC_PASSWORD))
    if not es.ping():
        log.error("Cannot connect to Elasticsearch. Exiting.")
        sys.exit(1)
    log.info("Elasticsearch is up")

    for name, fn in [
        ("Emerging Threats", fetch_emerging_threats),
        ("SSL Blacklist",    fetch_ssl_blacklist),
        ("NEWS feeds",        fetch_NEWS_feeds),
        ("OpenPhish",        fetch_openphish),
        ("CERT.pl",          fetch_certpl),
    ]:
        log.info("")
        try:
            fn(es)
        except Exception as e:
            log.error(f"{name} failed: {e}", exc_info=True)

    log.info("")
    log.info(f"Complete in {time.time()-start:.1f}s")

if __name__ == "__main__":
    main()
