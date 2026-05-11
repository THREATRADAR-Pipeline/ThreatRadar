#!/usr/bin/env python3
"""
Feedback_loop: sync analyst feedback from MISP to Elasticsearch and retrain the model.

© 2026 THREATRADAR Team
"""
from __future__ import annotations

import os
import json
import logging
from typing import Any
from datetime import datetime, timezone, timedelta

import re

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk as es_bulk

log = logging.getLogger("feedback_misp")


MISP_ENABLED       = os.getenv("MISP_ENABLED", "true").lower() not in ("0", "false", "no")
ES_BULK_SIZE       = int(os.getenv("FEEDBACK_ES_BULK_SIZE",   "500"))
MISP_BATCH_SIZE    = int(os.getenv("MISP_FETCH_BATCH_SIZE",   "200"))
MISP_INITIAL_DAYS  = int(os.getenv("MISP_INITIAL_LOOKBACK_DAYS", "30"))
MODEL_DIR          = os.getenv("MODEL_DIR", "/app/models")

TAG_CONFIRMED = os.getenv("FEEDBACK_TAG_ANALYST_TRUE", "threatradar:analyst_confirmed=true")
MIN_SIGHTINGS = int(os.getenv("TRAIN_MIN_SIGHTINGS", "2"))

_TYPE_TO_INDEX: dict[str, str] = {
    "ip-dst":          "ti_ip",
    "ip-src":          "ti_ip",
    "ip-dst|port":     "ti_ip",
    "ip-src|port":     "ti_ip",
    "domain":          "ti_domain",
    "hostname":        "ti_domain",
    "domain|ip":       "ti_domain",
    "url":             "ti_url",
    "uri":             "ti_url",
    "md5":             "ti_hash",
    "sha1":            "ti_hash",
    "sha256":          "ti_hash",
    "sha512":          "ti_hash",
    "filename|md5":    "ti_hash",
    "filename|sha1":   "ti_hash",
    "filename|sha256": "ti_hash",
    "vulnerability":   "ti_cve",
    "btc":             "ti_wallet",
    "xmr":             "ti_wallet",
    "dash":            "ti_wallet",
    "crypto-address":  "ti_wallet",
    "threat-actor":    "ti_ransomware",
}

_INDICATOR_FIELD = os.getenv("ES_INDICATOR_FIELD", "ioc_value")

_SYNC_STATE_FILE = "last_misp_sync.json"


def _load_sync_state() -> str:
    path = os.path.join(MODEL_DIR, _SYNC_STATE_FILE)
    try:
        with open(path) as fh:
            state = json.load(fh)
        ts = state.get("last_sync_at", "")
        if ts:
            log.info("[STATE] last_sync_at=%s", ts[:19])
            return ts
    except FileNotFoundError:
        log.info("[STATE] %s not found — using lookback of %d days", path, MISP_INITIAL_DAYS)
    except Exception as exc:
        log.warning("[STATE] could not read %s: %s — using lookback", path, exc)

    return (datetime.now(timezone.utc) - timedelta(days=MISP_INITIAL_DAYS)).isoformat()


def _save_sync_state(ts: str) -> None:
    os.makedirs(MODEL_DIR, exist_ok=True)
    path     = os.path.join(MODEL_DIR, _SYNC_STATE_FILE)
    tmp_path = path + ".tmp"
    try:
        with open(tmp_path, "w") as fh:
            json.dump({"last_sync_at": ts, "written_at": _now()}, fh, indent=2)
        os.replace(tmp_path, path)
        log.info("[STATE] saved last_sync_at=%s", ts[:19])
    except OSError as exc:
        log.warning("[STATE] could not write %s: %s", path, exc)


def _get_es_client() -> Elasticsearch:
    host   = os.getenv("ELASTIC_HOST") or os.getenv("ES_URL", "http://elasticsearch:9200")
    user   = os.getenv("ELASTIC_USER") or os.getenv("ES_USER", "elastic")
    pw     = os.getenv("ELASTIC_PASSWORD") or os.getenv("ES_PASSWORD", "")
    verify = os.getenv("ES_VERIFY_SSL", "false").lower() in ("1", "true", "yes")
    kwargs: dict = {"hosts": [host], "verify_certs": verify}
    if pw:
        kwargs["basic_auth"] = (user, pw)
    return Elasticsearch(**kwargs)


def _get_misp_client() -> Any:
    from pymisp import PyMISP
    url    = os.getenv("MISP_URL", "").rstrip("/")
    key    = os.getenv("MISP_KEY", "")
    verify = os.getenv("MISP_VERIFY_SSL", "false").lower() in ("1", "true", "yes")
    if not url or not key:
        raise EnvironmentError("MISP_URL and MISP_KEY must be set")
    log.info("[MISP] Connecting to %s ...", url)
    client = PyMISP(url, key, ssl=verify, debug=False)
    log.info("[MISP] Connected")
    return client


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _event_id(event: Any) -> str:
    if hasattr(event, "id"):
        return str(event.id)
    if isinstance(event, dict):
        return str(event.get("Event", event).get("id", ""))
    return ""



def _tag_name(t: Any) -> str:
    if isinstance(t, dict):
        return str(t.get("name", ""))
    name = getattr(t, "name", None)
    return str(name) if name is not None else str(t)


def _event_has_tag(event: Any, tag: str) -> bool:
    tag_list = getattr(event, "tags", None)
    if isinstance(tag_list, list):
        if any(tag in _tag_name(t) for t in tag_list):
            return True
        for attr in getattr(event, "attributes", None) or []:
            for t in getattr(attr, "tags", None) or []:
                if tag in _tag_name(t):
                    return True
        return False

    if not isinstance(event, dict):
        return False
    ev = event.get("Event", event)

    for et in ev.get("EventTag", []):
        tag_obj = et if isinstance(et, dict) and "name" in et else et.get("Tag", {})
        if tag in str(tag_obj.get("name", "")):
            return True
    for t in ev.get("Tag", []):
        if isinstance(t, dict) and tag in str(t.get("name", "")):
            return True
    for attr in ev.get("Attribute", []):
        if not isinstance(attr, dict):
            continue
        for at in attr.get("AttributeTag", []):
            tag_obj = at if isinstance(at, dict) and "name" in at else at.get("Tag", {})
            if tag in str(tag_obj.get("name", "")):
                return True
        for t in attr.get("Tag", []):
            if isinstance(t, dict) and tag in str(t.get("name", "")):
                return True
    return False


_SIGHTING_TRUE_POSITIVE = {"0", "", "true_positive"}


def _parse_sightings_list(sightings: list) -> int:
    count = 0
    for s in sightings:
        if isinstance(s, dict):
            inner = s.get("Sighting", s)
            stype = str(inner.get("type", "0") or "0")
        else:
            stype = str(getattr(s, "type", "0") or "0")
        if stype in _SIGHTING_TRUE_POSITIVE:
            count += 1
    return count


def _count_sightings_in_event(event: Any) -> int:

    total = 0
    if hasattr(event, "attributes"):
        for attr in getattr(event, "attributes", None) or []:
            total += _parse_sightings_list(getattr(attr, "sightings", None) or [])
        total += _parse_sightings_list(getattr(event, "sightings", None) or [])
        return total

    if isinstance(event, dict):
        ev = event.get("Event", event)
        total += _parse_sightings_list(ev.get("Sighting", ev.get("sightings", [])))
        for attr in ev.get("Attribute", []):
            if not isinstance(attr, dict):
                continue
            total += _parse_sightings_list(attr.get("Sighting", attr.get("sightings", [])))
    return total



def _fetch_misp_events_since(misp: Any, since_ts: str) -> list[Any]:
    try:
        dt = datetime.fromisoformat(since_ts)
    except ValueError:
        dt = datetime.now(timezone.utc) - timedelta(days=MISP_INITIAL_DAYS)

    epoch = int(dt.timestamp())
    log.info("[MISP] Fetching events modified since %s (epoch=%d) ...", since_ts[:19], epoch)

    all_events: list[Any] = []
    page = 1
    while True:
        try:
            results = misp.search(
                timestamp=epoch,
                page=page,
                limit=MISP_BATCH_SIZE,
                include_sightings=True,
                include_event_tags=True,
            )
        except Exception as exc:
            log.warning("[MISP] fetch page %d failed: %s", page, exc)
            break

        items: list = []
        if isinstance(results, list):
            items = results
        elif isinstance(results, dict):
            resp = results.get("response", results)
            items = resp if isinstance(resp, list) else ([resp] if resp else [])

        if not items:
            break

        all_events.extend(items)
        log.info("[MISP] page %d → %d events (total so far: %d)", page, len(items), len(all_events))

        if len(items) < MISP_BATCH_SIZE:
            break  
        page += 1

    log.info("[MISP] Total events fetched: %d", len(all_events))
    return all_events


def _extract_attributes(event: Any) -> list[dict]:
    out: list[dict] = []

    def _process(atype: str, avalue: str) -> None:
        atype  = (atype  or "").strip().lower()
        avalue = (avalue or "").strip()
        if not atype or not avalue:
            return
        index = _TYPE_TO_INDEX.get(atype)
        if not index:
            return
        if "|" in avalue and atype in ("ip-dst|port", "ip-src|port"):
            avalue = avalue.split("|")[0]
        out.append({"type": atype, "value": avalue, "index": index})

    
    if hasattr(event, "attributes"):
        for attr in getattr(event, "attributes", None) or []:
            _process(
                getattr(attr, "type",  None) or "",
                getattr(attr, "value", None) or "",
            )
        return out

    if isinstance(event, dict):
        ev = event.get("Event", event)
        for attr in ev.get("Attribute", []):
            if not isinstance(attr, dict):
                continue
            _process(attr.get("type", ""), attr.get("value", ""))

    return out

def _normalize_value(atype: str, value: str) -> list[str]:
    t = atype.lower()
    if t in ("domain", "hostname", "domain|ip"):
        norm = value.lower().rstrip(".")
        return list({value, norm})
    if t in ("url", "uri"):
        norm = value.rstrip("/")
        return list({value, norm})
    if t in ("md5", "sha1", "sha256", "sha512",
             "filename|md5", "filename|sha1", "filename|sha256"):
        return [value.lower()]
    return [value]


_RE_URL    = re.compile(r'https?://[^\s<>"\']+', re.I)
_RE_DOMAIN = re.compile(r'\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b', re.I)
_RE_IP     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_RE_HASH   = re.compile(r'\b[0-9a-f]{32,64}\b', re.I)


_TR_IOC_TAG = re.compile(r'threatradar:ioc_type=(\S+)', re.I)

def _get_threatradar_index(event: Any) -> str | None:

    _ioc_to_index = {
        "ip": "ti_ip", "domain": "ti_domain", "url": "ti_url",
        "hash": "ti_hash", "cve": "ti_cve", "wallet": "ti_wallet",
        "ransomware": "ti_ransomware",
    }
    tag_names: list[str] = []

    if isinstance(event, dict):
        ev = event.get("Event", event)
        for et in ev.get("EventTag", []):
            tag_obj = et if "name" in et else et.get("Tag", {})
            tag_names.append(str(tag_obj.get("name", "")))
        for t in ev.get("Tag", []):
            if isinstance(t, dict):
                tag_names.append(str(t.get("name", "")))
    else:
        for t in getattr(event, "tags", None) or []:
            tag_names.append(_tag_name(t))

    for name in tag_names:
        m = _TR_IOC_TAG.search(name)
        if m:
            return _ioc_to_index.get(m.group(1).lower())
    return None


def _extract_text_candidates(event: Any) -> list[dict]:
    texts: list[str] = []

    if isinstance(event, dict):
        ev = event.get("Event", event)
        texts.append(ev.get("info", "") or "")
        for attr in ev.get("Attribute", []):
            if isinstance(attr, dict) and attr.get("type") in ("comment", "text", "other"):
                texts.append(attr.get("value", "") or "")
    else:
        texts.append(getattr(event, "info", "") or "")
        for attr in getattr(event, "attributes", None) or []:
            if getattr(attr, "type", "") in ("comment", "text", "other"):
                texts.append(getattr(attr, "value", "") or "")

    combined = " ".join(texts)
    seen: set[str] = set()
    candidates: list[dict] = []

    def _add(itype: str, val: str, idx: str) -> None:
        if val and val not in seen:
            seen.add(val)
            candidates.append({"type": itype, "value": val, "index": idx})

    for url in _RE_URL.findall(combined):
        _add("url", url, "ti_url")

    for ip in _RE_IP.findall(combined):
        _add("ip", ip, "ti_ip")
    url_set = {u.lower() for u in _RE_URL.findall(combined)}

    for dom in _RE_DOMAIN.findall(combined):
        if not any(dom.lower() in u for u in url_set):
            _add("domain", dom.lower(), "ti_domain")

    for h in _RE_HASH.findall(combined):
        if len(h) in (32, 40, 64):   
            _add("hash", h.lower(), "ti_hash")

    return candidates

def _es_search(es: Elasticsearch, index: str, query: dict, size: int = 100) -> list[dict]:
    try:
        res = es.search(index=index, query=query, size=size, _source=False)
        return [{"_id": h["_id"], "_index": h["_index"]} for h in res["hits"]["hits"]]
    except Exception as exc:
        log.debug("[ES] search failed index=%s: %s", index, exc)
    return []


def _msearch_batch(
    es: Elasticsearch,
    requests: list[dict],
) -> list[list[dict]]:
    if not requests:
        return []

    body = []
    for req in requests:
        body.append({"index": req["index"]})
        body.append({"query": req["query"], "size": 100, "_source": False})

    try:
        resp = es.msearch(body=body)
        out = []
        for r in resp["responses"]:
            if "error" in r:
                log.debug("[MSEARCH] sub-query error: %s", r["error"].get("reason", r["error"]))
                out.append([])
            else:
                out.append([
                    {"_id": h["_id"], "_index": h["_index"]}
                    for h in r["hits"]["hits"]
                ])
        return out
    except Exception as exc:
        log.error("[MSEARCH] batch failed: %s", exc)
        return [[] for _ in requests]


def _find_es_docs(
    es: Elasticsearch,
    index: str,
    indicator_value: str,
    atype: str = "",
    event_id: str = "",
) -> list[dict]:
  
    candidates = _normalize_value(atype, indicator_value) if atype else [indicator_value]

    should: list[dict] = []
    for c in candidates:
        should.append({"term": {_INDICATOR_FIELD:                  c}})
        should.append({"term": {f"{_INDICATOR_FIELD}.keyword":     c}})

    if event_id:
        should.append({"term": {"misp_event_id": event_id}})

    return _es_search(es, index,
                      {"bool": {"should": should, "minimum_should_match": 1}})


def _find_es_docs_ransomware(
    es: Elasticsearch,
    actor_name: str,
) -> list[dict]:
    name = actor_name.lower().strip()
    should = [
        {"term": {"group_name":              name}},
        {"term": {"group_name.keyword":      name}},
        {"term": {"ransomware_group":         name}},
        {"term": {"ransomware_group.keyword": name}},
    ]
    return _es_search(es, "ti_ransomware",
                      {"bool": {"should": should, "minimum_should_match": 1}})


def _find_es_docs_by_event_id(
    es: Elasticsearch,
    event_id: str,
    valid_indices: set[str],
) -> list[dict]:
    
    if not event_id:
        return []
    return _es_search(es, ",".join(sorted(valid_indices)),
                      {"term": {"misp_event_id": event_id}})


def _find_es_docs_by_push_time(
    es: Elasticsearch,
    event: Any,
    valid_indices: set[str],
) -> list[dict]:
 
    ts_raw = None
    if isinstance(event, dict):
        ev = event.get("Event", event)
        ts_raw = ev.get("publish_timestamp") or ev.get("timestamp")
    else:
        ts_raw = getattr(event, "publish_timestamp", None) or getattr(event, "timestamp", None)

    if not ts_raw:
        return []
    try:
        if isinstance(ts_raw, str):
            dt = datetime.fromisoformat(ts_raw)
        else:
            dt = datetime.fromtimestamp(int(ts_raw), tz=timezone.utc)
    except Exception:
        return []

    gte = (dt - timedelta(hours=1)).isoformat()
    lte = (dt + timedelta(hours=1)).isoformat()
    query = {
        "bool": {
            "must": [
                {"term":  {"pushed_to_misp": True}},
                {"range": {"misp_push_timestamp": {"gte": gte, "lte": lte}}},
            ]
        }
    }
    return _es_search(es, ",".join(sorted(valid_indices)), query, size=50)

def _bulk_update(es: Elasticsearch, updates: list[dict]) -> tuple[int, int]:
    if not updates:
        return 0, 0
    actions = [
        {
            "_op_type": "update",
            "_index":   u["_index"],
            "_id":      u["_id"],
            "doc":      u["doc"],
            "retry_on_conflict": 3,
        }
        for u in updates
    ]
    try:
        success, errors = es_bulk(es, actions, raise_on_error=False, chunk_size=ES_BULK_SIZE)
        return int(success), len(errors or [])
    except Exception as exc:
        log.error("[ES-BULK] %s", exc)
        return 0, len(actions)


_debug_fired = False

def _debug_event_structure(event: Any, eid: str) -> None:
    global _debug_fired
    if _debug_fired:
        return
    _debug_fired = True
    try:
        if isinstance(event, dict):
            ev = event.get("Event", event)
            attrs = ev.get("Attribute", [])
            first = attrs[0] if attrs else {}
            log.info(
                "[DEBUG-STRUCTURE] eid=%s  event_keys=%s  "
                "EventTag_count=%d  Attribute_count=%d  "
                "first_attr_keys=%s  first_attr_Sighting=%s",
                eid, sorted(ev.keys()),
                len(ev.get("EventTag", [])), len(attrs),
                sorted(first.keys()) if first else "no-attrs",
                first.get("Sighting", "MISSING") if first else "n/a",
            )
        else:
            attrs = list(getattr(event, "attributes", None) or [])
            first = attrs[0] if attrs else None
            log.info(
                "[DEBUG-STRUCTURE] eid=%s  type=%s  attr_count=%d  "
                "first_attr.sightings=%s",
                eid, type(event).__name__, len(attrs),
                getattr(first, "sightings", "MISSING") if first else "n/a",
            )
    except Exception as exc:
        log.warning("[DEBUG-STRUCTURE] could not introspect event: %s", exc)


def sync_misp_feedback_to_es(indices: list[str], dry_run: bool = False) -> dict:
    if not MISP_ENABLED:
        return {"skipped": True, "reason": "MISP_ENABLED=false",
                "scanned": 0, "updated": 0, "failures": 0,
                "analyst_confirmed": 0, "sightings_refreshed": 0}

    log.info("[VERSION] v4.0 — MISP-first sync (batched msearch)")

    sync_start   = _now()
    last_sync_at = _load_sync_state()

    es   = _get_es_client()
    misp = _get_misp_client()

    valid_indices    = set(indices)
    all_index_pat    = ",".join(sorted(valid_indices))

    misp_events = _fetch_misp_events_since(misp, last_sync_at)
    if not misp_events:
        log.info("[SYNC] No MISP events modified since %s — nothing to do", last_sync_at[:19])
        _save_sync_state(sync_start)
        return {
            "scanned": 0, "updated": 0, "failures": 0, "skipped": 0,
            "analyst_confirmed": 0, "sightings_refreshed": 0, "dry_run": dry_run,
        }

    for ev in misp_events:
        _debug_event_structure(ev, _event_id(ev))
        break

    EventMeta = dict  
    event_meta:  list[EventMeta] = []
    query_plan:  list[dict]      = []   

    for event_idx, event in enumerate(misp_events):
        eid       = _event_id(event)
        confirmed = _event_has_tag(event, TAG_CONFIRMED)
        sightings = _count_sightings_in_event(event)

        if confirmed:
            log.info("[TAG]   event=%s  analyst_confirmed=True", eid)
        if sightings > 0:
            log.info("[SIGHT] event=%s  sightings=%d", eid, sightings)

        attrs     = _extract_attributes(event)
        has_attrs = False

        for attr in attrs:
            if attr["index"] not in valid_indices:
                continue
            has_attrs = True

            if attr["type"] == "threat-actor":
                name = attr["value"].lower().strip()
                query_plan.append({
                    "event_idx": event_idx,
                    "index":     "ti_ransomware",
                    "query": {"bool": {"should": [
                        {"term": {"group_name":              name}},
                        {"term": {"group_name.keyword":      name}},
                        {"term": {"ransomware_group":         name}},
                        {"term": {"ransomware_group.keyword": name}},
                    ], "minimum_should_match": 1}},
                })
            else:
                candidates = _normalize_value(attr["type"], attr["value"])
                should: list[dict] = []
                for c in candidates:
                    should.append({"term": {_INDICATOR_FIELD:              c}})
                    should.append({"term": {f"{_INDICATOR_FIELD}.keyword": c}})
                should.append({"term": {"misp_event_id": eid}})
                query_plan.append({
                    "event_idx": event_idx,
                    "index":     attr["index"],
                    "query":     {"bool": {"should": should,
                                           "minimum_should_match": 1}},
                })

        if not has_attrs:
            query_plan.append({
                "event_idx": event_idx,
                "index":     all_index_pat,
                "query":     {"term": {"misp_event_id": eid}},
            })

        event_meta.append({
            "eid": eid, "confirmed": confirmed, "sightings": sightings,
            "attrs": attrs, "has_attrs": has_attrs, "event": event,
        })

    log.info("[MSEARCH] firing %d primary queries for %d events",
             len(query_plan), len(misp_events))

    primary_results = _msearch_batch(es, query_plan)

    from collections import defaultdict
    event_hits:  dict[int, list[dict]] = defaultdict(list)
    event_seen:  dict[int, set[str]]   = defaultdict(set)

    for req, hits in zip(query_plan, primary_results):
        idx = req["event_idx"]
        for h in hits:
            if h["_id"] not in event_seen[idx]:
                event_seen[idx].add(h["_id"])
                event_hits[idx].append(h)

    fallback_plan: list[dict] = []

    for event_idx, meta in enumerate(event_meta):
        if event_hits.get(event_idx):
            continue  

        hint_index = _get_threatradar_index(meta["event"])
        if hint_index and hint_index in valid_indices:
            for attr in meta["attrs"]:
                for c in _normalize_value(attr["type"], attr["value"]):
                    fallback_plan.append({
                        "event_idx": event_idx,
                        "index":     hint_index,
                        "query":     {"term": {_INDICATOR_FIELD: c}},
                    })

        for tc in _extract_text_candidates(meta["event"]):
            if tc["index"] not in valid_indices:
                continue
            candidates = _normalize_value(tc["type"], tc["value"])
            should = []
            for c in candidates:
                should.append({"term": {_INDICATOR_FIELD:              c}})
                should.append({"term": {f"{_INDICATOR_FIELD}.keyword": c}})
            should.append({"term": {"misp_event_id": meta["eid"]}})
            fallback_plan.append({
                "event_idx": event_idx,
                "index":     tc["index"],
                "query":     {"bool": {"should": should,
                                        "minimum_should_match": 1}},
            })

    if fallback_plan:
        log.info("[MSEARCH] firing %d fallback queries", len(fallback_plan))
        fallback_results = _msearch_batch(es, fallback_plan)
        for req, hits in zip(fallback_plan, fallback_results):
            idx = req["event_idx"]
            for h in hits:
                if h["_id"] not in event_seen[idx]:
                    event_seen[idx].add(h["_id"])
                    event_hits[idx].append(h)

    for event_idx, meta in enumerate(event_meta):
        if event_hits.get(event_idx):
            continue
        hits = _find_es_docs_by_push_time(es, meta["event"], valid_indices)
        if hits:
            log.info("[MATCH] event=%s  strategy=push_time  +%d doc(s) "
                     "(weak — verify manually)", meta["eid"], len(hits))
            for h in hits:
                if h["_id"] not in event_seen[event_idx]:
                    event_seen[event_idx].add(h["_id"])
                    event_hits[event_idx].append(h)

    scanned = updated = failures = skipped = 0
    total_confirmed = total_sightings = 0
    es_batch: list[dict] = []

    for event_idx, meta in enumerate(event_meta):
        matched_docs = event_hits.get(event_idx, [])
        scanned += len(meta["attrs"]) if meta["has_attrs"] else 1

        if not matched_docs:
            log.debug("[SYNC]  event=%s  no ES docs matched — skipping", meta["eid"])
            skipped += 1
            continue

        log.debug("[SYNC]  event=%s  matched=%d doc(s)", meta["eid"], len(matched_docs))

        now = _now()
        doc: dict = {
            "feedback_synced_at":  now,
            "misp_sightings":      meta["sightings"],
            "sighting_updated_at": now,
            "misp_event_id":       meta["eid"],
        }
        if meta["confirmed"]:
            doc["analyst_confirmed"] = True
            total_confirmed += 1
        if meta["sightings"] > 0:
            total_sightings += 1

        for es_doc in matched_docs:
            es_batch.append({
                "_index": es_doc["_index"],
                "_id":    es_doc["_id"],
                "doc":    doc,
            })
            if len(es_batch) >= ES_BULK_SIZE:
                if not dry_run:
                    s, f = _bulk_update(es, es_batch)
                    updated += s; failures += f
                else:
                    updated += len(es_batch)
                es_batch.clear()

    if es_batch:
        if not dry_run:
            s, f = _bulk_update(es, es_batch)
            updated += s; failures += f
        else:
            updated += len(es_batch)

    if not dry_run:
        _save_sync_state(sync_start)

    summary = {
        "scanned":             scanned,
        "updated":             updated,
        "failures":            failures,
        "skipped":             skipped,
        "analyst_confirmed":   total_confirmed,
        "sightings_refreshed": total_sightings,
        "dry_run":             dry_run,
    }
    log.info("[DONE] %s", summary)
    return summary


def main():
    import argparse
    p = argparse.ArgumentParser(description="MISP → ES feedback sync (MISP-first)")
    p.add_argument("--indices", default="ti_ip,ti_url,ti_domain,ti_hash,ti_cve,ti_wallet,ti_ransomware")
    p.add_argument("--dry-run", action="store_true")
    args    = p.parse_args()
    indices = [s.strip() for s in args.indices.split(",") if s.strip()]
    sync_misp_feedback_to_es(indices, dry_run=args.dry_run)


if __name__ == "__main__":
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    main()