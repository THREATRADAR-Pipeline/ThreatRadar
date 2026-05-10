"""
misp_pusher.py
Routes each IOC type to the correct MISP object and pushes to MISP.
Routing logic:
  ip / url / hash / domain  → standard IOC attribute
      pushed if: verdict in (CRITICAL, HIGH)
              OR final_action in (BLOCK, QUARANTINE, REVIEW)
              OR ml_tier == HIGH
              OR llm_confidence >= 70
              OR poisoning_flagged is True
              OR analyst_confirmed is True
              OR composite_poison_score >= 0.45

  cve to vulnerability object
      pushed if: cvss_severity in HIGH, CRITICAL

  ransomware to threat-actor object
      ALWAYS pushed regardless of verdict

  wallet to btc/crypto attribute
      pushed if: action == "alert_soc" OR should_push(doc) is True

  Poisoned IOCs (poisoning_flagged=True):
      - Fetched first in a dedicated priority pass
© 2026 THREATRADAR Team
"""
import logging
import logging.config
import os
import sys
import time
import threading
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
from pymisp import MISPObject

_HERE = os.path.dirname(os.path.abspath(__file__))
for _candidate in (_HERE, os.path.dirname(_HERE)):
    if _candidate not in sys.path:
        sys.path.insert(0, _candidate)

from misp_helpers import (
    get_es_client, get_misp_client,
    build_base_event, bulk_mark_pushed, mark_pushed_failed,
    build_comment,
    enrich_label, set_attribute_timestamps, set_event_tlp,
    _safe_tag_value,
    add_enrichment_attributes, add_fusion_object,
)
from common import OUTPUT_INDICES

load_dotenv()

_log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=_log_level,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("misp_pusher")

es:   "Elasticsearch | None" = None
misp: "PyMISP | None"        = None

INDEX_MAP = OUTPUT_INDICES

HANDLED_TYPES = {"ip", "url", "hash", "domain", "cve", "ransomware", "wallet"}
assert HANDLED_TYPES == set(INDEX_MAP), (
    f"HANDLED_TYPES and INDEX_MAP are out of sync: "
    f"INDEX_MAP keys={set(INDEX_MAP)}, HANDLED_TYPES={HANDLED_TYPES}"
)

ATTR_TYPE_MAP = {
    "ip":     "ip-dst",
    "url":    "url",
    "domain": "domain",
}

HASH_LENGTH_MAP = {
    32:  "md5",
    40:  "sha1",
    56:  "sha224",
    64:  "sha256",
    96:  "sha384",
    128: "sha512",
    7:   "crc32",
    16:  "md4",
}

WALLET_ATTR_MAP = {
    "bitcoin": "btc",
    "monero":  "xmr",
    "dash":    "dash",
}

MISP_SIGHTING_BY_VALUE = os.getenv("MISP_SIGHTING_BY_VALUE", "true").lower() != "false"

MISP_PUSH_DELAY   = float(os.getenv("MISP_PUSH_DELAY",   "0.05"))
MISP_SEARCH_DELAY = float(os.getenv("MISP_SEARCH_DELAY", "0.02"))

MISP_PUSH_WORKERS = int(os.getenv("MISP_PUSH_WORKERS", "16"))

ES_FETCH_RETRIES      = int(os.getenv("ES_FETCH_RETRIES",      "3"))
ES_FETCH_RETRY_DELAY  = float(os.getenv("ES_FETCH_RETRY_DELAY", "2.0"))

MISP_MAX_IOC_AGE_DAYS = int(os.getenv("MISP_MAX_IOC_AGE_DAYS", "180"))

PUSH_LLM_CONFIDENCE_MIN    = int(os.getenv("PUSH_LLM_CONFIDENCE_MIN",    "70"))
PUSH_POISON_SCORE_MIN      = float(os.getenv("PUSH_POISON_SCORE_MIN",    "0.45"))

MISP_CLEAN_DISTRIBUTION    = int(os.getenv("MISP_CLEAN_DISTRIBUTION",    "1"))
MISP_CORROBORATED_DIST     = int(os.getenv("MISP_CORROBORATED_DIST",     "1"))
MISP_CVE_EXPLOITED_DIST    = int(os.getenv("MISP_CVE_EXPLOITED_DIST",    "1"))

_pushed_this_run: dict = {}
_cache_lock = threading.Lock()

_mark_batch: list = []
_batch_lock  = threading.Lock()
BULK_FLUSH_SIZE = int(os.getenv("MISP_BULK_FLUSH", "500"))

_reconnect_lock = threading.Lock()

_stats: dict = defaultdict(lambda: defaultdict(int))
_stats_lock = threading.Lock()

_IOC_SOURCE_FIELDS = [
    "ioc_value", "ioc_type",
    "verdict", "final_action", "action", "ml_tier",
    "llm_confidence", "composite_poison_score",
    "analyst_confirmed", "poisoning_flagged",
    "poison_strategy", "source_count", "sources",
    "first_seen", "last_seen", "processed_at",
    "hash_type", "wallet_type", "group_name",
    "actor_danger_score", "actor_threat_level", "activity",
    "cvss_severity", "cvss_score", "cvss_vector",
    "cvss_version", "cvss_exploitability", "cvss_impact",
    "cwes", "product", "vendor", "vuln_name",
    "required_action", "due_date", "nvd_enriched",
    "ml_score", "final_score", "cortex_score", "cortex_final_score",
    "fusion_confidence", "fusion_reasoning",
    "llm_verdict", "llm_contradiction_class",
    "llm_poison_score", "final_likelihood",
    "contradictions_count",
    "score_breakdown", "ioc_port",
    "enriched", "owasp", "intel_class",
    "misp_event_id",
]

def _reconnect_misp():
    global misp
    if not _reconnect_lock.acquire(timeout=10):
        log.debug("[RECONNECT] waited for peer reconnect — reusing refreshed client")
        return
    try:
        misp = get_misp_client()
        log.info("[RECONNECT] MISP client reinitialized")
    except Exception as exc:
        log.error("[RECONNECT FAIL] Could not reinitialize MISP client: %s", exc)
    finally:
        _reconnect_lock.release()


def _is_auth_error(exc: Exception) -> bool:
    code = getattr(exc, "status_code", None) or getattr(exc, "code", None)
    if code == 403:
        return True
    s = str(exc)
    return "403 Forbidden" in s or "Authentication failed" in s


def _record_stat(ioc_type: str, status: str):
    with _stats_lock:
        _stats[ioc_type][status] += 1


def _register_pushed(attr_type: str, ioc_value: str, misp_event_id: str = ""):
    with _cache_lock:
        _pushed_this_run[f"{attr_type}:{ioc_value}"] = misp_event_id


def _is_already_pushed_this_run(attr_type: str, ioc_value: str) -> bool:
    with _cache_lock:
        return f"{attr_type}:{ioc_value}" in _pushed_this_run


def _get_cached_event_id(attr_type: str, ioc_value: str) -> str:
    with _cache_lock:
        return _pushed_this_run.get(f"{attr_type}:{ioc_value}", "")


def _queue_mark_pushed(index: str, doc_id: str, misp_event_id: str = ""):
    flush_batch = None
    with _batch_lock:
        _mark_batch.append({"_index": index, "_id": doc_id, "misp_event_id": misp_event_id})
        if len(_mark_batch) >= BULK_FLUSH_SIZE:
            flush_batch = list(_mark_batch)
            _mark_batch.clear()

    if flush_batch is not None:
        _do_bulk_flush(flush_batch)


def _flush_mark_batch():
    with _batch_lock:
        if not _mark_batch:
            return
        batch = list(_mark_batch)
        _mark_batch.clear()
    _do_bulk_flush(batch)


def _do_bulk_flush(batch: list):
    for attempt in range(ES_FETCH_RETRIES):
        success = bulk_mark_pushed(es, batch)
        if success == len(batch):
            log.info("[BULK-MARK] marked %d/%d docs as pushed_to_misp=true", success, len(batch))
            return
        remaining = len(batch) - success
        if attempt < ES_FETCH_RETRIES - 1:
            log.warning("[BULK-MARK] %d/%d updates failed — retrying in %.1fs (attempt %d/%d)",
                        remaining, len(batch), ES_FETCH_RETRY_DELAY, attempt + 1, ES_FETCH_RETRIES)
            time.sleep(ES_FETCH_RETRY_DELAY)
        else:
            log.error("[BULK-MARK] %d/%d updates permanently failed after %d attempts — "
                      "affected IOCs may be re-pushed on next run",
                      remaining, len(batch), ES_FETCH_RETRIES)


def get_ioc_value(doc: dict, doc_id: str) -> str:
    value = doc.get("ioc_value")
    if value is None:
        value = doc.get("value")
    if not value:
        raise ValueError(f"Doc {doc_id} has no 'ioc_value' or 'value' field — skipping")
    return value


def get_threat_level(verdict: str) -> int:
    return {
        "HIGH":       1, "CRITICAL":   1,
        "BLOCK":      1, "QUARANTINE": 2,
        "MEDIUM":     2,
        "LOW":        3, "ACCEPT":     3,
        "UNKNOWN":    4,
    }.get(str(verdict).upper(), 4)


def get_fusion_threat_level(doc: dict, base_verdict: str) -> int:
    final_action = str(doc.get("final_action", "")).upper()
    ml_tier      = str(doc.get("ml_tier", "")).upper()

    if final_action in ("BLOCK", "QUARANTINE"):
        return 1
    if ml_tier == "HIGH":
        return 1
    if ml_tier == "MEDIUM":
        return min(get_threat_level(base_verdict), 2)
    return get_threat_level(base_verdict)


def _is_stale_ioc(doc: dict) -> bool:
    if MISP_MAX_IOC_AGE_DAYS <= 0:
        return False
    if doc.get("analyst_confirmed") or doc.get("poisoning_flagged"):
        return False

    date_str = doc.get("last_seen") or doc.get("first_seen") or doc.get("processed_at")
    if not date_str:
        return False

    try:
        dt = datetime.fromisoformat(str(date_str).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        cutoff = datetime.now(timezone.utc) - timedelta(days=MISP_MAX_IOC_AGE_DAYS)
        return dt < cutoff
    except (ValueError, TypeError):
        return False


def should_push(doc: dict) -> bool:
    verdict      = str(doc.get("verdict", "")).upper()
    final_action = str(doc.get("final_action", "")).upper()
    ml_tier      = str(doc.get("ml_tier", "")).upper()
    llm_conf     = int(float(doc.get("llm_confidence") or 0))

    if doc.get("analyst_confirmed") is True:           return True
    if doc.get("poisoning_flagged") is True:           return True
    if verdict in ("CRITICAL", "HIGH"):                return True
    if final_action in ("BLOCK", "QUARANTINE"):        return True
    if ml_tier == "HIGH":                              return True
    if final_action == "REVIEW":                       return True
    if llm_conf >= PUSH_LLM_CONFIDENCE_MIN:                   return True

    cps = float(doc.get("composite_poison_score") or 0)
    if cps >= PUSH_POISON_SCORE_MIN:
        return True

    return False


def get_hash_attr_type(doc: dict, ioc_value: str) -> str:
    hash_type = doc.get("hash_type", "").lower().strip()
    if hash_type:
        _aliases = {
            "sha-1":    "sha1",
            "sha-256":  "sha256",
            "sha-384":  "sha384",
            "sha-512":  "sha512",
            "sha-224":  "sha224",
            "sha2":     "sha256",
            "sha2-256": "sha256",
        }
        return _aliases.get(hash_type, hash_type)

    clean    = ioc_value.replace("-", "").strip()
    inferred = HASH_LENGTH_MAP.get(len(clean))
    if inferred:
        return inferred

    return "authentihash"


def resolve_wallet_attr_type(doc: dict) -> str:
    wallet_type = doc.get("wallet_type", "")
    return WALLET_ATTR_MAP.get(wallet_type, "hex")


def _apply_event_settings(event, distribution: int, threat_level_id: int):
    event.distribution    = distribution
    event.threat_level_id = threat_level_id
    event.analysis        = 2
    event.publish()


def _extract_misp_event_id(result) -> str:
    if isinstance(result, dict):
        eid = (result.get("Event") or {}).get("id")
        if eid:
            return str(eid)
        eid = result.get("id")
        if eid:
            return str(eid)
        log.debug("[EXTRACT-ID] dict result has no id — keys: %s", list(result.keys())[:10])
        return ""
    eid = getattr(result, "id", None)
    if eid:
        return str(eid)
    log.debug("[EXTRACT-ID] non-dict type=%s has no .id — repr: %s",
              type(result).__name__, repr(result)[:200])
    return ""


def _check_misp_result(result, ioc_label: str) -> bool:
    if result is None:
        log.error("[FAIL] %s — MISP returned None (connection issue?)", ioc_label)
        return False
    if isinstance(result, dict) and result.get("errors"):
        log.error("[FAIL] %s — %s", ioc_label, result["errors"])
        return False
    event_id = _extract_misp_event_id(result)
    if not event_id:
        log.error("[FAIL] %s — no event id in response: %s", ioc_label, result)
        return False
    return True


class _CacheHit:
    """Sentinel returned by find_existing_event() for in-run cache hits."""
    __slots__ = ()


_CACHE_HIT = _CacheHit()


def find_existing_event(ioc_value: str, attr_type: str):
    if _is_already_pushed_this_run(attr_type, ioc_value):
        return _CACHE_HIT

    try:
        time.sleep(MISP_SEARCH_DELAY)
        results = misp.search(
            value=ioc_value,
            type_attribute=attr_type,
            limit=1,
            pythonify=True,
        )
        return results[0] if results else None
    except Exception as exc:
        if _is_auth_error(exc):
            log.warning("[AUTH] 403 during dedup search for %r — reconnecting", ioc_value)
            _reconnect_misp()
        else:
            log.warning("[WARN] dedup search failed for %r: %s", ioc_value, exc)
        return None


MISP_EVENT_PUSH_RETRIES = int(os.getenv("MISP_EVENT_PUSH_RETRIES", "3"))


def push_with_retry(event, ioc_label: str, index: str = "", doc_id: str = "",
                    retries: int = MISP_EVENT_PUSH_RETRIES):
    global misp
    last_exc = None
    for attempt in range(retries):
        try:
            time.sleep(MISP_PUSH_DELAY)
            return misp.add_event(event)
        except Exception as exc:
            last_exc = exc
            if _is_auth_error(exc):
                log.warning("[AUTH] 403 on attempt %d for %s — reconnecting", attempt + 1, ioc_label)
                _reconnect_misp()
            if attempt == retries - 1:
                error_msg = str(last_exc)
                log.error("[FAIL] %s — all %d attempts failed: %s", ioc_label, retries, error_msg)
                if index and doc_id:
                    mark_pushed_failed(es, index, doc_id, error_msg)
                return None
            wait = 2 ** attempt
            log.warning("[RETRY] %s — attempt %d failed (%s), retrying in %ds",
                        ioc_label, attempt + 1, exc, wait)
            time.sleep(wait)




def _add_sighting(ioc_value: str, existing_event=None):
    sighting: dict = {"type": "0"}
    source_name = os.getenv("MISP_SIGHTING_SOURCE", "threatradar")
    if source_name:
        sighting["source"] = source_name

    if (
        not MISP_SIGHTING_BY_VALUE
        and existing_event is not None
        and not isinstance(existing_event, _CacheHit)
    ):
        event_uuid = getattr(existing_event, "uuid", None)
        if event_uuid:
            sighting["uuid"] = event_uuid
            return misp.add_sighting(sighting)

    sighting["value"] = ioc_value
    return misp.add_sighting(sighting)


def push_network_ioc(doc: dict, doc_id: str, index: str, ioc_value: str) -> str:
    ioc_type     = doc["ioc_type"]
    verdict      = doc.get("verdict", "")
    final_action = str(doc.get("final_action", "")).upper()
    ml_tier      = str(doc.get("ml_tier", "")).upper()

    if _is_stale_ioc(doc):
        last_seen = doc.get("last_seen") or doc.get("first_seen", "unknown")
        log.info("[STALE] [%7s] %s — last_seen:%s exceeds %dd threshold",
                 ioc_type, ioc_value, last_seen, MISP_MAX_IOC_AGE_DAYS)
        return "stale"

    if ioc_type == "hash":
        attr_type = get_hash_attr_type(doc, ioc_value)
    else:
        attr_type = ATTR_TYPE_MAP.get(ioc_type, "text")

    existing = find_existing_event(ioc_value, attr_type)
    if existing:
        if doc.get("poisoning_flagged") and not isinstance(existing, _CacheHit):
            try:
                misp.tag(existing, "threatradar:poisoning_detected=true")
                misp.tag(existing, "PAP:RED")
                strategy = doc.get("poison_strategy", "unknown")
                misp.tag(existing, f"threatradar:poison_strategy={_safe_tag_value(strategy)}")
                try:
                    misp.publish(existing)
                except Exception as pub_exc:
                    log.warning("[WARN] publish after poison re-tag failed for %s: %s",
                                ioc_value, pub_exc)
                _add_sighting(ioc_value, existing)
                existing_event_id = _extract_misp_event_id(existing) or str(getattr(existing, "uuid", "") or "")
                _queue_mark_pushed(index, doc_id, misp_event_id=existing_event_id)
                _register_pushed(attr_type, ioc_value, misp_event_id=existing_event_id)
                return "pushed"
            except Exception as exc:
                log.warning("[WARN] poison tag on existing event failed for %s: %s", ioc_value, exc)
                return "failed"
        else:
            try:
                _add_sighting(ioc_value, existing)
                if isinstance(existing, _CacheHit):
                    existing_event_id = _get_cached_event_id(attr_type, ioc_value)
                else:
                    existing_event_id = (
                        _extract_misp_event_id(existing)
                        or str(getattr(existing, "uuid", "") or "")
                    )
                _queue_mark_pushed(index, doc_id, misp_event_id=existing_event_id)
                _register_pushed(attr_type, ioc_value, misp_event_id=existing_event_id)
                log.info("[SIGHT] [%7s] %s — sighting added to existing event", ioc_type, ioc_value)
                return "pushed"
            except Exception as exc:
                log.error("[FAIL]  [%s] sighting failed for %s: %s — not creating duplicate",
                          ioc_type, ioc_value, exc)
                return "failed"

    label_extra = f"fusion:{final_action}" if final_action else f"verdict:{verdict}"
    if ml_tier:
        label_extra += f" | ml:{ml_tier}"

    base_label = (
        f"THREATRADAR | {ioc_type.upper()} | {ioc_value} | {label_extra} | "
        f"score:{doc.get('final_score', '?')}"
    )

    if doc.get("poisoning_flagged"):
        base_label = f"FEED POISON | {base_label}"

    label = enrich_label(doc, base_label, doc_id)
    event = build_base_event(doc, label)

    is_poisoned = bool(doc.get("poisoning_flagged"))
    attr = event.add_attribute(
        attr_type,
        ioc_value,
        comment=build_comment(doc),
        to_ids=not is_poisoned,
        disable_correlation=False,
    )
    set_attribute_timestamps(attr, doc)

    add_enrichment_attributes(event, doc)
    add_fusion_object(event, doc)

    if is_poisoned:
        pap_green = os.getenv("MISP_PAP_TAG", "PAP:GREEN")
        event.tags = [
            t for t in (event.tags or [])
            if t.name.lower() != pap_green.lower()
        ]
        event.add_tag("PAP:RED")
        event.add_tag("threatradar:poisoning_detected=true")
        event.add_tag(f"threatradar:poison_strategy={_safe_tag_value(doc.get('poison_strategy', 'unknown'))}")
        _apply_event_settings(event, distribution=0, threat_level_id=1)
        set_event_tlp(event)
    else:
        threat_level = get_fusion_threat_level(doc, verdict)
        _apply_event_settings(event, distribution=MISP_CLEAN_DISTRIBUTION, threat_level_id=threat_level)
        set_event_tlp(event)

    result = push_with_retry(event, f"[{ioc_type}] {ioc_value}", index=index, doc_id=doc_id)
    if _check_misp_result(result, f"[{ioc_type}] {ioc_value}"):
        misp_event_id = _extract_misp_event_id(result)
        _queue_mark_pushed(index, doc_id, misp_event_id=misp_event_id)
        _register_pushed(attr_type, ioc_value, misp_event_id=misp_event_id)
        poison_flag = " POISON" if is_poisoned else ""
        log.info("[OK]   [%7s] %s (attr:%s)%s", ioc_type, ioc_value, attr_type, poison_flag)
        return "pushed"
    return "failed"


def push_cve(doc: dict, doc_id: str, index: str, ioc_value: str) -> str:
    severity          = doc.get("cvss_severity", "UNKNOWN")
    score             = doc.get("cvss_score", "?")
    cvss_vector       = doc.get("cvss_vector", "")
    cvss_version      = doc.get("cvss_version", "")
    cvss_exploit      = doc.get("cvss_exploitability")
    cvss_impact       = doc.get("cvss_impact")
    vuln_name         = doc.get("vuln_name", "")
    due_date          = doc.get("due_date", "")
    required_action   = doc.get("required_action", "")
    nvd_enriched      = doc.get("nvd_enriched")

    if _is_stale_ioc(doc):
        last_seen = doc.get("last_seen") or doc.get("first_seen", "unknown")
        log.info("[STALE] [    cve] %s — last_seen:%s exceeds %dd threshold",
                 ioc_value, last_seen, MISP_MAX_IOC_AGE_DAYS)
        return "stale"

    existing = find_existing_event(ioc_value, "vulnerability")
    if existing:
        try:
            _add_sighting(ioc_value, existing)
            if isinstance(existing, _CacheHit):
                existing_event_id = _get_cached_event_id("vulnerability", ioc_value)
            else:
                existing_event_id = (
                    _extract_misp_event_id(existing)
                    or str(getattr(existing, "uuid", "") or "")
                )
            _queue_mark_pushed(index, doc_id, misp_event_id=existing_event_id)
            _register_pushed("vulnerability", ioc_value, misp_event_id=existing_event_id)
            log.info("[SIGHT] [    cve] %s — sighting added", ioc_value)
            return "pushed"
        except Exception as exc:
            log.error("[FAIL]  [cve] sighting failed for %s: %s — not creating duplicate",
                      ioc_value, exc)
            return "failed"

    label = enrich_label(
        doc,
        f"THREATRADAR | CVE | {ioc_value} | {severity} | CVSS:{score}",
        doc_id,
    )

    event = build_base_event(doc, label)

    try:
        vuln = MISPObject("vulnerability")

        id_attr = vuln.add_attribute("id", value=ioc_value)
        set_attribute_timestamps(id_attr, doc)

        vuln.add_attribute("cvss-score", value=str(score))
        if cvss_vector:
            vuln.add_attribute("cvss-string", value=cvss_vector)

        if vuln_name:
            vuln.add_attribute("summary", value=str(vuln_name))

        extra_lines = []
        if cvss_version:
            extra_lines.append(f"CVSS version: {cvss_version}")
        if cvss_exploit is not None:
            extra_lines.append(f"CVSS exploitability: {cvss_exploit}")
        if cvss_impact is not None:
            extra_lines.append(f"CVSS impact: {cvss_impact}")
        if due_date:
            extra_lines.append(f"CISA due date: {due_date}")
        if required_action:
            extra_lines.append(f"Required action: {str(required_action)[:300]}")
        if nvd_enriched is not None:
            extra_lines.append(f"NVD enriched: {nvd_enriched}")

        description = (
            f"{severity} severity | "
            f"Product: {doc.get('product', 'N/A')} | "
            f"Vendor: {doc.get('vendor', 'N/A')} | "
            f"CWEs: {', '.join(doc.get('cwes', []))} | "
            f"{build_comment(doc)}"
        )
        if extra_lines:
            description = description + "\n" + "\n".join(extra_lines)

        desc_attr = vuln.add_attribute("description", value=description)
        set_attribute_timestamps(desc_attr, doc)

        event.add_object(vuln)

    except Exception as exc:
        log.warning("[WARN] vulnerability object template missing (%s) — using flat attribute", exc)
        extras = []
        if cvss_vector:
            extras.append(f"Vector:{cvss_vector}")
        if cvss_version:
            extras.append(f"CVSSv:{cvss_version}")
        if cvss_exploit is not None:
            extras.append(f"Exploit:{cvss_exploit}")
        if cvss_impact is not None:
            extras.append(f"Impact:{cvss_impact}")
        if vuln_name:
            extras.append(f"Name:{str(vuln_name)[:80]}")
        if due_date:
            extras.append(f"Due:{due_date}")
        if required_action:
            extras.append(f"Action:{str(required_action)[:120]}")
        extra_str = " | ".join(extras)
        attr = event.add_attribute(
            "vulnerability",
            ioc_value,
            comment=(
                f"CVSS:{score} | {severity} | "
                f"Product:{doc.get('product','N/A')} | "
                + (f"{extra_str} | " if extra_str else "")
                + build_comment(doc)
            ),
        )
        set_attribute_timestamps(attr, doc)

    add_enrichment_attributes(event, doc)
    add_fusion_object(event, doc)

    mitre_techniques   = (doc.get("enriched") or {}).get("mitre", {}).get("techniques", [])
    actively_exploited = bool(doc.get("analyst_confirmed") or mitre_techniques)
    cve_distribution   = MISP_CVE_EXPLOITED_DIST if actively_exploited else 1

    _apply_event_settings(event, distribution=cve_distribution, threat_level_id=1)
    set_event_tlp(event)

    result = push_with_retry(event, f"[cve] {ioc_value}", index=index, doc_id=doc_id)
    if _check_misp_result(result, f"[cve] {ioc_value}"):
        misp_event_id = _extract_misp_event_id(result)
        _queue_mark_pushed(index, doc_id, misp_event_id=misp_event_id)
        _register_pushed("vulnerability", ioc_value, misp_event_id=misp_event_id)
        dist_label = f"dist:{MISP_CVE_EXPLOITED_DIST}(exploited)" if actively_exploited else "dist:1(community)"
        log.info("[OK]   [    cve] %s (%s, %s)", ioc_value, severity, dist_label)
        return "pushed"
    return "failed"


def push_threat_actor(doc: dict, doc_id: str, index: str, ioc_value: str) -> str:
    group  = doc.get("group_name", ioc_value)
    danger = doc.get("actor_danger_score", 0)
    level  = doc.get("actor_threat_level", "UNKNOWN")

    if _is_stale_ioc(doc):
        last_seen = doc.get("last_seen") or doc.get("first_seen", "unknown")
        log.info("[STALE] [ransomware] %s — last_seen:%s exceeds %dd threshold",
                 group, last_seen, MISP_MAX_IOC_AGE_DAYS)
        return "stale"

    existing = find_existing_event(ioc_value, "threat-actor")
    if existing:
        try:
            _add_sighting(ioc_value, existing)
            if isinstance(existing, _CacheHit):
                existing_event_id = _get_cached_event_id("threat-actor", ioc_value)
            else:
                existing_event_id = (
                    _extract_misp_event_id(existing)
                    or str(getattr(existing, "uuid", "") or "")
                )
            _queue_mark_pushed(index, doc_id, misp_event_id=existing_event_id)
            _register_pushed("threat-actor", ioc_value, misp_event_id=existing_event_id)
            log.info("[SIGHT] [ransomware] %s — sighting added", group)
            return "pushed"
        except Exception as exc:
            log.error("[FAIL]  [ransomware] sighting failed for %s: %s — not creating duplicate",
                      group, exc)
            return "failed"

    label = enrich_label(
        doc,
        f"THREATRADAR | THREAT ACTOR | {group} | Danger:{danger} | {level}",
        doc_id,
    )

    event = build_base_event(doc, label)
    mitre = (doc.get("enriched") or {}).get("mitre", {})

    attr = event.add_attribute(
        "threat-actor",
        group,
        comment=(
            f"Actor danger score: {danger}/100 | "
            f"Level: {level} | "
            f"Activity: {doc.get('activity', 'N/A')} | "
            f"Techniques: {mitre.get('technique_count', 0)} | "
            f"Feed: {(doc.get('sources') or [{}])[0].get('feed_name', 'N/A')}"
        ),
        disable_correlation=False,
    )
    set_attribute_timestamps(attr, doc)

    add_enrichment_attributes(event, doc)
    add_fusion_object(event, doc)
    event.add_tag("threatradar:score_type=actor_danger_rating")

    source_count    = int(doc.get("source_count") or 1)
    corroborated    = source_count > 1 or bool(doc.get("analyst_confirmed"))
    actor_distribution = MISP_CORROBORATED_DIST if corroborated else 0

    _apply_event_settings(event, distribution=actor_distribution, threat_level_id=1)
    set_event_tlp(event)

    result = push_with_retry(event, f"[ransomware] {group}", index=index, doc_id=doc_id)
    if _check_misp_result(result, f"[ransomware] {group}"):
        misp_event_id = _extract_misp_event_id(result)
        _queue_mark_pushed(index, doc_id, misp_event_id=misp_event_id)
        _register_pushed("threat-actor", ioc_value, misp_event_id=misp_event_id)
        dist_label = f"dist:{MISP_CORROBORATED_DIST}(corroborated)" if corroborated else "dist:0(single-source)"
        log.info("[OK]   [ransomware] %s (danger:%s, %s)", group, danger, dist_label)
        return "pushed"
    return "failed"


def push_wallet(doc: dict, doc_id: str, index: str, ioc_value: str) -> str:
    wallet_type = doc.get("wallet_type", "bitcoin")
    attr_type   = resolve_wallet_attr_type(doc)

    if _is_stale_ioc(doc):
        last_seen = doc.get("last_seen") or doc.get("first_seen", "unknown")
        log.info("[STALE] [ wallet] %s — last_seen:%s exceeds %dd threshold",
                 ioc_value[:30], last_seen, MISP_MAX_IOC_AGE_DAYS)
        return "stale"

    if attr_type != "hex":
        existing = find_existing_event(ioc_value, attr_type)
    else:
        if _is_already_pushed_this_run("wallet-hex", ioc_value):
            existing = _CACHE_HIT
        else:
            try:
                time.sleep(MISP_SEARCH_DELAY)
                candidates = misp.search(value=ioc_value, limit=10, pythonify=True) or []
                existing   = next(
                    (e for e in candidates
                     if any("threatradar:ioc_type=wallet" in str(t)
                            for t in getattr(e, "tags", []))),
                    None,
                )
            except Exception as exc:
                if _is_auth_error(exc):
                    log.warning("[AUTH] 403 during wallet dedup search — reconnecting")
                    _reconnect_misp()
                else:
                    log.warning("[WARN] wallet dedup search failed for %r: %s", ioc_value[:30], exc)
                existing = None

    if existing:
        try:
            _add_sighting(ioc_value, existing)
            if isinstance(existing, _CacheHit):
                cache_key = "wallet-hex" if attr_type == "hex" else attr_type
                existing_event_id = _get_cached_event_id(cache_key, ioc_value)
            else:
                existing_event_id = (
                    _extract_misp_event_id(existing)
                    or str(getattr(existing, "uuid", "") or "")
                )
            _queue_mark_pushed(index, doc_id, misp_event_id=existing_event_id)
            _register_pushed(
                "wallet-hex" if attr_type == "hex" else attr_type,
                ioc_value,
                misp_event_id=existing_event_id,
            )
            log.info("[SIGHT] [ wallet] %s... — sighting added", ioc_value[:30])
            return "pushed"
        except Exception as exc:
            log.error("[FAIL]  [wallet] sighting failed for %s: %s — not creating duplicate",
                      ioc_value[:30], exc)
            return "failed"

    label = enrich_label(
        doc,
        f"THREATRADAR | WALLET | {wallet_type.upper()} | "
        f"Ransomware payment evidence | score:{doc.get('final_score', '?')}",
        doc_id,
    )

    event = build_base_event(doc, label)

    attr = event.add_attribute(
        attr_type,
        ioc_value,
        comment=(
            f"Ransomware payment wallet | "
            f"type:{wallet_type} | "
            f"misp_attr:{attr_type} | "
            f"{build_comment(doc)}"
        ),
        disable_correlation=False,
    )
    set_attribute_timestamps(attr, doc)

    add_enrichment_attributes(event, doc)
    add_fusion_object(event, doc)

    source_count = int(doc.get("source_count") or 1)
    corroborated = source_count > 1 or bool(doc.get("analyst_confirmed"))
    wallet_distribution = MISP_CORROBORATED_DIST if corroborated else 0

    _apply_event_settings(event, distribution=wallet_distribution, threat_level_id=1)
    set_event_tlp(event)

    result = push_with_retry(event, f"[wallet] {ioc_value[:30]}", index=index, doc_id=doc_id)
    log.debug("[WALLET-RESULT] type=%s keys=%s repr=%s",
              type(result).__name__,
              list(result.keys())[:10] if isinstance(result, dict) else "N/A",
              repr(result)[:300] if result is not None else "None")
    if _check_misp_result(result, f"[wallet] {ioc_value[:30]}"):
        misp_event_id = _extract_misp_event_id(result)
        if not misp_event_id:
            log.warning("[ID-MISSING] [wallet] %s — event created in MISP but could not extract "
                        "event id from response (type=%s). Check LOG_LEVEL=DEBUG for raw response.",
                        ioc_value[:30], type(result).__name__)
        else:
            log.debug("[ID-OK] [wallet] %s → misp_event_id=%s", ioc_value[:30], misp_event_id)
        _queue_mark_pushed(index, doc_id, misp_event_id=misp_event_id)
        _register_pushed(
            "wallet-hex" if attr_type == "hex" else attr_type,
            ioc_value,
            misp_event_id=misp_event_id,
        )
        dist_label = f"dist:{MISP_CORROBORATED_DIST}(corroborated)" if corroborated else "dist:0(single-source)"
        log.info("[OK]   [ wallet] %s... (attr:%s, %s)", ioc_value[:30], attr_type, dist_label)
        return "pushed"
    return "failed"



def route_and_push(doc: dict, doc_id: str, index: str) -> str:
    ioc_type     = doc.get("ioc_type", "")
    verdict      = doc.get("verdict", "")
    severity     = doc.get("cvss_severity", "")
    action       = doc.get("action", "")
    final_action = str(doc.get("final_action", "")).upper()
    ml_tier      = str(doc.get("ml_tier", "")).upper()

    ioc_value = get_ioc_value(doc, doc_id)

    if ioc_type == "ransomware":
        status = push_threat_actor(doc, doc_id, index, ioc_value)

    elif ioc_type == "wallet":
        if action == "alert_soc" or should_push(doc):
            status = push_wallet(doc, doc_id, index, ioc_value)
        else:
            log.debug("[SKIP] [wallet] %s — verdict:%s | final_action:%s | analyst:%s",
                      ioc_value[:30], verdict, final_action, doc.get("analyst_confirmed"))
            status = "skipped"

    elif ioc_type == "cve":
        if severity in ("HIGH", "CRITICAL"):
            status = push_cve(doc, doc_id, index, ioc_value)
        else:
            log.debug("[SKIP] [cve] %s — severity:%s not HIGH/CRITICAL", ioc_value, severity)
            status = "skipped"

    elif ioc_type in ("ip", "url", "hash", "domain"):
        if should_push(doc):
            status = push_network_ioc(doc, doc_id, index, ioc_value)
        else:
            log.debug("[SKIP] [%s] %s — verdict:%s | final_action:%s | ml_tier:%s",
                      ioc_type, ioc_value, verdict, final_action, ml_tier)
            status = "skipped"

    elif ioc_type in INDEX_MAP:
        log.warning("[WARN] [%s] fetched but has no push handler — add one or remove from INDEX_MAP",
                    ioc_type)
        status = "skipped"

    else:
        log.warning("[SKIP] unknown ioc_type:%r", ioc_type)
        status = "skipped"

    _record_stat(ioc_type or "unknown", status)
    return status


def _build_unpushed_filter() -> dict:
    max_retries = int(os.getenv("MISP_MAX_PUSH_RETRIES", "5"))

    unpushed_clause: dict = {
        "bool": {
            "should": [
                {"term":  {"pushed_to_misp": False}},
                {"bool":  {"must_not": {"exists": {"field": "pushed_to_misp"}}}},
            ],
            "minimum_should_match": 1,
        }
    }

    if max_retries > 0:
        return {
            "bool": {
                "must": [unpushed_clause],
                "should": [
                    {"bool": {"must_not": {"exists": {"field": "misp_push_fail_count"}}}},
                    {"range": {"misp_push_fail_count": {"lt": max_retries}}},
                ],
                "minimum_should_match": 1,
            }
        }

    return unpushed_clause


def fetch_poisoned_iocs() -> list:
    all_hits: list = []
    all_hits_lock  = threading.Lock()

    def _fetch_index(ioc_type: str, index_pattern: str) -> list:
        hits         = []
        search_after = None
        index_total  = 0
        last_res     = None

        while True:
            body: dict = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"poisoning_flagged": True}},
                            _build_unpushed_filter(),
                        ],
                    }
                },
                "_source": _IOC_SOURCE_FIELDS,
                "size": 500,
                "sort": [
                    {"processed_at": {"order": "asc", "unmapped_type": "date"}},
                    {"_shard_doc":   "asc"},
                ],
            }
            if search_after:
                body["search_after"] = search_after

            _fetch_ok = False
            for attempt in range(ES_FETCH_RETRIES):
                try:
                    last_res  = es.search(index=index_pattern, **body)
                    _fetch_ok = True
                    break
                except Exception as exc:
                    err = str(exc).lower()
                    if "index_not_found" in err or "no such index" in err:
                        return hits
                    if attempt < ES_FETCH_RETRIES - 1:
                        log.warning("[WARN] poisoned fetch %s attempt %d failed (%s) — retrying in %.1fs",
                                    index_pattern, attempt + 1, exc, ES_FETCH_RETRY_DELAY)
                        time.sleep(ES_FETCH_RETRY_DELAY)
                    else:
                        log.error("[ERROR] poisoned fetch %s — all %d attempts failed: %s",
                                  index_pattern, ES_FETCH_RETRIES, exc)
            if not _fetch_ok:
                break

            page = last_res["hits"]["hits"]
            if not page:
                break

            for h in page:
                hits.append({
                    "_id":     h["_id"],
                    "_index":  h["_index"],
                    "_source": h["_source"],
                })

            index_total  += len(page)
            search_after  = page[-1]["sort"]

            if len(page) < 500:
                total_available = last_res["hits"]["total"]["value"]
                if index_total > 0:
                    log.info("[POISON-FETCH] %5d / %d poisoned unpushed from %s",
                             index_total, total_available, index_pattern)
                break

        return hits

    with ThreadPoolExecutor(max_workers=len(INDEX_MAP)) as executor:
        futures = {
            executor.submit(_fetch_index, ioc_type, index_pattern): ioc_type
            for ioc_type, index_pattern in INDEX_MAP.items()
        }
        for future in as_completed(futures):
            ioc_type = futures[future]
            try:
                result = future.result()
                with all_hits_lock:
                    all_hits.extend(result)
            except Exception as exc:
                log.error("[ERROR] parallel poisoned fetch for %s: %s", ioc_type, exc)

    return all_hits


def fetch_unpushed_iocs() -> list:
    all_hits: list = []
    all_hits_lock  = threading.Lock()
    cortex_clause: dict = {"term": {"cortex_analyzed": True}}

    push_filter = {
        "bool": {
            "should": [
                {"terms": {"verdict":                ["CRITICAL", "HIGH"]}},
                {"terms": {"final_action":   ["BLOCK", "QUARANTINE", "REVIEW"]}},
                {"term":  {"ml_tier":        "HIGH"}},
                {"term":  {"poisoning_flagged":      True}},
                {"term":  {"analyst_confirmed":      True}},
                {"range": {"llm_confidence":         {"gte": PUSH_LLM_CONFIDENCE_MIN}}},
                {"range": {"composite_poison_score": {"gte": PUSH_POISON_SCORE_MIN}}},
                {"terms": {"ioc_type":               ["ransomware"]}},
                {"terms": {"cvss_severity":          ["HIGH", "CRITICAL"]}},
                {"term":  {"action":                 "alert_soc"}},
            ],
            "minimum_should_match": 1,
        }
    }

    def _fetch_index(ioc_type: str, index_pattern: str) -> list:
        hits         = []
        search_after = None
        last_res     = None

        while True:
            body: dict = {
                "query": {
                    "bool": {
                        "must": [
                            _build_unpushed_filter(),
                            push_filter,
                            cortex_clause,
                        ],
                    }
                },
                "_source": _IOC_SOURCE_FIELDS,
                "size": 500,
                "sort": [
                    {"processed_at": {"order": "asc", "missing": "_last", "unmapped_type": "date"}},
                    {"_shard_doc": "asc"},
                ],
            }
            if search_after:
                body["search_after"] = search_after

            _fetch_ok = False
            for attempt in range(ES_FETCH_RETRIES):
                try:
                    last_res  = es.search(index=index_pattern, **body)
                    _fetch_ok = True
                    break
                except Exception as exc:
                    err_str = str(exc).lower()
                    if "index_not_found" in err_str or "no such index" in err_str:
                        return hits
                    if attempt < ES_FETCH_RETRIES - 1:
                        log.warning("[WARN] fetch %s attempt %d failed (%s) — retrying in %.1fs",
                                    index_pattern, attempt + 1, exc, ES_FETCH_RETRY_DELAY)
                        time.sleep(ES_FETCH_RETRY_DELAY)
                    else:
                        log.error("[ERROR] %s — all %d fetch attempts failed: %s",
                                  index_pattern, ES_FETCH_RETRIES, exc)
            if not _fetch_ok:
                break

            page = last_res["hits"]["hits"]
            if not page:
                break

            for hit in page:
                hits.append({
                    "_id":     hit["_id"],
                    "_index":  hit["_index"],
                    "_source": hit["_source"],
                })

            search_after = page[-1]["sort"]
            if len(page) < 500:
                break

        if hits and last_res is not None:
            total_available = last_res["hits"]["total"]["value"]
            log.info("  Fetched %5d / %d pushable from %s",
                     len(hits), total_available, index_pattern)
        return hits

    with ThreadPoolExecutor(max_workers=len(INDEX_MAP)) as executor:
        futures = {
            executor.submit(_fetch_index, ioc_type, index_pattern): ioc_type
            for ioc_type, index_pattern in INDEX_MAP.items()
        }
        for future in as_completed(futures):
            ioc_type = futures[future]
            try:
                result = future.result()
                with all_hits_lock:
                    all_hits.extend(result)
            except Exception as exc:
                log.error("[ERROR] parallel fetch for %s: %s", ioc_type, exc)

    return all_hits


def _prewarm_dedup_cache_from_es(iocs: list) -> None:
    cached = 0
    for item in iocs:
        doc           = item["_source"]
        misp_event_id = doc.get("misp_event_id", "")
        if not misp_event_id:
            continue

        ioc_type  = doc.get("ioc_type", "")
        ioc_value = doc.get("ioc_value") or doc.get("value", "")
        if not ioc_value or not ioc_type:
            continue

        if ioc_type == "hash":
            attr_type = get_hash_attr_type(doc, ioc_value)
        elif ioc_type == "cve":
            attr_type = "vulnerability"
        elif ioc_type == "ransomware":
            attr_type = "threat-actor"
        elif ioc_type == "wallet":
            resolved  = resolve_wallet_attr_type(doc)
            attr_type = "wallet-hex" if resolved == "hex" else resolved
        else:
            attr_type = ATTR_TYPE_MAP.get(ioc_type, "text")

        _register_pushed(attr_type, ioc_value, misp_event_id=misp_event_id)
        cached += 1

    total   = len(iocs)
    unknown = total - cached
    log.info(
        "[PREWARM] %d / %d IOCs have misp_event_id in ES → skip MISP search() | "
        "%d need live MISP dedup check",
        cached, total, unknown,
    )

def push_to_misp():
    global es, misp

    try:
        es   = get_es_client()
        misp = get_misp_client()
    except EnvironmentError as exc:
        log.error("[FAIL] Client configuration error: %s", exc)
        return

    with _cache_lock:
        _pushed_this_run.clear()

    with _stats_lock:
        _stats.clear()

    run_start = time.monotonic()

    log.info("=" * 60)
    log.info("THREATRADAR -MISP Pusher")
    log.info("=" * 60)
    log.info("MISP URL          : %s", os.getenv("MISP_URL"))
    log.info("ELASTIC_HOST      : %s", os.getenv("ELASTIC_HOST"))
    log.info("Push workers      : %d", MISP_PUSH_WORKERS)
    log.info("Bulk flush size   : %d", BULK_FLUSH_SIZE)
    log.info("Push delay (s)    : %.3f", MISP_PUSH_DELAY)
    log.info("Search delay (s)  : %.3f", MISP_SEARCH_DELAY)
    log.info("Max IOC age (days): %s",
             str(MISP_MAX_IOC_AGE_DAYS) if MISP_MAX_IOC_AGE_DAYS > 0 else "disabled")
    log.info("Max push retries (ES gate)   : %s",
             str(os.getenv("MISP_MAX_PUSH_RETRIES", "5")) + " (0=unlimited)")
    log.info("Event push retries (MISP API): %d", MISP_EVENT_PUSH_RETRIES)
    log.info("TLP tag           : %s", os.getenv("MISP_TLP_TAG", "tlp:green"))
    log.info("PAP tag (default) : %s", os.getenv("MISP_PAP_TAG", "PAP:GREEN"))
    log.info("ES fetch retries  : %d", ES_FETCH_RETRIES)
    log.info("Sighting source   : %s", os.getenv("MISP_SIGHTING_SOURCE", "threatradar"))
    log.info("Sighting by value : %s", os.getenv("MISP_SIGHTING_BY_VALUE", "true"))
    log.info("Distribution      : clean=%d  corroborated=%d  cve_exploited=%d",
             MISP_CLEAN_DISTRIBUTION, MISP_CORROBORATED_DIST, MISP_CVE_EXPLOITED_DIST)
    log.info("Push thresholds   : llm_confidence>=%d  poison_score>=%.2f",
             PUSH_LLM_CONFIDENCE_MIN, PUSH_POISON_SCORE_MIN)

    _tlp = os.getenv("MISP_TLP_TAG", "tlp:green").lower()
    _tlp_dist_guide = {
        "tlp:red":    (0,),
        "tlp:amber":  (0, 1),
        "tlp:green":  (1, 2),
        "tlp:white":  (2, 3),
        "tlp:clear":  (2, 3),
    }
    _allowed = _tlp_dist_guide.get(_tlp)
    if _allowed is not None:
        _bad = [
            (label, val) for label, val in [
                ("MISP_CLEAN_DISTRIBUTION",  MISP_CLEAN_DISTRIBUTION),
                ("MISP_CORROBORATED_DIST",   MISP_CORROBORATED_DIST),
                ("MISP_CVE_EXPLOITED_DIST",  MISP_CVE_EXPLOITED_DIST),
            ]
            if val not in _allowed
        ]
        if _bad:
            for var, val in _bad:
                log.warning(
                    "[CONFIG] TLP/distribution mismatch: %s=%d is not valid for %s "
                    "(expected one of %s). Events will trigger MISP distribution warnings.",
                    var, val, _tlp, _allowed,
                )

    try:
        ver = misp.misp_instance_version
        log.info("[OK] MISP connected — version %s", ver.get("version", "?"))
    except Exception as exc:
        log.error("[FAIL] MISP connection failed: %s", exc)
        return

    try:
        es.info()
        log.info("[OK] Elasticsearch connected")
    except Exception as exc:
        log.error("[FAIL] Elasticsearch connection failed: %s", exc)
        return

    try:
        log.info("\n[FETCH] Priority pass — querying for poisoned IOCs (parallel)...")
        poisoned_iocs = fetch_poisoned_iocs()
        poisoned_ids  = {i["_id"] for i in poisoned_iocs}
        log.info("        %d poisoned IOCs queued for priority push", len(poisoned_iocs))

        log.info("\n[FETCH] Regular pass — querying all indices in parallel...")
        regular_iocs = fetch_unpushed_iocs()
        regular_iocs = [i for i in regular_iocs if i["_id"] not in poisoned_ids]
        iocs = poisoned_iocs + regular_iocs
        log.info("\n[PUSH] Processing %d IOCs (%d poisoned + %d regular)...",
                 len(iocs), len(poisoned_iocs), len(regular_iocs))

        _prewarm_dedup_cache_from_es(iocs)

        pushed = failed = skipped = stale = 0
        poisoned_pushed = 0
        _counters_lock = threading.Lock()

        def _handle_status(doc: dict, status: str):
            nonlocal pushed, failed, skipped, stale, poisoned_pushed
            with _counters_lock:
                if status == "pushed":
                    pushed += 1
                    if doc.get("poisoning_flagged"):
                        poisoned_pushed += 1
                elif status == "skipped":
                    skipped += 1
                elif status == "stale":
                    stale += 1
                else:
                    failed += 1

        if MISP_PUSH_WORKERS > 1 and iocs:

            with ThreadPoolExecutor(max_workers=MISP_PUSH_WORKERS) as executor:
                futures = {
                    executor.submit(
                        route_and_push,
                        item["_source"],
                        item["_id"],
                        item["_index"],
                    ): item
                    for item in iocs 
                }
                for future in as_completed(futures):
                    item = futures[future]
                    doc  = item["_source"]
                    try:
                        status = future.result()
                    except ValueError as exc:
                        log.error("[ERROR] doc:%s — %s", item["_id"], exc)
                        status = "failed"
                    except Exception as exc:
                        ioc_val = doc.get("ioc_value") or doc.get("value", "?")
                        log.error("[ERROR] %s: %s", ioc_val, exc)
                        status = "failed"
                    _handle_status(doc, status)
        else:
            for item in iocs:
                doc    = item["_source"]
                doc_id = item["_id"]
                index  = item["_index"]
                try:
                    status = route_and_push(doc, doc_id, index)
                except ValueError as exc:
                    log.error("[ERROR] doc:%s — %s", doc_id, exc)
                    status = "failed"
                except Exception as exc:
                    ioc_val = doc.get("ioc_value") or doc.get("value", "?")
                    log.error("[ERROR] %s: %s", ioc_val, exc)
                    status = "failed"
                _handle_status(doc, status)

    finally:
        _flush_mark_batch()

    elapsed = time.monotonic() - run_start

    log.info("\n" + "=" * 60)
    log.info("Done in %.1fs — pushed:%d  failed:%d  skipped:%d  stale:%d",
             elapsed, pushed, failed, skipped, stale)
    if poisoned_pushed:
        log.warning("  poisoned IOCs pushed to MISP : %d", poisoned_pushed)
    if stale:
        log.info("  stale IOCs skipped (>%dd)     : %d", MISP_MAX_IOC_AGE_DAYS, stale)

    log.info("\nPer-type breakdown:")
    with _stats_lock:
        for ioc_type in sorted(_stats.keys()):
            counts = _stats[ioc_type]
            parts  = ", ".join(f"{s}:{counts[s]}" for s in ("pushed", "failed", "skipped", "stale") if counts[s])
            log.info("  %-12s %s", ioc_type, parts or "—")
    log.info("=" * 60)

if __name__ == "__main__":
    push_to_misp()
