"""
misp_daily_refresh.py
Daily job: find IOCs already pushed to MISP whose ES scores changed, and update them.
and check if there i new data not puhsed to MISP
© 2026 THREATRADAR Team
"""
import logging
import os
import time
from datetime import datetime, timezone
from dotenv import load_dotenv
from misp_helpers import get_es_client, get_misp_client, build_ml_comment, _safe_tag_value
from common import OUTPUT_INDICES

load_dotenv()

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("misp_daily_refresh")

PAGE_SIZE     = int(os.getenv("REFRESH_PAGE_SIZE", "200"))
REFRESH_DELAY = float(os.getenv("REFRESH_DELAY", "0.2"))

INDEX_PATTERNS = list(OUTPUT_INDICES.values())


def fetch_stale_docs(es) -> list:
    all_hits = []
    for index in INDEX_PATTERNS:
        search_after = None
        count = 0
        while True:
            body = {
                "query": {
                    "bool": {
                        "must": [
                            {"term":   {"pushed_to_misp": True}},
                            {"exists": {"field": "misp_event_id"}},
                            {
                                "script": {
                                    "script": {
                                        "source": """
                                            def pushed = doc.containsKey('misp_push_timestamp') && doc['misp_push_timestamp'].size() > 0
                                                ? doc['misp_push_timestamp'].value.toInstant().toEpochMilli() : 0L;
                                            def updated = doc.containsKey('last_seen') && doc['last_seen'].size() > 0
                                                ? doc['last_seen'].value.toInstant().toEpochMilli() : 0L;
                                            return updated > pushed;
                                        """,
                                        "lang": "painless",
                                    }
                                }
                            },
                        ]
                    }
                },
                "size": PAGE_SIZE,
                "sort": [
                    {"last_seen": {"order": "asc", "unmapped_type": "date"}},
                    {"_id": "asc"},
                ],
                "_source": [
                    "ioc_value", "value", "verdict",
                    "ml_score", "ml_tier", "final_action",
                    "fusion_confidence", "fusion_reasoning",
                    "llm_confidence", "llm_verdict",
                    "composite_poison_score", "poisoning_flagged", "poison_strategy",
                    "misp_event_id",
                    "final_likelihood",
                    "contradictions_count",
                    "llm_poison_score",
                    "llm_contradiction_class",
                    "final_score",
                ],
            }
            if search_after:
                body["search_after"] = search_after
            try:
                res = es.search(index=index, **body)
            except Exception as exc:
                err = str(exc).lower()
                if "index_not_found" in err or "no such index" in err:
                    break
                log.error("[ERROR] %s: %s", index, exc)
                break

            hits = res["hits"]["hits"]
            if not hits:
                break
            for hit in hits:
                all_hits.append({"_id": hit["_id"], "_index": hit["_index"], "_source": hit["_source"]})
            count += len(hits)
            search_after = hits[-1]["sort"]
            if len(hits) < PAGE_SIZE:
                break

        if count:
            log.info("  %5d stale docs from %s", count, index)
    return all_hits


def update_event(misp, es, item: dict) -> str:
    doc           = item["_source"]
    doc_id        = item["_id"]
    index         = item["_index"]
    misp_event_id = doc.get("misp_event_id")

    if not misp_event_id:
        _clear_flags(es, doc_id, index)
        return "requeued"

    try:
        event = misp.get_event(misp_event_id, pythonify=True)
    except Exception as exc:
        log.warning("[WARN] get_event %s: %s", misp_event_id, exc)
        return "failed"

    if not getattr(event, "id", None) or (isinstance(event, dict) and "errors" in event):
        _clear_flags(es, doc_id, index)
        return "requeued"

    changed = False
    verdict = doc.get("verdict", "")
    if verdict:
        new_tag = f"threatradar:verdict={_safe_tag_value(verdict)}"
        if new_tag not in [t.name for t in (event.tags or [])]:
            misp.tag(event, new_tag)
            changed = True
    ml_comment = build_ml_comment(doc)
    if ml_comment:
        event.add_attribute(
            "comment",
            f"[REFRESH {datetime.now(timezone.utc).strftime('%Y-%m-%d')}] {ml_comment}",
            disable_correlation=True,
        )
        try:
            misp.update_event(event)
            changed = True
        except Exception as exc:
            log.warning("[WARN] update_event %s: %s", misp_event_id, exc)
            return "failed"

    try:
        ioc_value = doc.get("ioc_value") or doc.get("value", "")
        if ioc_value:
            misp.add_sighting({"value": ioc_value, "type": "0"})
    except Exception:
        pass
    try:
        es.update(
            index=index, id=doc_id,
            doc={"misp_push_timestamp": datetime.now(timezone.utc).isoformat()},
            retry_on_conflict=3,
        )
    except Exception as exc:
        log.warning("[WARN] stamp timestamp %s: %s", doc_id, exc)

    return "updated" if changed else "unchanged"


def _clear_flags(es, doc_id: str, index: str):
    try:
        es.update(
            index=index, id=doc_id,
            script={
                "source": (
                    "ctx._source.remove('pushed_to_misp'); "
                    "ctx._source.remove('misp_event_id'); "
                    "ctx._source.remove('misp_push_timestamp');"
                ),
                "lang": "painless",
            },
            retry_on_conflict=3,
        )
    except Exception as exc:
        log.warning("[WARN] clear flags %s: %s", doc_id, exc)


def run():
    log.info("=" * 60)
    log.info("MISP Daily Refresh — %s", datetime.now(timezone.utc).isoformat())
    log.info("=" * 60)

    try:
        es   = get_es_client()
        misp = get_misp_client()
    except EnvironmentError as exc:
        log.error("[FAIL] %s", exc)
        return

    try:
        es.info()
        log.info("[OK] Elasticsearch connected")
    except Exception as exc:
        log.error("[FAIL] Elasticsearch: %s", exc)
        return

    try:
        ver = misp.misp_instance_version
        log.info("[OK] MISP connected — version %s", ver.get("version", "?"))
    except Exception as exc:
        log.error("[FAIL] MISP: %s", exc)
        return

    docs = fetch_stale_docs(es)
    log.info("[REFRESH] %d docs to process", len(docs))

    updated = unchanged = requeued = failed = 0
    for item in docs:
        status = update_event(misp, es, item)
        if status == "updated":       updated   += 1
        elif status == "unchanged":   unchanged += 1
        elif status == "requeued":    requeued  += 1
        else:                         failed    += 1
        time.sleep(REFRESH_DELAY)

    log.info("=" * 60)
    log.info("Done — updated:%d  unchanged:%d  requeued:%d  failed:%d",
             updated, unchanged, requeued, failed)
    log.info("=" * 60)

if __name__ == "__main__":
    run()
