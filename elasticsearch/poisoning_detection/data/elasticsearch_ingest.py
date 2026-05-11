import os
from typing import Optional

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

DEFAULT_ES_URL  = os.getenv("ELASTIC_HOST", "http://elasticsearch:9200")
DEFAULT_INDEX   = os.getenv("ES_SOURCE_INDEX", "ti_ip,ti_url,ti_domain,ti_hash,ti_cve,ti_wallet,ti_ransomware")
DEFAULT_SCROLL  = "5m"
DEFAULT_BATCH   = 5000

_ENV_ES_USER      = os.getenv("ELASTIC_USER") or ""
_ENV_ES_PASSWORD  = os.getenv("ELASTIC_PASSWORD") or ""
_ENV_VERIFY_CERTS = os.getenv("ES_VERIFY_CERTS", "false").lower() not in ("0", "false", "no")


def _parse_es_hosts(es_url: str) -> list[str]:
    if not es_url:
        return []
    return [h.strip() for h in es_url.split(",") if h.strip()]


def _build_es_client(
    hosts: list[str],
    verify_certs: bool,
    es_user: Optional[str],
    es_password: Optional[str],
) -> Elasticsearch:
    kwargs: dict = {"hosts": hosts, "verify_certs": verify_certs}
    if es_user and es_password:
        kwargs["basic_auth"] = (es_user, es_password)
    return Elasticsearch(**kwargs)


def _connect_es(
    es_url: str,
    es_user: Optional[str] = None,
    es_password: Optional[str] = None,
    verify_certs: bool = _ENV_VERIFY_CERTS,
) -> Elasticsearch:
    user     = es_user     or _ENV_ES_USER     or None
    password = es_password or _ENV_ES_PASSWORD or None

    hosts = _parse_es_hosts(es_url)
    if not hosts:
        raise ConnectionError("ELASTIC_HOST is empty — cannot connect to Elasticsearch.")

    client = _build_es_client(hosts, verify_certs, user, password)
    if not client.ping():
        raise ConnectionError(f"Cannot reach Elasticsearch at {es_url!r}.")
    return client


def _build_query(
    query_filter: Optional[dict] = None,
    time_range_field: str = "@timestamp",
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> dict:
    must: list[dict] = []

    if time_from or time_to:
        range_clause: dict = {"range": {time_range_field: {}}}
        if time_from:
            range_clause["range"][time_range_field]["gte"] = time_from
        if time_to:
            range_clause["range"][time_range_field]["lte"] = time_to
        must.append(range_clause)

    if query_filter:
        must.append(query_filter)
    return {"query": {"bool": {"must": must}}}


def _apply_cortex_filter(query_body: dict) -> dict:

    existing_must   = query_body.get("query", {}).get("bool", {}).get("must",   [])
    existing_filter = query_body.get("query", {}).get("bool", {}).get("filter", [])
    cortex_clause: dict = {
        "bool": {
            "should": [
                {"term": {"cortex_analyzed": True}},
                {"term": {"cortex_analyzed": "true"}},
            ],
            "minimum_should_match": 1,
        }
    }

    return {
        "query": {
            "bool": {
                "must":   existing_must,
                "filter": existing_filter + [cortex_clause],
            }
        }
    }


def _normalize_record(hit: dict) -> dict:
    parsed = dict(hit.get("_source", {}))
    parsed["_id"]    = hit.get("_id",    "")
    parsed["_index"] = hit.get("_index", "")
    if "ioc_id" not in parsed:
        parsed["ioc_id"] = parsed["_id"]
    return parsed

def ingest_from_elasticsearch(
    es_url: str = DEFAULT_ES_URL,
    index: str = DEFAULT_INDEX,
    query_filter: Optional[dict] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
    max_docs: int = 0,
    scroll: str = DEFAULT_SCROLL,
    batch_size: int = DEFAULT_BATCH,
    es_user: Optional[str] = None,
    es_password: Optional[str] = None,
    verify_certs: bool = _ENV_VERIFY_CERTS,
    cortex_analyzed_only: bool = True,        
) -> list[dict]:

    print(f"[ingest] cortex_analyzed_only = {cortex_analyzed_only}")
    print(f"[ingest] index                = {index}")
    print(f"[ingest] es_url               = {es_url}")

    try:
        es = _connect_es(es_url, es_user, es_password, verify_certs)
    except Exception as exc:
        print(f"[ingest] Connection failed: {exc}")
        return []

    query_body = _build_query(query_filter, time_from=time_from, time_to=time_to)

    if cortex_analyzed_only:
        query_body = _apply_cortex_filter(query_body)

    effective_batch = min(batch_size, max_docs) if max_docs else batch_size

    records: list[dict] = []
    total_available: Optional[int] = None
    scroll_id: Optional[str] = None
    try:
        resp = es.search(
            index=index,
            body={
                **query_body,
                "size": effective_batch,
                "track_total_hits": True,
            },
            scroll=scroll,
        )

        total_available = resp["hits"]["total"]["value"]
        print(f"[ingest] Total documents matching query: {total_available:,}")

        scroll_id = resp.get("_scroll_id")
        hits      = resp["hits"]["hits"]

        while hits:
            for hit in hits:
                records.append(_normalize_record(hit))
                if max_docs and len(records) >= max_docs:
                    break                          

            if max_docs and len(records) >= max_docs:
                break                              

            if not scroll_id:
                break

            resp      = es.scroll(scroll_id=scroll_id, scroll=scroll)
            scroll_id = resp.get("_scroll_id")
            hits      = resp["hits"]["hits"]

    except Exception as exc:
        print(f"[ingest] Elasticsearch error during fetch: {exc}")
        print(f"[ingest] WARNING: Only {len(records):,} records fetched before error.")
        return records

    finally:
        if scroll_id:
            try:
                es.clear_scroll(scroll_id=scroll_id)
            except Exception:
                pass

    if total_available is not None:
        expected = min(max_docs, total_available) if max_docs else total_available
        if len(records) < expected:
            print(
                f"[ingest] WARNING: Expected {expected:,} records but got "
                f"{len(records):,}. Data may be incomplete."
            )
        else:
            print(f"[ingest] Ingested {len(records):,} / {total_available:,} records from {index!r}")

    return records

_ANALYSIS_WRITE_FIELDS: frozenset[str] = frozenset({
    "ml_score",
    "poisoning_flagged",
    "poison_strategy",
    "infrastructure_age_days",  
    "llm_verdict",
    "llm_confidence",
    "llm_poison_score",
    "llm_contradiction_class",
    "llm_contradictions_found",
    "llm_coherence_reasoning",
    "llm_red_flags",
    "llm_analyst_challenge",
    "llm_raw_response",
    "composite_poison_score",
    "final_action",
    "final_likelihood",
    "fusion_confidence",
    "fusion_reasoning",
    "ml_tier",
    "contradictions_count",
    "analysis_ts",
})


def update_documents_with_analysis(
    records: list[dict],
    es_url: str = DEFAULT_ES_URL,
    es_user: Optional[str] = None,
    es_password: Optional[str] = None,
    verify_certs: bool = _ENV_VERIFY_CERTS,
    chunk_size: int = 500,
) -> None:

    if not records:
        print("[update] No records to update — skipping.")
        return

    try:
        es = _connect_es(es_url, es_user, es_password, verify_certs)
    except Exception as exc:
        print(f"[update] Connection failed: {exc}")
        return

    actions: list[dict] = []
    skipped = 0

    for rec in records:
        doc_id    = rec.get("_id")
        doc_index = rec.get("_index")

        if not doc_id or not doc_index:
            skipped += 1
            continue

        doc_fields = {
            k: v for k, v in rec.items()
            if k in _ANALYSIS_WRITE_FIELDS
        }

        if not doc_fields:
            skipped += 1
            continue

        actions.append({
            "_op_type": "update",
            "_index":   doc_index,
            "_id":      doc_id,
            "doc":      doc_fields,
        })

    if skipped:
        print(f"[update] Skipped {skipped:,} records missing _id or _index.")

    if not actions:
        print("[update] No valid actions to execute.")
        return

    try:
        success, failed = bulk(es, actions, chunk_size=chunk_size, refresh=True)
        print(f"[update] Bulk update complete: {success:,} succeeded, {len(failed):,} failed.")
        if failed:
            for item in failed[:5]:
                print(f"[update]   failed item: {item}")
    except Exception as exc:
        print(f"[update] Bulk update raised an exception: {exc}")
