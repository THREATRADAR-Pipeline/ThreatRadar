#!/usr/bin/env python3
"""
Retrain with Feedback: retrain the anomaly detection model using analyst feedback synced from MISP to Elasticsearch.

© 2026 THREATRADAR Team
"""
from __future__ import annotations

import os
import json
import logging
import inspect
from datetime import datetime, timezone, timedelta
from typing import Any

from elasticsearch import Elasticsearch

try:
    from data.elasticsearch_ingest import ingest_from_elasticsearch
except ImportError:
    from elasticsearch_ingest import ingest_from_elasticsearch  
try:
    from anomaly_detector import AnomalyDetector
except ImportError:
    from models.anomaly_detector import AnomalyDetector  

log = logging.getLogger("retrain_feedback")

MODEL_DIR          = os.getenv("MODEL_DIR", "/app/models")
CONTAMINATION      = float(os.getenv("CONTAMINATION_MAX", "0.05"))
MIN_SIGHTINGS      = int(os.getenv("TRAIN_MIN_SIGHTINGS", "2"))
PAGE_SIZE          = int(os.getenv("TRAIN_PAGE_SIZE", "500"))
MAX_DOCS_TOTAL     = int(os.getenv("TRAIN_MAX_DOCS", "20000"))
MIN_DOCS           = int(os.getenv("TRAIN_MIN_DOCS", "50"))
ES_REQUEST_TIMEOUT = int(os.getenv("ES_REQUEST_TIMEOUT", "30"))


_RETRAIN_STATE_FILE = "last_retrain_state.json"

_EPOCH_FALLBACK = "2000-01-01T00:00:00+00:00"


def _get_es_client() -> Elasticsearch:
    host     = os.getenv("ELASTIC_HOST") or os.getenv("ES_URL", "http://elasticsearch:9200")
    user     = os.getenv("ELASTIC_USER") or os.getenv("ES_USER", "elastic")
    password = os.getenv("ELASTIC_PASSWORD") or os.getenv("ES_PASSWORD", "")
    verify   = os.getenv("ES_VERIFY_SSL", "false").lower() in ("1", "true", "yes")

    es_sig    = inspect.signature(Elasticsearch.__init__)
    es_params = list(es_sig.parameters.keys())

    kwargs: dict = {
        "hosts": [host],
        "verify_certs": verify,
        "retry_on_timeout": True,
        "max_retries": 3,
    }
    if password:
        kwargs["basic_auth"] = (user, password)

    if "request_timeout" in es_params:
        kwargs["request_timeout"] = ES_REQUEST_TIMEOUT
    elif "timeout" in es_params:
        kwargs["timeout"] = ES_REQUEST_TIMEOUT

    return Elasticsearch(**kwargs)


def _es_search_with_timeout(es: Elasticsearch, **kwargs) -> Any:
    try:
        return es.options(request_timeout=ES_REQUEST_TIMEOUT).search(**kwargs)
    except (TypeError, AttributeError):
        return es.search(**kwargs)


def _es_count_with_timeout(es: Elasticsearch, **kwargs) -> Any:
    try:
        return es.options(request_timeout=ES_REQUEST_TIMEOUT).count(**kwargs)
    except (TypeError, AttributeError):
        return es.count(**kwargs)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()



def load_retrain_state(model_dir: str) -> dict:
    path = os.path.join(model_dir, _RETRAIN_STATE_FILE)
    try:
        with open(path) as fh:
            state = json.load(fh)
        log.debug("[STATE] loaded %s", path)
        return state
    except FileNotFoundError:
        log.info("[STATE] %s not found — treating as first run", path)
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("[STATE] could not read %s (%s) — using defaults", path, exc)
    return {
        "last_retrain_at":            _EPOCH_FALLBACK,
        "confirmed_count_at_retrain": 0,
        "sighted_count_at_retrain":   0,
    }


def save_retrain_state(
    model_dir: str,
    last_retrain_at: str,
    confirmed_total: int,
    sighted_total: int,
) -> None:

    os.makedirs(model_dir, exist_ok=True)
    state = {
        "last_retrain_at":            last_retrain_at,
        "confirmed_count_at_retrain": confirmed_total,
        "sighted_count_at_retrain":   sighted_total,
        "written_at":                 _utc_now(),
    }
    path     = os.path.join(model_dir, _RETRAIN_STATE_FILE)
    tmp_path = path + ".tmp"
    try:
        with open(tmp_path, "w") as fh:
            json.dump(state, fh, indent=2)
        os.replace(tmp_path, path)         
        log.info("[STATE] saved retrain state → %s", path)
    except OSError as exc:
        log.warning("[STATE] could not write %s: %s", path, exc)

def count_feedback_delta(
    es: Elasticsearch,
    indices: list[str],
    since_ts: str,
    min_sightings: int,
    fresh_days: int,
) -> dict:
    
    now           = datetime.now(timezone.utc)
    fresh_cutoff  = (now - timedelta(days=fresh_days)).isoformat()

    try:
        since_dt = datetime.fromisoformat(since_ts)
    except ValueError:
        since_dt = datetime.fromisoformat(_EPOCH_FALLBACK)
    fresh_lower = max(since_dt, now - timedelta(days=fresh_days)).isoformat()

    _poisoning_filter = [
        {"term":  {"poisoning_flagged": True}},
        {"range": {"composite_poison_score": {"gte": 0.45}}},
    ]
    _sighting_core = {
        "must": [
            {"range": {"misp_sightings": {"gte": min_sightings}}},
        ],
        "must_not": _poisoning_filter,
    }

    queries = {
        "new_confirmed": {
            "bool": {"must": [
                {"term":  {"analyst_confirmed": True}},
                {"range": {"feedback_synced_at": {"gt": since_ts}}},
            ]}
        },
        "new_sighted": {
            "bool": {
                "must": [
                    *_sighting_core["must"],
                    {"range": {"feedback_synced_at": {"gt": since_ts}}},
                ],
                "must_not": _poisoning_filter,
            }
        },
        "fresh_new": {
            "bool": {
                "must": [
                    {"range": {"feedback_synced_at": {"gt": fresh_lower}}},
                ],
                "should": [
                    {"term": {"analyst_confirmed": True}},
                    {"bool": _sighting_core},
                ],
                "minimum_should_match": 1,
            }
        },
        "total_confirmed": {
            "term": {"analyst_confirmed": True}
        },
        "total_sighted": {
            "bool": _sighting_core
        },
    }

    totals: dict[str, int] = {k: 0 for k in queries}

    for idx in indices:
        for key, query in queries.items():
            try:
                resp         = _es_count_with_timeout(es, index=idx, query=query)
                totals[key] += int(resp.get("count", 0))
            except Exception as exc:
            
                log.debug("[DELTA] count(%s) on %s failed: %s", key, idx, exc)

    result = {
        **totals,
        "since_ts":    since_ts,
        "fresh_cutoff": fresh_lower,
        "fresh_days":   fresh_days,
    }
    log.info(
        "[DELTA] new_confirmed=%d  new_sighted=%d  fresh_new=%d  "
        "total_confirmed=%d  total_sighted=%d  (since=%s  fresh_cutoff=%s)",
        result["new_confirmed"], result["new_sighted"], result["fresh_new"],
        result["total_confirmed"], result["total_sighted"],
        since_ts[:19], fresh_lower[:19],
    )
    return result

def _build_analyst_confirmed_query() -> dict:
    return {"bool": {"must": [{"term": {"analyst_confirmed": True}}]}}


def _build_sighting_trusted_query(min_sightings: int) -> dict:
    return {
        "bool": {
            "must": [
                {"range": {"misp_sightings": {"gte": min_sightings}}},
            ],
            "must_not": [
                {"term":  {"poisoning_flagged": True}},
                {"range": {"composite_poison_score": {"gte": 0.45}}},
            ],
        }
    }


def fetch_trusted_training_docs(
    es: Elasticsearch,
    index_pattern: str,
    min_sightings: int,
    page_size: int,
    max_docs: int,
) -> list[dict]:
    seen_ids: set[str] = set()
    out: list[dict]    = []

    def _paginate(query: dict, label: str) -> None:
        nonlocal out
        search_after = None
        while True:
            if max_docs and len(out) >= max_docs:
                return
            kwargs = {
                "index": index_pattern,
                "query": query,
                "size":  min(page_size, max_docs - len(out)) if max_docs else page_size,
                "sort":  [
                    {"processed_at": {"order": "asc", "missing": "_last", "unmapped_type": "date"}},
                    {"_shard_doc": "asc"},
                ],
            }
            if search_after:
                kwargs["search_after"] = search_after
            try:
                res = _es_search_with_timeout(es, **kwargs)
            except Exception as exc:
                log.warning("[ES] %s search on %s failed: %s", label, index_pattern, exc)
                break
            hits = res["hits"]["hits"]
            if not hits:
                break
            for h in hits:
                doc_id = h["_id"]
                if doc_id not in seen_ids:
                    seen_ids.add(doc_id)
                    src        = h.get("_source") or {}
                    src["_id"]    = doc_id
                    src["_index"] = h["_index"]
                    out.append(src)
            search_after = hits[-1]["sort"]
            if len(hits) < page_size:
                break

    _paginate(_build_analyst_confirmed_query(),             "gate-A-confirmed")
    gate_a = len(out)
    _paginate(_build_sighting_trusted_query(min_sightings), "gate-B-sightings")
    log.debug("[TRAIN] %s gate-A=%d total=%d", index_pattern, gate_a, len(out))
    return out


def _count_training_candidates(
    es: Elasticsearch,
    index: str,
    min_sightings: int,
) -> dict:
    counts = {
        "analyst_confirmed": 0, "sighted": 0,
        "any_sightings":     0, "poisoned_excluded": 0,
    }
    queries = {
        "analyst_confirmed": {"term": {"analyst_confirmed": True}},
        "sighted": {
            "bool": {
                "must": [
                    {"range": {"misp_sightings": {"gte": min_sightings}}},
                ],
                "must_not": [
                    {"term":  {"poisoning_flagged": True}},
                    {"range": {"composite_poison_score": {"gte": 0.45}}},
                ],
            }
        },
        "any_sightings":    {"range": {"misp_sightings": {"gte": 1}}},
        "poisoned_excluded": {
            "bool": {
                "should": [
                    {"term":  {"poisoning_flagged": True}},
                    {"range": {"composite_poison_score": {"gte": 0.45}}},
                ],
                "minimum_should_match": 1,
            }
        },
    }
    for key, q in queries.items():
        try:
            r         = _es_count_with_timeout(es, index=index, query=q)
            counts[key] = r.get("count", 0)
        except Exception as exc:
            log.debug("[PREFLIGHT] count %s on %s failed: %s", key, index, exc)
    return counts

def retrain_from_feedback(
    indices:        list[str],
    model_dir:      str           = MODEL_DIR,
    contamination:  float         = CONTAMINATION,
    min_sightings:  int           = MIN_SIGHTINGS,
    page_size:      int           = PAGE_SIZE,
    max_docs_total: int           = MAX_DOCS_TOTAL,
    es_url:         str | None    = None,
    es_user:        str | None    = None,
    es_password:    str | None    = None,
) -> dict:

    _es_url      = es_url      or os.getenv("ELASTIC_HOST") or os.getenv("ES_URL", "http://elasticsearch:9200")
    _es_user     = es_user     or os.getenv("ELASTIC_USER") or os.getenv("ES_USER", "elastic")
    _es_password = es_password or os.getenv("ELASTIC_PASSWORD") or os.getenv("ES_PASSWORD", "")
    max_scored   = int(os.getenv("TRAIN_MAX_SCORED_DOCS", "500000"))

    es           = _get_es_client()
    per_index_cap = max(1000, int(max_docs_total / max(1, len(indices))))
    all_records: list[dict] = []

    for idx in indices:
        preflight = _count_training_candidates(es, idx, min_sightings)
        log.info(
            "[PREFLIGHT] %-25s  confirmed=%d  sighted=%d  any_sightings=%d  poisoned_excluded=%d",
            idx,
            preflight["analyst_confirmed"], preflight["sighted"],
            preflight["any_sightings"],     preflight["poisoned_excluded"],
        )
        docs = fetch_trusted_training_docs(es, idx, min_sightings, page_size, per_index_cap)
        log.info("[TRAINSET] %-25s  tier1=%d", idx, len(docs))
        all_records.extend(docs)

    tier1_count = len(all_records)
    tier1_ids   = {d["_id"] for d in all_records}

    index_pattern = ",".join(indices)
    log.info(
        "[TRAINSET] gate-D — ingesting all scored docs from %s (max=%d)",
        index_pattern, max_scored,
    )
    try:
        scored_docs = ingest_from_elasticsearch(
            es_url=_es_url,
            index=index_pattern,
            max_docs=max_scored,
            batch_size=page_size,
            es_user=_es_user,
            es_password=_es_password,
            verify_certs=False,
            cortex_analyzed_only=True,
        )
    except Exception as exc:
        log.warning("[TRAINSET] gate-D ingest failed (%s) — continuing with tier-1 only", exc)
        scored_docs = []

    new_scored = [d for d in scored_docs if d.get("_id") not in tier1_ids]
    log.info("[TRAINSET] gate-D  raw=%d  after_dedup=%d", len(scored_docs), len(new_scored))
    all_records.extend(new_scored)
    tier2_count = len(new_scored)

    log.info(
        "[TRAINSET] total  tier1=%d  tier2=%d  combined=%d",
        tier1_count, tier2_count, len(all_records),
    )

    if len(all_records) < MIN_DOCS:
        msg = (
            f"Not enough docs (got {len(all_records)}, need >= {MIN_DOCS}). "
            f"Actions: (1) run the production pipeline so ml_score is populated, "
            f"(2) lower TRAIN_MIN_DOCS (currently {MIN_DOCS})."
        )
        log.warning("[SKIP] %s", msg)
        return {
            "trained":      False,
            "reason":       msg,
            "trusted_docs": len(all_records),
            "ts":           _utc_now(),
        }

    log.info("[TRAIN] Training on %d docs  contamination=%.3f", len(all_records), contamination)
    detector = AnomalyDetector(model_dir=model_dir, contamination=contamination)
    detector.train(all_records)
    detector.save(model_dir)

    ts = _utc_now()
    meta = {
        "trained":        True,
        "trusted_docs":   len(all_records),
        "tier1_labelled": tier1_count,
        "tier2_scored":   tier2_count,
        "model_dir":      model_dir,
        "ts":             ts,
        "contamination":  contamination,
        "indices":        indices,
    }
    try:
        meta_path = os.path.join(model_dir, "training_metadata.json")
        with open(meta_path, "w") as fh:
            json.dump(meta, fh, indent=2, default=str)
    except Exception as exc:
        log.debug("Could not save metadata: %s", exc)

    log.info("[TRAIN] Model saved to %s", model_dir)
    return meta


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Retrain from MISP feedback")
    parser.add_argument(
        "--indices",
        default=os.getenv(
            "TRAIN_ES_INDICES",
            "ti_ip,ti_url,ti_domain,ti_hash,ti_cve,ti_wallet,ti_ransomware",
        ),
    )
    parser.add_argument("--model-dir",      default=MODEL_DIR)
    parser.add_argument("--contamination",  type=float, default=CONTAMINATION)
    parser.add_argument("--min-sightings",  type=int,   default=MIN_SIGHTINGS)
    args    = parser.parse_args()
    indices = [s.strip() for s in args.indices.split(",") if s.strip()]
    result  = retrain_from_feedback(
        indices=indices,
        model_dir=args.model_dir,
        contamination=args.contamination,
        min_sightings=args.min_sightings,
    )
    log.info("[DONE] %s", result)


if __name__ == "__main__":
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    main()