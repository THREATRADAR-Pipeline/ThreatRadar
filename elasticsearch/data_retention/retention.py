#!/usr/bin/env python3
"""
Two-pass retention policy for the THREATRADAR pipeline that run concurrently).

PASS 1 for Raw dated indices
  Delete entire index when its date > RETENTION_DAYS (180).
  Protected (never deleted — feed a protected clean index):
    ti_ransomware-*            
    ti_cisa-*                   
    ti_ioc_extracted_from_news-*
    ti_news-*     (upstream of ti_ioc_extracted_from_news)

PASS 2 for Clean canonical indices
  Delete documents where last_seen = MAX(processed_at) > RETENTION_DAYS (180).
  Protected (never touched by Pass 2):
    ti_cve        — Reference data; not time-bounded.
    ti_ransomware — Threat actor intel stays relevant indefinitely.
    ti_wallet     — Crypto wallet IOCs linked to ransomware actors.

© 2026 THREATRADAR Team
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta

_env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
if os.path.exists(_env_path):
    with open(_env_path) as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip())


ELASTIC_HOST       = os.environ.get("ELASTIC_HOST", "http://elasticsearch:9200")
ELASTIC_USER       = os.environ.get("ELASTIC_USER", "elastic")
ELASTIC_PASSWORD   = os.environ.get("ELASTIC_PASSWORD", "")
RETENTION_DAYS     = 180

CLEAN_INDICES = [
    "ti_ip",
    "ti_url",
    "ti_hash",
    "ti_domain",
]

TIMESTAMP_PRIMARY  = "last_seen"

TASK_POLL_INTERVAL   = 10     
TASK_TIMEOUT_SECONDS = 3600

FORCEMERGE_THRESHOLD = 0.10  

RETENTION_LOG_INDEX = "ti_retention_log"
# PASS 1
_RAW_DATE_RE = re.compile(
    r"^ti_[a-z0-9_]+-(\d{4})\.(\d{2})\.(\d{2})$"
)

PASS1_PROTECTED_PREFIXES: tuple[str, ...] = (
    "ti_ransomware-",
    "ti_cisa-",
    "ti_ransomwhere-",
    "ti_ioc_extracted_from_news-",
    "ti_news-",
    "ti_cve-",
    "ti_wallet-",
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("retention")

def _auth_headers() -> dict:
    creds = base64.b64encode(f"{ELASTIC_USER}:{ELASTIC_PASSWORD}".encode()).decode()
    return {
        "Authorization": f"Basic {creds}",
        "Content-Type":  "application/json",
    }

def _request(method: str, path: str, body: dict | None = None, timeout: int = 60):
    url  = f"{ELASTIC_HOST}{path}"
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(url, data=data, method=method, headers=_auth_headers())
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        raise RuntimeError(f"HTTP {e.code} {method} {path}: {raw[:300]}") from e


def _get(path: str)              -> dict: return _request("GET",    path)
def _delete(path: str)           -> dict: return _request("DELETE", path)
def _post(path: str, body: dict) -> dict: return _request("POST",   path, body)
def _put(path: str, body: dict)  -> dict: return _request("PUT",    path, body)


def _parse_index_date(name: str) -> datetime | None:
    m = _RAW_DATE_RE.match(name)
    if not m:
        return None
    try:
        return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)),
                        tzinfo=timezone.utc)
    except ValueError:
        return None


def delete_old_raw_indices(cutoff: datetime, dry_run: bool) -> dict:
    log.info("=" * 55)
    log.info("PASS 1: Raw dated indices (ti_*-YYYY.MM.DD)")
    log.info("=" * 55)

    try:
        resp = _get("/_cat/indices/ti_*?h=index&format=json")
    except RuntimeError as e:
        log.warning(f"  Could not list indices: {e}")
        return {"checked": 0, "deleted": 0, "skipped": 0, "errors": 0,
                "deleted_indices": []}

    all_indices = [r["index"] for r in resp]
    raw_indices = [(name, _parse_index_date(name)) for name in all_indices]
    raw_indices = [(name, dt) for name, dt in raw_indices if dt is not None]

    log.info(f"  Found {len(raw_indices)} raw dated indices out of {len(all_indices)} total")

    checked = deleted = skipped = errors = 0
    deleted_indices: list[str] = []

    for name, dt in sorted(raw_indices):
        checked += 1
        age_days = (datetime.now(timezone.utc) - dt).days

        if any(name.startswith(p) for p in PASS1_PROTECTED_PREFIXES):
            log.debug(f"  PROTECTED  {name}  (excluded from Pass 1)")
            skipped += 1
            continue

        if dt >= cutoff:
            log.debug(f"  KEEP  {name}  (age={age_days}d < {RETENTION_DAYS}d)")
            skipped += 1
            continue

        log.info(f"  {'[DRY-RUN] WOULD DELETE' if dry_run else 'DELETE'}  "
                 f"{name}  (age={age_days}d, date={dt.date()})")

        if dry_run:
            deleted_indices.append(name)
            deleted += 1
            continue

        try:
            _delete(f"/{name}")
            log.info(f"  Deleted {name}")
            deleted_indices.append(name)
            deleted += 1
        except RuntimeError as e:
            log.warning(f"  Failed to delete {name}: {e}")
            errors += 1

    log.info(f"  Summary — checked: {checked} | deleted: {deleted} | "
             f"kept: {skipped} | errors: {errors}")
    return {
        "checked":         checked,
        "deleted":         deleted,
        "skipped":         skipped,
        "errors":          errors,
        "deleted_indices": deleted_indices,
    }

# PASS 2
def _build_delete_query(cutoff: datetime) -> dict:
    return {
        "query": {
            "range": {
                TIMESTAMP_PRIMARY: {"lt": cutoff.isoformat()}
            }
        }
    }

#Return total document count for the index, or -1 on error.
def _get_index_total_docs(index: str) -> int:
    try:
        return _get(f"/{index}/_count").get("count", 0)
    except RuntimeError:
        return -1

 #Submit an async delete_by_query and return the task ID.
def _submit_delete_task(index: str, query: dict) -> str | None:
    try:
        resp = _post(
            f"/{index}/_delete_by_query"
            "?wait_for_completion=false&conflicts=proceed&refresh=true",
            query,
        )
        task_id = resp.get("task")
        if not task_id:
            raise RuntimeError(f"No task ID in response: {resp}")
        return task_id
    except RuntimeError as e:
        log.warning(f"  Failed to submit delete task for {index}: {e}")
        return None


def _poll_task(task_id: str, index: str) -> dict:
    deadline = time.monotonic() + TASK_TIMEOUT_SECONDS
    attempt  = 0

    while True:
        attempt += 1
        try:
            resp     = _get(f"/_tasks/{task_id}")
            complete = resp.get("completed", False)

            if complete:
                status = resp.get("response", resp.get("task", {}).get("status", {}))
                log.info(f"    Task {task_id} done after {attempt} poll(s) — "
                         f"deleted: {status.get('deleted', 0):,}, "
                         f"failures: {len(status.get('failures', []))}")
                return status

            if attempt % 6 == 0:
                s = resp.get("task", {}).get("status", {})
                log.info(f"    [{index}] In progress — "
                         f"{s.get('deleted', 0):,}/{s.get('total', 0):,} docs deleted ...")

        except RuntimeError as e:
            log.warning(f"    Poll attempt {attempt} failed: {e}")

        if time.monotonic() >= deadline:
            log.warning(f"  Task {task_id} exceeded {TASK_TIMEOUT_SECONDS}s — cancelling")
            try:
                _post(f"/_tasks/{task_id}/_cancel", {})
            except RuntimeError:
                pass
            raise RuntimeError(f"Task timed out after {TASK_TIMEOUT_SECONDS}s")

        time.sleep(TASK_POLL_INTERVAL)


def _forcemerge_if_needed(index: str, deleted: int, total: int) -> None:
    if total <= 0 or deleted <= 0:
        return
    fraction = deleted / total
    if fraction < FORCEMERGE_THRESHOLD:
        log.info(f"    Forcemerge skipped ({fraction:.1%} < {FORCEMERGE_THRESHOLD:.0%} threshold)")
        return

    log.info(f"    Running forcemerge on {index} ({fraction:.1%} of docs deleted) ...")
    try:
        _post(f"/{index}/_forcemerge?only_expunge_deletes=true", {})
        log.info(f" Forcemerge complete for {index}")
    except RuntimeError as e:
        log.warning(f" Forcemerge failed for {index} (non-fatal): {e}")


def delete_old_docs_in_clean_index(index: str, cutoff: datetime, dry_run: bool) -> dict:
    log.info(f"  Index: {index}")
    total_docs = _get_index_total_docs(index)
    if total_docs < 0:
        log.info(f"    Index {index} does not exist — skipping")
        return {"index": index, "total_docs": 0, "deleted": 0, "errors": 0}

    log.info(f"    Total documents: {total_docs:,}")

    query = _build_delete_query(cutoff)

    if dry_run:
        try:
            old_count = _post(f"/{index}/_count", query).get("count", 0)
        except RuntimeError as e:
            log.warning(f"    Could not count old docs: {e}")
            old_count = -1

        if old_count == 0:
            log.info(f"    No documents older than {RETENTION_DAYS}d — nothing to do")
        elif old_count > 0 and total_docs > 0:
            log.info(f"    [DRY-RUN] Would delete {old_count:,} / {total_docs:,} "
                     f"({old_count / total_docs:.1%})")
        else:
            log.info(f"    [DRY-RUN] Would delete {max(old_count, 0):,} documents")

        return {"index": index, "total_docs": total_docs,
                "deleted": max(old_count, 0), "errors": 0}

    task_id = _submit_delete_task(index, query)
    if task_id is None:
        return {"index": index, "total_docs": total_docs, "deleted": 0, "errors": 1}

    log.info(f"   Async delete task submitted: {task_id}")

    try:
        status   = _poll_task(task_id, index)
        deleted  = status.get("deleted", 0)
        failures = status.get("failures", [])
        n_errors = len(failures)

        log.info(f"   Deleted {deleted:,} / {total_docs:,}"
                 + (f" | {n_errors} failures" if n_errors else ""))

        for f in failures[:3]:
            log.warning(f"   Failure detail: {f}")

        _forcemerge_if_needed(index, deleted, total_docs)

        return {"index": index, "total_docs": total_docs,
                "deleted": deleted, "errors": n_errors}

    except RuntimeError as e:
        log.warning(f"  delete_by_query failed for {index}: {e}")
        return {"index": index, "total_docs": total_docs, "deleted": 0, "errors": 1}


def delete_old_clean_docs(cutoff: datetime, dry_run: bool) -> dict:
    #Run Pass 2 across all clean canonical indices sequentially.
    log.info("=" * 55)
    log.info("PASS 2: Clean canonical indices (document-level)")
    log.info("=" * 55)
    log.info(f"  Indices            : {', '.join(CLEAN_INDICES)}")
    log.info(f"  Protected (skipped): ti_cve, ti_ransomware, ti_wallet (Pass 2); "
             f"ti_ransomware-, ti_cisa-, ti_ransomwhere-, ti_cve-, ti_wallet-, ti_news- (Pass 1)")
    log.info(f"  Primary timestamp  : {TIMESTAMP_PRIMARY}")
    log.info(f"  Cutoff             : {cutoff.date()}")
    log.info(f"  Async task timeout : {TASK_TIMEOUT_SECONDS}s per index")
    log.info(f"  Forcemerge trigger : >{FORCEMERGE_THRESHOLD:.0%} of index deleted")

    total_deleted = total_errors = 0
    results = []

    for index in CLEAN_INDICES:
        result = delete_old_docs_in_clean_index(index, cutoff, dry_run)
        results.append(result)
        total_deleted += result["deleted"]
        total_errors  += result["errors"]

    log.info(f"  Summary — deleted: {total_deleted:,} | errors: {total_errors}")
    return {
        "indices":       results,
        "total_deleted": total_deleted,
        "total_errors":  total_errors,
    }

# RETENTION LOG 

def _ensure_retention_log_index() -> None:
    try:
        _get(f"/{RETENTION_LOG_INDEX}")
        return
    except RuntimeError:
        pass

    try:
        _put(f"/{RETENTION_LOG_INDEX}", {
            "settings": {
                "number_of_shards":   1,
                "number_of_replicas": 0,
            },
            "mappings": {
                "properties": {
                    "run_at":           {"type": "date"},
                    "dry_run":          {"type": "boolean"},
                    "retention_days":   {"type": "integer"},
                    "cutoff_date":      {"type": "date"},
                    "duration_seconds": {"type": "integer"},
                    "status":           {"type": "keyword"},
                    "pass1": {
                        "properties": {
                            "checked":         {"type": "integer"},
                            "deleted":         {"type": "integer"},
                            "skipped":         {"type": "integer"},
                            "errors":          {"type": "integer"},
                            "error_rate":      {"type": "float"},
                            "deleted_indices": {"type": "keyword"},
                        }
                    },
                    "pass2": {
                        "properties": {
                            "total_deleted": {"type": "integer"},
                            "total_errors":  {"type": "integer"},
                            "error_rate":    {"type": "float"},
                            "indices": {
                                "type": "nested",
                                "properties": {
                                    "index":      {"type": "keyword"},
                                    "total_docs": {"type": "integer"},
                                    "deleted":    {"type": "integer"},
                                    "errors":     {"type": "integer"},
                                }
                            }
                        }
                    },
                }
            }
        })
        log.info(f"  Created index: {RETENTION_LOG_INDEX}")
    except RuntimeError as e:
        log.warning(f"  Could not create {RETENTION_LOG_INDEX}: {e} (non-fatal)")


def _compute_exit_code(p1: dict, p2: dict) -> int:
    p1_denom = max(p1["checked"], 1)
    p2_denom = max(len(CLEAN_INDICES), 1)

    p1_rate = p1["errors"] / p1_denom
    p2_rate = p2["total_errors"] / p2_denom

    total_errors = p1["errors"] + p2["total_errors"]

    if total_errors == 0:
        return 0
    if p1_rate > 0.5 or p2_rate > 0.5:
        return 2
    return 1


def write_retention_log(
    run_at: datetime,
    dry_run: bool,
    retention_days: int,
    cutoff: datetime,
    elapsed: int,
    p1: dict,
    p2: dict,
    exit_code: int,
) -> None:
    if exit_code == 0:
        status = "ok"
    elif exit_code == 1:
        status = "degraded"
    else:
        status = "failed"

    if dry_run:
        status = f"dry_run:{status}"

    p1_denom = max(p1["checked"], 1)
    p2_denom = max(len(CLEAN_INDICES), 1)

    doc = {
        "run_at":           run_at.isoformat(),
        "dry_run":          dry_run,
        "retention_days":   retention_days,
        "cutoff_date":      cutoff.date().isoformat(),
        "duration_seconds": elapsed,
        "status":           status,
        "pass1": {
            "checked":         p1["checked"],
            "deleted":         p1["deleted"],
            "skipped":         p1["skipped"],
            "errors":          p1["errors"],
            "error_rate":      round(p1["errors"] / p1_denom, 4),
            "deleted_indices": p1.get("deleted_indices", []),
        },
        "pass2": {
            "total_deleted": p2["total_deleted"],
            "total_errors":  p2["total_errors"],
            "error_rate":    round(p2["total_errors"] / p2_denom, 4),
            "indices":       p2["indices"],
        },
    }

    _ensure_retention_log_index()

    try:
        _post(f"/{RETENTION_LOG_INDEX}/_doc", doc)
        log.info(f"  Retention log written → {RETENTION_LOG_INDEX}  (status={status})")
    except RuntimeError as e:
        log.warning(f"  Could not write retention log: {e} (non-fatal)")


def main() -> None:
    parser = argparse.ArgumentParser(description="THREATRADAR TI data retention cleanup")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be deleted without deleting anything")
    parser.add_argument("--days", type=int, default=RETENTION_DAYS,
                        help=f"Retention window in days (default: {RETENTION_DAYS})")
    args = parser.parse_args()

    retention_days = args.days
    dry_run        = args.dry_run
    cutoff         = datetime.now(timezone.utc) - timedelta(days=retention_days)

    log.info("=" * 55)
    log.info(f"THREATRADAR Data Retention{'  [DRY-RUN]' if dry_run else ''}")
    log.info(f"Retention window  : {retention_days}d")
    log.info(f"Cutoff date       : {cutoff.date()}")
    log.info(f"Elasticsearch     : {ELASTIC_HOST}")
    log.info(f"Pass 2 indices    : {', '.join(CLEAN_INDICES)}")
    log.info(f"Pass 1 protected  : ti_ransomware-*, ti_cisa-*, ti_ransomwhere-*, "
             f"ti_cve-*, ti_wallet-*, ti_ioc_extracted_from_news-*, ti_news-*")
    log.info(f"Pass 2 protected  : ti_cve, ti_ransomware, ti_wallet (reference data)")
    log.info(f"Concurrency       : Pass 1 + Pass 2 run in parallel")
    log.info(f"Audit log index   : {RETENTION_LOG_INDEX}")
    log.info("=" * 55)

    if not ELASTIC_PASSWORD:
        log.error("ELASTIC_PASSWORD is not set — cannot authenticate. Exiting.")
        sys.exit(1)

    try:
        health = _get("/_cluster/health")
        log.info(f"Elasticsearch status: {health.get('status', '?')}")
    except RuntimeError as e:
        log.error(f"Cannot connect to Elasticsearch: {e}")
        sys.exit(1)

    run_at = datetime.now(timezone.utc)
    start  = time.monotonic()

    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(delete_old_raw_indices, cutoff, dry_run)
        f2 = pool.submit(delete_old_clean_docs,  cutoff, dry_run)
        p1 = f1.result()
        p2 = f2.result()

    elapsed   = int(time.monotonic() - start)
    exit_code = _compute_exit_code(p1, p2)

    p1_rate = p1["errors"] / max(p1["checked"], 1)
    p2_rate = p2["total_errors"] / max(len(CLEAN_INDICES), 1)

    log.info("=" * 55)
    log.info(f"Retention complete in {elapsed}s"
             f"{'  [DRY-RUN — nothing deleted]' if dry_run else ''}")
    log.info(f"  Raw indices deleted : {p1['deleted']} / {p1['checked']}  "
             f"(error rate: {p1_rate:.1%})")
    log.info(f"  Clean docs deleted  : {p2['total_deleted']:,}  "
             f"(error rate: {p2_rate:.1%})")
    log.info(f"  Exit code           : {exit_code}"
             f"  ({'ok' if exit_code == 0 else 'degraded' if exit_code == 1 else 'failed'})")
    log.info("=" * 55)

    write_retention_log(run_at, dry_run, retention_days, cutoff, elapsed, p1, p2, exit_code)

    sys.exit(exit_code)

if __name__ == "__main__":
    main()
