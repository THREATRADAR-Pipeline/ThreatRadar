#!/usr/bin/env python3
"""
Feedback Daemon: a long-running process that periodically syncs analyst feedback 

© 2026 THREATRADAR Team 
"""
from __future__ import annotations

import os
import sys
import time
import signal
import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger("feedback_daemon")


_shutdown_requested = False


def _signal_handler(signum: int, frame: Any) -> None:
    global _shutdown_requested
    log.info("Received signal %d — initiating graceful shutdown", signum)
    _shutdown_requested = True


signal.signal(signal.SIGTERM, _signal_handler)
signal.signal(signal.SIGINT,  _signal_handler)



def _build_indices() -> list[str]:
    raw = os.getenv(
        "FEEDBACK_SYNC_INDICES",
        "ti_ip,ti_url,ti_domain,ti_hash,ti_cve,ti_wallet,ti_ransomware",
    )
    return [s.strip() for s in raw.split(",") if s.strip()]


def _build_retrain_config() -> dict:
    return {
        "min_total_signal":             int(os.getenv("FEEDBACK_RETRAIN_MIN_TOTAL_SIGNAL",            "200")),
        "cooldown_seconds":             int(os.getenv("FEEDBACK_RETRAIN_COOLDOWN_SECONDS",            "21600")),
        "fresh_days":                   int(os.getenv("FEEDBACK_RETRAIN_FRESH_DAYS",                  "14")),
        "train_min_docs":               int(os.getenv("TRAIN_MIN_DOCS",                               "50")),
        "min_sightings":                int(os.getenv("TRAIN_MIN_SIGHTINGS",                          "2")),
    }

def _check_retrain_trigger(
    indices:    list[str],
    model_dir:  str,
    cfg:        dict,
    retrain_fn: Any,      
    state_fn:   Any,      
    delta_fn:   Any,       
    es_fn:      Any,       
) -> tuple[bool, str, dict]:
   
  
    state           = state_fn(model_dir)
    last_retrain_at = state.get("last_retrain_at", "2000-01-01T00:00:00+00:00")

    try:
        last_dt     = datetime.fromisoformat(last_retrain_at)
        age_seconds = (datetime.now(timezone.utc) - last_dt).total_seconds()
    except (ValueError, TypeError):
        age_seconds = float("inf")

    cooldown = cfg["cooldown_seconds"]
    if age_seconds < cooldown:
        remaining = cooldown - age_seconds
        reason = (
            f"cooldown not elapsed — {age_seconds / 3600:.1f}h since last retrain, "
            f"need {cooldown / 3600:.1f}h ({remaining / 60:.0f} min remaining)"
        )
        return False, reason, {}

    es    = es_fn()
    delta = delta_fn(
        es,
        indices,
        last_retrain_at,
        cfg["min_sightings"],
        cfg["fresh_days"],
    )

    nc  = delta["new_confirmed"]
    ns  = delta["new_sighted"]
    fn_ = delta["fresh_new"]
    total_new = nc + ns

    min_t  = cfg["min_total_signal"]
    min_d  = cfg["train_min_docs"]

    log.info(
        "[RETRAIN-CHECK] last=%s  age=%.1fh  "
        "Δconfirmed=%d  Δsighted=%d  Δtotal=%d (need %d)  "
        "fresh_new=%d  total_tier1=%d (need %d)",
        last_retrain_at[:19],
        age_seconds / 3600,
        nc, ns, total_new, min_t,
        fn_,
        delta["total_confirmed"] + delta["total_sighted"],
        min_d,
    )

    if total_new < min_t:
        reason = (
            f"insufficient new signal — "
            f"confirmed={nc} + sighted={ns} = {total_new} (need >={min_t})"
        )
        return False, reason, delta

    if fn_ < 1:
        reason = (
            f"backlog-resync guard — 0 fresh items with "
            f"feedback_synced_at within last {cfg['fresh_days']}d; "
            f"this looks like an old-data re-sync, not new analyst activity"
        )
        return False, reason, delta

    total_tier1 = delta["total_confirmed"] + delta["total_sighted"]
    if total_tier1 < min_d:
        reason = (
            f"safety floor — total tier-1 docs={total_tier1} < TRAIN_MIN_DOCS={min_d}; "
            f"run the production pipeline to accumulate more labelled data"
        )
        return False, reason, delta

    reason = (
        f"TRIGGER — Δconfirmed={nc} + Δsighted={ns} = {total_new} >= {min_t}  |  "
        f"age={age_seconds / 3600:.1f}h >= {cooldown / 3600:.1f}h  |  "
        f"fresh_new={fn_}  |  total_tier1={total_tier1}"
    )
    return True, reason, delta


def main() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        stream=sys.stdout,
    )

    indices      = _build_indices()
    retrain_cfg  = _build_retrain_config()
    loop_seconds = int(os.getenv("FEEDBACK_LOOP_SECONDS", "1800"))   
    model_dir    = os.getenv("MODEL_DIR", "/app/models")
    run_once     = os.getenv("FEEDBACK_RUN_ONCE", "false").lower() in ("1", "true", "yes")
    misp_enabled = os.getenv("MISP_ENABLED", "true").lower() not in ("0", "false", "no")

    try:
        from poisoning_detection.feedback.misp_feedback_loop import sync_misp_feedback_to_es
    except ImportError as exc:
        log.error("Cannot import misp_feedback_loop: %s", exc)
        sys.exit(1)

    try:
        from poisoning_detection.feedback.retrain_with_feedback import (
            retrain_from_feedback,
            load_retrain_state,
            save_retrain_state,
            count_feedback_delta,
            _get_es_client,
        )
    except ImportError as exc:
        log.error("Cannot import retrain_with_feedback: %s", exc)
        sys.exit(1)

    log.info("=" * 70)
    log.info("  FEEDBACK DAEMON v3.0 STARTING  (SOC-friendly retrain trigger)")
    log.info("  indices                      : %s", indices)
    log.info("  loop_seconds                 : %d", loop_seconds)
    log.info("  misp_enabled                 : %s", misp_enabled)
    log.info("  model_dir                    : %s", model_dir)
    log.info("  run_once                     : %s", run_once)
    log.info("  ── Retrain gates ─────────────────────────────────────────────")
    log.info("  G1 min_total_signal          : %d", retrain_cfg["min_total_signal"])
    log.info("  G2 cooldown_seconds          : %d (%.1f h)", retrain_cfg["cooldown_seconds"], retrain_cfg["cooldown_seconds"] / 3600)
    log.info("  G3 fresh_days                : %d", retrain_cfg["fresh_days"])
    log.info("  G4 train_min_docs            : %d", retrain_cfg["train_min_docs"])
    log.info("=" * 70)

    n = 0
    while not _shutdown_requested:
        n += 1
        loop_start = time.monotonic()
        log.info("=" * 70)
        log.info("[LOOP %d] starting — %s", n, datetime.now(timezone.utc).isoformat())

        log.info("[LOOP %d] step 1/2 — MISP → ES feedback sync", n)
        sync_summary = {"scanned": 0, "updated": 0, "failures": 0}
        try:
            sync_summary = sync_misp_feedback_to_es(indices, dry_run=False)
            log.info(
                "[LOOP %d] sync done — scanned:%d updated:%d failures:%d confirmed:%d",
                n,
                sync_summary.get("scanned",          0),
                sync_summary.get("updated",           0),
                sync_summary.get("failures",          0),
                sync_summary.get("analyst_confirmed", 0),
            )
        except Exception as exc:
            log.error(
                "[LOOP %d] sync failed (continuing): %s", n, exc,
                exc_info=log.isEnabledFor(logging.DEBUG),
            )

        log.info("[LOOP %d] step 2/2 — evaluating retrain gates", n)
        try:
            should_retrain, gate_reason, delta = _check_retrain_trigger(
                indices=indices,
                model_dir=model_dir,
                cfg=retrain_cfg,
                retrain_fn=retrain_from_feedback,   
                state_fn=load_retrain_state,
                delta_fn=count_feedback_delta,
                es_fn=_get_es_client,
            )
        except Exception as exc:
            log.error(
                "[LOOP %d] gate check failed (skipping retrain): %s", n, exc,
                exc_info=log.isEnabledFor(logging.DEBUG),
            )
            should_retrain, gate_reason, delta = False, "gate-check exception", {}

        if should_retrain:
            log.info("[LOOP %d] RETRAIN — %s", n, gate_reason)
            try:
                result = retrain_from_feedback(
                    indices=indices,
                    model_dir=model_dir,
                    es_url=os.getenv("ELASTIC_HOST") or os.getenv("ES_URL"),
                    es_user=os.getenv("ELASTIC_USER") or os.getenv("ES_USER"),
                    es_password=os.getenv("ELASTIC_PASSWORD") or os.getenv("ES_PASSWORD"),
                )
                log.info(
                    "[LOOP %d] retrain done — trained:%s docs:%d "
                    "(tier1_labelled:%d tier2_scored:%d) dir:%s",
                    n,
                    result.get("trained",        False),
                    result.get("trusted_docs",   0),
                    result.get("tier1_labelled", 0),
                    result.get("tier2_scored",   0),
                    result.get("model_dir",      model_dir),
                )

                if result.get("trained"):
                    save_retrain_state(
                        model_dir=model_dir,
                        last_retrain_at=result["ts"],
                        confirmed_total=delta.get("total_confirmed", 0),
                        sighted_total=delta.get("total_sighted",   0),
                    )
                    log.info(
                        "[LOOP %d] state saved — next retrain eligible after %.1f h",
                        n, retrain_cfg["cooldown_seconds"] / 3600,
                    )
                else:
                    log.warning(
                        "[LOOP %d] retrain_from_feedback returned trained=False: %s",
                        n, result.get("reason", "unknown"),
                    )

            except Exception as exc:
                log.error(
                    "[LOOP %d] retrain failed: %s", n, exc,
                    exc_info=log.isEnabledFor(logging.DEBUG),
                )
        else:
            log.info("[LOOP %d] retrain skipped — %s", n, gate_reason)

        if run_once:
            log.info("[DONE] run-once mode — exiting after loop %d", n)
            return

        elapsed   = time.monotonic() - loop_start
        sleep_for = max(5, loop_seconds - elapsed)
        log.info("[SLEEP] %.1fs until next loop …", sleep_for)

        slept = 0.0
        while slept < sleep_for and not _shutdown_requested:
            chunk  = min(5.0, sleep_for - slept)
            time.sleep(chunk)
            slept += chunk

    log.info("=" * 70)
    log.info("Shutdown complete.  Total loops: %d", n)
    log.info("=" * 70)


if __name__ == "__main__":
    main()