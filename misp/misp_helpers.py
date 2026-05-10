"""
misp_helpers.py
Shared helper functions for MISP integration.
Used by misp_pusher.py and misp_daily_refresh.py.
© 2026 THREATRADAR Team
"""
import logging
import os
import urllib3
from datetime import datetime, timezone
from pymisp import PyMISP, MISPEvent
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk as es_bulk

log = logging.getLogger("misp_helpers")

if (
    os.getenv("MISP_VERIFY_SSL",    "true").lower() == "false"
    or os.getenv("ELASTIC_VERIFY_SSL", "true").lower() == "false"
):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_es_client() -> Elasticsearch:
    host     = os.getenv("ELASTIC_HOST")
    password = os.getenv("ELASTIC_PASSWORD")
    if not host:
        raise EnvironmentError(
            "ELASTIC_HOST environment variable is not set or empty — cannot connect to Elasticsearch"
        )
    if not password:
        raise EnvironmentError(
            "ELASTIC_PASSWORD environment variable is not set or empty — cannot connect to Elasticsearch"
        )

    verify_ssl = os.getenv("ELASTIC_VERIFY_SSL", "true").lower() != "false"
    ca_certs   = os.getenv("ELASTIC_CA_CERTS")

    kwargs: dict = dict(
        hosts=host,
        basic_auth=(
            os.getenv("ELASTIC_USER", "elastic"),
            password,
        ),
        verify_certs=verify_ssl,
    )
    if ca_certs:
        kwargs["ca_certs"] = ca_certs

    return Elasticsearch(**kwargs)


def get_misp_client() -> PyMISP:
    key = os.getenv("MISP_KEY", "")
    if not key:
        raise EnvironmentError(
            "MISP_KEY environment variable is not set or empty — cannot connect to MISP"
        )
    url    = os.getenv("MISP_URL", "https://localhost:8443")
    verify = os.getenv("MISP_VERIFY_SSL", "true").lower() != "false"
    return PyMISP(url, key, verify)


def _safe_tag_value(value: str) -> str:
    if not value:
        return value
    sanitized = (
        str(value)
        .replace("=", "-")
        .replace(":", "-")
        .replace('"', "")
        .replace("'", "")
        .replace("\n", " ")
        .replace("\r", "")
        .replace(" ", "_")
        .strip()
    )
    return sanitized[:100]


def _safe_galaxy_value(value: str) -> str:
    if not value:
        return value
    sanitized = (
        str(value)
        .replace("=", "-")
        .replace(":", "-")
        .replace('"', "")
        .replace("'", "")
        .replace("\n", " ")
        .replace("\r", "")
        .strip()
    )
    return sanitized[:100]


def _tactic_to_kill_chain_slug(tactic: str) -> str:

    _MAP = {
        "reconnaissance":          "reconnaissance",
        "resource development":    "resource-development",
        "initial access":          "initial-access",
        "execution":               "execution",
        "persistence":             "persistence",
        "privilege escalation":    "privilege-escalation",
        "defense evasion":         "defense-evasion",
        "credential access":       "credential-access",
        "discovery":               "discovery",
        "lateral movement":        "lateral-movement",
        "collection":              "collection",
        "command and control":     "command-and-control",
        "exfiltration":            "exfiltration",
        "impact":                  "impact",
    }
    slug = _MAP.get(tactic.lower().strip())
    if slug:
        return slug
    return tactic.lower().strip().replace(" ", "-")


def _get_ml_score(ioc: dict) -> float | None:
    
    score = ioc.get("ml_score")
    if score is not None:
        return float(score)
    return None


def _get_llm_verdict(ioc: dict) -> str:
    verdict = ioc.get("llm_verdict", "")
    if verdict and verdict not in ("N/A", "null", ""):
        return verdict
    return ""





def build_base_event(ioc: dict, info_label: str) -> MISPEvent:
    event = MISPEvent()
    event.info            = info_label
    event.threat_level_id = 2 
    event.analysis        = 2   
    event.distribution    = 0
    date_str = ioc.get("first_seen") or ioc.get("processed_at")
    if date_str:
        try:
            dt = datetime.fromisoformat(str(date_str).replace("Z", "+00:00"))
            event.date = dt.strftime("%Y-%m-%d")
        except (ValueError, TypeError):
            pass

    _add_standard_tags(event, ioc)
    return event


def set_event_tlp(event: MISPEvent) -> None:
    event.tags = [
        t for t in (event.tags or [])
        if not str(getattr(t, "name", t)).lower().startswith("tlp:")
    ]

    distribution = int(getattr(event, "distribution", 0))
    if distribution == 0:
        event.add_tag("tlp:amber")
    else:
        event.add_tag(os.getenv("MISP_TLP_TAG", "tlp:green"))


def _add_standard_tags(event: MISPEvent, ioc: dict):
    event.add_tag("threatradar:pipeline=true")

    pap_tag = os.getenv("MISP_PAP_TAG", "PAP:GREEN")
    event.add_tag(pap_tag)

    verdict = ioc.get("verdict") or ioc.get("actor_threat_level", "")
    if verdict:
        event.add_tag(f"threatradar:verdict={_safe_tag_value(verdict)}")

    ioc_type = ioc.get("ioc_type", "")
    if ioc_type:
        event.add_tag(f"threatradar:ioc_type={_safe_tag_value(ioc_type)}")

    cs = ioc.get("final_score")
    if cs is None:
        cs = ioc.get("actor_danger_score")
    if cs is not None:
        event.add_tag(f"threatradar:confidence={cs}")

    cortex = ioc.get("cortex_final_score")
    if cortex is None:
        cortex = ioc.get("cortex_score")
    if cortex is not None:
        event.add_tag(f"threatradar:cortex_score={cortex}")

    final = ioc.get("final_score")
    if final is not None:
        event.add_tag(f"threatradar:final_score={final}")

    ml = _get_ml_score(ioc)
    if ml is not None:
        event.add_tag(f"threatradar:ml_score={round(ml, 4)}")

    ml_tier = ioc.get("ml_tier", "")
    if ml_tier:
        event.add_tag(f"threatradar:ml_tier={_safe_tag_value(ml_tier)}")

    final_action = ioc.get("final_action", "")
    if final_action:
        event.add_tag(f"threatradar:fusion_action={_safe_tag_value(final_action)}")

    cps = ioc.get("composite_poison_score")
    if cps is not None:
        event.add_tag(f"threatradar:composite_poison_score={round(float(cps), 4)}")

    llm_conf = ioc.get("llm_confidence")
    if llm_conf is not None:
        event.add_tag(f"threatradar:llm_confidence={llm_conf}")

    llm_verdict = _get_llm_verdict(ioc)
    if llm_verdict:
        event.add_tag(f"threatradar:llm_verdict={_safe_tag_value(llm_verdict)}")

    llm_class = ioc.get("llm_contradiction_class")
    if llm_class:
        event.add_tag(f"threatradar:llm_contradiction_class={_safe_tag_value(llm_class)}")

    if ioc.get("poisoning_flagged"):
        event.add_tag("threatradar:poisoning_detected=true")
        ps = ioc.get("poison_strategy", "")
        if ps:
            event.add_tag(f"threatradar:poison_strategy={_safe_tag_value(ps)}")

    
    mitre = (ioc.get("enriched") or {}).get("mitre", {})
    use_galaxy = os.getenv("MISP_USE_GALAXY_TAGS", "true").lower() != "false"

    seen_tactics: set = set()
    for tactic in mitre.get("tactics", []):
        if tactic and tactic not in seen_tactics:
            slug = _tactic_to_kill_chain_slug(tactic)
            event.add_tag(f"kill-chain:mitre-enterprise-attack={slug}")
            seen_tactics.add(tactic)

    seen_techniques: set = set()
    for tech in mitre.get("techniques", []):
        tid  = tech.get("id", "")
        name = tech.get("name", "")
        if not tid or tid in seen_techniques:
            continue
        seen_techniques.add(tid)
        if use_galaxy and name:
            tag_value = _safe_galaxy_value(f"{name} ({tid})")
            event.add_tag(f"misp-galaxy:mitre-attack-pattern={tag_value}")
        else:
            event.add_tag(f"mitre-attack:attack-pattern={_safe_tag_value(tid)}")

    cvss = ioc.get("cvss_score")
    if cvss is not None:
        event.add_tag(f"threatradar:cvss={cvss}")
        sev = ioc.get("cvss_severity", "")
        if sev:
            event.add_tag(f"threatradar:cvss_severity={_safe_tag_value(sev)}")

    intel = ioc.get("intel_class", "")
    if intel:
        event.add_tag(f"threatradar:intel_class={_safe_tag_value(intel)}")


def mark_pushed(es: Elasticsearch, index: str, doc_id: str, misp_event_id: str = "") -> bool:
   
    try:
        doc_update: dict = {
            "pushed_to_misp":      True,
            "misp_push_timestamp": datetime.now(timezone.utc).isoformat(),
        }
        if misp_event_id:
            doc_update["misp_event_id"] = str(misp_event_id)
        else:
            log.warning("mark_pushed: misp_event_id is empty for doc %s in %s — "
                        "pushed_to_misp will be set but misp_event_id will not", doc_id, index)
        es.update(
            index=index,
            id=doc_id,
            doc=doc_update,
            retry_on_conflict=3,
        )
        return True
    except Exception as exc:
        log.warning("mark_pushed failed for %s in %s: %s", doc_id, index, exc)
        return False


def mark_pushed_failed(es: Elasticsearch, index: str, doc_id: str, error: str) -> bool:
    
    try:
        es.update(
            index=index,
            id=doc_id,
            script={
                "source": (
                    "ctx._source.misp_push_failed = true; "
                    "ctx._source.misp_push_error = params.error; "
                    "ctx._source.misp_push_fail_at = params.ts; "
                    "if (ctx._source.misp_push_fail_count == null) { "
                    "  ctx._source.misp_push_fail_count = 1; "
                    "} else { "
                    "  ctx._source.misp_push_fail_count += 1; "
                    "}"
                ),
                "lang":   "painless",
                "params": {
                    "error": str(error)[:500],
                    "ts":    datetime.now(timezone.utc).isoformat(),
                },
            },
            retry_on_conflict=3,
        )
        return True
    except Exception as exc:
        log.warning("mark_pushed_failed could not write failure record for %s: %s", doc_id, exc)
        return False


def bulk_mark_pushed(es: Elasticsearch, items: list) -> int:
    if not items:
        return 0
    now     = datetime.now(timezone.utc).isoformat()
    actions = []
    for item in items:
        doc_fields: dict = {
            "pushed_to_misp":      True,
            "misp_push_timestamp": now,
        }
        if item.get("misp_event_id"):
            doc_fields["misp_event_id"] = str(item["misp_event_id"])
        actions.append({
            "_op_type":          "update",
            "_index":            item["_index"],
            "_id":               item["_id"],
            "doc":               doc_fields,
            "doc_as_upsert":     True,
            "retry_on_conflict": 3,
        })
    try:
        success, errors = es_bulk(es, actions, raise_on_error=False, stats_only=False)
        if errors:
            failed_ids = []
            for err in errors[:5]:
                if isinstance(err, dict):
                    doc_id = (err.get("update") or err.get("index") or {}).get("_id", "?")
                    failed_ids.append(doc_id)
            log.warning("bulk_mark_pushed: %d/%d failures — first failed IDs: %s",
                        len(errors), len(items), failed_ids)
        return success
    except Exception as exc:
        log.error("bulk_mark_pushed failed entirely: %s", exc)
        return 0


def build_comment(ioc: dict) -> str:
    parts = []

    cortex_val = ioc.get("cortex_final_score")
    if cortex_val is None:
        cortex_val = ioc.get("cortex_score")
    if cortex_val is not None:
        parts.append(f"Cortex:{cortex_val}")

    if ioc.get("final_score") is not None:
        parts.append(f"Final:{ioc['final_score']}")

    source_count = ioc.get("source_count")
    if source_count is not None:
        parts.append(f"Sources:{source_count}")

    ml_score = _get_ml_score(ioc)
    if ml_score is not None:
        parts.append(f"ML:{round(ml_score, 4)}")

    ml_tier = ioc.get("ml_tier", "")
    if ml_tier:
        parts.append(f"MLTier:{ml_tier}")

    cps = ioc.get("composite_poison_score")
    if cps is not None:
        parts.append(f"PoisonScore:{round(float(cps), 4)}")

    llm_conf = ioc.get("llm_confidence")
    if llm_conf is not None and int(float(llm_conf)) > 0:
        parts.append(f"LLM:{llm_conf}")

    llm_v = _get_llm_verdict(ioc)
    if llm_v:
        parts.append(f"LLMVerdict:{llm_v}")

    reasoning = ioc.get("fusion_reasoning", "")
    if reasoning:
        parts.append(f"Reasoning:{str(reasoning)[:200]}")

    breakdown = (ioc.get("score_breakdown") or {}).get("analyzer_detail") or {}
    if breakdown:
        detail = " ".join(
            f"{k}:{v}" for k, v in breakdown.items() if v not in (None, 0, "")
        )
        if detail:
            parts.append(f"Analyzers:{detail}")

    sources = ioc.get("sources") or []
    if sources:
        feed = sources[0].get("feed_name", "")
        if feed:
            parts.append(f"Feed:{feed}")

    ioc_port = ioc.get("ioc_port")
    if ioc_port:
        parts.append(f"Port:{ioc_port}")

    if ioc.get("poisoning_flagged"):
        parts.append(f"POISON:{ioc.get('poison_strategy', 'unknown')}")

    return " | ".join(parts)

def build_ml_comment(ioc: dict) -> str:
    lines = []

    ml_score = _get_ml_score(ioc)
    if ml_score is not None:
        lines.append(f"ML Anomaly Score: {round(ml_score, 4)}")

    ml_tier = ioc.get("ml_tier", "")
    if ml_tier:
        lines.append(f"ML Tier: {ml_tier}")

    final_action = ioc.get("final_action", "")
    if final_action:
        lines.append(f"Fusion Action: {final_action}")

    final_likelihood = ioc.get("final_likelihood", "")
    if final_likelihood:
        lines.append(f"Fusion Likelihood: {final_likelihood}")

    fusion_conf = ioc.get("fusion_confidence")
    if fusion_conf is not None:
        lines.append(f"Fusion Confidence: {round(float(fusion_conf), 4)}")

    cps = ioc.get("composite_poison_score")
    if cps is not None:
        lines.append(f"Composite Poison Score: {round(float(cps), 4)}")

    llm_poison = ioc.get("llm_poison_score")
    if llm_poison is not None:
        lines.append(f"LLM Poison Score: {round(float(llm_poison), 4)}")

    llm_conf = ioc.get("llm_confidence")
    if llm_conf is not None:
        lines.append(f"LLM Confidence: {llm_conf}")

    llm_v = _get_llm_verdict(ioc)
    if llm_v:
        lines.append(f"LLM Verdict: {llm_v}")

    contradictions = ioc.get("contradictions_count")
    if contradictions is not None:
        lines.append(f"Contradictions Count: {contradictions}")

    llm_class = ioc.get("llm_contradiction_class")
    if llm_class:
        lines.append(f"Contradiction Class: {llm_class}")

    reasoning = ioc.get("fusion_reasoning", "")
    if reasoning:
        lines.append(f"Reasoning: {str(reasoning)[:200]}")

    return " | ".join(lines) if lines else ""


def enrich_label(doc: dict, base_label: str, doc_id: str = "") -> str:

    source_count = doc.get("source_count", "?")
    sources      = doc.get("sources") or [{}]
    primary_feed = sources[0].get("feed_name") or "N/A"
    suffix       = f" | feeds:{source_count} | {primary_feed}"

    combined = base_label + suffix
    if len(combined) <= 255:
        return combined

    available = 255 - len(base_label)
    if available > 10:
        trimmed = suffix[:available].rstrip()
        if doc_id:
            log.warning("event label suffix trimmed to fit 255 chars (doc:%s)", doc_id)
        return base_label + trimmed

    truncated = base_label[:252] + "..."
    if doc_id:
        log.warning("event label base truncated to 255 chars (doc:%s)", doc_id)
    return truncated

def set_attribute_timestamps(attr, ioc: dict):
    first_seen = ioc.get("first_seen")
    last_seen  = ioc.get("last_seen")
    if first_seen:
        try:
            attr.first_seen = first_seen
        except Exception as _ts_exc:
            log.debug("set_attribute_timestamps: first_seen unsupported on this attr type (%s)", _ts_exc)
    if last_seen:
        try:
            attr.last_seen = last_seen
        except Exception as _ts_exc:
            log.debug("set_attribute_timestamps: last_seen unsupported on this attr type (%s)", _ts_exc)

def add_enrichment_attributes(event, ioc: dict) -> None:
    mitre = (ioc.get("enriched") or {}).get("mitre") or {}

    for tech in mitre.get("techniques", []):
        tid  = tech.get("id", "")
        name = tech.get("name", "")
        if not tid:
            continue
        comment = f"MITRE ATT&CK: {tid} - {name}" if name else f"MITRE ATT&CK: {tid}"
        try:
            event.add_attribute("text", tid, comment=comment, disable_correlation=True)
        except Exception as exc:
            log.debug("add_enrichment_attributes: technique attr failed (%s)", exc)

    owasp = (ioc.get("enriched") or {}).get("owasp") or {}
    if not owasp:
        owasp = ioc.get("owasp") or {}
    highest_risk = owasp.get("highest_risk", "")
    if highest_risk:
        try:
            event.add_attribute(
                "text", f"OWASP:{highest_risk}",
                comment="OWASP Top 10 highest risk category",
                disable_correlation=True,
            )
        except Exception as exc:
            log.debug("add_enrichment_attributes: owasp attr failed (%s)", exc)


def add_fusion_object(event, ioc: dict) -> None:
    comment = build_ml_comment(ioc)
    if not comment:
        return
    try:
        event.add_attribute(
            "text", "[ThreatRadar Fusion Analysis]",
            comment=comment,
            disable_correlation=True,
        )
    except Exception as exc:
        log.debug("add_fusion_object: attr failed (%s)", exc)
