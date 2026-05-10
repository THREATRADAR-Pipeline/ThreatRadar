"""
THREATRADAR — shared pipeline constants.
© 2026 THREATRADAR Team
"""
from __future__ import annotations

OUTPUT_INDICES: dict[str, str] = {
    "ip":         "ti_ip",
    "url":        "ti_url",
    "hash":       "ti_hash",
    "domain":     "ti_domain",
    "cve":        "ti_cve",
    "ransomware": "ti_ransomware",
    "wallet":     "ti_wallet",
}

TARGET_INDICES: list[str] = list(OUTPUT_INDICES.values())

_DOWNSTREAM_RESET: dict = {
    "cortex_analyzed":         False,
    "cortex_analyzed_at":      None,
    "scoring_timestamp":       None,
    "cortex_score":            None,
    "cortex_final_score":      None,
    "cortex_severity":         "UNSCORED",
    "cortex_action":           "PENDING",
    "cortex_verdict":          "UNSCORED",
    "cortex_analyzers":        [],
    "final_score":             None,
    "verdict":                 "UNSCORED",
    "severity":                "UNSCORED",
    "action":                  "PENDING",
    "has_score":               False,
    "actor_danger_score":      None,
    "actor_threat_level":      "UNSCORED",
    "ml_score":                None,
    "poisoning_flagged":       False,
    "poison_strategy":         None,
    "ml_tier":                 "UNKNOWN",
    "llm_verdict":             "UNSCORED",
    "llm_confidence":          None,
    "llm_contradiction_class": "UNKNOWN",
    "llm_poison_score":        None,
    "llm_contradictions_found": [],
    "llm_coherence_reasoning": None,
    "llm_red_flags":           [],
    "llm_analyst_challenge":   None,
    "llm_raw_response":        None,
    "composite_poison_score":  None,
    "contradictions_count":    0,
    "final_action":            "PENDING",
    "final_likelihood":        "UNKNOWN",
    "fusion_confidence":       None,
    "fusion_reasoning":        None,
    "analysis_ts":             None,
}
