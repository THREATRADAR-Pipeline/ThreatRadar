import json
import os
import re
import math
import time
import requests
from typing import Optional


OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_FALLBACK_MODELS = os.getenv(
    "OPENROUTER_FALLBACK_MODELS",
    "openai/gpt-4o-mini,meta-llama/llama-3.1-8b-instruct,anthropic/claude-3.5-sonnet",
)

LLM_CALL_TIMEOUT = int(os.getenv("LLM_CALL_TIMEOUT", "45"))
def _load_contradiction_classes() -> str:

    config_path = os.path.join(
        os.path.dirname(__file__),
        "..",
        "config",
        "contradiction_classes.json"
    )

    try:
        with open(config_path, "r") as f:
            config = json.load(f)

        lines = ["CONTRADICTION CLASSES TO LOOK FOR:"]
        for item in config.get("contradiction_classes", []):
            code = item.get("code", "?")
            name = item.get("name", "?")
            desc = item.get("description", "?")
            lines.append(f"  {code} - {name:25s} : {desc}")

        result = "\n".join(lines)
        num_classes = len(config.get("contradiction_classes", []))
        version = config.get("version", "unknown")
        print(f"Loaded contradiction_classes.json (v{version}): {num_classes} classes")
        return result

    except Exception as e:
        print(f" Could not load contradiction_classes.json: {e}")
        print("   Falling back to hardcoded definitions")
        return """CONTRADICTION CLASSES TO LOOK FOR:
  C1 - APT_SECTOR_MISMATCH      : The attributed threat group has no known history targeting this sector
  C2 - TTP_MALWARE_MISMATCH     : The listed TTPs are inconsistent with the malware family's known behavior
  C3 - TTP_SECTOR_MISMATCH      : The listed TTPs do not align with attacks on this type of sector
  C4 - SEVERITY_CONTEXT_MISMATCH: The claimed severity is implausible given the malware family and sector
  C5 - MALWARE_APT_MISMATCH     : This malware family is not associated with this APT group
  C6 - IMPLAUSIBLE_COMBINATION  : The overall combination of APT + malware + sector + TTPs has never been observed in real threat intelligence
  C7 - FEED_CREDIBILITY_CONCERN : Based on the feed description, single-source high-severity claims are a known injection vector
  C8 - INFRASTRUCTURE_IMPLAUSIBLE: The infrastructure age contradicts the claimed sophistication of the attributed actor"""

CONTRADICTION_CLASSES = _load_contradiction_classes()


def build_semantic_prompt(ioc: dict) -> str:
    enriched      = ioc.get("enriched") or {}
    mitre_block   = enriched.get("mitre") or {}
    raw_techniques = mitre_block.get("techniques") or []
    if isinstance(raw_techniques, list):
        ttps = [
            t.get("id") or t if isinstance(t, dict) else str(t)
            for t in raw_techniques
            if t
        ]
    else:
        ttps = []
    mitre_groups = mitre_block.get("groups") or []
    if isinstance(mitre_groups, list) and mitre_groups:
        attributed_apt = ", ".join(str(g) for g in mitre_groups if g)
    else:
        attributed_apt = ioc.get("group_name") or ioc.get("ransomware_group") or "Unknown"
    feeds = ioc.get("source_names") or ioc.get("source_name", [])
    if not isinstance(feeds, list):
        feeds = [feeds] if feeds else []

    targeted_sector = ioc.get("activity") or "Unknown"

    feed_count = ioc.get("source_count", 0)
    desc = ioc.get("description", "No description provided.") or "No description provided."
    feed_dataset = ioc.get("feed_dataset", "unknown")

    extra_context_lines = []
    if ioc.get("ransomware_group"):
        extra_context_lines.append(f"Ransomware Group  : {ioc['ransomware_group']}")
    if ioc.get("ransomware_title"):
        extra_context_lines.append(f"Ransomware Victim : {ioc['ransomware_title']}")
    if ioc.get("required_action"):
        extra_context_lines.append(f"CISA Action       : {ioc['required_action']}")
    if ioc.get("ioc_port"):
        extra_context_lines.append(f"IOC Port/Status    : {ioc['ioc_port']} / {ioc.get('c2_status', '?')}")
    if ioc.get("country"):
        extra_context_lines.append(f"Country/ASN        : {ioc['country']} / {ioc.get('c2_as_name', '?')}")
    if ioc.get("threat_type"):
        extra_context_lines.append(f"Threat Type       : {ioc['threat_type']}")
    if ioc.get("hash_type"):
        extra_context_lines.append(f"Hash Type         : {ioc['hash_type']}")
    if ioc.get("wallet_type"):
        extra_context_lines.append(f"Wallet Type       : {ioc['wallet_type']}")
    if ioc.get("source_confidence"):
        extra_context_lines.append(f"Source Confidence : {ioc['source_confidence']}")
    if ioc.get("source_tier"):
        extra_context_lines.append(f"Source Tier       : {ioc['source_tier']}")
    if ioc.get("ioc_type_weight"):
        extra_context_lines.append(f"Type Weight       : {ioc['ioc_type_weight']}")

    extra_block = "\n".join(extra_context_lines)
    if extra_block:
        extra_block = f"\n── Feed-Specific Context ──\n{extra_block}"

    return f"""You are a senior threat intelligence analyst with 15 years of experience.
You have deep knowledge of APT groups, malware families, threat techniques, and how legitimate threat intelligence reads versus fabricated or poisoned intelligence.

You are acting as an INDEPENDENT SEMANTIC JUDGE.
Your job is to read the following IOC record and determine whether the intelligence it presents is internally coherent and consistent with known real-world threat behavior.

CRITICAL RULES:
- You must reason from YOUR OWN KNOWLEDGE of threat actors, TTPs, and malware — not from any score.
- Do not mention or reference any ML model output.
- Think like a skeptical analyst reviewing a submission for publication.
- Focus on SEMANTIC CONTRADICTIONS — things that don't add up when you read the intelligence as a story.
- For IOCs with limited metadata (single hash, single IP), assess plausibility of the combination of feed source, threat classification, and indicator type.

INTELLIGENCE RECORD TO EVALUATE

IOC Type           : {ioc.get('ioc_type', 'unknown').upper()}
IOC Value          : {ioc.get('ioc_value', '?')}
Attributed APT     : {attributed_apt}
Malware Family     : {ioc.get('malware', 'Unknown')}
Targeted Sector    : {targeted_sector}
TTPs               : {', '.join(ttps) if ttps else 'None listed'}
Severity Claimed   : {ioc.get('severity', 'Unknown')}
Feed Source        : {', '.join(feeds) if isinstance(feeds, list) else feeds} ({feed_count} source(s))
Feed Dataset       : {feed_dataset}
Infrastructure Age : {ioc.get('infrastructure_age_days', '?')} days
First Seen         : {ioc.get('first_seen', '?')}
Description        : {desc}
{extra_block}

{CONTRADICTION_CLASSES}

YOUR TASK:
1. Read the record above as a complete intelligence narrative.
2. Identify any semantic contradictions from the classes above (C1–C8).
3. Reason step by step about whether this intelligence makes sense.
4. Deliver a structured verdict.

Decision strictness rules (very important):
- Default to COHERENT unless there is concrete contradiction evidence.
- Do NOT mark SUSPICIOUS from one weak/ambiguous mismatch alone.
- Use SUSPICIOUS only when there are at least 2 specific, defensible red flags.
- Use CONTRADICTED only for clear, strong incompatibilities or multiple severe contradictions.
- If metadata is sparse or uncertain, keep verdict COHERENT with lower confidence and explain uncertainty.
- You are a skeptic. Every flag requires a clear explanation.

Respond ONLY with a valid JSON object. No markdown, no preamble, no explanation outside the JSON:

{{
  "semantic_verdict": "CONTRADICTED | SUSPICIOUS | COHERENT",
  "confidence": <float 0.0-1.0>,
  "contradictions_found": [
    {{
      "class": "<C1-C8 code>",
      "label": "<contradiction class name>",
      "detail": "<specific explanation of why this is a contradiction for this IOC>"
    }}
  ],
  "coherence_reasoning": "<2-3 sentences: what the intelligence claims and whether the overall narrative holds together>",
  "semantic_red_flags": [<list of brief red flag phrases, e.g. "FIN7 has no ICS history">],
  "llm_poison_score": <float 0.0-1.0, where 1.0 = certainly poisoned based on semantic analysis alone>,
  "analyst_challenge": "<one direct question a senior analyst should ask the submitting feed about this IOC>"
}}

Verdict guide:
- CONTRADICTED : One or more clear, specific contradictions found. Intelligence narrative does not hold.
- SUSPICIOUS   : Unusual combination or minor contradictions — warrants scrutiny but not impossible.
- COHERENT     : Intelligence is consistent with known threat actor behavior. No red flags.

Poison-score rubric (important):
- COHERENT score should be in 0.00-0.25
- SUSPICIOUS score should be in 0.26-0.69
- CONTRADICTED score should be in 0.70-1.00
- Increase score when multiple strong contradictions are present.
- Do not always reuse the same score value across different IOCs.
"""


def _ml_tier_and_action(ml_score: float) -> tuple[str, str, float]:

    if ml_score > 0.70:
        return "HIGH",   "QUARANTINE", 0.70
    if ml_score > 0.50:
        return "MEDIUM", "MONITOR",    0.45
    return "LOW",    "ACCEPT",      0.15



_STRATEGY_PRIORITY: list[tuple[frozenset, str]] = [
    (frozenset({"C1", "C5", "C6"}), "fabricated_apt"),      
    (frozenset({"C1", "C2", "C6"}), "fabricated_apt"),
    (frozenset({"C2", "C5"}),       "fabricated_apt"),       
    (frozenset({"C4", "C7"}),       "score_inflation"),     
    (frozenset({"C4"}),             "score_inflation"),
    (frozenset({"C7"}),             "score_inflation"),     
    (frozenset({"C8"}),             "infrastructure_mismatch"),
    (frozenset({"C1", "C3"}),       "sector_mismatch"),
    (frozenset({"C3"}),             "sector_mismatch"),
    (frozenset({"C1"}),             "apt_mismatch"),
]

def _derive_poison_strategy(semantic: str, contradictions: list) -> str:
    if semantic not in ("CONTRADICTED", "SUSPICIOUS") or not contradictions:
        return "unknown"

    codes = frozenset(
        _extract_class_code(c)
        for c in contradictions
        if isinstance(c, dict) and _extract_class_code(c)
    )

    for trigger_codes, strategy in _STRATEGY_PRIORITY:
        if trigger_codes & codes:
            return strategy

    return "generic_contradiction"


_ACTION_SEVERITY: dict[str, int] = {
    "ACCEPT":     0,
    "MONITOR":    1,
    "QUARANTINE": 2,
    "BLOCK":      3,
}

_MAX_ACTION_BY_IOC_TYPE: dict[str, str] = {
    "cve":        "MONITOR",
    "ransomware": "MONITOR",
    "wallet":     "MONITOR",   
    "hash":       "QUARANTINE", 

}


def _apply_ioc_type_action_cap(action: str, ioc_type: str) -> tuple:
    cap = _MAX_ACTION_BY_IOC_TYPE.get(ioc_type)
    if cap is None:
        return action, None
    if _ACTION_SEVERITY.get(action, 0) > _ACTION_SEVERITY[cap]:
        reason = (
            f"action capped {action}\u2192{cap}: "
            f"ioc_type={ioc_type!r} has no enforcement surface for {action}"
        )
        return cap, reason
    return action, None


def fuse_verdicts(ioc: dict, llm_verdict: dict) -> dict:

    ml_score       = float(ioc.get("ml_score", 0))
    ioc_type       = str(ioc.get("ioc_type", "")).lower()
    semantic       = llm_verdict.get("semantic_verdict", "COHERENT")
    llm_pscore     = float(llm_verdict.get("llm_poison_score", 0))
    contradictions = llm_verdict.get("contradictions_found", [])

    ml_tier, _, _ = _ml_tier_and_action(ml_score)

    matrix = {
        ("HIGH",   "CONTRADICTED"): ("BLOCK",      "CRITICAL", 0.99),
        ("HIGH",   "SUSPICIOUS"):   ("QUARANTINE", "CRITICAL", 0.98),
        ("HIGH",   "COHERENT"):     ("MONITOR",    "MEDIUM",   0.60),
        ("MEDIUM", "CONTRADICTED"): ("QUARANTINE", "CRITICAL", 0.98),
        ("MEDIUM", "SUSPICIOUS"):   ("QUARANTINE", "CRITICAL", 0.97),
        ("MEDIUM", "COHERENT"):     ("ACCEPT",     "MEDIUM",   0.45),
        ("LOW",    "CONTRADICTED"): ("QUARANTINE", "CRITICAL", 0.95),
        ("LOW",    "SUSPICIOUS"):   ("MONITOR",    "MEDIUM",   0.55),
        ("LOW",    "COHERENT"):     ("ACCEPT",     "LOW",      0.15),
    }

    action, final_likelihood, base_conf = matrix.get(
        (ml_tier, semantic), ("MONITOR", "UNKNOWN", 0.50)
    )
    action, cap_reason = _apply_ioc_type_action_cap(action, ioc_type)

    n_contradictions = len(contradictions)
    confidence_boost = min(n_contradictions * 0.04, 0.15)
    final_confidence = round(min(base_conf + confidence_boost, 0.99), 3)

    composite_poison_score = round(0.45 * ml_score + 0.55 * llm_pscore, 4)

    llm_contradiction_class = ""
    if contradictions:
        llm_contradiction_class = contradictions[0].get("class", "")

    poison_strategy = _derive_poison_strategy(semantic, contradictions)

    base_reasoning = (
        f"ML ({ml_tier} anomaly, score={ml_score:.2f}) + "
        f"LLM ({semantic}, {n_contradictions} contradiction(s), "
        f"llm_score={llm_pscore:.2f}) \u2192 {action}"
    )
    fusion_reasoning = (
        f"{base_reasoning}; {cap_reason}" if cap_reason else base_reasoning
    )

    return {
        "ml_tier":                 ml_tier,
        "llm_verdict":             semantic,
        "llm_poison_score":        round(llm_pscore, 4),
        "llm_confidence":          int(float(llm_verdict.get("confidence", 0.5)) * 100),
        "llm_contradiction_class": llm_contradiction_class,
        "contradictions_count":    n_contradictions,
        "final_action":            action,
        "final_likelihood":        final_likelihood,
        "fusion_confidence":       final_confidence,
        "composite_poison_score":  composite_poison_score,
        "poison_strategy":         poison_strategy,
        "fusion_reasoning":        fusion_reasoning,
    }
def call_llm(prompt: str, timeout: int = LLM_CALL_TIMEOUT) -> Optional[str]:

    if not OPENROUTER_API_KEY:
        print("  OpenRouter API key not configured")
        return None

    fallback_from_env = [m.strip() for m in OPENROUTER_FALLBACK_MODELS.split(",") if m.strip()]
    FALLBACK_MODELS = [OPENROUTER_MODEL] + [m for m in fallback_from_env if m != OPENROUTER_MODEL]

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "HTTP-Referer": "https://cyberhorizon.io",
        "X-Title": "Threat Intelligence Pipeline"
    }

    max_retries_per_model = 1
    rate_limit_wait_base = 120
    consecutive_429_count = 0
    max_consecutive_429 = 3

    for model in FALLBACK_MODELS:
        for attempt in range(max_retries_per_model):
            if consecutive_429_count >= max_consecutive_429:
                print(f"  Circuit breaker triggered ({consecutive_429_count} consecutive 429s). Skipping LLM analysis.")
                return None

            payload = {
                "model": model,
                "messages": [
                    {
                        "role": "user",
                        "content": "Analyze these IOC details for semantic contradictions. Reply ONLY with valid JSON.\n\n" + prompt
                    }
                ],
                "temperature": 0.1,
                "max_tokens": 512
            }

            try:
                response = requests.post(
                    OPENROUTER_URL,
                    headers=headers,
                    json=payload,
                    timeout=timeout
                )

                if response.status_code == 429:
                    consecutive_429_count += 1
                    wait_time = rate_limit_wait_base * (2 ** attempt)
                    print(f"  Rate limited (429 #{consecutive_429_count}) for {model}. Waiting {wait_time}s...")
                    time.sleep(wait_time)
                    continue

                if response.status_code == 404:
                    try:
                        body = response.json()
                        msg = str((body.get("error") or {}).get("message", ""))
                    except Exception:
                        msg = response.text[:200]
                    if "guardrail restrictions" in msg.lower() or "data policy" in msg.lower():
                        print(f"  OpenRouter policy blocked model {model}. Trying next fallback model...")
                        time.sleep(2)
                        continue

                consecutive_429_count = 0
                if response.status_code != 200:
                    time.sleep(5)
                    continue

                response_data = response.json()
                if "choices" in response_data and len(response_data["choices"]) > 0:
                    message_content = response_data["choices"][0].get("message", {}).get("content")
                    if message_content:
                        content = message_content.strip()
                        if model != OPENROUTER_MODEL:
                            print(f"  Fallback used: {model}")
                        return content
                else:
                    time.sleep(5)
                    continue

            except requests.Timeout:
                print(f"  Timeout for {model} (Attempt {attempt+1})")
                time.sleep(5)
                continue
            except Exception as e:
                print(f"  Request failed ({model}): {e}")
                time.sleep(5)
                continue

        if consecutive_429_count > 0:
            print(f"   Cooling down {45}s before trying next model...")
            time.sleep(45)

    print(" All LLM models failed or were rate-limited. Using ML-only verdict.")
    return None


def parse_llm_response(raw: str) -> dict:
    raw = raw.strip()
    if "```" in raw:
        parts = raw.split("```")
        for part in parts:
            part = part.strip().lstrip("json").strip()
            try:
                return json.loads(part)
            except Exception:
                continue
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r'\{.*\}', raw, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except Exception:
                pass
    return {
        "semantic_verdict":       "UNKNOWN",
        "confidence":             0.0,
        "contradictions_found":   [],
        "coherence_reasoning":    "Parse failed — raw response stored.",
        "semantic_red_flags":     [],
        "llm_poison_score":       0.5,
        "analyst_challenge":      "Manual review required.",
        "parse_error":            True,
        "raw_response":           raw[:500],
    }


def _clamp(x: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, x))


def _to_float(value, default: float) -> float:
    try:
        f = float(value)
        if not math.isfinite(f):
            return default
        return f
    except Exception:
        return default


def _derived_poison_score(semantic_verdict: str, contradictions_count: int) -> float:
    c = max(0, int(contradictions_count))
    if semantic_verdict == "CONTRADICTED":
        return _clamp(0.78 + 0.05 * min(c, 4), 0.70, 0.99)
    if semantic_verdict == "SUSPICIOUS":
        return _clamp(0.34 + 0.08 * min(c, 4), 0.26, 0.69)
    if semantic_verdict == "COHERENT":
        return _clamp(0.08 + 0.03 * min(c, 3), 0.00, 0.25)
    return 0.50


def _extract_class_code(item: dict) -> str:
    cls = str((item or {}).get("class", "")).upper()
    m = re.search(r"C([1-8])", cls)
    return f"C{m.group(1)}" if m else ""


def _clean_contradictions(contradictions: list, ioc: dict) -> list:

    if not isinstance(contradictions, list):
        return []

    apt      = str((ioc or {}).get("group_name", "")).upper()
    sector   = str((ioc or {}).get("activity") or "").upper()
    severity = str((ioc or {}).get("severity", "")).upper()
    feed_count = int((ioc or {}).get("source_count", 0) or 0)
    infra_age = _to_float((ioc or {}).get("infrastructure_age_days", 0), 0.0)

    seen = set()
    kept = []
    for item in contradictions:
        if not isinstance(item, dict):
            continue
        code = _extract_class_code(item)
        if not code:
            continue

        detail = str(item.get("detail", "") or "").strip()
        if len(detail) < 20:
            continue

        if code == "C3" and not re.search(r"T\d{4}", detail.upper()):
            continue

        if code == "C7" and not (feed_count <= 1 and severity in {"HIGH", "CRITICAL"}):
            continue

        if code == "C8" and infra_age > 14:
            continue

        key = (code, detail.lower())
        if key in seen:
            continue
        seen.add(key)
        item["class"] = code
        kept.append(item)
    return kept


def _recalibrate_semantic_verdict(semantic: str, contradictions: list, confidence: float) -> str:
    codes = [_extract_class_code(c) for c in contradictions if isinstance(c, dict)]
    codes = [c for c in codes if c]
    unique_codes = set(codes)
    n = len(codes)
    n_unique = len(unique_codes)

    strong_codes = {"C6", "C7", "C8"}
    medium_codes = {"C4", "C5"}
    n_strong = sum(1 for c in codes if c in strong_codes)
    n_medium = sum(1 for c in codes if c in medium_codes)

    if semantic == "CONTRADICTED":
        if n == 0:
            return "COHERENT"
        if n_strong >= 1 and n >= 2:
            return "CONTRADICTED"
        if n_unique >= 3 and n >= 3 and confidence >= 0.75:
            return "CONTRADICTED"
        return "SUSPICIOUS"

    if semantic == "SUSPICIOUS":
        if n == 0:
            return "COHERENT"
        if n == 1:
            return "COHERENT"
        if n_unique < 2 and n_strong == 0:
            return "COHERENT"
        if n == 2 and confidence < 0.80 and n_strong == 0:
            return "COHERENT"
        return "SUSPICIOUS"

    if semantic == "COHERENT":
        if n_strong >= 1 and confidence >= 0.70:
            return "SUSPICIOUS"
        if n_unique >= 3 and n >= 3 and confidence >= 0.75:
            return "SUSPICIOUS"
        return "COHERENT"

    return semantic


def normalize_llm_verdict(verdict: dict, ioc: dict | None = None) -> dict:

    out = dict(verdict or {})

    semantic = str(out.get("semantic_verdict", "UNKNOWN")).strip().upper()
    if semantic not in {"CONTRADICTED", "SUSPICIOUS", "COHERENT"}:
        semantic = "UNKNOWN"
    out["semantic_verdict"] = semantic

    contradictions = _clean_contradictions(out.get("contradictions_found"), ioc or {})
    out["contradictions_found"] = contradictions
    n_contradictions = len(contradictions)

    base_confidence = _clamp(_to_float(out.get("confidence", 0.5), 0.5), 0.0, 1.0)
    semantic = _recalibrate_semantic_verdict(semantic, contradictions, base_confidence)
    out["semantic_verdict"] = semantic

    reported = out.get("llm_poison_score", None)
    reported_score = _to_float(reported, default=float("nan"))
    derived_score = _derived_poison_score(semantic, n_contradictions)

    bands = {
        "COHERENT": (0.00, 0.25),
        "SUSPICIOUS": (0.26, 0.69),
        "CONTRADICTED": (0.70, 1.00),
    }

    if semantic in bands:
        lo, hi = bands[semantic]
        if math.isfinite(reported_score) and lo <= reported_score <= hi:
            signal_divergence = abs(reported_score - derived_score)

            if signal_divergence < 0.10:
                llm_weight = 0.80
            elif signal_divergence < 0.20:
                llm_weight = 0.75
            elif signal_divergence > 0.35:
                llm_weight = 0.45
            else:
                llm_weight = 0.65

            calibrated = llm_weight * reported_score + (1 - llm_weight) * derived_score
        else:
            calibrated = derived_score
        out["llm_poison_score"] = round(_clamp(calibrated, lo, hi), 4)
    else:
        out["llm_poison_score"] = round(
            derived_score if not math.isfinite(reported_score)
            else _clamp(reported_score, 0.0, 1.0),
            4,
        )

    out["confidence"] = round(base_confidence, 4)
    return out



def judge_ioc(ioc: dict, verbose: bool = True) -> dict:

    if verbose:
        ioc_id = ioc.get('_id') or ioc.get('ioc_value') or '?'
        _enriched     = ioc.get("enriched") or {}
        _mitre_groups = (_enriched.get("mitre") or {}).get("groups") or []
        apt = (
            ", ".join(str(g) for g in _mitre_groups if g)
            if _mitre_groups
            else (ioc.get("group_name") or ioc.get("ransomware_group") or "Unknown")
        )
        sector = ioc.get("activity") or "Unknown"

        if apt == "Unknown" and sector == "Unknown":
            print(f"\n  Semantic judge: {ioc_id}")
        else:
            print(f"\n  Semantic judge: {ioc_id}  [{apt} -> {sector}]")

    prompt = build_semantic_prompt(ioc)

    raw = call_llm(prompt)

    if raw is None:
        return {**ioc,
                "llm_semantic": None,
                "fusion":       None,
                "llm_error":    "OpenRouter unreachable or API key missing"}

    llm_verdict = normalize_llm_verdict(parse_llm_response(raw), ioc=ioc)
    fusion      = fuse_verdicts(ioc, llm_verdict)

    if verbose:
        sv   = fusion.get("llm_verdict", "?")
        lps  = fusion.get("llm_poison_score", 0)
        nc   = fusion.get("contradictions_count", 0)
        fa   = fusion.get("final_action", "?")
        fc   = fusion.get("fusion_confidence", 0)
        print(f"     LLM: {sv} (poison_score={lps:.2f}, {nc} contradiction(s))")
        print(f"     FUSION -> {fa}  (confidence={fc:.0%})")
        for c in llm_verdict.get("contradictions_found", []):
            print(f"         [{c.get('class')}] {c.get('detail', '')}")

    return {
        **ioc,
        "llm_semantic":      llm_verdict,
        "llm_raw_response":  raw,
        "fusion":            fusion,
        "analysis_ts":       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def batch_judge(iocs: list, max_items: int = 500, verbose: bool = True) -> list:

    total = len(iocs)

    ranked = sorted(iocs, key=lambda r: float(r.get("ml_score", 0)), reverse=True)

    llm_queue = ranked[:max_items]
    ml_only   = ranked[max_items:]

    n_flagged = sum(1 for r in iocs if r.get("poisoning_flagged"))
    print(f"\nSemantic Judge Strategy (dataset: {total:,} IOCs):")
    print(f"   ML flagged {n_flagged:,} IOCs as anomalous")
    print(f"   LLM will analyze top {len(llm_queue):,} most suspicious IOCs")
    print(f"   {len(ml_only):,} lower-risk IOCs keep ML-only verdict")
    if llm_queue:
        print(f"   Score range sent to LLM: "
              f"{float(llm_queue[-1].get('ml_score',0)):.4f} — "
              f"{float(llm_queue[0].get('ml_score',0)):.4f}")

    results = []
    for i, ioc in enumerate(llm_queue, 1):
        print(f"\n[{i}/{len(llm_queue)}]", end="")
        result = judge_ioc(ioc, verbose=verbose)
        results.append(result)
        time.sleep(0.3)

    def get_any_id(ioc):
        return ioc.get("ioc_id") or ioc.get("_id") or ioc.get("ioc_value")
    llm_map = {get_any_id(r): r for r in results}
    final = []
    for ioc in iocs:
        ioc_id = get_any_id(ioc)
        if ioc_id in llm_map:
            final.append(llm_map[ioc_id])
        else:
            try:
                ml_score = float(ioc.get("ml_score", 0.0))
            except Exception:
                ml_score = 0.0

            ml_tier, ml_action, ml_conf = _ml_tier_and_action(ml_score)

            ml_only_fusion = {
                "ml_tier": ml_tier,
                "llm_verdict": "N/A",
                "llm_poison_score": 0.0,
                "contradictions_count": 0,
                "final_action": ml_action,
                "final_likelihood": ml_tier,
                "fusion_confidence": round(ml_conf, 3),
                "composite_poison_score": round(ml_score, 4),
                "fusion_reasoning": f"ML-only (no LLM analysis): {ml_action} based on anomaly score {ml_score:.2f}",
            }
            final.append({**ioc, "llm_semantic": None, "fusion": ml_only_fusion})

    n_analyzed = len(results)
    n_contradicted = sum(
        1 for r in results
        if (r.get("llm_semantic") or {}).get("semantic_verdict") == "CONTRADICTED"
    )
    print(f"\n\n LLM Analysis Complete:")
    print(f"   Analyzed: {n_analyzed:,} / {total:,} IOCs")
    print(f"   Contradicted: {n_contradicted:,}")

    return final
