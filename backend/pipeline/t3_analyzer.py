import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import config
from .t2_ml_classifier import VerdictRecord

logger = logging.getLogger("t3_analyzer")

try:
    import anthropic
    ANTHROPIC_SDK_AVAILABLE = True
except ImportError:
    ANTHROPIC_SDK_AVAILABLE = False


@dataclass
class FlowResult:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: object
    dst_port: object
    protocol: str
    source: str
    attack_type: str
    confidence: float
    severity_label: str
    risk_score: int
    evidence: List[str]
    is_attack: bool
    explanation: str = ""
    explanation_mode: str = "offline"
    features: Dict[str, Any] = field(default_factory=dict)
    top_features: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class Tier3Report:
    detections: List[FlowResult] = field(default_factory=list)
    file_summary: Dict = field(default_factory=dict)
    benign_summary: str = ""
    llm_mode: str = "offline"


_CONFIRMED_DETECTION_TIERS = {"tier1", "tier2_ml_confirmed"}


def _is_online_mode() -> bool:
    return bool(config.ANTHROPIC_API_KEY) and ANTHROPIC_SDK_AVAILABLE


def _offline_explanation(v: VerdictRecord) -> str:
    evidence_str = "; ".join(v.evidence) if v.evidence else "no additional evidence recorded"
    if v.detection_tier in _CONFIRMED_DETECTION_TIERS:
        return (
            f"[{v.source}] Flow {v.flow_id} classified as '{v.attack_type}' "
            f"(confidence {v.confidence:.0%}, severity {v.severity_label}, risk score {v.risk_score}/100). "
            f"Evidence: {evidence_str}."
        )

    score_str = f"{v.anomaly_score:.0f}" if v.anomaly_score is not None else "N/A"
    return (
        f"[{v.source}] Flow {v.flow_id} flagged anomalous (score {score_str}/100). "
        f"Tentative category '{v.attack_type}'. Evidence: {evidence_str}."
    )


def _build_prompt(v: VerdictRecord) -> str:
    is_confirmed = v.detection_tier in _CONFIRMED_DETECTION_TIERS
    header = "CONFIRMED detection" if is_confirmed else "UNCONFIRMED anomaly"
    
    return (
        f"You are a SOC analyst assistant triaging a {header}.\n"
        f"Source: {v.source} | Attack: {v.attack_type} | Confidence: {v.confidence:.0%}\n"
        f"Severity: {v.severity_label} ({v.risk_score}/100)\n"
        f"Evidence: {', '.join(v.evidence)}\n"
        f"Flow: {v.src_ip}:{v.src_port} -> {v.dst_ip}:{v.dst_port} ({v.protocol})\n"
        "Explain this decision to an analyst in 3-5 sentences with actionable steps."
    )


def _get_flow_explanation(client: Optional[anthropic.Anthropic], v: VerdictRecord, online: bool) -> tuple[str, str]:
    if not online or not client:
        return _offline_explanation(v), "offline"

    try:
        response = client.messages.create(
            model=config.ANTHROPIC_MODEL,
            max_tokens=400,
            messages=[{"role": "user", "content": _build_prompt(v)}],
        )
        text = "".join(b.text for b in response.content if getattr(b, "type", "") == "text").strip()
        return text or _offline_explanation(v), "online" if text else "offline"
    except Exception as exc:
        logger.error("Anthropic API failed for %s (%s); falling back to offline.", v.flow_id, exc)
        return _offline_explanation(v), "offline"


def _to_flow_result(v: VerdictRecord, explanation: str, mode: str) -> FlowResult:
    return FlowResult(
        flow_id=v.flow_id, src_ip=v.src_ip, dst_ip=v.dst_ip,
        src_port=v.src_port, dst_port=v.dst_port, protocol=v.protocol,
        source=v.source, attack_type=v.attack_type, confidence=v.confidence,
        severity_label=v.severity_label, risk_score=v.risk_score,
        evidence=list(v.evidence), is_attack=v.is_attack,
        explanation=explanation, explanation_mode=mode,
        features=getattr(v, "features", {}),
        top_features=getattr(v, "top_features", []),
    )


def analyze(verdicts: List[VerdictRecord]) -> Tier3Report:
    online = _is_online_mode()
    client = None
    if online:
        try:
            client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
        except Exception as exc:
            logger.error("Failed to init Anthropic client: %s", exc)
            online = False

    detections: List[FlowResult] = []
    benign_count = 0

    for v in verdicts:
        if v.is_attack:
            exp, mode = _get_flow_explanation(client, v, online)
            detections.append(_to_flow_result(v, exp, mode))
        else:
            benign_count += 1
            detections.append(_to_flow_result(
                v, "No signature/ML indicator of attack; BENIGN.", "offline"
            ))

    benign_summary = f"{benign_count} flow(s) classified BENIGN." if benign_count else "No benign flows."
    
    return Tier3Report(
        detections=detections,
        file_summary={},  # Calculated by external build_file_summary if needed
        benign_summary=benign_summary,
        llm_mode="online" if online else "offline"
    )