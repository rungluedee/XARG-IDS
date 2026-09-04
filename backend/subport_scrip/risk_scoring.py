"""
risk_scoring.py
-----------------
Shared severity / risk-score rules used by BOTH Tier 1 (t1_suricata.py, via
main.py's verdict construction) and Tier 2 (t2_ml_classifier.py), so a
`severity` value means the same thing regardless of which tier produced it.

Tier 3 (t3_analyzer.py) NEVER recomputes severity or risk_score -- it only
narrates whatever Tier 1/2 already decided. Keeping the scoring rules here,
independent of both tiers, is what makes that separation enforceable rather
than just a convention.
"""

from typing import Optional

SEVERITY_LEVELS = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Suricata's own alert severity is 1 (highest priority) .. 3 (lowest), by
# long-standing convention (see classification.config). Mapped onto a 0-100
# risk score. This is intentionally independent of whether we could
# confidently name the attack_type -- a real signature fired either way.
_SURICATA_SEVERITY_TO_RISK = {1: 95, 2: 75, 3: 55}
_DEFAULT_SURICATA_RISK = 65  # unexpected/missing severity value

# Baseline risk per attack_type, multiplied by model confidence for Tier 2
# (ML) flows. Includes both the 9 CICIDS2017 Attack Families (Tier 2's
# vocabulary) AND the extra signature-native types Tier 1 can emit that
# have no CICIDS2017 analogue (C2, UNKNOWN) -- see t1_suricata.py.
ATTACK_TYPE_BASE_RISK = {
    "BENIGN": 0,
    "PortScan": 45,
    "BruteForce": 65,
    "WebAttack": 75,
    "DoS": 80,
    "DDoS": 90,
    "Infiltration": 88,
    "Botnet": 90,
    "Heartbleed": 95,
    "C2": 92,        # Tier-1-only: Suricata C2/CNC/Trojan-beacon signature match
    "UNKNOWN": 60,    # Tier-1-only: signature fired but couldn't be confidently named
    # Tier-2.5-only: heuristic-triaged anomalies. Baselines set slightly
    # BELOW their confirmed-classification counterparts above, since a
    # tentative pattern match is inherently less certain than a signature
    # match or a confident supervised-model prediction -- confidence
    # scaling (see risk_from_attack_type) pulls the final score down
    # further still, since Tier 2.5 confidence is capped at 0.70.
    "Potential BruteForce": 55,
    "Potential DoS": 70,
    "Potential PortScan": 40,
    "Potential C2/Infiltration": 75,
    "Anomaly - Unclassified": 45,   # genuinely unknown; flagged but not named -- stay cautious, not alarmist
}
_DEFAULT_ATTACK_TYPE_RISK = 50  # any other attack_type we don't have a baseline for


def severity_from_risk(risk_score: float) -> str:
    if risk_score <= 0:
        return "NONE"
    if risk_score < 40:
        return "LOW"
    if risk_score < 70:
        return "MEDIUM"
    if risk_score < 90:
        return "HIGH"
    return "CRITICAL"


def risk_from_suricata_severity(severity: Optional[int]) -> int:
    """Tier 1 risk score, from Suricata's own alert severity (1-3)."""
    return _SURICATA_SEVERITY_TO_RISK.get(severity, _DEFAULT_SURICATA_RISK)


def risk_from_attack_type(attack_type: str, confidence: float, is_attack: bool) -> int:
    """Tier 2 risk score: baseline for the predicted class, scaled by the
    model's own confidence. BENIGN (or is_attack=False) is always 0."""
    if not is_attack:
        return 0
    base = ATTACK_TYPE_BASE_RISK.get(attack_type, _DEFAULT_ATTACK_TYPE_RISK)
    return max(0, min(100, round(base * confidence)))
