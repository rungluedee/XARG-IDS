"""
t2_5_heuristic_triage.py
---------------------------
Tier 2.5: Heuristic & Pattern Triage.

Takes flows the Isolation Forest (Tier 2) flagged anomalous, that the
supervised XGBoost model (Tier 2a) either couldn't or wouldn't confidently
name, and inspects raw flow metadata already present in the 78-column
CICIDS2017 feature vector (destination port, packet-rate stats, SYN/ACK
flag ratios) plus simple same-capture connection-frequency patterns to
assign a TENTATIVE category.

Design discipline (same as t1_suricata.py's alert->attack_type mapping):
this module NEVER forces a confident-sounding label onto an anomaly it
can't actually explain. Every tentative category is prefixed "Potential "
(never a bare family name -- that would look as certain as a real
classification) and capped at a modest confidence ceiling. If nothing
here confidently matches, the result is "Anomaly - Unclassified" -- never
a guess.
"""

import logging
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List

import pandas as pd

import config
from extractor import ExtractedFlows
from t2_anomaly_detector import AnomalyResult
from subport_scrip.risk_scoring import risk_from_attack_type, severity_from_risk

logger = logging.getLogger("t2_5_heuristic_triage")

# Ports commonly targeted by credential brute-forcing.
_BRUTE_FORCE_PORTS = {21, 22, 23, 3389, 445, 5900, 3306, 1433}

# Confidence ceiling for ANY heuristic tag -- this tier is explicitly
# tentative and must never look as certain as a signature match (T1,
# confidence 1.0) or a confident ML classification (T2a, >=0.85).
_MAX_HEURISTIC_CONFIDENCE = 0.70
_MIN_HEURISTIC_CONFIDENCE = 0.35


@dataclass
class TriageResult:
    flow_id: str
    tentative_category: str    # "Potential BruteForce" | "Potential DoS" | "Potential PortScan"
                                 # | "Potential C2/Infiltration" | "Anomaly - Unclassified"
    confidence: float
    evidence: List[str]


def _connection_frequency_context(five_tuple_df: pd.DataFrame) -> Dict[str, Counter]:
    """
    Pre-computes, ACROSS THE WHOLE ANOMALOUS BATCH being triaged, two
    lightweight frequency tables used by multiple heuristics below:
      - how many times each (src_ip -> dst_ip:dst_port) pair repeats
        (repeated hits on the same service -> brute-force signal)
      - how many DISTINCT destination ports each src_ip has touched
        (many distinct ports from one source -> port-scan signal)
    This looks only at 5-tuples already extracted for this file -- no new
    packet parsing.
    """
    pair_counts = Counter(
        (row.get("src_ip", ""), row.get("dst_ip", ""), str(row.get("dst_port", "")))
        for _, row in five_tuple_df.iterrows()
    )
    distinct_ports_per_src = {}
    for _, row in five_tuple_df.iterrows():
        src = row.get("src_ip", "")
        distinct_ports_per_src.setdefault(src, set()).add(str(row.get("dst_port", "")))
    return {"pair_counts": pair_counts, "distinct_ports_per_src": distinct_ports_per_src}


def _triage_one_flow(
    flow_stats: pd.Series,
    five_tuple: pd.Series,
    context: Dict,
) -> TriageResult:
    """
    Applies pattern rules in order of specificity. Each rule accumulates
    (evidence, confidence_delta) when it fires; the flow is tagged with the
    FIRST rule category that reaches _MIN_HEURISTIC_CONFIDENCE, using the
    corroborating-signal count to scale confidence up to the ceiling.
    Falls through to "Anomaly - Unclassified" if nothing fires.
    """
    dst_port = int(flow_stats.get("Destination Port", -1) or -1)
    flow_packets_per_s = float(flow_stats.get("Flow Packets/s", 0) or 0)
    syn_count = float(flow_stats.get("SYN Flag Count", 0) or 0)
    ack_count = float(flow_stats.get("ACK Flag Count", 0) or 0)
    flow_duration_us = float(flow_stats.get("Flow Duration", 0) or 0)
    total_fwd_packets = float(flow_stats.get("Total Fwd Packets", 0) or 0)

    src_ip = five_tuple.get("src_ip", "")
    dst_ip = five_tuple.get("dst_ip", "")
    pair_key = (src_ip, dst_ip, str(dst_port))
    repeat_hits = context["pair_counts"].get(pair_key, 1)
    distinct_ports_from_src = len(context["distinct_ports_per_src"].get(src_ip, set()))

    # --- Rule 1: Potential BruteForce ---
    # A known credential-service port, hit repeatedly from the same source
    # in this capture, with short-lived connections (consistent with rapid
    # login attempts rather than one long legitimate session).
    signals = []
    if dst_port in _BRUTE_FORCE_PORTS:
        signals.append(f"Destination port {dst_port} is commonly targeted for credential brute-forcing")
        if repeat_hits >= 3:
            signals.append(f"{repeat_hits} connection attempts observed from {src_ip} to {dst_ip}:{dst_port} in this capture")
        if 0 < flow_duration_us < 2_000_000:  # under 2s, CICIDS Flow Duration is in microseconds
            signals.append(f"Short flow duration ({flow_duration_us/1e6:.2f}s) typical of a single login attempt")
    if len(signals) >= 2:
        conf = min(_MAX_HEURISTIC_CONFIDENCE, _MIN_HEURISTIC_CONFIDENCE + 0.1 * len(signals))
        return TriageResult(flow_id="", tentative_category="Potential BruteForce", confidence=conf, evidence=signals)

    # --- Rule 2: Potential DoS / DDoS ---
    # Very high packet rate and/or a SYN-heavy, ACK-light flag ratio (SYN
    # flood pattern: many connection attempts never completing a handshake).
    signals = []
    if flow_packets_per_s > 1000:
        signals.append(f"Abnormally high packet rate ({flow_packets_per_s:.0f} packets/s)")
    if syn_count > 0 and ack_count == 0 and syn_count >= 3:
        signals.append(f"SYN-heavy flag pattern ({int(syn_count)} SYN, 0 ACK) consistent with a SYN flood / half-open connection attempt")
    if len(signals) >= 1 and flow_packets_per_s > 1000:
        conf = min(_MAX_HEURISTIC_CONFIDENCE, _MIN_HEURISTIC_CONFIDENCE + 0.15 * len(signals))
        return TriageResult(flow_id="", tentative_category="Potential DoS", confidence=conf, evidence=signals)

    # --- Rule 3: Potential PortScan ---
    # Same source touching many distinct destination ports in this
    # capture, each with minimal data transferred (reconnaissance, not a
    # real service interaction).
    signals = []
    if distinct_ports_from_src >= 5:
        signals.append(f"Source {src_ip} contacted {distinct_ports_from_src} distinct destination ports in this capture")
        if total_fwd_packets <= 3:
            signals.append(f"Minimal packets exchanged ({int(total_fwd_packets)} forward packets) -- consistent with probing rather than a real session")
    if len(signals) >= 1 and distinct_ports_from_src >= 5:
        conf = min(_MAX_HEURISTIC_CONFIDENCE, _MIN_HEURISTIC_CONFIDENCE + 0.15 * len(signals))
        return TriageResult(flow_id="", tentative_category="Potential PortScan", confidence=conf, evidence=signals)

    # --- Rule 4: Potential C2 / Infiltration ("low and slow") ---
    # Long-lived, low-throughput connection -- the opposite profile of a
    # scan/flood, and a common beaconing/exfiltration shape.
    signals = []
    if flow_duration_us > 60_000_000 and flow_packets_per_s < 1:  # >60s, <1 packet/s
        signals.append(f"Long-lived, low-throughput flow ({flow_duration_us/1e6:.0f}s duration, {flow_packets_per_s:.2f} packets/s) -- consistent with beaconing or slow exfiltration")
    if signals:
        conf = _MIN_HEURISTIC_CONFIDENCE
        return TriageResult(flow_id="", tentative_category="Potential C2/Infiltration", confidence=conf, evidence=signals)

    # --- No confident pattern -- do NOT guess ---
    return TriageResult(
        flow_id="",
        tentative_category="Anomaly - Unclassified",
        confidence=_MIN_HEURISTIC_CONFIDENCE,
        evidence=[
            "Statistically anomalous relative to the benign traffic baseline "
            "(Isolation Forest), but no known attack pattern (brute-force port "
            "repetition, packet-rate flood, port-scan fan-out, or long-and-slow "
            "beaconing) confidently matched.",
        ],
    )


def triage(extracted: ExtractedFlows, row_positions: List[int], anomaly_results: Dict[str, AnomalyResult]) -> Dict[str, TriageResult]:
    """
    Main entry point used by main.py.

    `row_positions`: positional indices into `extracted` for the flows to
    triage (i.e. anomalous AND not confidently resolved by Tier 2a).
    `anomaly_results`: {flow_id: AnomalyResult}, used only for logging
    context here (the score itself is carried on the VerdictRecord by
    main.py, not recomputed).

    Returns {flow_id: TriageResult}.
    """
    if not row_positions:
        return {}

    subset_five_tuple = extracted.five_tuple_df.iloc[row_positions].reset_index(drop=True)
    # Connection-frequency context is computed across the FULL anomalous
    # batch (not just this subset) so repeated-connection and port-fanout
    # signals aren't blind to related flows that Tier 2a already resolved.
    context = _connection_frequency_context(extracted.five_tuple_df)

    results: Dict[str, TriageResult] = {}
    for local_idx, pos in enumerate(row_positions):
        flow_id = extracted.flow_ids[pos]
        flow_stats = extracted.cic_df.iloc[pos]
        five_tuple = extracted.five_tuple_df.iloc[pos]
        result = _triage_one_flow(flow_stats, five_tuple, context)
        result.flow_id = flow_id
        results[flow_id] = result

    logger.info(
        "Tier 2.5: triaged %d anomalous flow(s) -> %s",
        len(results), dict(Counter(r.tentative_category for r in results.values())),
    )
    return results
