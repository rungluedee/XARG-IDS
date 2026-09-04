import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

import config
from subport_scrip.risk_scoring import risk_from_suricata_severity, severity_from_risk

logger = logging.getLogger("t1_suricata")

# Constants
UNKNOWN_LABEL = "UNKNOWN"
DEFAULT_SEVERITY = 3

_CATEGORY_TO_ATTACK_TYPE = {
    "a network trojan was detected": "Botnet",
    "a client was infected by a trojan and is attempting to infect other hosts": "Botnet",
    "detection of a network scan": "PortScan",
    "attempted denial of service": "DoS",
    "denial of service": "DoS",
    "web application attack": "WebAttack",
}

_KEYWORD_RULES = [
    ("DDoS", [r"\bddos\b", r"distributed denial of service"]),
    ("DoS", [r"\bdos\b", r"denial of service"]),
    ("PortScan", [r"\bportscan\b", r"port scan", r"\bnmap\b", r"\bscan\b"]),
    ("BruteForce", [r"brute[\s-]?force", r"credential stuffing", r"login attack", r"ftp[-_\s]?patator", r"ssh[-_\s]?patator"]),
    ("WebAttack", [r"sql injection", r"\bsqli\b", r"cross[\s-]?site scripting", r"\bxss\b", r"web attack"]),
    ("Heartbleed", [r"heartbleed"]),
    ("Infiltration", [r"\binfiltration\b"]),
    ("Botnet", [r"command\s*(and|&)\s*control", r"\bc2\b", r"\bcnc\b", r"\btrojan\b", r"\bbotnet\b", r"\bbackdoor\b", r"\brat\b"]),
]


def map_suricata_alert_to_attack_type(category: str, signature: str) -> str:
    """Maps a Suricata alert's category/signature to an attack_type."""
    normalized_category = (category or "").strip().lower()
    if normalized_category in _CATEGORY_TO_ATTACK_TYPE:
        return _CATEGORY_TO_ATTACK_TYPE[normalized_category]

    text = f"{category or ''} {signature or ''}".lower()
    for attack_type, patterns in _KEYWORD_RULES:
        if any(re.search(p, text) for p in patterns):
            return attack_type

    return UNKNOWN_LABEL


@dataclass
class SuricataMatch:
    signature: str
    category: str
    severity: int
    src_ip: str = ""
    dst_ip: str = ""
    proto: str = ""
    src_port: str = ""
    dst_port: str = ""
    rule_id: str = ""
    gid: str = ""
    rev: str = ""

    attack_type: str = UNKNOWN_LABEL
    confidence: float = 1.0
    risk_score: int = 0
    severity_label: str = "NONE"
    evidence: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.attack_type == UNKNOWN_LABEL and (self.category or self.signature):
            self.attack_type = map_suricata_alert_to_attack_type(self.category, self.signature)
        self.risk_score = risk_from_suricata_severity(self.severity)
        self.severity_label = severity_from_risk(self.risk_score)
        if not self.evidence:
            self.evidence = [
                f"Suricata signature match: '{self.signature}' (SID {self.rule_id or 'N/A'})",
                f"Category: {self.category or 'unknown'}",
                f"Flow: {self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} ({self.proto})",
            ]


@dataclass
class Tier1Result:
    pcap_path: str
    matched: bool
    matches: List[SuricataMatch] = field(default_factory=list)
    mode: str = "real"
    warning: Optional[str] = None


def _suricata_binary_available() -> bool:
    return bool(shutil.which(config.SURICATA_BIN))


def _parse_event_to_match(event: dict) -> Optional[SuricataMatch]:
    """Helper to safely transform an eve.json record into a SuricataMatch."""
    if event.get("event_type") != "alert":
        return None

    alert = event.get("alert", {})
    return SuricataMatch(
        signature=alert.get("signature", "unknown"),
        category=alert.get("category", "unknown"),
        severity=alert.get("severity", DEFAULT_SEVERITY),
        src_ip=event.get("src_ip", ""),
        dst_ip=event.get("dest_ip", ""),
        proto=event.get("proto", ""),
        src_port=str(event.get("src_port", "")),
        dst_port=str(event.get("dest_port", "")),
        rule_id=str(alert.get("signature_id", "")),
        gid=str(alert.get("gid", "")),
        rev=str(alert.get("rev", "")),
    )


def _parse_eve_json(eve_path: str) -> List[SuricataMatch]:
    matches: List[SuricataMatch] = []
    if not os.path.exists(eve_path):
        return matches

    with open(eve_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                match = _parse_event_to_match(event)
                if match:
                    matches.append(match)
            except json.JSONDecodeError:
                continue
    return matches


def _run_real_suricata(pcap_path: str) -> Tier1Result:
    os.makedirs(config.SURICATA_WORKDIR, exist_ok=True)
    binary = shutil.which(config.SURICATA_BIN)

    cmd = [binary, "-r", pcap_path, "-k", "none", "-l", config.SURICATA_WORKDIR]
    if os.path.exists(config.SURICATA_RULES_PATH):
        cmd += ["-S", config.SURICATA_RULES_PATH]
    else:
        logger.warning("Suricata rules file not found at '%s'", config.SURICATA_RULES_PATH)

    logger.info("Running Suricata offline: %s", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, timeout=600, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"suricata exited with code {proc.returncode}: {proc.stderr.strip()[:1000]}")

    eve_path = os.path.join(config.SURICATA_WORKDIR, "eve.json")
    matches = _parse_eve_json(eve_path)
    return Tier1Result(pcap_path=pcap_path, matched=bool(matches), matches=matches, mode="real")


def run_tier1(pcap_path: str) -> Tier1Result:
    if not _suricata_binary_available():
        msg = f"Suricata binary '{config.SURICATA_BIN}' not found on PATH. Tier 1 disabled."
        logger.warning(msg)
        return Tier1Result(pcap_path=pcap_path, matched=False, matches=[], mode="unavailable", warning=msg)

    try:
        return _run_real_suricata(pcap_path)
    except Exception as exc:
        msg = f"Suricata run failed on '{pcap_path}': {exc}. Tier 1 disabled."
        logger.error(msg)
        return Tier1Result(pcap_path=pcap_path, matched=False, matches=[], mode="unavailable", warning=msg)