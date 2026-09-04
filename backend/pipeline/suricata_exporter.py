import json
import logging
from collections import defaultdict
from typing import List, Dict, Any, Union
import pandas as pd

logger = logging.getLogger("suricata_exporter")

# ==============================================================================
# 1. Mapping Attack Type กับ Suricata Classtype
# ==============================================================================
CLASSTYPE_MAP = {
    "BruteForce": "attempted-recon",
    "FTP-Patator": "attempted-recon",
    "SSH-Patator": "attempted-recon",
    "WebScan": "web-application-attack",
    "Web Attack - SQL Injection": "web-application-attack",
    "Web Attack - XSS": "web-application-attack",
    "Web Attack - Brute Force": "web-application-attack",
    "DoS": "attempted-dos",
    "DoS attack": "attempted-dos",
    "DoS GoldenEye": "attempted-dos",
    "DoS Hulk": "attempted-dos",
    "DoS Slowloris": "attempted-dos",
    "DDoS": "attempted-dos",
    "PortScan": "attempted-recon",
    "Bot": "trojan-activity",
    "Infiltration": "successful-admin-compromise",
    "Heartbleed": "attempted-admin",
}

def normalize_protocol(proto: Union[str, int, None]) -> str:
    """แปลง Protocol ตัวเลขให้เป็นข้อความที่ Suricata รองรับ (tcp, udp, icmp, ip)"""
    if proto is None:
        return "ip"
    proto_str = str(proto).lower().strip()
    if proto_str in ["6", "tcp"]:
        return "tcp"
    elif proto_str in ["17", "udp"]:
        return "udp"
    elif proto_str in ["1", "icmp"]:
        return "icmp"
    return "ip"

# ==============================================================================
# 2. Pipeline Core Logic
# ==============================================================================

def export_df_to_json(result_df: pd.DataFrame, json_output_path: str = "detection_results.json") -> List[Dict[str, Any]]:
    """
    ขั้นตอนที่ 1: แปลง DataFrame เป็น JSON อย่างปลอดภัย (รองรับ NumPy types & NaN)
    """
    # ✅ FIX: ใช้ to_json() ของ pandas เพื่อแปลง NumPy types (int64, float64, NaN) ให้เป็น native JSON
    json_str = result_df.to_json(orient="records", date_format="iso")
    records = json.loads(json_str)

    with open(json_output_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2, ensure_ascii=False)

    logger.info("Saved %d flow records to '%s'", len(records), json_output_path)
    return records


def aggregate_flows(json_data: List[Dict[str, Any]], generalize_src_ip: bool = True) -> List[Dict[str, Any]]:
    """
    ขั้นตอนที่ 2: Flow Aggregation
    - กรองเฉพาะ flow ที่เป็น attack แท้จริง (ป้องกัน Benign หลุด)
    - ยุบ src_ip เป็น '$EXTERNAL_NET' เพื่อป้องกัน Rule งอกตามจำนวน IP
    - ยุบ dst_port ให้เป็น 'any' สำหรับ PortScan / Recon
    """
    grouped = defaultdict(lambda: {
        "count": 0,
        "conf_sum": 0.0,
        "max_risk": 0,
        "severities": set(),
        "flow_ids": [],
        "actual_src_ips": set()
    })

    for flow in json_data:
        attack_type = str(flow.get("attack_type", "")).strip()
        verdict = str(flow.get("verdict", "")).strip().lower()

        # ✅ FIX: กรองเฉพาะ Attack เท่านั้น ป้องกัน Benign / Normal หลุดไปสร้าง Rule
        is_attack_flag = flow.get("is_attack", False)
        if not is_attack_flag or verdict in ["benign", "normal"] or attack_type.lower() in ["benign", "normal", "0"]:
            continue

        raw_src_ip = flow.get("src_ip") or "any"
        # ✅ FIX: แปลง src_ip เป็น $EXTERNAL_NET เพื่อรวมการโจมตีจากหลาย IP เข้า 1 Rule
        src_ip = "$EXTERNAL_NET" if generalize_src_ip else raw_src_ip

        dst_ip = flow.get("dst_ip") or "any"
        proto = normalize_protocol(flow.get("protocol"))
        raw_dst_port = flow.get("dst_port") or "any"

        # ✅ FIX: บังคับให้ PortScan / Recon ใช้ dst_port = "any"
        is_scan = any(kw in attack_type.lower() for kw in ["portscan", "scan", "recon"])
        effective_dst_port = "any" if is_scan else raw_dst_port

        key = (src_ip, dst_ip, effective_dst_port, proto, attack_type)

        grouped[key]["count"] += 1
        grouped[key]["conf_sum"] += float(flow.get("confidence", 0.0))
        grouped[key]["max_risk"] = max(grouped[key]["max_risk"], int(flow.get("risk_score", 0)))
        if flow.get("severity"):
            grouped[key]["severities"].add(flow.get("severity"))
        if flow.get("flow_id"):
            grouped[key]["flow_ids"].append(flow.get("flow_id"))
        grouped[key]["actual_src_ips"].add(raw_src_ip)

    aggregated_results = []
    for (src_ip, dst_ip, dst_port, proto, attack_type), stats in grouped.items():
        avg_conf = stats["conf_sum"] / stats["count"]
        aggregated_results.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": proto,
            "attack_type": attack_type,
            "count": stats["count"],
            "avg_confidence": round(avg_conf, 4),
            "max_risk_score": stats["max_risk"],
            "severities": list(stats["severities"]),
            "flow_ids": stats["flow_ids"],
            "actual_src_ips": list(stats["actual_src_ips"])
        })

    logger.info("Aggregated attack flows into %d unique patterns.", len(aggregated_results))
    return aggregated_results


def generate_suricata_rules(
    aggregated_flows: List[Dict[str, Any]], 
    start_sid: int = 1000001,
    rule_output_path: str = "generated_attacks.rules"
) -> List[str]:
    """
    ขั้นตอนที่ 3: สร้าง Suricata Rules จากกลุ่ม Attack ที่ผ่าน Aggregation แล้ว
    """
    rules = []
    current_sid = start_sid

    for item in aggregated_flows:
        src_ip = item["src_ip"]
        dst_ip = item["dst_ip"]
        dst_port = item["dst_port"]
        proto = item["protocol"]
        attack_type = item["attack_type"]
        count = item["count"]

        # ✅ FIX: คำนวณ Confidence ไม่ให้หลุดไปเป็น 9500 (ถ้าสเกลเป็น 0.0-1.0 ให้คูณ 100)
        raw_conf = item["avg_confidence"]
        avg_conf = int(raw_conf * 100) if raw_conf <= 1.0 else int(raw_conf)
        risk = item["max_risk_score"]

        classtype = CLASSTYPE_MAP.get(attack_type, "bad-unknown")

        filter_clause = f"detection_filter:track by_src, count {count}, seconds 60; " if count > 1 else ""

        # ✅ FIX: established ใช้ได้เฉพาะ TCP เท่านั้น (UDP/ICMP ไม่รองรับ established)
        is_scan = any(kw in attack_type.lower() for kw in ["portscan", "scan", "recon"])
        if proto == "tcp":
            flow_option = "flow:to_server; " if is_scan else "flow:to_server,established; "
        elif proto == "udp":
            flow_option = "flow:to_server; "
        else:
            flow_option = ""

        rule_str = (
            f'alert {proto} {src_ip} any -> {dst_ip} {dst_port} ('
            f'msg:"AUTOMATED DETECTED {attack_type} Pattern"; '
            f'{flow_option}'
            f'{filter_clause}'
            f'metadata:confidence {avg_conf}, risk_score {risk}; '
            f'classtype:{classtype}; '
            f'sid:{current_sid}; rev:1;)'
        )
        rules.append(rule_str)
        current_sid += 1

    with open(rule_output_path, "w", encoding="utf-8") as f:
        f.write("# Automatically Generated Suricata Rules\n")
        f.write("\n".join(rules) + "\n")

    logger.info("Saved %d Suricata rules to '%s'", len(rules), rule_output_path)
    return rules