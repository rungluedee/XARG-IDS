"""
extractor.py
------------
Feature extraction layer using NFStream (PRODUCTION MODE).

Backend: `nfstream` converts a raw .pcap into bidirectional flow records.
Provides a stable, high-performance alternative to cicflowmeter on Windows.
Guarantees:
  * cic_df has EXACTLY config.cic_feature_columns (78 cols) PLUS Timestamp, in that order
  * No NaN / Inf values reach the model (zero-filled)
  * A parallel 5-tuple DataFrame (same row order) is always returned
"""

import logging
import os
from dataclasses import dataclass, field
from typing import List

import numpy as np
import pandas as pd

import config
from subport_scrip.feature_mapping import apply_feature_aliases, apply_duplicate_columns

logger = logging.getLogger("extractor")

try:
    from nfstream import NFStreamer
    NFSTREAM_AVAILABLE = True
except Exception:
    NFSTREAM_AVAILABLE = False


class ExtractorError(RuntimeError):
    """Raised when .pcap -> flow-feature extraction cannot be completed."""
    pass


@dataclass
class ExtractedFlows:
    """Container returned by extract_features()."""
    cic_df: pd.DataFrame
    five_tuple_df: pd.DataFrame
    flow_ids: list = field(default_factory=list)


def _align_to_schema(df: pd.DataFrame, schema_columns: List[str]) -> pd.DataFrame:
    """Strict Schema Alignment against config.cic_feature_columns."""
    missing = [c for c in schema_columns if c not in df.columns]
    if missing:
        logger.warning(
            "extractor: %d/%d schema column(s) not found in NFStream output "
            "and were zero-filled: %s.",
            len(missing), len(schema_columns), missing,
        )

    aligned = pd.DataFrame(index=df.index)
    for col in schema_columns:
        if col in df.columns:
            aligned[col] = pd.to_numeric(df[col], errors="coerce")
        else:
            aligned[col] = 0.0

    aligned = aligned.replace([np.inf, -np.inf], 0.0)
    aligned = aligned.fillna(0.0)
    return aligned[schema_columns]


def _extract_five_tuple(raw_df: pd.DataFrame) -> pd.DataFrame:
    aliases = {
        "src_ip": ["src_ip", "Src IP", "Source IP", "src_ip"],
        "dst_ip": ["dst_ip", "Dst IP", "Destination IP", "dst_ip"],
        "src_port": ["src_port", "Src Port", "Source Port", "src_port"],
        "dst_port": ["dst_port", "Dst Port", "Destination Port", "dst_port"],
        "protocol": ["protocol", "proto", "Protocol", "protocol"],
    }
    five_tuple = pd.DataFrame(index=raw_df.index)
    for canonical, candidates in aliases.items():
        found = next((c for c in candidates if c in raw_df.columns), None)
        five_tuple[canonical] = raw_df[found] if found is not None else ""
    return five_tuple


def _run_nfstream(pcap_path: str) -> pd.DataFrame:
    """
    Invokes NFStreamer against the pcap and converts flows to a Pandas DataFrame.
    """
    try:
        # เปิดใช้งาน statistical_analysis เพื่อดึงสถิติต่างๆ ครบถ้วน
        streamer = NFStreamer(source=pcap_path, statistical_analysis=True)
        raw_df = streamer.to_pandas()
    except Exception as exc:
        raise ExtractorError(
            f"NFStream failed to process '{pcap_path}': {type(exc).__name__}: {exc}"
        ) from exc

    if raw_df is None or raw_df.empty:
        raise ExtractorError(
            f"NFStream produced an empty flow table for '{pcap_path}' (0 flows)."
        )

    return raw_df


def extract_features(pcap_path: str) -> ExtractedFlows:
    """Main entry point used by main.py."""
    if not os.path.exists(pcap_path):
        raise ExtractorError(f"PCAP file not found: '{pcap_path}'")

    if not NFSTREAM_AVAILABLE:
        raise ExtractorError(
            "nfstream is not installed in this environment. Install it with `pip install nfstream`."
        )

    raw_df = _run_nfstream(pcap_path)

    # แปลงชื่อคอลัมน์ของ NFStream ให้เข้ากับระบบตั้งต้น (เช่น mapping ชื่อฟิลด์ 5-tuple และเวลา)
    # NFStream ใช้ชื่อคอลัมน์มาตรฐาน เช่น src_ip, dst_ip, src_port, dst_port, protocol, bidirection_packets_s เป็นต้น
    # เราทำการ mapping ชื่อคอลัมน์ให้ตรงกับที่ feature_mapping และ config คาดหวัง
    
    # Mapping เบื้องต้นสำหรับคอลัมน์เวลาและพารามิเตอร์หลัก
    if "bidirectional_first_seen_ms" in raw_df.columns:
        # แปลง milliseconds timestamp เป็นรูปแบบวันที่/เวลา 문자열 ตามที่ _parse_timestamp ใน time_window.py รองรับ
        raw_df["Timestamp"] = pd.to_datetime(raw_df["bidirectional_first_seen_ms"], unit="ms").dt.strftime("%d/%m/%Y %H:%M:%S")
    else:
        raw_df["Timestamp"] = pd.Timestamp.now().strftime("%d/%m/%Y %H:%M:%S")

    # Map ชื่อคอลัมน์ของ nfstream ให้เข้ากับ alias ที่ระบบมีอยู่แล้ว
    column_mapping = {
        "src_ip": "Src IP",
        "dst_ip": "Destination IP",
        "src_port": "Src Port",
        "dst_port": "Destination Port",
        "protocol": "Protocol",
        "bidirectional_packets_s": "Flow Packets/s",
        "bidirectional_bytes_s": "Flow Bytes/s",
    }
    raw_df = raw_df.rename(columns=column_mapping)

    five_tuple_df = _extract_five_tuple(raw_df)

    # ทำการ apply aliases และ duplicate ตามโครงสร้างเดิม
    raw_df = apply_feature_aliases(raw_df)
    raw_df = apply_duplicate_columns(raw_df)

    cic_df = _align_to_schema(raw_df, config.cic_feature_columns)
    cic_df["Timestamp"] = raw_df["Timestamp"]

    assert not cic_df.drop(columns=["Timestamp"]).isnull().values.any(), "NaN leaked into cic_df after alignment"
    assert not np.isinf(cic_df.drop(columns=["Timestamp"]).values).any(), "Inf leaked into cic_df after alignment"

    flow_ids = [f"flow-{i:06d}" for i in range(len(cic_df))]

    logger.info("NFStream extracted and aligned %d flow(s) from %s", len(cic_df), pcap_path)
    return ExtractedFlows(cic_df=cic_df, five_tuple_df=five_tuple_df, flow_ids=flow_ids)


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    target = sys.argv[1] if len(sys.argv) > 1 else "sample.pcap"
    result = extract_features(target)
    print(f"CIC shape: {result.cic_df.shape}")
    print(result.five_tuple_df.head())