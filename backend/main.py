"""
main.py
-------
FastAPI backend + pipeline orchestrator.

Pipeline (per uploaded .pcap), FLOW-LEVEL Tier1/Tier2/Tier2.5/Tier3 cascade:
    1. extractor.py extracts every flow up front (cic_df + five_tuple_df).
    2. Tier 1 (Suricata) screens the whole file; matches are correlated back
       to specific flows by 5-tuple.
    3. Tier 2 (Anomaly Detection + XGBoost Cascade) processes unmatched flows:
       - Isolation Forest gates on deviation (normal vs anomalous).
       - If anomalous, XGBoost attempts to name a known family (confidence >= 0.85).
       - Flows are chronologically sorted and batched (10 flows per batch) to fit model dimensions.
    4. Tier 2.5 (Heuristic Triage) categorizes unclassified anomalies using metadata rules.
    5. Tier 3 (LLM Analyzer) explains verdicts and generates file-level summary.
"""

import argparse
import json
import logging
import os
import time
import uuid
from dataclasses import asdict
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings
from extractor import extract_features, ExtractedFlows, ExtractorError
from models.schemas import FeatureAttribution
from pipeline.llm_service import narrate
from pipeline.t1_suricata import run_tier1, SuricataMatch
from pipeline.t2_ml_classifier import run_tier2, VerdictRecord, ModelNotReadyError
from pipeline.t3_analyzer import analyze as run_tier3

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("main")


def _tuple_key(row, ip_only: bool = False) -> Tuple:
    ips = frozenset([str(row.get("src_ip", "") or ""), str(row.get("dst_ip", "") or "")])
    if ip_only:
        return (ips,)
    ports = frozenset([str(row.get("src_port", "") or ""), str(row.get("dst_port", "") or "")])
    return (ips, ports)


def correlate_signatures_with_flows(
    five_tuple_df: pd.DataFrame,
    matches: List[SuricataMatch],
) -> Dict[int, SuricataMatch]:
    if not matches or five_tuple_df is None or len(five_tuple_df) == 0:
        return {}

    flow_keys_full = {i: _tuple_key(row) for i, row in five_tuple_df.iterrows()}
    flow_keys_ip_only = {i: _tuple_key(row, ip_only=True) for i, row in five_tuple_df.iterrows()}

    matched: Dict[int, SuricataMatch] = {}
    for m in matches:
        has_ports = bool(m.src_port or m.dst_port)
        m_key_full = (frozenset([m.src_ip or "", m.dst_ip or ""]), frozenset([m.src_port or "", m.dst_port or ""]))
        m_key_ip = (frozenset([m.src_ip or "", m.dst_ip or ""]),)

        hit_row = None
        if has_ports and (m.src_ip or m.dst_ip):
            for row_idx, key in flow_keys_full.items():
                if row_idx not in matched and key == m_key_full:
                    hit_row = row_idx
                    break
        if hit_row is None and (m.src_ip or m.dst_ip):
            for row_idx, key in flow_keys_ip_only.items():
                if row_idx not in matched and key == m_key_ip:
                    hit_row = row_idx
                    break
        if hit_row is not None:
            matched[hit_row] = m

    return matched


class PipelineError(RuntimeError):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _chunk_flows_chronologically(extracted: ExtractedFlows, unmatched_positions: List[int], batch_size: int = 10) -> List[List[int]]:
    """
    Sorts unmatched flows chronologically and groups them into batches of fixed size (default 10 flows)
    to match feature dimension expectations for ML classification.
    """
    if not unmatched_positions:
        return []
    
    # Sort positions by start timestamp if available, otherwise by index order
    if hasattr(extracted, "cic_df") and "timestamp" in extracted.cic_df.columns:
        sorted_pos = sorted(unmatched_positions, key=lambda p: extracted.cic_df.iloc[p].get("timestamp", p))
    else:
        sorted_pos = sorted(unmatched_positions)

    # Chunk into batches of batch_size
    batches = [sorted_pos[i:i + batch_size] for i in range(0, len(sorted_pos), batch_size)]
    return batches


def run_pipeline_on_pcap(pcap_path: str) -> dict:
    logger.info("=== Processing %s ===", pcap_path)

    try:
        extracted = extract_features(pcap_path)
    except ExtractorError as exc:
        raise PipelineError(str(exc), status_code=422) from exc

    n_flows = len(extracted.cic_df)
    logger.info("Extracted %d flow(s) from %s", n_flows, pcap_path)

    t1_result = run_tier1(pcap_path)
    flow_to_match = correlate_signatures_with_flows(extracted.five_tuple_df, t1_result.matches)
    matched_positions = sorted(flow_to_match.keys())
    unmatched_positions = [i for i in range(n_flows) if i not in flow_to_match]

    logger.info(
        "Tier 1: %d/%d flow(s) matched a signature; %d forwarded to Tier 2/2.5.",
        len(matched_positions), n_flows, len(unmatched_positions),
    )

    tier1_verdicts: List[VerdictRecord] = []
    for pos in matched_positions:
        m = flow_to_match[pos]
        tup = extracted.five_tuple_df.iloc[pos]

        # ดึง All Features สำหรับ Tier 1 Flow เพื่อแสดงผลบน UI
        raw_feats = extracted.cic_df.iloc[pos].to_dict() if hasattr(extracted, "cic_df") and pos < len(extracted.cic_df) else {}
        flow_feats = {}
        for k, v in raw_feats.items():
            if pd.isna(v):
                flow_feats[str(k)] = 0
            elif isinstance(v, (int, float, np.number)):
                if np.isinf(v):
                    flow_feats[str(k)] = 0
                elif isinstance(v, (np.integer, int)):
                    flow_feats[str(k)] = int(v)
                else:
                    flow_feats[str(k)] = round(float(v), 4)
            else:
                flow_feats[str(k)] = str(v)

        tier1_verdicts.append(VerdictRecord(
            flow_id=extracted.flow_ids[pos],
            src_ip=tup.get("src_ip", ""), dst_ip=tup.get("dst_ip", ""),
            src_port=tup.get("src_port", ""), dst_port=tup.get("dst_port", ""),
            protocol=tup.get("protocol", ""),
            source="rule", attack_type=m.attack_type, confidence=m.confidence,
            severity_label=m.severity_label, risk_score=m.risk_score,
            evidence=list(m.evidence), is_attack=True,
            detection_tier="tier1",
            rule_id=m.rule_id, rule_category=m.category, rule_severity=m.severity,
            features=flow_feats,
            top_features=[],
        ))

    tier2_verdicts: List[VerdictRecord] = []
    if unmatched_positions:
        try:
            flow_batches = _chunk_flows_chronologically(extracted, unmatched_positions, batch_size=10)
            for batch_pos in flow_batches:
                batch_verdicts = run_tier2(extracted, row_positions=batch_pos)
                tier2_verdicts.extend(batch_verdicts)
        except ModelNotReadyError as exc:
            raise PipelineError(str(exc), status_code=503) from exc
    else:
        logger.info("No unmatched flows remain — Tier 2 skipped entirely.")

    all_verdicts = tier1_verdicts + tier2_verdicts
    tier3_report = run_tier3(all_verdicts)

    # ------------------------------------------------------------------
    #  ประมวลผล Gemini LLM Narrative
    # ------------------------------------------------------------------
    attack_verdicts = [v for v in all_verdicts if v.is_attack]
    if attack_verdicts:
        top_v = max(attack_verdicts, key=lambda x: (x.risk_score, x.confidence))
        top_attack_type = top_v.attack_type
        top_confidence = float(top_v.confidence)
        
        # ดึง Top Features ของ Flow ที่เสี่ยงที่สุดส่งให้ Gemini LLM Narrative
        if getattr(top_v, "top_features", None):
            top_features = [
                FeatureAttribution(
                    name=item.get("name", ""),
                    importance=float(item.get("importance", 0.0)),
                    value=str(item.get("value", ""))
                )
                for item in top_v.top_features[:3]
            ]
        else:
            top_features = [
                FeatureAttribution(name="Protocol", importance=0.95, value=str(top_v.protocol)),
                FeatureAttribution(name="Dst Port", importance=0.88, value=str(top_v.dst_port)),
                FeatureAttribution(name="Risk Score", importance=0.82, value=str(top_v.risk_score)),
            ]
    else:
        top_attack_type = "BENIGN"
        top_confidence = 1.0
        top_features = []

    try:
        llm_res = narrate(
            attack_type=top_attack_type,
            confidence=top_confidence,
            features=top_features
        )
        llm_dict = {
            "summary": llm_res.summary,
            "recommendedAction": llm_res.recommendedAction,
            "status": llm_res.status,
            "model": llm_res.model,
        }
    except Exception as exc:
        logger.error("LLM Narrative generation failed: %s", exc)
        llm_dict = {
            "summary": "เกิดข้อผิดพลาดในการดึงข้อมูลจาก Gemini LLM",
            "recommendedAction": "โปรดตรวจสอบ API Key หรือ Logs บน Backend",
        }

    def _clean_types(obj):
        if isinstance(obj, np.integer):
            return int(obj)
        elif isinstance(obj, np.floating):
            return float(obj)
        elif isinstance(obj, dict):
            return {k: _clean_types(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [_clean_types(item) for item in obj]
        return obj

    result = {
        "status": "success",
        "pcap": os.path.basename(pcap_path),
        "flows": int(n_flows),
        "tier1": {
            "mode": t1_result.mode,
            "warning": t1_result.warning,
            "flows_matched": int(len(matched_positions)),
            "matches": [asdict(m) for m in t1_result.matches],
        },
        "tier2": {
            "flows_forwarded": int(len(unmatched_positions)),
        },
        "tier3": {
            "llm_mode": tier3_report.llm_mode,
            "benign_summary": tier3_report.benign_summary,
        },
        "summary": _clean_types(tier3_report.file_summary),
        "attack_distribution": _clean_types(tier3_report.file_summary.get("attack_distribution", {})),
        "detections": [asdict(d) for d in tier3_report.detections],
        "llm_narrative": _clean_types(llm_dict),
    }
    return _clean_types(result)


def _save_result(result: dict) -> str:
    result_id = uuid.uuid4().hex[:12]
    result["result_id"] = result_id
    result["generated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    path = os.path.join(settings.results_dir, f"{result_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False, default=str)
    return result_id


app = FastAPI(title="Network Attack Detection API", version="1.0.0")

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)


@app.get("/api/health")
def health_check():
    model_ready = os.path.exists(settings.model_cic_path) and os.path.exists(settings.label_encoder_cic_path)
    return {
        "status": "ok",
        "model_ready": model_ready,
        "suricata_configured": bool(settings.suricata_bin),
    }


@app.post("/api/analyze-pcap")
async def analyze_pcap(file: UploadFile = File(...)):
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in settings.allowed_upload_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type '{ext}'. Allowed: {sorted(settings.allowed_upload_extensions)}",
        )

    upload_id = uuid.uuid4().hex[:12]
    saved_path = os.path.join(settings.uploads_dir, f"{upload_id}{ext}")
    contents = await file.read()
    if len(contents) > settings.max_upload_mb * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File exceeds {settings.max_upload_mb}MB limit.")
    with open(saved_path, "wb") as f:
        f.write(contents)

    try:
        result = run_pipeline_on_pcap(saved_path)
    except PipelineError as exc:
        return JSONResponse(
            status_code=exc.status_code,
            content={"status": "error", "message": str(exc)},
        )
    except Exception as exc:
        logger.exception("Unexpected pipeline failure for %s", saved_path)
        return JSONResponse(
            status_code=500,
            content={"status": "error", "message": f"Unexpected error: {exc}"},
        )

    result_id = _save_result(result)
    result["result_id"] = result_id
    return result


@app.get("/api/detection-result/{result_id}")
def get_detection_result(result_id: str):
    path = os.path.join(settings.results_dir, f"{result_id}.json")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"No result found for id '{result_id}'.")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _cli():
    parser = argparse.ArgumentParser(description="Network Attack Detection backend.")
    parser.add_argument("--pcap", help="Run the pipeline once on this .pcap and print JSON, then exit.")
    parser.add_argument("--host", default=settings.api_host)
    parser.add_argument("--port", type=int, default=settings.api_port)
    args = parser.parse_args()

    if args.pcap:
        try:
            result = run_pipeline_on_pcap(args.pcap)
        except PipelineError as exc:
            print(json.dumps({"status": "error", "message": str(exc)}, indent=2, ensure_ascii=False))
            raise SystemExit(1)
        result_id = _save_result(result)
        result["result_id"] = result_id
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    else:
        import uvicorn
        uvicorn.run("main:app", host=args.host, port=args.port, reload=False)


if __name__ == "__main__":
    _cli()