import json
import logging
import os
import pickle
from dataclasses import dataclass
from typing import List, Optional

import numpy as np
import pandas as pd

import config
from extractor import ExtractedFlows

logger = logging.getLogger("t2_anomaly_detector")


class AnomalyModelNotReadyError(RuntimeError):
    """Raised when anomaly detection artifacts are missing or invalid."""
    pass


@dataclass
class AnomalyResult:
    flow_id: str
    is_anomaly: bool
    anomaly_score: float
    raw_score: float


class AnomalyDetector:
    def __init__(self):
        self._validate_and_load_artifacts()

    def _validate_and_load_artifacts(self):
        required_files = [
            (config.ANOMALY_MODEL_PATH, "Isolation Forest model"),
            (config.ANOMALY_SCALER_PATH, "Feature scaler"),
            (config.ANOMALY_SCORE_BOUNDS_PATH, "Score bounds"),
        ]
        for path, desc in required_files:
            if not os.path.exists(path):
                raise AnomalyModelNotReadyError(f"{desc} missing at '{path}'. Run training script first.")

        with open(config.ANOMALY_MODEL_PATH, "rb") as f:
            self.model = pickle.load(f)
        with open(config.ANOMALY_SCALER_PATH, "rb") as f:
            self.scaler = pickle.load(f)
        with open(config.ANOMALY_SCORE_BOUNDS_PATH, "r", encoding="utf-8") as f:
            bounds = json.load(f)

        self.score_low = bounds["p1"]
        self.score_high = bounds["p99"]
        
        if self.score_high <= self.score_low:
            raise AnomalyModelNotReadyError("Invalid score bounds: p99 <= p1.")

    def _normalize_score(self, raw_scores: np.ndarray) -> np.ndarray:
        span = self.score_high - self.score_low
        normalized = (self.score_high - raw_scores) / span * 100.0
        return np.clip(normalized, 0.0, 100.0)

    def detect(self, cic_df: pd.DataFrame) -> List[AnomalyResult]:
        scaled = self.scaler.transform(cic_df.values)
        raw_scores = self.model.decision_function(scaled)
        anomaly_scores = self._normalize_score(raw_scores)

        return [
            AnomalyResult(
                flow_id="",
                is_anomaly=bool(score >= config.ANOMALY_SCORE_THRESHOLD),
                anomaly_score=float(score),
                raw_score=float(raw),
            )
            for score, raw in zip(anomaly_scores, raw_scores)
        ]


def run_tier2_anomaly(extracted: ExtractedFlows, row_positions: Optional[List[int]] = None) -> List[AnomalyResult]:
    if row_positions is not None:
        cic_df = extracted.cic_df.iloc[row_positions].reset_index(drop=True)
        flow_ids = [extracted.flow_ids[i] for i in row_positions]
    else:
        cic_df, flow_ids = extracted.cic_df, extracted.flow_ids

    if len(cic_df) == 0:
        return []

    results = AnomalyDetector().detect(cic_df)
    for res, flow_id in zip(results, flow_ids):
        res.flow_id = flow_id
    return results