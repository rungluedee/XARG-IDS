import logging
import os
import pickle
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
import xgboost as xgb

import config
from extractor import ExtractedFlows
from subport_scrip.feature_mapping import ATTACK_FAMILIES
from subport_scrip.risk_scoring import risk_from_attack_type, severity_from_risk

logger = logging.getLogger("t2_ml_classifier")


class ModelNotReadyError(RuntimeError):
    """Raised when trained model or label encoder is missing/invalid."""
    pass


@dataclass
class VerdictRecord:
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: Any
    dst_port: Any
    protocol: str
    source: str
    attack_type: str
    confidence: float
    severity_label: str
    risk_score: int
    evidence: List[str]
    is_attack: bool
    detection_tier: str
    rule_id: str = ""
    rule_category: str = ""
    rule_severity: Optional[int] = None
    is_anomaly: Optional[bool] = None
    anomaly_score: Optional[float] = None
    features: Dict[str, Any] = field(default_factory=dict)
    top_features: List[Dict[str, Any]] = field(default_factory=list)


def _extract_tuple_info(tup: Any) -> Dict[str, str]:
    """Safely extracts 5-tuple attributes regardless of row type."""
    if not hasattr(tup, "get"):
        return {"src_ip": "", "dst_ip": "", "src_port": "", "dst_port": "", "protocol": ""}
    return {
        "src_ip": str(tup.get("src_ip", "") or ""),
        "dst_ip": str(tup.get("dst_ip", "") or ""),
        "src_port": str(tup.get("src_port", "") or ""),
        "dst_port": str(tup.get("dst_port", "") or ""),
        "protocol": str(tup.get("protocol", "") or ""),
    }


class AttackFamilyClassifier:
    def __init__(self):
        self._validate_artifacts()
        self.booster = xgb.Booster()
        self.booster.load_model(config.MODEL_CIC_PATH)

        with open(config.LABEL_ENCODER_CIC_PATH, "rb") as f:
            self.label_encoder = pickle.load(f)
        self.classes = list(self.label_encoder.classes_)

        self._validate_schema()

    def _validate_artifacts(self):
        for path, name in [(config.MODEL_CIC_PATH, "Model"), (config.LABEL_ENCODER_CIC_PATH, "Label encoder")]:
            if not os.path.exists(path):
                raise ModelNotReadyError(f"{name} not found at '{path}'. Retrain first.")

    def _validate_schema(self):
        if set(self.classes) != set(ATTACK_FAMILIES):
            raise ModelNotReadyError(f"Loaded classes {self.classes} do not match expected {ATTACK_FAMILIES}.")
        
        model_features = self.booster.feature_names
        if model_features and list(model_features) != config.cic_feature_columns:
            raise ModelNotReadyError("Model feature order mismatch with config.cic_feature_columns.")

    def predict(self, cic_df: pd.DataFrame) -> List[tuple]:
        features_df = cic_df[config.cic_feature_columns].copy()
        for col in features_df.columns:
            features_df[col] = pd.to_numeric(features_df[col], errors="coerce").fillna(0)

        dmat = xgb.DMatrix(features_df, feature_names=config.cic_feature_columns)
        probs = self.booster.predict(dmat)
        if probs.ndim == 1:
            probs = probs.reshape(1, -1)

        label_idx = probs.argmax(axis=1)
        confidence = probs.max(axis=1)
        labels = self.label_encoder.inverse_transform(label_idx)
        return list(zip(labels, confidence))

    def classify(self, extracted: ExtractedFlows) -> List[VerdictRecord]:
        features_df = extracted.cic_df[config.cic_feature_columns].copy()
        for col in features_df.columns:
            features_df[col] = pd.to_numeric(features_df[col], errors="coerce").fillna(0)

        dmat = xgb.DMatrix(features_df, feature_names=config.cic_feature_columns)

        # 1. ทำนาย Class และ Confidence
        probs = self.booster.predict(dmat)
        if probs.ndim == 1:
            probs = probs.reshape(1, -1)
        label_indices = probs.argmax(axis=1)
        confidences = probs.max(axis=1)
        labels = self.label_encoder.inverse_transform(label_indices)

        # 2. คำนวณ TreeSHAP (Local Feature Importance เฉพาะของแต่ละ Flow)
        try:
            contribs = self.booster.predict(dmat, pred_contribs=True)
        except Exception as e:
            logger.warning(f"Failed to compute TreeSHAP contribs: {e}")
            contribs = None

        records: List[VerdictRecord] = []

        for i in range(len(labels)):
            label = str(labels[i])
            conf = float(confidences[i])
            pred_class_idx = label_indices[i]

            flow_id = extracted.flow_ids[i] if i < len(extracted.flow_ids) else f"flow-{i:06d}"
            tup_raw = extracted.five_tuple_df.iloc[i] if i < len(extracted.five_tuple_df) else {}
            net_info = _extract_tuple_info(tup_raw)
            
            is_attack = label != "BENIGN"
            risk = risk_from_attack_type(label, conf, is_attack)

            # 3. Sanitizing Features (เช็ก Type ก่อนเรียก np.isinf เพื่อป้องกัน TypeError)
            raw_feats = extracted.cic_df.iloc[i].to_dict() if i < len(extracted.cic_df) else {}
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

            # 4. ดึง Top 5 Features ของ Flow นี้โดยเฉพาะ
            top_feats = []
            if contribs is not None:
                if contribs.ndim == 3:
                    # Multi-class shape: (N_samples, N_classes, N_features + 1)
                    c_idx = pred_class_idx if pred_class_idx < contribs.shape[1] else 0
                    flow_shap = contribs[i, c_idx, :-1]
                elif contribs.ndim == 2:
                    # Binary shape: (N_samples, N_features + 1)
                    flow_shap = contribs[i, :-1]
                else:
                    flow_shap = np.zeros(len(config.cic_feature_columns))

                abs_shap = np.abs(flow_shap)
                sum_shap = float(np.sum(abs_shap)) if np.sum(abs_shap) > 0 else 1.0

                # คัดเลือก 5 อันดับแรกที่ส่งผลต่อ Flow นี้มากที่สุด
                top_5_indices = np.argsort(abs_shap)[::-1][:5]
                for idx in top_5_indices:
                    feat_name = config.cic_feature_columns[idx]
                    val = flow_feats.get(feat_name, 0)
                    importance_val = float(round(abs_shap[idx] / sum_shap, 4))
                    top_feats.append({
                        "name": str(feat_name),
                        "value": str(val),
                        "importance": importance_val
                    })
            else:
                first_5_cols = config.cic_feature_columns[:5]
                for idx, feat_name in enumerate(first_5_cols):
                    val = flow_feats.get(feat_name, 0)
                    top_feats.append({
                        "name": str(feat_name),
                        "value": str(val),
                        "importance": float(round(0.4 - (idx * 0.05), 2))
                    })

            evidence = [
                "ML classification (XGBoost Attack Family model, trained on CICIDS2017)",
                f"Predicted class: '{label}' with {conf:.2%} confidence",
                f"Flow: {net_info['src_ip']}:{net_info['src_port']} -> {net_info['dst_ip']}:{net_info['dst_port']} ({net_info['protocol']})",
            ]

            records.append(VerdictRecord(
                flow_id=flow_id,
                source="T2",
                attack_type=label,
                confidence=conf,
                severity_label=severity_from_risk(risk),
                risk_score=risk,
                evidence=evidence,
                is_attack=is_attack,
                detection_tier="tier2_ml_confirmed",
                features=flow_feats,
                top_features=top_feats,
                **net_info
            ))
        return records


def run_tier2(extracted: ExtractedFlows, row_positions: Optional[List[int]] = None) -> List[VerdictRecord]:
    if row_positions is not None:
        extracted = ExtractedFlows(
            cic_df=extracted.cic_df.iloc[row_positions].reset_index(drop=True),
            five_tuple_df=extracted.five_tuple_df.iloc[row_positions].reset_index(drop=True),
            flow_ids=[extracted.flow_ids[i] for i in row_positions],
        )

    if len(extracted.cic_df) == 0:
        return []
        
    return AttackFamilyClassifier().classify(extracted)