import os
import json
import pickle
import numpy as np
import pandas as pd
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, average_precision_score,
    classification_report
)

try:
    from subport_scrip.feature_mapping import map_label_to_family
except ImportError:
    map_label_to_family = None

DATA_DIR = r"D:\pjb2\dashboard\backend\Dataset\Mapped_Dataset"
MODEL_DIR = r"D:\pjb2\dashboard\backend\models"

print("📥 กำลังโหลดข้อมูล test_dataset.csv...")
test_df = pd.read_csv(os.path.join(DATA_DIR, "test_dataset.csv"), low_memory=False)

if 'label' in test_df.columns and map_label_to_family is not None:
    test_df['Family'] = test_df['label'].apply(map_label_to_family)
elif 'label' in test_df.columns and 'Family' not in test_df.columns:
    test_df['Family'] = test_df['label']

# ==============================================================================
# 1. ISOLATION FOREST EVALUATION
# ==============================================================================
print("\n" + "="*50)
print("🌲 [1/2] ISOLATION FOREST EVALUATION")
print("="*50)

with open(os.path.join(MODEL_DIR, "anomaly_iso_forest.pkl"), "rb") as f:
    iso_model = pickle.load(f)

with open(os.path.join(MODEL_DIR, "anomaly_scaler.pkl"), "rb") as f:
    iso_scaler = pickle.load(f)

with open(os.path.join(MODEL_DIR, "anomaly_score_bounds.json"), "r", encoding="utf-8") as f:
    iso_bounds = json.load(f)

iso_features = iso_bounds.get("feature_columns", [])

X_iso = test_df.reindex(columns=iso_features, fill_value=0.0)
X_iso = X_iso.replace([np.inf, -np.inf], np.nan).fillna(0.0)
X_iso = X_iso.apply(pd.to_numeric, errors='coerce').fillna(0.0)

y_true_iso = np.where(test_df['Family'] == 'BENIGN', 0, 1)

X_iso_scaled = iso_scaler.transform(X_iso)
y_pred_iso_raw = iso_model.predict(X_iso_scaled)
y_pred_iso = np.where(y_pred_iso_raw == -1, 1, 0)
y_scores_iso = -iso_model.decision_function(X_iso_scaled)

tn, fp, fn, tp = confusion_matrix(y_true_iso, y_pred_iso).ravel()
precision_iso = precision_score(y_true_iso, y_pred_iso, zero_division=0)
recall_iso = recall_score(y_true_iso, y_pred_iso, zero_division=0)
f1_iso = f1_score(y_true_iso, y_pred_iso, zero_division=0)
fpr_iso = fp / (fp + tn) if (fp + tn) > 0 else 0.0
roc_auc_iso = roc_auc_score(y_true_iso, y_scores_iso)
pr_auc_iso = average_precision_score(y_true_iso, y_scores_iso)

print(f"Precision : {precision_iso:.4f}")
print(f"Recall    : {recall_iso:.4f}")
print(f"F1-Score  : {f1_iso:.4f}")
print(f"FPR       : {fpr_iso:.4f}")
print(f"ROC-AUC   : {roc_auc_iso:.4f}")
print(f"PR-AUC    : {pr_auc_iso:.4f}")

# ==============================================================================
# 2. XGBOOST EVALUATION
# ==============================================================================
print("\n" + "="*50)
print("⚡ [2/2] XGBOOST EVALUATION")
print("="*50)

xgb_model = XGBClassifier()
xgb_model.load_model(os.path.join(MODEL_DIR, "model_cic.json"))

with open(os.path.join(MODEL_DIR, "le_cic.pkl"), "rb") as f:
    le_cic = pickle.load(f)

with open(os.path.join(MODEL_DIR, "feature_schema_cic.json"), "r", encoding="utf-8") as f:
    feature_schema_data = json.load(f)
    if isinstance(feature_schema_data, dict):
        xgb_features = feature_schema_data.get("feature_columns", feature_schema_data.get("feature_names", []))
    else:
        xgb_features = feature_schema_data

X_xgb = test_df.reindex(columns=xgb_features, fill_value=0.0)
X_xgb = X_xgb.replace([np.inf, -np.inf], np.nan).fillna(0.0)
X_xgb = X_xgb.apply(pd.to_numeric, errors='coerce').fillna(0.0)

y_true_xgb = test_df['Family']

# กรองเอาเฉพาะ Class ที่อยู่ใน LabelEncoder
valid_mask = y_true_xgb.isin(le_cic.classes_)
X_xgb_valid = X_xgb[valid_mask]
y_true_xgb_valid = y_true_xgb[valid_mask]

y_true_xgb_encoded = le_cic.transform(y_true_xgb_valid)

# Predict
y_pred_xgb_encoded = xgb_model.predict(X_xgb_valid)

# คำนวณ Overall Metrics
acc_xgb = accuracy_score(y_true_xgb_encoded, y_pred_xgb_encoded)
macro_prec = precision_score(y_true_xgb_encoded, y_pred_xgb_encoded, average='macro', zero_division=0)
macro_rec = recall_score(y_true_xgb_encoded, y_pred_xgb_encoded, average='macro', zero_division=0)
macro_f1 = f1_score(y_true_xgb_encoded, y_pred_xgb_encoded, average='macro', zero_division=0)
weighted_f1 = f1_score(y_true_xgb_encoded, y_pred_xgb_encoded, average='weighted', zero_division=0)

# กำหนด Index คลาสทั้งหมด (0 ถึง N-1) เพื่อให้ Confusion Matrix บังคับสร้างครบ 9x9
all_class_indices = np.arange(len(le_cic.classes_))
cm_xgb = confusion_matrix(y_true_xgb_encoded, y_pred_xgb_encoded, labels=all_class_indices)

print(f"Overall Accuracy : {acc_xgb:.4f}")
print(f"Macro Precision  : {macro_prec:.4f}")
print(f"Macro Recall     : {macro_rec:.4f}")
print(f"Macro F1         : {macro_f1:.4f}")
print(f"Weighted F1      : {weighted_f1:.4f}")

print("\n--- Confusion Matrix ---")
cm_df = pd.DataFrame(cm_xgb, index=le_cic.classes_, columns=le_cic.classes_)
print(cm_df)

print("\n--- Per-Class Performance Report ---")
print(classification_report(
    y_true_xgb_encoded, 
    y_pred_xgb_encoded, 
    labels=all_class_indices, 
    target_names=le_cic.classes_, 
    digits=4, 
    zero_division=0
))