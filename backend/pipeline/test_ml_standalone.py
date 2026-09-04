import os
import json
import joblib
import pandas as pd
import numpy as np
import xgboost as xgb

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", "models"))

print(f"📁 Loading models from: {MODELS_DIR}\n")

iso_forest_path = os.path.join(MODELS_DIR, "anomaly_iso_forest.pkl")
scaler_path = os.path.join(MODELS_DIR, "anomaly_scaler.pkl")
xgb_model_path = os.path.join(MODELS_DIR, "model_cic.json")
le_path = os.path.join(MODELS_DIR, "le_cic.pkl")

# 1. ดึง Feature Names จาก Scaler หรือ Schema
feature_names = []
if os.path.exists(scaler_path):
    scaler = joblib.load(scaler_path)
    if hasattr(scaler, "feature_names_in_"):
        feature_names = list(scaler.feature_names_in_)

if not feature_names:
    schema_path = os.path.join(MODELS_DIR, "feature_schema_cic.json")
    if os.path.exists(schema_path):
        with open(schema_path, "r", encoding="utf-8") as f:
            schema_data = json.load(f)
            if isinstance(schema_data, list):
                feature_names = schema_data
            elif isinstance(schema_data, dict):
                feature_names = schema_data.get("feature_names", schema_data.get("features", []))

print(f"📋 Found {len(feature_names)} features.")

if len(feature_names) == 0:
    print("❌ Error: ไม่พบรายชื่อ Feature กรุณาตรวจสอบไฟล์ anomaly_scaler.pkl หรือ feature_schema_cic.json")
    exit(1)

# 2. จำลองข้อมูล 1 Row (กำหนด Type เป็น float64)
mock_data = {feat: [0.0] for feat in feature_names}

for key in mock_data:
    if "PORT" in key.upper(): mock_data[key] = [80.0]
    elif "DURATION" in key.upper(): mock_data[key] = [1500.0]
    elif "PACKET" in key.upper(): mock_data[key] = [20.0]

df_input = pd.DataFrame(mock_data, dtype=np.float64)

# ==========================================
# 🧪 TEST 1: Isolation Forest (Tier 2 Anomaly Detection)
# ==========================================
print("\n=== 1. Testing Isolation Forest (Tier 2) ===")
if os.path.exists(iso_forest_path) and os.path.exists(scaler_path):
    X_scaled = scaler.transform(df_input)
    X_scaled_df = pd.DataFrame(X_scaled, columns=feature_names)
    
    iso_model = joblib.load(iso_forest_path)
    iso_pred = iso_model.predict(X_scaled_df.values)
    iso_score = iso_model.decision_function(X_scaled_df.values)[0]

    result_label = "Anomaly (ส่งต่อ Tier 3)" if iso_pred[0] == -1 else "Normal (Benign)"
    print(f"  [+] Isolation Forest Prediction : {iso_pred[0]} -> {result_label}")
    print(f"  [+] Anomaly Score              : {iso_score:.4f}")
else:
    print("  [-] ไม่พบไฟล์โมเดล Isolation Forest")

# ==========================================
# 🧪 TEST 2: XGBoost Multi-class (Tier 3 Classification)
# ==========================================
print("\n=== 2. Testing XGBoost Classifier (Tier 3) ===")
if os.path.exists(xgb_model_path) and os.path.exists(le_path):
    xgb_model = xgb.XGBClassifier()
    xgb_model.load_model(xgb_model_path)
    label_encoder = joblib.load(le_path)

    xgb_pred = xgb_model.predict(df_input)
    xgb_probs = xgb_model.predict_proba(df_input)

    attack_type = label_encoder.inverse_transform(xgb_pred)[0]
    confidence = np.max(xgb_probs) * 100

    print(f"  [+] Predicted Attack Type       : {attack_type}")
    print(f"  [+] Confidence Score           : {confidence:.2f}%")
else:
    print("  [-] ไม่พบไฟล์ model_cic.json หรือ le_cic.pkl")