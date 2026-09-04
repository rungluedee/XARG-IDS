import os
import joblib
import pandas as pd
import numpy as np
import xgboost as xgb
from nfstream import NFStreamer

def main():
    CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
    MODELS_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", "models"))
    
    # 🎯 1. กำหนด Custom Decision Threshold สำหรับ Isolation Forest
    # - ค่าเริ่มต้น scikit-learn = 0.0 (เข้มงวดเกินไปสำหรับ Network Flow)
    # - ค่าแนะนำ = 0.25 (ครอบคลุม Traffic ที่มี Anomaly Score ติดลบจนถึง 0.24)
    CUSTOM_THRESHOLD = 0.25

    # ระบุ Path ไฟล์ PCAP ที่ต้องการทดสอบ
    PCAP_PATH = r"C:\Users\Lenovo\Downloads\blackEnergy.pcap"

    if not os.path.exists(PCAP_PATH):
        print(f"❌ ไม่พบไฟล์ PCAP ที่: {PCAP_PATH}")
        return

    # 2. โหลด Scaler และ Models
    scaler = joblib.load(os.path.join(MODELS_DIR, "anomaly_scaler.pkl"))
    iso_model = joblib.load(os.path.join(MODELS_DIR, "anomaly_iso_forest.pkl"))

    xgb_model = xgb.XGBClassifier()
    xgb_model.load_model(os.path.join(MODELS_DIR, "model_cic.json"))
    label_encoder = joblib.load(os.path.join(MODELS_DIR, "le_cic.pkl"))

    feature_names = list(scaler.feature_names_in_)

    # 3. ดึงข้อมูล Flows จากไฟล์ PCAP
    print(f"🔍 Extracting Flows from PCAP: {PCAP_PATH} ...")
    streamer = NFStreamer(source=PCAP_PATH, statistical_analysis=True)

    flows_data = []
    metadata = []
    for flow in streamer:
        row = {}
        for feat in feature_names:
            attr_name = feat.lower().replace(" ", "_")
            row[feat] = getattr(flow, attr_name, 0.0)
        flows_data.append(row)
        
        metadata.append({
            "src_ip": flow.src_ip,
            "src_port": flow.src_port,
            "dst_ip": flow.dst_ip,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol
        })

    df_flows = pd.DataFrame(flows_data)
    df_meta = pd.DataFrame(metadata)

    # คลีนข้อมูลตัวเลข
    for col in df_flows.columns:
        df_flows[col] = pd.to_numeric(df_flows[col], errors='coerce').fillna(0.0)

    print(f"✅ Extracted {len(df_flows)} flows.\n")

    # 4. ประมวลผล TIER 2 (Isolation Forest ด้วย Custom Threshold)
    X_scaled = scaler.transform(df_flows)
    
    # คำนวณ Anomaly Score แบบละเอียด
    iso_scores = iso_model.decision_function(X_scaled.values if hasattr(X_scaled, 'values') else X_scaled)
    
    # 🛠️ ใช้ Custom Threshold ในการตัดสินใจ (-1 = Anomaly, 1 = Normal)
    iso_preds = np.where(iso_scores < CUSTOM_THRESHOLD, -1, 1)

    anomaly_mask = (iso_preds == -1)
    anomaly_count = np.sum(anomaly_mask)

    print("==================================================")
    print(f"📊 TIER 2 SUMMARY (Threshold = {CUSTOM_THRESHOLD})")
    print("==================================================")
    print(f"Total Flows Scanned : {len(df_flows)}")
    print(f"Normal Flows 🟢     : {len(df_flows) - anomaly_count}")
    print(f"Anomaly Flows 🚨    : {anomaly_count} ( forwarded to Tier 3 )\n")

    # 5. ประมวลผล TIER 3 (XGBoost) เฉพาะ Flow ที่ผ่านตัวกรอง Tier 2
    if anomaly_count > 0:
        df_anomalies = df_flows[anomaly_mask]
        df_meta_anomalies = df_meta[anomaly_mask].copy()

        xgb_preds = xgb_model.predict(df_anomalies)
        xgb_probs = xgb_model.predict_proba(df_anomalies)
        
        attack_labels = label_encoder.inverse_transform(xgb_preds)
        confidences = np.max(xgb_probs, axis=1) * 100

        df_meta_anomalies["Anomaly_Score"] = np.round(iso_scores[anomaly_mask], 4)
        df_meta_anomalies["XGB_Attack_Type"] = attack_labels
        df_meta_anomalies["Confidence(%)"] = np.round(confidences, 2)

        print("=== 🎯 TIER 3 DETECTED ATTACKS SUMMARY ===")
        print(df_meta_anomalies["XGB_Attack_Type"].value_counts().to_string())

        print("\n=========================================================================")
        print("🔍 DETAILED ANOMALY INSPECTION (Sample 5 Flows)")
        print("=========================================================================")
        cols_to_show = ["src_ip", "dst_ip", "dst_port", "Anomaly_Score", "XGB_Attack_Type", "Confidence(%)"]
        print(df_meta_anomalies[cols_to_show].head(5).to_string(index=True))
    else:
        print("=== TIER 3 ===")
        print("  - ไม่พบ Anomaly จาก Tier 2 จึงไม่มีข้อมูลส่งมาจำแนกประเภท")

if __name__ == '__main__':
    main()