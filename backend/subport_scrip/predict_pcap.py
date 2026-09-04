import os
import sys
import json
import pickle
import numpy as np
import pandas as pd
import xgboost as xgb
from nfstream import NFStreamer

def load_models(model_dir):
    print("📥 กำลังโหลดโมเดลและค่าคอนฟิกต่างๆ...")
    
    # โหลด XGBoost
    xgb_model = xgb.Booster()
    xgb_model.load_model(os.path.join(model_dir, "model_cic.json"))
    
    with open(os.path.join(model_dir, "le_cic.pkl"), "rb") as f:
        label_encoder = pickle.load(f)
        
    with open(os.path.join(model_dir, "feature_schema_cic.json"), "r", encoding="utf-8") as f:
        schema = json.load(f)
        feature_cols = schema["feature_columns"]
        
    # โหลด Isolation Forest & Scaler
    with open(os.path.join(model_dir, "anomaly_iso_forest.pkl"), "rb") as f:
        iso_forest = pickle.load(f)
        
    with open(os.path.join(model_dir, "anomaly_scaler.pkl"), "rb") as f:
        iso_scaler = pickle.load(f)
        
    return xgb_model, label_encoder, feature_cols, iso_forest, iso_scaler

def extract_features(pcap_path):
    print(f"🔎 กำลังสกัดฟีเจอร์จากไฟล์: {os.path.basename(pcap_path)}")
    streamer = NFStreamer(source=pcap_path, statistical_analysis=True)
    df = streamer.to_pandas()
    
    if df.empty:
        raise ValueError("ไม่พบข้อมูลทราฟฟิกในไฟล์ PCAP นี้")
    
    print(f"📊 สกัดทราฟฟิกได้ทั้งหมด: {len(df)} Flows")
    return df

def predict_traffic(pcap_path, model_dir):
    # 1. โหลดโมเดล
    xgb_model, le, feature_cols, iso_forest, iso_scaler = load_models(model_dir)
    
    # 2. สกัดฟีเจอร์จาก PCAP
    raw_df = extract_features(pcap_path)
    
    # 3. เตรียมข้อมูล (Data Preprocessing)
    print("⚙️ กำลังจัดเตรียมโครงสร้างข้อมูลให้ตรงกับโมเดล...")
    X = pd.DataFrame(index=raw_df.index)
    
    for col in feature_cols:
        if col in raw_df.columns:
            X[col] = raw_df[col]
        else:
            X[col] = 0.0
            
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    X = X.apply(pd.to_numeric, errors='coerce').fillna(0.0)
    X = X[feature_cols]
    
    # 4. วิเคราะห์ด้วย Isolation Forest
    print("🤖 กำลังวิเคราะห์หาความผิดปกติ (Anomaly Detection)...")
    X_scaled = iso_scaler.transform(X)
    iso_preds = iso_forest.predict(X_scaled) # 1 = ปกติ, -1 = ผิดปกติ
    
    # 5. วิเคราะห์ด้วย XGBoost
    print("🤖 กำลังวิเคราะห์ประเภทการโจมตี (Attack Classification)...")
    dmatrix = xgb.DMatrix(X, feature_names=feature_cols)
    xgb_probs = xgb_model.predict(dmatrix)
    xgb_preds_idx = xgb_probs.argmax(axis=1)
    xgb_labels = le.inverse_transform(xgb_preds_idx)
    
    # 6. ผสานผลลัพธ์ (Hybrid Logic: XGBoost First -> IsoForest Safety Net)
    print("🔄 ผสานผลลัพธ์การตัดสินใจ...")
    final_alerts = []

    for i in range(len(raw_df)):
        xgb_class = xgb_labels[i]
        iso_class = iso_preds[i]
    
        # Tier 1: ให้ XGBoost เช็ก Known Attack ก่อน
        if xgb_class != "BENIGN":
            final_alerts.append(f"🚨 {xgb_class}")
        # Tier 2: ถ้า XGBoost บอกว่าเป็น BENIGN -> ให้ Isolation Forest สแกนหา Zero-Day / C2
        elif iso_class == -1:
            final_alerts.append("⚠️ Unknown Anomaly (Zero-Day/C2)")
        # ปลอดภัยจริง ผ่านการยืนยันจากทั้ง 2 โมเดล
        else:
            final_alerts.append("✅ BENIGN")
        
    raw_df['Final_Alert'] = final_alerts
    
    # 7. สรุปผล
    print(f"\n{'='*50}")
    print(" 🎯 สรุปผลการวิเคราะห์ทราฟฟิก")
    print(f"{'='*50}")
    print(raw_df['Final_Alert'].value_counts())
    print(f"{'='*50}\n")
    
    attacks = raw_df[raw_df['Final_Alert'] != "✅ BENIGN"]
    if not attacks.empty:
        print("ตัวอย่าง IP ที่ต้องสงสัย (5 รายการแรก):")
        cols_to_show = ['src_ip', 'dst_ip', 'dst_port', 'Final_Alert']
        print(attacks[cols_to_show].head(5).to_string(index=False))
    else:
        print("🎉 ระบบปลอดภัย: ไม่พบการโจมตีในทราฟฟิกนี้")

if __name__ == "__main__":
    MODEL_DIR = r"D:\backend (1)\backend\models"
    TEST_PCAP = r"C:\Users\Lenovo\Downloads\blackEnergy.pcap"
    
    if os.path.exists(TEST_PCAP):
        predict_traffic(TEST_PCAP, MODEL_DIR)
    else:
        print(f"❌ ไม่พบไฟล์ {TEST_PCAP}")
        print("กรุณาระบุที่อยู่ไฟล์ PCAP ที่ต้องการทดสอบในตัวแปร TEST_PCAP")