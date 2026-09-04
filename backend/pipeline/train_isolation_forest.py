import os
import glob
import json
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# นำเข้าฟังก์ชันจัดกลุ่ม Label จากไฟล์ของคุณ
from subport_scrip.feature_mapping import map_label_to_family

# คอลัมน์ที่ต้องลบทิ้งเพื่อป้องกันโมเดลจำข้อสอบ (อัปเดตให้ตรงกับ XGBoost)
IDENTIFIERS_TO_DROP = [
    'id', 'expiration_id', 'src_ip', 'src_mac', 'src_oui', 'src_port',
    'dst_ip', 'dst_mac', 'dst_oui', 'dst_port', 'protocol', 'vlan_id', 'tunnel_id',
    # --- เพิ่มคอลัมน์เวลา Timestamp ---
    'bidirectional_first_seen_ms', 'bidirectional_last_seen_ms', 
    'src2dst_first_seen_ms', 'src2dst_last_seen_ms',
    'dst2src_first_seen_ms', 'dst2src_last_seen_ms'
]

def load_benign_data(data_dir):
    csv_files = glob.glob(os.path.join(data_dir, "*_Mapped.csv"))
    if not csv_files:
        raise FileNotFoundError(f"❌ ไม่พบไฟล์ _Mapped.csv ใน {data_dir}")

    print(f"📥 กำลังโหลดข้อมูลจาก {len(csv_files)} ไฟล์...")
    # อัปเดต: เพิ่ม low_memory=False เพื่อป้องกัน DtypeWarning
    df_list = [pd.read_csv(f, low_memory=False) for f in csv_files]
    df = pd.concat(df_list, ignore_index=True)
    
    # 1. แมปปิ้ง Label และกรองเอาเฉพาะ 'BENIGN' (ทราฟฟิกปกติ)
    print("🔍 กำลังคัดกรองเฉพาะทราฟฟิกปกติ (BENIGN)...")
    df['Family'] = df['label'].apply(map_label_to_family)
    benign_df = df[df['Family'] == 'BENIGN'].copy()
    
    print(f"📊 พบข้อมูล BENIGN ทั้งหมด: {len(benign_df):,} บรรทัด (จากทั้งหมด {len(df):,} บรรทัด)")
    
    if len(benign_df) < 1000:
        raise RuntimeError("มีข้อมูล BENIGN น้อยเกินไป ไม่สามารถเทรน Isolation Forest ได้")

    # 2. ลบคอลัมน์ Identifiers และ Label ดิบ
    cols_to_drop = [c for c in IDENTIFIERS_TO_DROP + ['label', 'Family'] if c in benign_df.columns]
    X = benign_df.drop(columns=cols_to_drop)

    # 3. จัดการค่า NaN และ Infinity
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    X = X.apply(pd.to_numeric, errors='coerce').fillna(0.0)
    
    # บันทึกชื่อฟีเจอร์ไว้ใช้ตอน Inference
    feature_names = list(X.columns)
    
    return X, feature_names

def main():
    DATA_DIR = r"D:\backend (1)\backend\Dataset\Mapped_Dataset"
    MODEL_DIR = r"D:\backend (1)\backend\models"
    os.makedirs(MODEL_DIR, exist_ok=True)

    # 1. เตรียมข้อมูล (ใช้เฉพาะ BENIGN)
    X, feature_names = load_benign_data(DATA_DIR)
    
    # ตรวจสอบจำนวนฟีเจอร์ให้แน่ใจว่าได้ 67 เท่ากับ XGBoost
    print(f"✨ จำนวนฟีเจอร์ที่ใช้เทรน: {len(feature_names)} ฟีเจอร์")

    # แบ่งข้อมูล 80% เทรน / 20% ไว้สำหรับคำนวณขอบเขตคะแนน (Threshold Bounds)
    X_train, X_holdout = train_test_split(X, test_size=0.2, random_state=42)

    # 2. ทำ Data Scaling (Isolation Forest ทำงานได้ดีกว่าถ้าข้อมูลถูก Scale)
    print("⚖️ กำลังปรับสเกลข้อมูล (StandardScaler)...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_holdout_scaled = scaler.transform(X_holdout)

    # 3. เทรนโมเดล Isolation Forest
    contamination_rate = 0.01 # คาดการณ์ว่าในทราฟฟิกปกติ อาจมีข้อมูลแปลกปลอมหลุดมา 1%
    print(f"🚀 เริ่มเทรน Isolation Forest (Contamination={contamination_rate})... อาจใช้เวลาสักครู่")
    
    model = IsolationForest(
        n_estimators=200, 
        contamination=contamination_rate,
        random_state=42, 
        n_jobs=-1 # ใช้ CPU ทุกคอร์ที่มี
    )
    model.fit(X_train_scaled)

    # 4. คำนวณขอบเขตคะแนน (Score Bounds) จากข้อมูล Holdout
    # เพื่อให้รู้ว่าคะแนนความปกติอยู่ที่ช่วงไหน หากต่ำกว่านี้คือผิดปกติ
    print("📈 กำลังคำนวณเกณฑ์ตัดสินใจ (Decision Bounds)...")
    holdout_scores = model.decision_function(X_holdout_scaled)
    p1 = float(np.percentile(holdout_scores, 1))
    p99 = float(np.percentile(holdout_scores, 99))
    
    flagged = (model.predict(X_holdout_scaled) == -1).sum()
    print(f"   - พบทราฟฟิกที่ถูกมองว่าผิดปกติในชุดทดสอบ: {flagged:,} บรรทัด ({(flagged/len(X_holdout))*100:.2f}%)")
    print(f"   - Score Bounds: P1 = {p1:.4f}, P99 = {p99:.4f}")

    # 5. บันทึกไฟล์โมเดล, Scaler และ Bounds
    print("💾 กำลังบันทึกไฟล์โมเดล...")
    with open(os.path.join(MODEL_DIR, "anomaly_iso_forest.pkl"), "wb") as f:
        pickle.dump(model, f)
    with open(os.path.join(MODEL_DIR, "anomaly_scaler.pkl"), "wb") as f:
        pickle.dump(scaler, f)
    with open(os.path.join(MODEL_DIR, "anomaly_score_bounds.json"), "w", encoding="utf-8") as f:
        json.dump({"p1": p1, "p99": p99, "feature_columns": feature_names}, f, indent=2)

    print("🎉 เสร็จสิ้น! ระบบพร้อมสำหรับใช้กรองการโจมตีแบบ Zero-day แล้ว")

if __name__ == "__main__":
    main()