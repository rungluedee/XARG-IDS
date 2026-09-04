import os
import glob
import json
import pickle
import sys
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
from sklearn.utils.class_weight import compute_sample_weight

# นำเข้า Logic การจัดกลุ่ม 9 Attack Families
from subport_scrip.feature_mapping import ATTACK_FAMILIES, map_label_to_family

# คอลัมน์ที่ต้องลบทิ้งเพื่อป้องกันโมเดลจำข้อสอบ (Data Leakage Guard)
# อัปเดต: เพิ่มคอลัมน์ Timestamp ทั้ง 4 ตัวของ NFStream เพื่อป้องกันไม่ให้โมเดลจำเวลา
IDENTIFIERS_TO_DROP = [
    'id', 'expiration_id', 'src_ip', 'src_mac', 'src_oui', 'src_port',
    'dst_ip', 'dst_mac', 'dst_oui', 'dst_port', 'protocol', 'vlan_id', 'tunnel_id',
    'bidirectional_first_seen_ms', 'bidirectional_last_seen_ms', 
    'src2dst_first_seen_ms', 'src2dst_last_seen_ms',
    'dst2src_first_seen_ms', 'dst2src_last_seen_ms'
]

def load_and_prepare_data(data_dir):
    csv_files = glob.glob(os.path.join(data_dir, "*_Mapped.csv"))
    if not csv_files:
        raise FileNotFoundError(f"❌ ไม่พบไฟล์ _Mapped.csv ใน {data_dir}")

    print(f"📥 กำลังโหลดข้อมูลจาก {len(csv_files)} ไฟล์...")
    df_list = []
    for f in csv_files:
        print(f"   - โหลด: {os.path.basename(f)}")
        # ป้องกัน DtypeWarning
        df_list.append(pd.read_csv(f, low_memory=False))
        
    df = pd.concat(df_list, ignore_index=True)
    print(f"\n📊 ขนาดข้อมูลเริ่มต้น: {df.shape[0]:,} บรรทัด | {df.shape[1]} คอลัมน์")

    print("🔄 กำลังจัดกลุ่ม Label เป็น 9 Attack Families...")
    df['Family'] = df['label'].apply(map_label_to_family)
    
    # ลบแถวที่ไม่มี Label ใน 9 กลุ่มหลัก
    df = df.dropna(subset=['Family']).reset_index(drop=True)

    # ลบคลาสที่มีจำนวนไม่ถึง 2 บรรทัด (เช่น Heartbleed) เพื่อให้แบ่ง Train/Test ได้
    valid_classes = df['Family'].value_counts()[df['Family'].value_counts() >= 2].index
    df = df[df['Family'].isin(valid_classes)].reset_index(drop=True)

    print("🧹 กำลังลบคอลัมน์ระบุตัวตนและคอลัมน์เวลา (Identifiers & Timestamps)...")
    cols_to_drop = [c for c in IDENTIFIERS_TO_DROP + ['label'] if c in df.columns]
    df = df.drop(columns=cols_to_drop)

    print("✨ กำลังจัดการค่าสูญหาย (NaN/Inf)...")
    # เปลี่ยน Inf เป็น NaN แล้วเติมด้วย 0
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    
    # บังคับให้คอลัมน์ฟีเจอร์ทั้งหมดเป็นตัวเลข (ป้องกัน Error ตอนเข้า XGBoost)
    feature_cols = [c for c in df.columns if c != 'Family']
    df[feature_cols] = df[feature_cols].apply(pd.to_numeric, errors='coerce').fillna(0.0)

    print(f"✅ ข้อมูลพร้อมเทรน: {df.shape[0]:,} บรรทัด | {len(feature_cols)} ฟีเจอร์")
    return df, feature_cols

def main():
    DATA_DIR = r"D:\backend (1)\backend\Dataset\Mapped_Dataset"
    MODEL_DIR = r"D:\backend (1)\backend\models"
    os.makedirs(MODEL_DIR, exist_ok=True)

    # 1. โหลดข้อมูล
    try:
        df, feature_cols = load_and_prepare_data(DATA_DIR)
    except Exception as e:
        print(f"❌ เกิดข้อผิดพลาดในการโหลดข้อมูล: {e}")
        sys.exit(1)

    X = df[feature_cols]
    y_raw = df['Family']

    # 2. แปลง Label เป็นตัวเลข (0-8)
    print("\n🏷️ กำลังเข้ารหัส Label (Label Encoding)...")
    le = LabelEncoder()
    le.fit(ATTACK_FAMILIES) # ฟิกซ์คลาสไว้ที่ 9 คลาสเสมอ
    y = le.transform(y_raw)

    # 3. แบ่งข้อมูล (80% Train / 20% Test)
    print("✂️ กำลังแบ่งข้อมูล Train/Test (80/20)...")
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print("⚖️ กำลังคำนวณ Class Weights เพื่อชดเชยข้อมูลที่ไม่สมดุล...")
    sample_weights = compute_sample_weight(class_weight='balanced', y=y_train)

    # 4. เทรนโมเดล XGBoost
    dtrain = xgb.DMatrix(X_train, label=y_train, weight=sample_weights, feature_names=feature_cols)
    dtest = xgb.DMatrix(X_test, label=y_test, feature_names=feature_cols)

    params = {
        "objective": "multi:softprob",
        "num_class": len(le.classes_),
        "max_depth": 8,
        "eta": 0.15,
        "eval_metric": "mlogloss",
        "tree_method": "hist" 
    }

    print("\n🚀 เริ่มเทรน XGBoost (อาจใช้เวลาหลายนาที)...")
    booster = xgb.train(
        params, dtrain, num_boost_round=300,
        evals=[(dtrain, "Train"), (dtest, "Test")],
        early_stopping_rounds=20, verbose_eval=20
    )

    # 5. ประเมินผล
    print("\n📈 กำลังประเมินผลโมเดล...")
    preds = booster.predict(dtest).argmax(axis=1)
    
    present_classes = sorted(list(set(y_test) | set(preds)))
    present_class_names = [le.classes_[i] for i in present_classes]

    report = classification_report(y_test, preds, labels=present_classes, target_names=present_class_names)
    print("\n" + report)

    # 6. บันทึกไฟล์ที่จำเป็นสำหรับการทำ Inference
    print("\n💾 กำลังบันทึกไฟล์โมเดลและโครงสร้างฟีเจอร์...")
    model_path = os.path.join(MODEL_DIR, "model_cic.json")
    le_path = os.path.join(MODEL_DIR, "le_cic.pkl")
    schema_path = os.path.join(MODEL_DIR, "feature_schema_cic.json")
    report_path = os.path.join(MODEL_DIR, "train_report.txt")
    
    booster.save_model(model_path)
    
    with open(le_path, "wb") as f:
        pickle.dump(le, f)
        
    with open(schema_path, "w", encoding="utf-8") as f:
        json.dump({
            "feature_columns": feature_cols,
            "n_features": len(feature_cols),
            "time_windows_seconds": None # ปรับเป็น None เพราะเราใช้ NFStream Flow
        }, f, indent=2)
        
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"🎉 เสร็จสมบูรณ์! ไฟล์ทั้งหมดถูกบันทึกไว้ที่: {MODEL_DIR}")

if __name__ == "__main__":
    main()