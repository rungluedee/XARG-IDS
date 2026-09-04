import pandas as pd
import numpy as np
from xgboost import XGBClassifier
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

# 1. โหลด Dataset
train_path = r"D:\pjb2\dashboard\backend\Dataset\Mapped_Dataset\trainXGB_multiclass.csv"
test_path = r"D:\pjb2\dashboard\backend\Dataset\Mapped_Dataset\testXGB_multiclass.csv"

df_train = pd.read_csv(train_path)
df_test = pd.read_csv(test_path)

# 2. จำลองสถานการณ์ Zero-Day: ซ่อนคลาส 'Botnet' ออกจากชุดข้อมูล Train ทั้งหมด!
ZERO_DAY_CLASS = "Botnet"
print(f"🧪 [Zero-Day Test] ซ่อนคลาส '{ZERO_DAY_CLASS}' ออกจากข้อมูลการเทรนอย่างสิ้นเชิง...")

df_train_sim = df_train[df_train['target_label'] != ZERO_DAY_CLASS].copy()
df_test_zeroday = df_test[df_test['target_label'] == ZERO_DAY_CLASS].copy()

# เตรียม Features และ Targets
X_train = df_train_sim.drop(columns=['target_label'])
y_train_str = df_train_sim['target_label']

X_zeroday = df_test_zeroday.drop(columns=['target_label'])

# Encoding สำหรับ XGBoost
le = LabelEncoder()
y_train_xgb = le.fit_transform(y_train_str)

# 3. เทรน XGBoost (ไม่เคยเห็น Botnet)
print("\n🤖 กำลังเทรน XGBoost (โดยไม่มีข้อมูล Botnet)...")
xgb = XGBClassifier(n_estimators=100, random_state=42, n_jobs=-1)
xgb.fit(X_train, y_train_xgb)

# 4. เทรน Isolation Forest (ไม่เคยเห็น Botnet เช่นกัน)
print("🤖 กำลังเทรน Isolation Forest...")
iso = IsolationForest(n_estimators=100, max_samples=4096, contamination='auto', random_state=42, n_jobs=-1)
iso.fit(X_train)

# 5. ทดสอบยิง Zero-Day Attack (Botnet) ใส่ทั้งสองโมเดล
print(f"\n⚡ ทดสอบส่งทราฟฟิก Zero-Day ({ZERO_DAY_CLASS} จำนวน {len(X_zeroday)} แถว) เข้าสู่ระบบ:")
print("=" * 65)

# ประเมิน XGBoost
xgb_preds_num = xgb.predict(X_zeroday)
xgb_preds_str = le.inverse_transform(xgb_preds_num)
benign_count = np.sum(xgb_preds_str == 'BENIGN')
xgb_miss_rate = (benign_count / len(X_zeroday)) * 100

print(f"🔴 XGBoost Result:")
print(f"   - มองการโจมตีใหม่นี้เป็น 'BENIGN' (หลุดรอด): {benign_count} / {len(X_zeroday)} แถว ({xgb_miss_rate:.2f}%)")
print(f"   - ทายว่าเป็นคลาสอื่นที่ไม่ตรงจริง: {len(X_zeroday) - benign_count} แถว")

# ประเมิน Isolation Forest
iso_scores = -iso.decision_function(X_zeroday)
# ใช้ Threshold percentile เดียวกับ script ล่าสุด
th = np.percentile(-iso.decision_function(X_train), 88) 
iso_detected = np.sum(iso_scores >= th)
iso_detect_rate = (iso_detected / len(X_zeroday)) * 100

print(f"\n🟢 Isolation Forest Result:")
print(f"   - ตรวจจับพบว่าเป็น Anomaly/ภัยคุกคามแปลกปลอม: {iso_detected} / {len(X_zeroday)} แถว ({iso_detect_rate:.2f}%)")
print("=" * 65)