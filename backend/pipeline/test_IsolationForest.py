import pandas as pd
import numpy as np
import time
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

# 1. โหลดข้อมูล Train และ Test Set
train_path = r"D:\pjb2\dashboard\backend\Dataset\Mapped_Dataset\trainISO_dataset.csv"
test_path = r"D:\pjb2\dashboard\backend\Dataset\Mapped_Dataset\testISO_dataset.csv"

print("📂 กำลังโหลดข้อมูล...")
df_train = pd.read_csv(train_path)
df_test = pd.read_csv(test_path)

y_train = df_train['target_label'].values
X_train = df_train.drop(columns=['target_label'])

y_test = df_test['target_label'].values
X_test = df_test.drop(columns=['target_label'])

# 2. คัดเฉพาะ Benign สำหรับ Fit (Novelty Detection)
X_train_benign = X_train[y_train == 0]

# 3. Fit StandardScaler (ปรับสเกลข้อมูลตามมาตรฐาน Production)
scaler = StandardScaler()
X_train_benign_scaled = scaler.fit_transform(X_train_benign)
X_test_scaled = scaler.transform(X_test)

# 4. เทรน Isolation Forest (ใช้อัตรา contamination 0.01 ตรงตาม Production)
print("🤖 กำลังเทรน Isolation Forest (Pure Unsupervised - Contamination 0.01)...")
iso_model = IsolationForest(
    n_estimators=100,
    max_samples=4096,
    contamination=0.01,
    random_state=42,
    n_jobs=-1
)
iso_model.fit(X_train_benign_scaled)

# 5. พยากรณ์ผลลัพธ์ดิบจาก Native Predict
print("🧪 กำลังพยากรณ์ผลลัพธ์จาก Native Predict...")
raw_preds = iso_model.predict(X_test_scaled)
y_pred = np.where(raw_preds == -1, 1, 0)

# 6. แสดงรายงานประเมินผลดิบจริง
print("\n" + "=" * 60)
print("      RAW UNSUPERVISED ISOLATION FOREST PERFORMANCE (PROD SCALE)")
print("=" * 60)
print(f"Accuracy         : {accuracy_score(y_test, y_pred):.4f}")
print(f"Precision        : {precision_score(y_test, y_pred, pos_label=1, zero_division=0):.4f}")
print(f"Recall (TPR)     : {recall_score(y_test, y_pred, pos_label=1, zero_division=0):.4f}")
print(f"F1-Score         : {f1_score(y_test, y_pred, pos_label=1, zero_division=0):.4f}")

try:
    anomaly_scores = -iso_model.decision_function(X_test_scaled)
    print(f"ROC-AUC Score    : {roc_auc_score(y_test, anomaly_scores):.4f}")
except Exception:
    pass

print("\n[ Confusion Matrix ]")
cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
print(pd.DataFrame(cm, index=['Actual Benign', 'Actual Attack'], columns=['Pred Benign', 'Pred Attack']))