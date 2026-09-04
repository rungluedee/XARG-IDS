import pandas as pd
import numpy as np
import time
from xgboost import XGBClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

# 1. โหลดข้อมูล Multi-Class Dataset
train_path = r"D:\pjb2\dashboard\backend\Dataset\Mapped_Dataset\trainXGB_multiclass.csv"
test_path = r"D:\pjb2\dashboard\backend\Dataset\Mapped_Dataset\testXGB_multiclass.csv"

print("📂 กำลังโหลดข้อมูล XGBoost Multi-Class Dataset...")
df_train = pd.read_csv(train_path)
df_test = pd.read_csv(test_path)

target_col = 'target_label'

# 2. แปลง Label ข้อความภัยคุกคามเป็นตัวเลข (Label Encoding)
le = LabelEncoder()
y_train = le.fit_transform(df_train[target_col].astype(str))
y_test = le.transform(df_test[target_col].astype(str))

X_train = df_train.drop(columns=[target_col])
X_test = df_test.drop(columns=[target_col])

class_names = [str(cls) for cls in le.classes_]
num_classes = len(class_names)

print(f"📊 พบคลาสการโจมตีทั้งหมด ({num_classes} ประเภท): {class_names}")

# 3. เทรนโมเดล XGBoost Classifier
print("\n🤖 กำลังเทรนโมเดล XGBoost Classifier (Multi-Class)...")
start_time = time.time()

xgb_model = XGBClassifier(
    n_estimators=100,
    learning_rate=0.1,
    max_depth=6,
    objective='multi:softprob' if num_classes > 2 else 'binary:logistic',
    num_class=num_classes if num_classes > 2 else None,
    tree_method='hist',
    random_state=42,
    n_jobs=-1
)

xgb_model.fit(X_train, y_train)
print(f"⚡ เทรนโมเดลเสร็จสิ้นในเวลา: {time.time() - start_time:.2f} วินาที")

# 4. ทำนายและประเมินผลบน Test Set
print("\n🧪 กำลังทดสอบประสิทธิภาพโมเดลกับ Test Set...")
y_pred = xgb_model.predict(X_test)

acc = accuracy_score(y_test, y_pred)
f1_macro = f1_score(y_test, y_pred, average='macro', zero_division=0)
f1_weighted = f1_score(y_test, y_pred, average='weighted', zero_division=0)

print("\n" + "=" * 65)
print("          XGBoost MULTI-CLASS PERFORMANCE REPORT")
print("=" * 65)
print(f"Accuracy                 : {acc:.4f} ({acc*100:.2f}%)")
print(f"Macro F1-Score           : {f1_macro:.4f}")
print(f"Weighted F1-Score        : {f1_weighted:.4f}")

print("\n[ Detailed Classification Report per Attack Class ]")
print(classification_report(y_test, y_pred, target_names=class_names, digits=4, zero_division=0))

print("\n[ Confusion Matrix ]")
cm = confusion_matrix(y_test, y_pred)
print(pd.DataFrame(cm, index=[f"Actual_{c}" for c in class_names], columns=[f"Pred_{c}" for c in class_names]))