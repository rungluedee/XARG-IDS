import os
import sys
import glob
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

# --------------------------------------------------
# เพิ่ม Path ของโฟลเดอร์ subport_scrip
# --------------------------------------------------
current_dir = os.path.dirname(os.path.abspath(__file__))
subport_path = os.path.join(current_dir, "subport_scrip")
abs_subport_path = r"D:\pjb2\dashboard\backend\subport_scrip"

for path in [subport_path, abs_subport_path]:
    if os.path.exists(path) and path not in sys.path:
        sys.path.insert(0, path)

try:
    from feature_mapping import map_label_to_family
    print("✅ โหลดโมดูล feature_mapping.py จาก subport_scrip สำเร็จ")
except ImportError:
    raise ImportError(f"❌ ไม่พบไฟล์ feature_mapping.py ในโฟลเดอร์ {abs_subport_path}")

# 1. กำหนด Path
folder_path = r"D:\pjb2\dashboard\backend\Dataset\Mapped_Dataset"
os.makedirs(folder_path, exist_ok=True)

# 2. อ่านไฟล์ CSV ทั้งหมด
file_pattern = os.path.join(folder_path, "*.csv")
all_files = glob.glob(file_pattern)
data_files = [f for f in all_files if not os.path.basename(f).startswith(('merged_', 'train_', 'test_', 'trainISO_', 'testISO_', 'trainXGB_', 'testXGB_'))]

if not data_files:
    print("❌ ไม่พบไฟล์ CSV สำหรับประมวลผล")
    exit()

df_list = [pd.read_csv(file, low_memory=False) for file in data_files]
df = pd.concat(df_list, ignore_index=True)
print(f"✅ รวมไฟล์สำเร็จ จำนวนข้อมูลทั้งหมด: {len(df)} แถว")

# 3. จัดการคอลัมน์เฉลยด้วย feature_mapping (9 Attack Families)
possible_labels = ["Label", "label", "attack_type", "verdict", "class"]
target_col = next((col for col in df.columns if col in possible_labels or col.lower() in ["label", "verdict"]), None)

if not target_col:
    raise ValueError("❌ ไม่พบคอลัมน์เฉลย ในไฟล์ CSV")

df['target_label'] = df[target_col].apply(map_label_to_family)

unmapped_count = df['target_label'].isna().sum()
if unmapped_count > 0:
    print(f"⚠️ ตัดข้อมูลที่ไม่ตรงกับ 9 Attack Families ออก: {unmapped_count} แถว")
    df = df.dropna(subset=['target_label']).copy()

print("\n📊 สรุปจำนวนข้อมูลแยกตาม 9 Attack Families:")
print(df['target_label'].value_counts())

# 4. Data Cleaning & Drop Metadata
metadata_keywords = ["ip", "port", "timestamp", "time", "date", "id", "mac", "flow"]
cols_to_drop = [
    col for col in df.columns 
    if col != 'target_label' and (col == target_col or any(kw in col.lower() for kw in metadata_keywords))
]

df.drop(columns=cols_to_drop, errors='ignore', inplace=True)
df.drop_duplicates(inplace=True)
print(f"\n✂️ ลบ Metadata และแถวซ้ำเรียบร้อย คงเหลือ: {len(df)} แถว")

target_series = df['target_label'].values
df_features = df.drop(columns=['target_label'])

# 5. จัดการชนิดข้อมูลตัวเลขและข้อความ
num_cols = df_features.select_dtypes(include=['number']).columns
cat_cols = df_features.select_dtypes(include=['object', 'category']).columns

df_features[num_cols] = df_features[num_cols].replace([np.inf, -np.inf], np.nan)
for col in num_cols:
    df_features[col] = df_features[col].fillna(df_features[col].median())

safe_cat_cols = [col for col in cat_cols if df_features[col].nunique() <= 50]
unsafe_cat_cols = [col for col in cat_cols if df_features[col].nunique() > 50]

if safe_cat_cols:
    df_features = pd.get_dummies(df_features, columns=safe_cat_cols, drop_first=True, dtype=np.int8)

if unsafe_cat_cols:
    print(f"✂️ ตัดคอลัมน์ข้อความซับซ้อนทิ้ง: {unsafe_cat_cols}")
    df_features.drop(columns=unsafe_cat_cols, inplace=True)

df_features['target_label'] = target_series

# 6. กรองคลาสที่มีข้อมูลน้อยกว่า 2 แถวออก
class_counts = df_features['target_label'].value_counts()
rare_classes = class_counts[class_counts < 2].index.tolist()

if rare_classes:
    print(f"⚠️ พบคลาสที่มีข้อมูลน้อยเกินไป (< 2 แถว): {rare_classes}")
    df_features = df_features[~df_features['target_label'].isin(rare_classes)].copy()

print(f"✅ ประมวลผล Features สุจริตสำเร็จ! จำนวน Features ตัวเลขทั้งหมด: {df_features.shape[1] - 1} ตัว")

# 7. แบ่ง Train / Test (80 / 20) และบันทึก
train_df, test_df = train_test_split(
    df_features, 
    test_size=0.20, 
    random_state=42, 
    stratify=df_features['target_label']
)

# บันทึกไฟล์ Multi-Class สำหรับ XGBoost (9 Classes)
train_df.to_csv(os.path.join(folder_path, "trainXGB_multiclass.csv"), index=False, encoding='utf-8-sig')
test_df.to_csv(os.path.join(folder_path, "testXGB_multiclass.csv"), index=False, encoding='utf-8-sig')

# แปลงเป็น Binary สำหรับ Isolation Forest แล้วบันทึก
train_iso = train_df.copy()
test_iso = test_df.copy()

train_iso['target_label'] = np.where(train_iso['target_label'] == "BENIGN", 0, 1)
test_iso['target_label'] = np.where(test_iso['target_label'] == "BENIGN", 0, 1)

train_iso.to_csv(os.path.join(folder_path, "trainISO_dataset.csv"), index=False, encoding='utf-8-sig')
test_iso.to_csv(os.path.join(folder_path, "testISO_dataset.csv"), index=False, encoding='utf-8-sig')

print("💾 บันทึกไฟล์ Dataset สำหรับ XGBoost (9 Classes) และ Isolation Forest เรียบร้อยแล้ว!")