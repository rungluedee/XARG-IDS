import pandas as pd
import os
import glob

def batch_merge_labels(nf_folder, cic_folder, output_folder):
    os.makedirs(output_folder, exist_ok=True)
    
    # 1. ค้นหาไฟล์ CSV ทั้งหมดที่เราเพิ่งสกัดจาก NFStream
    nf_files = glob.glob(os.path.join(nf_folder, "*.csv"))
    
    if not nf_files:
        print(f"❌ ไม่พบไฟล์ที่สกัดจาก NFStream ใน {nf_folder}")
        return

    print(f"🚀 พบข้อมูล NFStream จำนวน {len(nf_files)} วัน. เริ่มทำการแมปปิ้ง 5-Tuple...\n")

    for nf_path in nf_files:
        filename = os.path.basename(nf_path)
        day_prefix = filename.split('-')[0] # ดึงชื่อวันออกมา เช่น 'Friday', 'Monday'
        
        print(f"=========================================")
        print(f"📅 กำลังประมวลผลข้อมูลวัน: {day_prefix}")
        print(f"=========================================")
        
        # 2. โหลดไฟล์ NFStream
        df_nf = pd.read_csv(nf_path)
        
        # 3. ค้นหาไฟล์ Label ต้นฉบับจาก CIC ที่ตรงกับวันนั้นๆ (เช่น Friday-*.csv)
        cic_pattern = os.path.join(cic_folder, f"{day_prefix}*.csv")
        cic_files = glob.glob(cic_pattern)
        
        if not cic_files:
            print(f"⚠️ ไม่พบไฟล์ Label ต้นฉบับสำหรับ {day_prefix} ข้ามการทำงาน...")
            continue
            
        df_cic_list = []
        for c_file in cic_files:
            print(f"   📥 โหลด Label จาก: {os.path.basename(c_file)}")
            # ใช้เฉพาะคอลัมน์ 5-tuple และ Label
            # เพิ่ม encoding='cp1252' เพื่อให้อ่านอักขระพิเศษตัวขีดแดชยาวๆ ได้
            temp_df = pd.read_csv(c_file, usecols=[' Source IP', ' Destination IP', ' Source Port', ' Destination Port', ' Protocol', ' Label'], encoding='cp1252')
            df_cic_list.append(temp_df)
            
        # รวมไฟล์ Label ของวันนั้นๆ เข้าด้วยกัน
        df_cic = pd.concat(df_cic_list, ignore_index=True)
        df_cic.columns = df_cic.columns.str.strip()
        
        # 4. เปลี่ยนชื่อคอลัมน์เตรียม Merge
        df_cic.rename(columns={
            'Source IP': 'src_ip',
            'Destination IP': 'dst_ip',
            'Source Port': 'src_port',
            'Destination Port': 'dst_port',
            'Protocol': 'protocol',
            'Label': 'label'
        }, inplace=True)
        
        # ลบข้อมูลซ้ำเพื่อป้องกัน Data Explosion
        df_cic.drop_duplicates(subset=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol'], inplace=True)
        
        print(f"   🔗 กำลัง Merge ข้อมูล ({len(df_nf):,} บรรทัด)...")
        # 5. ทำ Left Join
        df_mapped = pd.merge(
            df_nf,
            df_cic,
            on=['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol'],
            how='left'
        )
        
        # เติม BENIGN ให้กับทราฟฟิกที่ไม่มี Label โจมตี
        df_mapped['label'] = df_mapped['label'].fillna('BENIGN')
        
        # 6. บันทึกไฟล์
        out_path = os.path.join(output_folder, f"{day_prefix}_Mapped.csv")
        df_mapped.to_csv(out_path, index=False)
        
        print(f"   ✅ แมปปิ้งเสร็จสิ้น: {os.path.basename(out_path)}")
        print(f"   📊 สรุป Label ของวัน {day_prefix}:")
        print(df_mapped['label'].value_counts().to_string())
        print("\n")

if __name__ == "__main__":
    # โฟลเดอร์ที่เก็บไฟล์จาก NFStream (ที่คุณเพิ่งรันเสร็จ)
    NF_DIR = r"D:\backend (1)\backend\Dataset\CICIDS2017_NF"
    
    # โฟลเดอร์ที่เก็บไฟล์ CSV ต้นฉบับจาก CIC ที่โหลดมา
    CIC_DIR = r"D:\backend (1)\backend\Dataset\CICIDS2017_CSV"
    
    # โฟลเดอร์ใหม่สำหรับเก็บไฟล์ที่พร้อมเทรน
    OUTPUT_DIR = r"D:\backend (1)\backend\Dataset\Mapped_Dataset"
    
    batch_merge_labels(NF_DIR, CIC_DIR, OUTPUT_DIR)