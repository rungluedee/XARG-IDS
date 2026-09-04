import os
import glob
from nfstream import NFStreamer

def batch_convert_pcaps(pcap_folder, output_csv_folder):
    # สร้างโฟลเดอร์ปลายทางถ้ายังไม่มี
    os.makedirs(output_csv_folder, exist_ok=True)
    
    # ค้นหาไฟล์ .pcap ทั้งหมดในโฟลเดอร์
    pcap_files = glob.glob(os.path.join(pcap_folder, "*.pcap"))
    
    if not pcap_files:
        print(f"ไม่พบไฟล์ .pcap ในโฟลเดอร์ {pcap_folder}")
        return

    print(f"พบไฟล์ PCAP ทั้งหมด {len(pcap_files)} ไฟล์. กำลังเริ่มดำเนินการ...")

    for pcap_file in pcap_files:
        filename = os.path.basename(pcap_file)
        csv_filename = filename.replace('.pcap', '.csv')
        csv_filepath = os.path.join(output_csv_folder, csv_filename)
        
        print(f"\nกำลังแปลงไฟล์: {filename} ... (อาจใช้เวลาหลายนาที โปรดรอสักครู่)")
        try:
            # 1. สร้าง Streamer (เปิดโหมดสถิติ)
            streamer = NFStreamer(source=pcap_file, statistical_analysis=True)
            
            # 2. ใช้คำสั่ง to_csv() ของ NFStream โดยตรง 
            # (ฟังก์ชันนี้จะจัดการเขียนลงไฟล์แบบประหยัด RAM ให้เองโดยอัตโนมัติ)
            total_flows = streamer.to_csv(csv_filepath)
            
            print(f"✅ สำเร็จ! บันทึกไฟล์ที่: {csv_filepath} (รวมทั้งหมด {total_flows:,} flows)")
            
        except Exception as e:
            print(f"❌ เกิดข้อผิดพลาดกับไฟล์ {filename}: {e}")

if __name__ == "__main__":
    # Path ที่คุณตั้งไว้ถูกต้องแล้วครับ
    INPUT_PCAP_DIR = r"D:\backend (1)\backend\Dataset\CLCIDS2017_pcap" 
    OUTPUT_CSV_DIR = r"D:\backend (1)\backend\Dataset\CICIDS2017_NF" 
    
    batch_convert_pcaps(INPUT_PCAP_DIR, OUTPUT_CSV_DIR)