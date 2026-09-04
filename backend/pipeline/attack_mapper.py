# attack_mapper.py
import re

# เรียงลำดับคำเฉพาะเจาะจงให้อยู่ก่อนเสมอ
ATTACK_CATEGORY_MAP = {
    # 1. DoS / DDoS (ต้องอยู่บนสุดเพื่อดัก slowhttptest ก่อน)
    'ddos': 'DDoS',
    'slowloris': 'DDoS',
    'slowhttptest': 'DDoS',
    'hulk': 'DDoS',
    'goldeneye': 'DDoS',
    'syn flood': 'DDoS',
    'udp flood': 'DDoS',
    'icmp flood': 'DDoS',
    'ping of death': 'DDoS',
    'smurf': 'DDoS',
    'dos': 'DDoS',
    
    # 2. Web Attack
    'web attack': 'Web Attack',
    'sql injection': 'Web Attack',
    'sqli': 'Web Attack',
    'sql': 'Web Attack',
    'xss': 'Web Attack',
    'cross-site': 'Web Attack',
    'command injection': 'Web Attack',
    'injection': 'Web Attack',
    'path traversal': 'Web Attack',
    'directory traversal': 'Web Attack',
    
    # 3. Brute Force
    'ftp-patator': 'Brute Force',
    'ssh-patator': 'Brute Force',
    'patator': 'Brute Force',
    'password guessing': 'Brute Force',
    'credential stuffing': 'Brute Force',
    'hydra': 'Brute Force',
    'brute': 'Brute Force',
    
    # 4. PortScan / Network Reconnaissance
    'port scan': 'PortScan',
    'portscan': 'PortScan',
    'nmap': 'PortScan',
    'masscan': 'PortScan',
    'reconnaissance': 'PortScan',
    'fingerprinting': 'PortScan',
    'scan': 'PortScan',
    
    # 5. Special / Exploit / Infiltration
    'heartbleed': 'Heartbleed',
    'botnet': 'Botnet',
    'c2': 'Botnet',
    'c&c': 'Botnet',
    'ares': 'Botnet',
    'mirai': 'Botnet',
    'bot': 'Botnet',
    'infiltration': 'Infiltration',
    'infil': 'Infiltration',
    'metasploit': 'Infiltration',
    'exploit': 'Infiltration',
    'backdoor': 'Infiltration',
    'privilege escalation': 'Infiltration'
}


def normalize_attack_category(raw_text: str) -> str:
    """
    แปลงข้อความชื่อการโจมตีหรือข้อความแจ้งเตือน (Rule Msg / Label)
    ให้อยู่ในหมวดหมู่มาตรฐานเดียวกัน
    """
    if raw_text is None or str(raw_text).strip() == '':
        return 'Unknown'
    
    text_clean = str(raw_text).strip().lower()
    
    # 1. จัดการกลุ่มทราฟฟิกปกติก่อน
    if text_clean in ['benign', 'normal', 'clean', '0', 'none']:
        return 'BENIGN'
    
    # 2. ตรวจสอบตามลำดับ Dictionary (slowhttptest จะถูกจับเป็น DDoS ตรงนี้ทันที)
    for keyword, standard_cat in ATTACK_CATEGORY_MAP.items():
        if keyword in text_clean:
            return standard_cat
            
    # 3. ดักจับคำว่า 'http' แบบเดี่ยวๆ (Word Boundary) เพื่อไม่ให้ชนกับ slowhttptest
    if re.search(r'\bhttp\b|\bhttps\b', text_clean):
        return 'Web Attack'
            
    # 4. หากไม่ตรงกลุ่มใดเลย ให้ส่งคืนชื่อเดิม
    return str(raw_text).strip()


if __name__ == "__main__":
    samples = [
        "BENIGN",
        "DoS slowhttptest",              # ต้องได้ DDoS
        "slowhttptest",                  # ต้องได้ DDoS
        "HTTP Traffic Attack Alert",     # ต้องได้ Web Attack (เพราะเป็นคำว่า HTTP เดี่ยวๆ)
        "DoS Hulk",                      # ต้องได้ DDoS
        "Web Attack – Brute Force",      # ต้องได้ Web Attack
        "SSH-Patator",                   # ต้องได้ Brute Force
        "PortScan",                      # ต้องได้ PortScan
        "Heartbleed",                    # ต้องได้ Heartbleed
        "Bot"                            # ต้องได้ Botnet
    ]
    print("--- ผลการทดสอบ Normalization ---")
    for s in samples:
        print(f"'{s}' -> '{normalize_attack_category(s)}'")