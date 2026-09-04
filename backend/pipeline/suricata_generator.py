import os
import re


class SuricataRuleGenerator:
    def __init__(self, rules_filepath="generated_suricata.rules", start_sid=2000001):
        self.rules_filepath = rules_filepath
        self.current_sid = start_sid
        self._init_sid_from_file()

    def _init_sid_from_file(self):
        """อ่านไฟล์กฎเดิมเพื่อค้นหาค่า SID สูงสุด ป้องกันการใช้ SID ซ้ำ"""
        if os.path.exists(self.rules_filepath):
            with open(self.rules_filepath, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    match = re.search(r'sid\s*:\s*(\d+)\s*;', line)
                    if match:
                        sid_val = int(match.group(1))
                        if sid_val >= self.current_sid:
                            self.current_sid = sid_val + 1

    def generate_rule_from_attack(self, attack_info: dict):
        """
        แปลงข้อมูล Attack เป็น Suricata Rule ระดับ Production ที่มี Flow Control และ Detection Filter
        """
        # 1. จัดการและแปลงค่า Destination Port
        dst_port_raw = attack_info.get('Destination Port', 'any')
        try:
            p = int(float(dst_port_raw))
            dst_port = str(p) if p > 0 else 'any'
        except (ValueError, TypeError):
            dst_port = 'any'

        # 2. จัดการและแปลงค่า Protocol
        proto_raw = str(attack_info.get('Protocol', 'tcp')).strip().lower()
        if proto_raw in ['6', '6.0', 'tcp']:
            proto = 'tcp'
        elif proto_raw in ['17', '17.0', 'udp']:
            proto = 'udp'
        elif proto_raw in ['1', '1.0', 'icmp']:
            proto = 'icmp'
        elif proto_raw not in ['tcp', 'udp', 'icmp']:
            proto = 'ip'
        else:
            proto = proto_raw

        attack_type = str(attack_info.get('Attack_Type', 'Unknown Attack')).strip()

        # 3. กำหนด Flow State สำหรับ TCP
        flow_option = "flow:to_server,established; " if proto == 'tcp' else ""

        # 4. กำหนด Threshold/Rate Limit และ Classtype ตามประเภทการโจมตี
        attack_type_clean = attack_type.lower()
        if 'dos' in attack_type_clean or 'ddos' in attack_type_clean:
            filter_option = "detection_filter: track by_src, count 100, seconds 5; "
            classtype = "denial-of-service"
        elif 'scan' in attack_type_clean or 'patator' in attack_type_clean or 'portscan' in attack_type_clean:
            filter_option = "detection_filter: track by_src, count 20, seconds 10; "
            classtype = "attempted-recon"
        elif 'web' in attack_type_clean or 'sql' in attack_type_clean or 'xss' in attack_type_clean:
            filter_option = ""
            classtype = "web-application-attack"
        elif 'bot' in attack_type_clean:
            filter_option = "detection_filter: track by_src, count 10, seconds 60; "
            classtype = "trojan-activity"
        else:
            filter_option = ""
            classtype = "attempted-admin"

        # 5. ประกอบเป็น Suricata Rule
        rule_str = (
            f'alert {proto} any any -> $HOME_NET {dst_port} '
            f'({flow_option}{filter_option}'
            f'msg:"AI-Generated Rule: Detected {attack_type}"; '
            f'classtype:{classtype}; sid:{self.current_sid}; rev:1;)\n'
        )

        # 6. บันทึกลงไฟล์
        with open(self.rules_filepath, 'a', encoding='utf-8') as f:
            f.write(rule_str)

        print(f"[+] สร้าง Production-Ready Suricata Rule (SID: {self.current_sid}): {rule_str.strip()}")

        assigned_sid = self.current_sid
        self.current_sid += 1
        return rule_str.strip(), assigned_sid


if __name__ == "__main__":
    generator = SuricataRuleGenerator(rules_filepath="test_suricata.rules")
    sample_attack = {
        'Destination Port': 80,
        'Protocol': 6,
        'Attack_Type': 'DDoS'
    }
    rule, sid = generator.generate_rule_from_attack(sample_attack)