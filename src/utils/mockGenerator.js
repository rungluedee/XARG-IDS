import { initialAttackDistribution, initialTimeline } from "../constants/mockData";

const SAMPLE_IPS = [
  "10.0.0.14", "10.0.0.88", "192.168.1.105", "172.16.0.4",
  "203.0.113.88", "198.51.100.12", "10.0.0.42", "192.0.2.145",
];

const ATTACK_TYPES = ["DoS", "DDoS", "Port Scan", "Brute Force", "Web Attack", "Bot"];
const SHAP_KEYS = ["bruteforce", "portscan", "ddos", "bruteforce2", "webattack"];
const DEST_PORTS = [80, 443, 22, 53, 3389, 8080, 6667];

const getRandomItem = (arr) => arr[Math.floor(Math.random() * arr.length)];
const getRandomInt = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

export function generateMockDataset() {
  const generatedFlows = Array.from({ length: 10 }, () => {
    const id = `FL-${getRandomInt(1000, 9999)}`;
    const isAttack = Math.random() < 0.6;
    const src = getRandomItem(SAMPLE_IPS);
    const dst = getRandomItem(SAMPLE_IPS);
    const sport = getRandomInt(1024, 51024);
    const dport = getRandomItem(DEST_PORTS);
    const proto = Math.random() > 0.25 ? "TCP" : "UDP";

    const now = new Date();
    const ts = `${String(now.getHours()).padStart(2, "0")}:${String(
      now.getMinutes()
    ).padStart(2, "0")}:${String(now.getSeconds()).padStart(2, "0")}.${getRandomInt(100, 999)}`;

    if (!isAttack) {
      return {
        id, src, dst, sport, dport, proto, ts,
        verdict: "Normal",
        source: "model1",
        model1Verdict: "Normal",
        conf: +(0.9 + Math.random() * 0.09).toFixed(3),
      };
    }

    const atk = getRandomItem(ATTACK_TYPES);
    const isRule = Math.random() < 0.3;

    return {
      id, src, dst, sport, dport, proto, ts,
      verdict: "Attack",
      source: isRule ? "rule" : "model2",
      attackType: atk,
      model1Verdict: "Attack",
      conf: +(0.85 + Math.random() * 0.14).toFixed(3),
      model1Confidence: +(0.9 + Math.random() * 0.09).toFixed(3),
      shapKey: getRandomItem(SHAP_KEYS),
      ...(isRule && {
        rule: `ET ${atk.toUpperCase()} Traffic Detected`,
        ruleId: String(getRandomInt(2000000, 2800000)),
        ruleMessage: `Possible ${atk} intrusion pattern identified`,
      }),
    };
  });

  const featuresMap = {};
  generatedFlows.forEach((f) => {
    featuresMap[f.id] = [
      ["Flow Duration", String(getRandomInt(50, 3050))],
      ["Total Fwd Packets", String(getRandomInt(1, 500))],
      ["Total Backward Packets", String(getRandomInt(0, 100))],
      ["Flow Bytes/s", (Math.random() * 10000 + 100).toFixed(1)],
      ["SYN Flag Count", String(getRandomInt(0, 10))],
      ["Packet Length Mean", (Math.random() * 800 + 40).toFixed(1)],
    ];
  });

  const attackDist = initialAttackDistribution.map((item) => ({
    ...item,
    count: getRandomInt(10, 160),
  }));

  const timelineList = initialTimeline.map((item) => ({
    ...item,
    normal: getRandomInt(20, 140),
    attack: getRandomInt(0, 25),
  }));

  return {
    flowsList: generatedFlows,
    featuresData: featuresMap,
    attackDist,
    timelineList,
    llmExplanation:
      "จากการวิเคราะห์ traffic พบความผิดปกติในลักษณะ DoS/DDoS โดยมีปริมาณ SYN Flag สูงผิดปกติ แนะนำให้ทำการระงับ IP ต้นทางและตรวจสอบ Firewall Rules เพิ่มเติม",
  };
}