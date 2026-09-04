import { C } from "../constants/theme";

// Helper: ดึงและจัดรูปแบบเวลาระดับมิลลิวินาที (HH:mm:ss.SSS)
function formatFlowTimestamp(item) {
  const rawTs =
    item.bidirectional_first_seen_ms ??
    item.first_seen_ms ??
    item.first_seen ??
    item.timestamp_ms ??
    item.timestamp ??
    item.time ??
    item.ts ??
    item.start_time ??
    item.created_at;

  // หากไม่มีฟิลด์เวลาส่งมาจาก Backend จะคืนค่า "—" (ไม่สุ่มเวลาปัจจุบัน)
  if (rawTs === undefined || rawTs === null || rawTs === "") {
    return "—";
  }

  try {
    let dateObj;
    if (typeof rawTs === "number") {
      dateObj = new Date(rawTs < 1e11 ? rawTs * 1000 : rawTs);
    } else if (typeof rawTs === "string") {
      const parsedNum = Number(rawTs);
      if (!isNaN(parsedNum) && parsedNum > 0) {
        dateObj = new Date(parsedNum < 1e11 ? parsedNum * 1000 : parsedNum);
      } else {
        dateObj = new Date(rawTs);
      }
    }

    if (dateObj && !isNaN(dateObj.getTime())) {
      return dateObj.toLocaleTimeString("th-TH", {
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        fractionalSecondDigits: 3,
      });
    }
  } catch (e) {
    console.warn("Timestamp format error:", e);
  }

  return String(rawTs);
}

export function adaptBackendPayload(backendData) {
  if (!backendData) {
    return {
      flowsList: [],
      attackDist: [],
      timelineList: [],
      summary: { totalFlows: 0, ruleMatched: 0, mlFlagged: 0, benign: 0, confirmedAttacks: 0 },
      llmExplanation: null,
      featuresData: {},
    };
  }

  const rawFlows = backendData.detections || backendData.flows || backendData.flows_list || [];
  const featuresData = {};

  const flowsList = Array.isArray(rawFlows) ? rawFlows.map((item, idx) => {
    // 🔍 ปริ้นท์ดูคีย์ทั้งหมดที่ Backend ส่งมาใน Console เพื่อตรวจชื่อฟิลด์เวลา
    if (idx === 0) {
      console.log("🔍 Backend Flow Keys (detections[0]):", Object.keys(item));
    }

    const isT1 = 
      item.detection_tier === "tier1" || 
      item.detection_tier === 1 ||
      item.source === "rule" || 
      item.source === "T1" ||
      item.source === "tier1" ||
      (typeof item.detected_by === "string" && item.detected_by.toLowerCase().includes("rule")) ||
      (typeof item.detected_by === "string" && item.detected_by.toLowerCase().includes("suricata")) ||
      Boolean(item.rule || item.rule_id || item.ruleId || item.rule_category);

    const isT2 = item.detection_tier === "tier2" || item.detection_tier === 2 || item.source === "model1" || item.source === "isolation_forest";

    const rawType = (item.attack_type || item.attackType || item.prediction || "").toString().trim();
    const upperType = rawType.toUpperCase();

    const isBenign = upperType === "BENIGN" || upperType === "NORMAL" || upperType === "";

    let verdict = "Normal";
    let attackType = "BENIGN";

    if (isBenign) {
      verdict = "Normal";
      attackType = "BENIGN";
    } else if (isT1 && (upperType === "UNKNOWN" || (item.evidence && item.evidence[0]?.includes("TLS Handshake Failure")))) {
      verdict = "Info";
      attackType = "TLS Handshake Info";
    } else {
      verdict = "Attack";
      attackType = rawType || "Malicious Traffic";
    }

    const rawId = item.flow_id || item.id || `FL-${idx + 1000}`;
    const id = `${rawId}-${idx}`;

    if (item.features || item.top_features || item.topKFeatures) {
      featuresData[id] = item.topKFeatures || item.top_features || item.features;
    }

    let sourceTag = "model2";
    if (isT1) sourceTag = "rule";
    else if (isT2) sourceTag = "model1";
    else if (item.source || item.detected_by) sourceTag = item.source || item.detected_by;

    return {
      id: id,
      src: item.src_ip || item.src || "-",
      dst: item.dst_ip || item.dst || "-",
      sport: item.src_port || item.sport || 0,
      dport: item.dst_port || item.dport || 0,
      proto: item.protocol || item.proto || "TCP",
      ts: formatFlowTimestamp(item),
      verdict: verdict,
      source: sourceTag,
      attackType: attackType,
      conf: item.confidence || item.conf || 0,
      features: item.features || {},
      top_features: item.top_features || item.topKFeatures || [],
      ...(isT1
        ? {
            rule: item.rule_category || item.rule || "Suricata Rule",
            ruleId: item.rule_id || item.ruleId || "SID-UNKNOWN",
            ruleMessage: item.evidence?.[0] || item.ruleMessage || "Signature match found",
          }
        : {}),
    };
  }) : [];

  const totalFlows = typeof backendData.flows === "number" 
    ? backendData.flows 
    : (backendData.summary?.totalFlows ?? backendData.total_flows ?? backendData.totalFlows ?? flowsList.length);
  
  const ruleMatched = backendData.summary?.ruleMatched ?? 
    backendData.tier1?.flows_matched ?? 
    flowsList.filter(f => f.source === "rule").length;
  
  const mlFlagged = backendData.summary?.mlFlagged ?? 
    backendData.tier2?.flows_flagged ?? 
    backendData.tier2?.flows_forwarded ??
    flowsList.filter(f => f.verdict === "Attack" || f.source === "model1" || f.source === "model2").length;

  const confirmedAttacks = backendData.summary?.confirmedAttacks ?? flowsList.filter(f => f.verdict === "Attack").length;
  const benign = backendData.summary?.benign ?? flowsList.filter(f => f.verdict === "Normal").length;

  const summary = {
    totalFlows,
    ruleMatched,
    mlFlagged,
    benign,
    confirmedAttacks,
  };

  let attackDist = [];
  if (flowsList.length > 0) {
    const distMap = {};
    flowsList.forEach(f => {
      let key = f.attackType;
      if (f.verdict === "Normal") key = "Benign";
      distMap[key] = (distMap[key] || 0) + 1;
    });

    const colorPalette = [C?.crimson || "#ef4444", C?.amber || "#f59e0b", C?.flare || "#f97316", "#a855f7"];
    let colorIdx = 0;

    attackDist = Object.entries(distMap).map(([name, count]) => ({
      name,
      count,
      color: name === "Benign" ? (C?.mint || "#10b981") : (name.includes("Info") ? "#3b82f6" : colorPalette[colorIdx++ % colorPalette.length]),
    }));
  }

  const timelineList = backendData.timeline || backendData.timelineList || [
    {
      t: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      normal: benign,
      attack: confirmedAttacks,
    },
  ];

  const rawLlm =
    backendData.llm_narrative ||
    backendData.llmNarrative ||
    backendData.llm ||
    backendData.llm_explanation ||
    backendData.tier3?.benign_summary;

  let llmExplanation = null;

  if (rawLlm) {
    if (typeof rawLlm === "object") {
      llmExplanation = {
        summary: rawLlm.summary || "ไม่พบสรุปข้อมูลจาก LLM",
        recommendedAction:
          rawLlm.recommendedAction ||
          rawLlm.recommended_action ||
          "ตรวจสอบรายละเอียดเพิ่มเติมใน Flow Inspector",
      };
    } else if (typeof rawLlm === "string") {
      llmExplanation = {
        summary: rawLlm,
        recommendedAction: "ตรวจสอบและเฝ้าระวัง Traffic ปลายทางเพิ่มเติม",
      };
    }
  }

  return {
    flowsList,
    summary,
    attackDist,
    timelineList,
    llmExplanation,
    featuresData,
  };
}