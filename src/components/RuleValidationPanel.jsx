import React, { useState, useMemo } from "react";
import { ShieldCheck, Check, X, Copy, Terminal, Layers, AlertCircle } from "lucide-react";
import { C, mono, ui } from "../constants/theme";

export function RuleValidationPanel({ flowsList = [], generatedRules = [] }) {
  // 1. ดึงเฉพาะ Flow ที่ถูกจำแนกว่าเป็น Attack
  // 1. ดึงเฉพาะ Flow ที่เป็น Attack จริงๆ (แปลงเป็น toLowerCase() เพื่อป้องกัน Case Sensitivity)
  const attackFlows = useMemo(() => {
    return flowsList.filter((f) => {
      const verdict = String(f.verdict || "").toLowerCase();
      const type = String(f.attackType || f.rule || "").toLowerCase();

      // กรองคำว่า benign, normal, 0 ออกไปทั้งหมด
      const isBenign = type.includes("benign") || type.includes("normal") || verdict === "benign";
      const isAttack = verdict === "attack" || (!isBenign && type !== "");

      return isAttack;
    });
  }, [flowsList]);

  // 2. ประมวลผล Rule (ใช้ Rule จาก Backend หากมี ถ้าไม่มีจะ Fallback ทำ Aggregation ใน Frontend)
  const displayRules = useMemo(() => {
    // กรณีที่ Backend ส่ง generatedRules มาให้ (ใช้ Rule ที่ Backend ประมวลผลแล้ว)
    if (Array.isArray(generatedRules) && generatedRules.length > 0) {
      return generatedRules.map((ruleText, idx) => {
        const sidMatch = typeof ruleText === "string" ? ruleText.match(/sid:(\d+);/) : null;
        const sid = sidMatch ? sidMatch[1] : 1000001 + idx;
        const msgMatch = typeof ruleText === "string" ? ruleText.match(/msg:"([^"]+)"/) : null;
        const attackType = msgMatch ? msgMatch[1] : "Detected Attack";

        return {
          id: `RULE-${sid}`,
          attackType,
          sid,
          ruleText: typeof ruleText === "string" ? ruleText : String(ruleText),
          flows: attackFlows.map((f) => f.id || f.flow_id || `FL-${idx}`),
          status: "Pending",
        };
      });
    }

    // กรณีไม่มี Rule จาก Backend ให้ทำ Fallback Aggregation ใน Frontend
    const groups = {};
    attackFlows.forEach((flow) => {
      const type = flow.attackType || flow.rule || "PortScan";
      const proto = String(flow.proto || flow.protocol || "tcp").toLowerCase();
      const dstIp = flow.dst || flow.dstIp || flow.dst_ip || "$HOME_NET";
      const rawPort = flow.dport || flow.dstPort || flow.dst_port || "any";

      // ✅ FIX: ป้องกัน Rule งอกเป็นพันๆ กฎ ด้วยการบังคับ dport = 'any' สำหรับ PortScan/Recon
      const isScan = type.toLowerCase().includes("scan") || type.toLowerCase().includes("recon");
      const effectiveDport = isScan ? "any" : rawPort;

      // Grouping Key ที่แท้จริง
      const groupKey = `${type}_${proto}_${dstIp}_${effectiveDport}`;

      if (!groups[groupKey]) {
        groups[groupKey] = {
          attackType: type,
          proto,
          dstIp,
          dport: effectiveDport,
          flows: [],
        };
      }
      groups[groupKey].flows.push(flow.id || flow.flow_id || `flow-${groups[groupKey].flows.length + 1}`);
    });

    return Object.values(groups).map((group, idx) => {
      const sid = 2000100 + idx;
      const isScan = group.attackType.toLowerCase().includes("scan") || group.attackType.toLowerCase().includes("recon");
      
      const flowOpt = isScan ? "flow:to_server;" : "flow:to_server,established;";
      const ruleText = `alert ${group.proto} $EXTERNAL_NET any -> ${group.dstIp} ${group.dport} (msg:"AUTOMATED DETECTED ${group.attackType} Pattern"; ${flowOpt} detection_filter:track by_src, count ${group.flows.length}, seconds 60; metadata:confidence 95; classtype:attempted-recon; sid:${sid}; rev:1;)`;

      return {
        id: `GRP-${sid}`,
        attackType: `${group.attackType} Dynamic Rule`,
        sid,
        ruleText,
        flows: group.flows,
        status: "Pending",
      };
    });
  }, [generatedRules, attackFlows]);

  const [ruleStates, setRuleStates] = useState({});
  const [copiedId, setCopiedId] = useState(null);

  const handleStatusChange = (ruleId, newStatus) => {
    setRuleStates((prev) => ({ ...prev, [ruleId]: newStatus }));
  };

  const handleCopy = (ruleId, text) => {
    navigator.clipboard.writeText(text);
    setCopiedId(ruleId);
    setTimeout(() => setCopiedId(null), 2000);
  };

  if (displayRules.length === 0) {
    return (
      <div
        className="rounded-xl p-6 text-center text-xs mt-6"
        style={{
          background: C.surface,
          border: `1px dashed ${C.hairline2}`,
          color: C.mute,
          ...ui,
        }}
      >
        <AlertCircle size={18} className="mx-auto mb-2 text-slate-500" />
        ไม่พบกลุ่มภัยคุกคามที่ต้องสร้าง Rule สำหรับ Validation
      </div>
    );
  }

  return (
    <div
      className="rounded-xl mt-6 p-5"
      style={{ background: C.surface, border: `1px solid ${C.hairline}` }}
    >
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Terminal size={18} style={{ color: C.flare }} />
          <h3 className="text-sm font-semibold" style={{ color: C.ink, ...ui }}>
            Generated Rules Validation Panel
          </h3>
          <span
            className="px-2 py-0.5 text-[11px] rounded-full"
            style={{ background: C.raised2, color: C.flare, ...mono }}
          >
            {displayRules.length} Proposed Rules
          </span>
        </div>
        <span className="text-xs" style={{ color: C.mute2, ...ui }}>
          * ตรวจสอบความถูกต้องของกฎและแมพกลุ่ม Flow ก่อน Deploy เข้า Suricata
        </span>
      </div>

      <div className="flex flex-col gap-3">
        {displayRules.map((rule) => {
          const currentStatus = ruleStates[rule.id] || rule.status;

          return (
            <div
              key={rule.id}
              className="rounded-lg p-4 transition-all"
              style={{
                background: C.raised,
                border: `1px solid ${
                  currentStatus === "Approved"
                    ? C.mint + "80"
                    : currentStatus === "Rejected"
                    ? C.crimson + "80"
                    : C.hairline
                }`,
              }}
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-3">
                  <span
                    className="text-xs font-semibold px-2.5 py-1 rounded"
                    style={{ background: C.flareSoft, color: C.flare, ...mono }}
                  >
                    {rule.attackType}
                  </span>

                  <div className="flex items-center gap-1.5 text-xs" style={{ color: C.mute, ...mono }}>
                    <Layers size={13} style={{ color: C.mute2 }} />
                    <span>Mapped ({rule.flows.length} Flows):</span>
                    <span className="text-slate-300 font-medium">
                      {rule.flows.slice(0, 4).join(", ")}
                      {rule.flows.length > 4 ? ` +${rule.flows.length - 4} more` : ""}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleCopy(rule.id, rule.ruleText)}
                    className="px-2.5 py-1 rounded text-xs flex items-center gap-1 transition-colors hover:opacity-80"
                    style={{ background: C.surface, color: C.ink, border: `1px solid ${C.hairline}`, ...ui }}
                  >
                    {copiedId === rule.id ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                    {copiedId === rule.id ? "คัดลอกแล้ว" : "Copy"}
                  </button>

                  <button
                    onClick={() => handleStatusChange(rule.id, "Approved")}
                    className="px-2.5 py-1 rounded text-xs flex items-center gap-1 font-medium transition-all active:scale-95"
                    style={{
                      background: currentStatus === "Approved" ? C.mint : C.mintSoft,
                      color: currentStatus === "Approved" ? C.void : C.mint,
                      ...ui,
                    }}
                  >
                    <ShieldCheck size={13} />
                    {currentStatus === "Approved" ? "Approved" : "Approve & Deploy"}
                  </button>

                  <button
                    onClick={() => handleStatusChange(rule.id, "Rejected")}
                    className="px-2.5 py-1 rounded text-xs flex items-center gap-1 font-medium transition-all active:scale-95"
                    style={{
                      background: currentStatus === "Rejected" ? C.crimson : C.crimsonSoft,
                      color: currentStatus === "Rejected" ? C.void : C.crimson,
                      ...ui,
                    }}
                  >
                    <X size={13} />
                    {currentStatus === "Rejected" ? "Rejected" : "Reject"}
                  </button>
                </div>
              </div>

              <div
                className="p-3 rounded font-mono text-xs break-all leading-5 select-all mt-2"
                style={{ background: C.void, color: C.mint }}
              >
                {rule.ruleText}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}