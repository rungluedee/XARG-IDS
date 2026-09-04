import { Brain, Dices, FileUp, Network, Radio, RotateCcw, Upload } from "lucide-react";
import { useMemo } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { C, ui } from "../constants/theme";
import { PipelineStage, StatCard } from "./CommonUI";
import LLMNarrativePanel from "./panels/LLMNarrativePanel";
import { RuleValidationPanel } from "./RuleValidationPanel";

export function OverviewTab({
  onUpload,
  onGenerateMock,
  onResetData,
  isGenerating,
  flowsList = [],
  attackDist = [],
  summaryData = {}, // รองรับค่า Summary จาก Backend โดยตรง
  generatedRules = [], // ✅ เพิ่มการรับ generatedRules จาก Backend หรือ State ส่วนกลาง
  llmExplanation,
  narrative,
  isNarrativeLoading = false,
  onRegenerateNarrative,
}) {
  // 1. ดึง/จัดเตรียม generatedRules จาก Props หรือดึงจาก summaryData หากมีแนบมา
  const effectiveGeneratedRules = useMemo(() => {
    if (Array.isArray(generatedRules) && generatedRules.length > 0) {
      return generatedRules;
    }
    if (Array.isArray(summaryData?.generatedRules) && summaryData.generatedRules.length > 0) {
      return summaryData.generatedRules;
    }
    if (Array.isArray(summaryData?.generated_rules) && summaryData.generated_rules.length > 0) {
      return summaryData.generated_rules;
    }
    return [];
  }, [generatedRules, summaryData]);

  // 2. คำนวณสถิติโดยมี Fallback รองรับทั้งข้อมูล Array และ Summary Object จาก Backend
  const totalFlows = useMemo(() => {
    return summaryData.totalFlows ?? summaryData.total_flows ?? flowsList.length;
  }, [flowsList, summaryData]);

  const ruleMatched = useMemo(() => {
    if (summaryData.ruleMatched !== undefined || summaryData.rule_matched !== undefined) {
      return summaryData.ruleMatched ?? summaryData.rule_matched;
    }
    return flowsList.filter((f) => f.source === "rule" || f.rule || f.ruleId).length;
  }, [flowsList, summaryData]);

  const model1Attack = useMemo(() => {
    if (summaryData.mlFlagged !== undefined || summaryData.ml_flagged !== undefined) {
      return summaryData.mlFlagged ?? summaryData.ml_flagged;
    }
    return flowsList.filter(
      (f) => (f.source === "model1" || f.source === "model2") && f.verdict === "Attack"
    ).length;
  }, [flowsList, summaryData]);

  const benignCount = useMemo(() => {
    if (summaryData.benign !== undefined) return summaryData.benign;
    return flowsList.filter((f) => f.verdict === "Normal" || f.verdict === "Benign").length;
  }, [flowsList, summaryData]);

  const confirmedAttacks = useMemo(() => {
    if (summaryData.confirmedAttacks !== undefined || summaryData.confirmed_attacks !== undefined) {
      return summaryData.confirmedAttacks ?? summaryData.confirmed_attacks;
    }
    return flowsList.filter((f) => f.verdict === "Attack").length;
  }, [flowsList, summaryData]);

  // 3. ปรับแต่งข้อมูลกราฟ Bar Chart (รวม BENIGN และ Benign เป็นกลุ่มเดียวกัน)
  const formattedAttackDist = useMemo(() => {
    // กรณีใช้ข้อมูล attackDist ที่แปลงมาจาก backend
    if (flowsList.length === 0 && attackDist.length > 0) {
      const mergedMap = {};
      attackDist.forEach((item) => {
        const isBenign = item.name.toUpperCase() === "BENIGN";
        const keyName = isBenign ? "Benign" : item.name;
        mergedMap[keyName] = (mergedMap[keyName] || 0) + item.count;
      });

      return Object.entries(mergedMap).map(([name, count]) => ({
        name,
        count,
        color: name === "Benign" ? C.mint : C.crimson,
      }));
    }

    if (flowsList.length === 0) {
      return [{ name: "Benign", count: 0, color: C.mint }];
    }

    const distMap = {};
    let benign = 0;

    flowsList.forEach((f) => {
      const rawVerdict = (f.verdict || f.label || "").toString().toUpperCase();
      const rawType = (f.attackType || f.attack_type || f.prediction || f.rule || "").toString().toUpperCase();

      // ตรวจจับกลุ่ม Benign ทั้งหมดไม่ว่าจะพิมพ์เล็กหรือใหญ่
      if (rawVerdict === "NORMAL" || rawVerdict === "BENIGN" || rawType === "BENIGN") {
        benign++;
      } else {
        const typeName = f.attackType || f.attack_type || f.prediction || f.rule || "Other Attack";
        if (typeName.toUpperCase() === "BENIGN") {
          benign++;
        } else {
          distMap[typeName] = (distMap[typeName] || 0) + 1;
        }
      }
    });

    const attackItems = Object.entries(distMap).map(([name, count]) => ({
      name,
      count,
      color: C.crimson,
    }));

    return [{ name: "Benign", count: benign, color: C.mint }, ...attackItems];
  }, [flowsList, attackDist]);

  // 4. ดึงข้อมูล LLM Narrative
  const activeNarrative = useMemo(() => {
    const raw = llmExplanation || narrative;
    if (!raw) return null;

    if (typeof raw === "object") {
      return {
        summary: raw.summary || raw.explanation || raw.text || raw.narrative || "",
        recommendation:
          raw.recommendation ||
          raw.recommended_action ||
          raw.recommendedAction ||
          raw.action ||
          "",
        latency: raw.latency || raw.latency_ms || raw.latencyMs || 0,
      };
    }

    if (typeof raw === "string") {
      try {
        const parsed = JSON.parse(raw);
        return {
          summary: parsed.summary || parsed.explanation || parsed.text || raw,
          recommendation:
            parsed.recommendation ||
            parsed.recommended_action ||
            parsed.recommendedAction ||
            "",
          latency: parsed.latency || parsed.latency_ms || 0,
        };
      } catch {
        return { summary: raw, recommendation: "", latency: 0 };
      }
    }

    return null;
  }, [llmExplanation, narrative]);

  return (
    <div className="flex flex-col gap-6">
      {/* Action Bar */}
      <div
        className="rounded-xl p-5 flex flex-wrap items-center justify-between gap-4"
        style={{
          background: C.surface,
          border: `1px dashed ${C.hairline2}`,
        }}
      >
        <div className="flex items-center gap-3">
          <div
            className="w-10 h-10 rounded-lg flex items-center justify-center"
            style={{ background: C.flareSoft }}
          >
            <Upload size={18} style={{ color: C.flare }} />
          </div>

          <div>
            <div className="text-sm font-medium" style={{ color: C.ink, ...ui }}>
              จัดการข้อมูล Network Traffic
            </div>
            <div className="text-xs" style={{ color: C.mute, ...ui }}>
              รองรับ .pcap, .pcapng หรือเลือกสุ่มสร้าง/รีเซ็ตข้อมูลทดสอบ
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          <button
            type="button"
            onClick={(e) => {
              e.preventDefault();
              onResetData?.();
            }}
            className="px-3.5 py-2 rounded-lg text-sm font-medium shrink-0 flex items-center gap-2 transition-all hover:bg-red-500/10 active:scale-95"
            style={{
              background: C.crimsonSoft,
              color: C.crimson,
              border: `1px solid ${C.crimson}40`,
              ...ui,
            }}
            title="รีเซ็ตสถิติและข้อมูล Traffic เป็น 0"
          >
            <RotateCcw size={15} />
            รีเซ็ตเป็น 0
          </button>

          <button
            type="button"
            onClick={(e) => {
              e.preventDefault();
              onGenerateMock?.();
            }}
            disabled={isGenerating}
            className="px-4 py-2 rounded-lg text-sm font-medium shrink-0 flex items-center gap-2 transition-all hover:opacity-90 active:scale-95 disabled:opacity-50"
            style={{
              background: C.raised2,
              color: C.ink,
              border: `1px solid ${C.hairline2}`,
              ...ui,
            }}
          >
            <Dices
              size={15}
              className={`text-amber-400 ${isGenerating ? "animate-spin" : ""}`}
            />
            {isGenerating ? "กำลังเจนข้อมูล..." : "สุ่มสร้างข้อมูลจำลอง"}
          </button>

          <button
            type="button"
            onClick={(e) => {
              e.preventDefault();
              onUpload?.();
            }}
            className="px-4 py-2 rounded-lg text-sm font-medium shrink-0 flex items-center gap-2 cursor-pointer"
            style={{
              background: C.flare,
              color: C.void,
              ...ui,
            }}
          >
            <FileUp size={15} />
            เลือกไฟล์
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
        <StatCard
          label="Total Flows"
          value={totalFlows.toLocaleString()}
          sub=""
        />

        <StatCard
          label="Rule Matched"
          value={ruleMatched.toLocaleString()}
          sub="Suricata IDS Rules"
          accent={C.amber}
        />

        <StatCard
          label="ML Flagged"
          value={model1Attack.toLocaleString()}
          sub="XGBoost Attack Classifier"
          accent={C.flare}
        />

        <StatCard
          label="Benign"
          value={benignCount.toLocaleString()}
          sub="Normal Traffic"
          accent={C.mint}
        />

        <StatCard
          label="Confirmed Attacks"
          value={confirmedAttacks.toLocaleString()}
          sub="Rule + ML Identified"
          accent={C.crimson}
        />
      </div>

      {/* Detection Pipeline */}
      <div>
        <div
          className="text-xs uppercase tracking-wider mb-2 font-medium"
          style={{ color: C.mute2, ...ui }}
        >
          Detection Pipeline Architecture
        </div>

        <div className="flex items-center gap-3 flex-wrap lg:flex-nowrap">
          <PipelineStage
            icon={Radio}
            title="Tier 1: Rule-based"
            sub="Suricata Signature Match"
            count={ruleMatched.toLocaleString()}
            tone={{
              bg: C.amberSoft,
              color: C.amber,
            }}
          />

          {/* Tier 2: XGBoost (แสดงจำนวนที่ XGBoost ตรวจพบ Attack) */}
          <PipelineStage
            icon={Network}
            title="Tier 2: XGBoost"
            sub="Multi-class Attack Classifier"
            count={model1Attack.toLocaleString()} // 1,697 (หรือจำนวนที่ XGBoost จำแนกได้)
            tone={{ bg: C.raised2, color: C.mute }}
          />

          {/* Tier 3: Isolation Forest (แสดงจำนวน Benign ที่ส่งเข้ามาสแกน Anomaly) */}
          <PipelineStage
            icon={Brain}
            title="Tier 3: Isolation Forest"
            sub="Anomaly & Zero-day Detection"
            count={benignCount.toLocaleString()} // 57 (จำนวน Traffic ปกติที่ส่งเข้ามาตรวจ Anomaly)
            tone={{ bg: C.flareSoft, color: C.flare }}
            last
          />
        </div>

        <div className="mt-3 text-xs flex items-center gap-4 flex-wrap" style={{ color: C.mute2, ...ui }}>
          <span>• Traffic ที่ตรงกับ Suricata Rules จะถูกจัดเก็บทันทีโดยไม่ผ่าน ML</span>
          <span>• Traffic ที่หลุดมาจะส่งให้ XGBoost จำแนกการโจมตีที่รู้จัก</span>
          <span>• ส่ง Traffic ที่เป็น Benign ให้ Isolation Forest สแกนหา Anomaly/Zero-day ต่อไป</span>
        </div>
      </div>

      {/* Content Grid: Bar Chart & LLM Narrative Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Bar Chart: Traffic & Attack Distribution */}
        <div
          className="rounded-xl p-5"
          style={{
            background: C.surface,
            border: `1px solid ${C.hairline}`,
          }}
        >
          <div
            className="text-sm font-medium mb-4"
            style={{ color: C.ink, ...ui }}
          >
            Traffic & Attack Distribution
          </div>

          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={formattedAttackDist} margin={{ left: -10 }}>
              <CartesianGrid
                strokeDasharray="3 3"
                stroke={C.hairline}
                vertical={false}
              />
              <XAxis
                dataKey="name"
                tick={{ fill: C.mute, fontSize: 10 }}
                axisLine={{ stroke: C.hairline }}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: C.mute, fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  background: C.raised,
                  border: `1px solid ${C.hairline2}`,
                  borderRadius: 8,
                  fontSize: 12,
                }}
                labelStyle={{ color: C.ink }}
                cursor={{ fill: C.raised2 }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {formattedAttackDist.map((d, i) => (
                  <Cell key={i} fill={d.color || C.flare} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Stage 06 · Language Layer: LLM Narrative Panel */}
        <LLMNarrativePanel
          narrative={activeNarrative}
          loading={isNarrativeLoading}
          onRegenerate={onRegenerateNarrative}
        />
      </div>

      {/* Rule Validation Panel - ส่งต่อทั้ง flowsList และ generatedRules ที่ประมวลผลแล้ว */}
      <RuleValidationPanel 
        flowsList={flowsList} 
        generatedRules={effectiveGeneratedRules} 
      />
    </div>
  );
}