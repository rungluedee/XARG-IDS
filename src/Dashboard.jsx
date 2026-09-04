import { Activity, Layers, RefreshCw, RotateCcw, ShieldAlert, ShieldCheck } from "lucide-react";
import { useRef, useState } from "react";
import { initialAttackDistribution, initialTimeline } from "./constants/mockData";
import { C, mono, ui } from "./constants/theme";
import { analyzePcapFile } from "./services/api";
import { adaptBackendPayload } from "./utils/dataAdapter";
import { generateMockDataset } from "./utils/mockGenerator";

import { FlowDrawer } from "./components/FlowDrawer";
import { FlowsTab } from "./components/FlowsTab";
import { OverviewTab } from "./components/OverviewTab";
import { PerformanceTab } from "./components/PerformanceTab";

const TABS = [
  { id: "overview", label: "ภาพรวม", icon: Activity },
  { id: "flows", label: "Flow Inspector", icon: Layers },
  { id: "performance", label: "ประสิทธิภาพโมเดล", icon: ShieldCheck },
];

export default function Dashboard() {
  const [tab, setTab] = useState("overview");
  const [selectedFlow, setSelectedFlow] = useState(null);

  // State เก็บข้อมูล Dashboard
  const [flowsList, setFlowsList] = useState([]);
  const [summaryData, setSummaryData] = useState({}); // ✅ เพิ่ม State สำหรับเก็บ Summary
  const [attackDist, setAttackDist] = useState(() =>
    initialAttackDistribution.map((item) => ({ ...item, count: 0 }))
  );
  const [timelineList, setTimelineList] = useState(() =>
    initialTimeline.map((item) => ({ ...item, normal: 0, attack: 0 }))
  );
  const [featuresData, setFeaturesData] = useState({});
  const [llmExplanation, setLlmExplanation] = useState("");

  // Status States
  const [isGenerating, setIsGenerating] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const fileInputRef = useRef(null);

  const handleUploadClick = (e) => {
    if (e && e.preventDefault) e.preventDefault();
    fileInputRef.current?.click();
  };

  const handleFileChange = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    setIsAnalyzing(true);
    try {
      // 1. เรียก API และเก็บผลลัพธ์ลงในตัวแปร rawPayload
      const rawPayload = await analyzePcapFile(file);
      console.log("📥 Raw Backend Response:", rawPayload);

      // 2. แปลงโครงสร้างข้อมูล
      const adapted = adaptBackendPayload(rawPayload) || {};
      const rawDetections = rawPayload?.detections || [];

      const baseFlows =
        adapted.flowsList && adapted.flowsList.length > 0
          ? adapted.flowsList
          : rawDetections;

      // 3. รวม features และ top_features เข้าไปในทุก Flow
      const extractedFlows = baseFlows.map((flow, idx) => {
        const rawMatch = rawDetections[idx] || {};
        return {
          ...flow,
          features: flow.features || rawMatch.features || {},
          top_features: flow.top_features || rawMatch.top_features || [],
        };
      });

      const extractedLlm =
        adapted.llmExplanation ||
        rawPayload?.llm_narrative ||
        rawPayload?.llmNarrative ||
        rawPayload?.llm ||
        "";

      // 4. อัปเดต State ต่างๆ ของ React
      setFlowsList(extractedFlows);
      setSummaryData(adapted.summary || rawPayload?.summary || {});

      if (adapted.attackDist && adapted.attackDist.length > 0) {
        setAttackDist(adapted.attackDist);
      }
      if (adapted.timelineList && adapted.timelineList.length > 0) {
        setTimelineList(adapted.timelineList);
      }
      setLlmExplanation(extractedLlm);
    } catch (error) {
      console.error("Analysis Error:", error);
      const errorMsg = error.response?.data?.message || error.message;
      alert(`เกิดข้อผิดพลาดในการวิเคราะห์ไฟล์: ${errorMsg}`);
    } finally {
      setIsAnalyzing(false);
      event.target.value = "";
    }
  };

  const resetDataToZero = () => {
    setFlowsList([]);
    setSummaryData({ totalFlows: 0, ruleMatched: 0, mlFlagged: 0, benign: 0, confirmedAttacks: 0 });
    setAttackDist((prev) => prev.map((item) => ({ ...item, count: 0 })));
    setTimelineList((prev) => prev.map((item) => ({ ...item, normal: 0, attack: 0 })));
    setFeaturesData({});
    setSelectedFlow(null);
    setLlmExplanation("");
  };

  const handleGenerateMockData = () => {
    setIsGenerating(true);
    setTimeout(() => {
      const mockData = generateMockDataset();
      setFlowsList(mockData.flowsList);
      setSummaryData(mockData.summary || {});
      setFeaturesData(mockData.featuresData);
      setAttackDist(mockData.attackDist);
      setTimelineList(mockData.timelineList);
      setLlmExplanation(mockData.llmExplanation);
      setIsGenerating(false);
    }, 600);
  };

  return (
    <div className="min-h-screen w-full" style={{ background: C.void, ...ui }}>
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileChange}
        accept=".pcap,.pcapng,.csv"
        className="hidden"
      />

      {/* Header Bar */}
      <header
        className="flex items-center gap-3 px-6 py-4"
        style={{ borderBottom: `1px solid ${C.hairline}` }}
      >
        <div className="w-8 h-8 rounded-lg flex items-center justify-center" style={{ background: C.flare }}>
          <ShieldAlert size={16} style={{ color: C.void }} />
        </div>

        <div>
          <h1 className="text-sm font-semibold" style={{ color: C.ink }}>NetGuard</h1>
          <p className="text-[11px]" style={{ color: C.mute2, ...mono }}>
            Hybrid Rule-based + ML Intrusion Detection Console
          </p>
        </div>

        {isAnalyzing && (
          <div className="flex items-center gap-2 text-xs font-semibold animate-pulse ml-4" style={{ color: C.amber, ...mono }}>
            <RefreshCw size={13} className="animate-spin" />
            ANALYZING PCAP FILE...
          </div>
        )}

        <div className="ml-auto flex items-center gap-2">
          <button
            type="button"
            onClick={resetDataToZero}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all hover:bg-red-500/10 active:scale-95"
            style={{ background: C.crimsonSoft, color: C.crimson, border: `1px solid ${C.crimson}40`, ...mono }}
            title="รีเซ็ตข้อมูลเป็น 0"
          >
            <RotateCcw size={13} />
            RESET TO 0
          </button>

          <button
            type="button"
            onClick={handleGenerateMockData}
            disabled={isGenerating || isAnalyzing}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all hover:opacity-90 active:scale-95 disabled:opacity-50"
            style={{ background: C.raised2, color: C.amber, border: `1px solid ${C.hairline2}`, ...mono }}
          >
            <RefreshCw size={13} className={isGenerating ? "animate-spin" : ""} />
            {isGenerating ? "GENERATING..." : "MOCK DATA"}
          </button>

          <div className="flex items-center gap-2 text-xs ml-2" style={{ color: C.mint, ...mono }}>
            <span className="w-1.5 h-1.5 rounded-full" style={{ background: C.mint }} />
            OFFLINE ANALYSIS
          </div>
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="flex items-center gap-1 px-6 pt-4" style={{ borderBottom: `1px solid ${C.hairline}` }}>
        {TABS.map(({ id, label, icon: Icon }) => {
          const active = tab === id;
          return (
            <button
              key={id}
              type="button"
              onClick={() => setTab(id)}
              className="flex items-center gap-2 px-4 py-2.5 text-sm font-medium rounded-t-lg transition-colors"
              style={{
                color: active ? C.ink : C.mute,
                background: active ? C.surface : "transparent",
                border: active ? `1px solid ${C.hairline}` : "1px solid transparent",
                borderBottom: active ? `1px solid ${C.surface}` : "none",
                marginBottom: -1,
              }}
            >
              <Icon size={14} />
              {label}
            </button>
          );
        })}
      </nav>

      {/* Main Content Area */}
      <main className="p-6">
        {tab === "overview" && (
          <OverviewTab
            onUpload={handleUploadClick}
            onGenerateMock={handleGenerateMockData}
            onResetData={resetDataToZero}
            isGenerating={isGenerating || isAnalyzing}
            flowsList={flowsList}
            summaryData={summaryData} // ✅ ส่ง summaryData ต่อให้ OverviewTab
            attackDist={attackDist}
            timelineList={timelineList}
            llmExplanation={llmExplanation}
          />
        )}

        {tab === "flows" && <FlowsTab flowsList={flowsList} onSelect={setSelectedFlow} />}
        {tab === "performance" && <PerformanceTab />}
      </main>

      <FlowDrawer
        flow={selectedFlow}
        featuresData={featuresData}
        onClose={() => setSelectedFlow(null)}
      />
    </div>
  );
}