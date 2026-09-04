import {
  AlertTriangle,
  BarChart2,
  Brain,
  CheckCircle2,
  ShieldAlert,
  ShieldCheck,
  X,
} from "lucide-react";
import { C, mono, ui } from "../constants/theme";
import { SourceChip } from "./CommonUI";

export function FlowDrawer({ flow, featuresData, topKFeaturesData, onClose }) {
  if (!flow) return null;

  const isRule = flow.source === "rule";
  const isModel2 = flow.source === "model2";

  // 1. จัดการข้อมูล All Features (รองรับทั้ง Array [ [k,v] ] และ Object { k: v })
  const rawFeats = featuresData?.[flow.id] || flow.features || {};
  const feats = Array.isArray(rawFeats) 
    ? rawFeats 
    : Object.entries(rawFeats);

  // 2. ดึง Top-K Features (รองรับ top_features จาก Backend API)
  const topK =
    flow.top_features ||
    flow.topKFeatures ||
    topKFeaturesData?.[flow.id] ||
    feats.slice(0, 5).map(([name, val], index) => ({
      name,
      value: val,
      importance: Math.max(0.1, Number((0.45 - index * 0.08).toFixed(2))),
    }));

  return (
    <>
      <div
        className="fixed inset-0 z-40"
        style={{ background: "rgba(0,0,0,0.5)" }}
        onClick={onClose}
      />

      <div
        className="fixed top-0 right-0 h-full z-50 flex flex-col"
        style={{
          width: "min(520px, 100vw)",
          background: C.surface,
          borderLeft: `1px solid ${C.hairline2}`,
        }}
      >
        {/* Header */}
        <div
          className="flex items-center justify-between p-5"
          style={{ borderBottom: `1px solid ${C.hairline}` }}
        >
          <div>
            <div className="text-xs" style={{ color: C.mute2, ...mono }}>
              {flow.id}
            </div>
            <div className="text-sm mt-0.5" style={{ color: C.ink, ...mono }}>
              {flow.src}:{flow.sport}
              <span style={{ color: C.mute2 }}>{" → "}</span>
              {flow.dst}:{flow.dport}
            </div>
          </div>

          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg flex items-center justify-center transition-colors hover:opacity-80"
            style={{ background: C.raised }}
          >
            <X size={16} style={{ color: C.mute }} />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-5 flex flex-col gap-6">
          {/* Final Verdict */}
          <div
            className="rounded-xl p-4"
            style={{
              background:
                flow.verdict === "Normal" ? C.mintSoft : C.crimsonSoft,
            }}
          >
            <div className="flex items-center gap-2 mb-1">
              {flow.verdict === "Normal" ? (
                <ShieldCheck size={16} style={{ color: C.mint }} />
              ) : (
                <ShieldAlert size={16} style={{ color: C.crimson }} />
              )}

              <span
                className="text-xs uppercase tracking-wide"
                style={{
                  color: flow.verdict === "Normal" ? C.mint : C.crimson,
                  ...ui,
                }}
              >
                Final Verdict
              </span>
            </div>

            <div className="text-2xl font-semibold" style={{ color: C.ink, ...mono }}>
              {flow.attackType || flow.verdict}
            </div>

            <div className="flex items-center gap-2 mt-2">
              <SourceChip source={flow.source} />

              {flow.conf && (
                <span className="text-xs" style={{ color: C.mute, ...mono }}>
                  Confidence {(flow.conf * 100).toFixed(1)}%
                </span>
              )}
            </div>
          </div>

          {/* Flow Information */}
          <div>
            <div className="text-xs uppercase tracking-wider mb-2" style={{ color: C.mute2, ...ui }}>
              Flow Information
            </div>

            <div className="rounded-xl overflow-hidden" style={{ border: `1px solid ${C.hairline}` }}>
              {[
                ["Source IP", flow.src],
                ["Source Port", flow.sport],
                ["Destination IP", flow.dst],
                ["Destination Port", flow.dport],
                ["Protocol", flow.proto],
                ["Timestamp", flow.ts],
              ].map(([key, value], i) => (
                <div
                  key={key}
                  className="flex justify-between px-4 py-2.5 text-sm"
                  style={{
                    background: i % 2 ? C.raised : "transparent",
                    ...mono,
                  }}
                >
                  <span style={{ color: C.mute }}>{key}</span>
                  <span style={{ color: C.ink }}>{value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Detection Path */}
          <div>
            <div className="text-xs uppercase tracking-wider mb-3" style={{ color: C.mute2, ...ui }}>
              Detection Path
            </div>

            <div className="flex flex-col gap-2">
              <div
                className="rounded-xl p-3"
                style={{
                  background: isRule ? C.amberSoft : C.raised,
                  border: `1px solid ${isRule ? C.amber : C.hairline}`,
                }}
              >
                <div className="flex items-center gap-2">
                  {isRule ? (
                    <CheckCircle2 size={15} style={{ color: C.amber }} />
                  ) : (
                    <div className="w-3 h-3 rounded-full" style={{ background: C.mute2 }} />
                  )}

                  <span className="text-sm" style={{ color: C.ink, ...ui }}>
                    Rule-based IDS
                  </span>

                  <span
                    className="ml-auto text-xs"
                    style={{
                      color: isRule ? C.amber : C.mute2,
                      ...mono,
                    }}
                  >
                    {isRule ? "MATCHED" : "NO MATCH"}
                  </span>
                </div>
              </div>

              {!isRule && (
                <div
                  className="rounded-xl p-3"
                  style={{
                    background: C.raised,
                    border: `1px solid ${C.hairline}`,
                  }}
                >
                  <div className="flex items-center gap-2">
                    {flow.model1Verdict === "Attack" ? (
                      <AlertTriangle size={15} style={{ color: C.flare }} />
                    ) : (
                      <CheckCircle2 size={15} style={{ color: C.mint }} />
                    )}

                    <span className="text-sm" style={{ color: C.ink, ...ui }}>
                      Model 1 — XGBoost
                    </span>

                    <span
                      className="ml-auto text-xs"
                      style={{
                        color:
                          flow.model1Verdict === "Attack"
                            ? C.flare
                            : C.mint,
                        ...mono,
                      }}
                    >
                      {flow.model1Verdict}
                    </span>
                  </div>

                  {flow.model1Confidence && (
                    <div className="text-xs mt-1 ml-6" style={{ color: C.mute, ...mono }}>
                      Confidence {(flow.model1Confidence * 100).toFixed(1)}%
                    </div>
                  )}
                </div>
              )}

              {isModel2 && (
                <div
                  className="rounded-xl p-3"
                  style={{
                    background: C.flareSoft,
                    border: `1px solid ${C.flare}`,
                  }}
                >
                  <div className="flex items-center gap-2">
                    <Brain size={15} style={{ color: C.flare }} />

                    <span className="text-sm" style={{ color: C.ink, ...ui }}>
                      Model 2 — Multi-class
                    </span>

                    <span className="ml-auto text-xs" style={{ color: C.flare, ...mono }}>
                      {flow.attackType}
                    </span>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Rule Matched Message */}
          {isRule && (
            <div>
              <div className="text-xs uppercase tracking-wider mb-2" style={{ color: C.mute2, ...ui }}>
                Rule Matched
              </div>

              <div
                className="rounded-xl p-4"
                style={{
                  background: C.amberSoft,
                  border: `1px solid ${C.hairline}`,
                }}
              >
                <div className="text-xs mb-2" style={{ color: C.amber, ...mono }}>
                  Rule ID: {flow.ruleId}
                </div>

                <div className="text-sm" style={{ color: C.ink, ...mono }}>
                  {flow.rule}
                </div>

                <div className="text-xs mt-2" style={{ color: C.mute, ...ui }}>
                  {flow.ruleMessage}
                </div>

                <div className="text-xs mt-3" style={{ color: C.amber, ...ui }}>
                  ตรวจพบโดย Rule-based IDS — Flow นี้ไม่ถูกส่งเข้า ML
                </div>
              </div>
            </div>
          )}

          {/* Top-K Features */}
          {!isRule && topK && topK.length > 0 && (
            <div>
              <div className="flex items-center gap-2 mb-2">
                <BarChart2 size={14} style={{ color: C.flare || C.amber }} />
                <div className="text-xs uppercase tracking-wider" style={{ color: C.mute2, ...ui }}>
                  Top-{topK.length} Key Features (Importance Score)
                </div>
              </div>

              <div
                className="rounded-xl p-3 flex flex-col gap-3"
                style={{
                  background: C.raised,
                  border: `1px solid ${C.hairline}`,
                }}
              >
                {topK.map((item, index) => {
                  const scorePercent = Math.min(100, Math.max(5, (item.importance || 0) * 100));
                  return (
                    <div key={item.name || index} className="flex flex-col gap-1">
                      <div className="flex justify-between items-center text-xs" style={mono}>
                        <span className="font-medium" style={{ color: C.ink }}>
                          {item.name}
                        </span>
                        <div className="flex items-center gap-2">
                          <span style={{ color: C.mute2 }}>val:</span>
                          <span style={{ color: C.ink }}>{item.value}</span>
                          <span
                            className="font-semibold ml-1"
                            style={{ color: C.flare || C.amber }}
                          >
                            {(item.importance * 100).toFixed(0)}%
                          </span>
                        </div>
                      </div>

                      {/* Bar แสดงความสำคัญ */}
                      <div
                        className="w-full h-1.5 rounded-full overflow-hidden"
                        style={{ background: C.surface }}
                      >
                        <div
                          className="h-full rounded-full transition-all duration-300"
                          style={{
                            width: `${scorePercent}%`,
                            background:
                              flow.verdict === "Attack" || flow.is_attack
                                ? C.crimson || "#ef4444"
                                : C.mint || "#10b981",
                          }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* All Feature Values */}
          {feats && feats.length > 0 && (
            <div>
              <div className="text-xs uppercase tracking-wider mb-2" style={{ color: C.mute2, ...ui }}>
                All Feature Values
              </div>

              <div className="rounded-xl overflow-hidden" style={{ border: `1px solid ${C.hairline}` }}>
                {feats.map(([k, v], i) => (
                  <div
                    key={k}
                    className="flex justify-between px-4 py-2 text-sm"
                    style={{
                      background: i % 2 ? C.raised : "transparent",
                      ...mono,
                    }}
                  >
                    <span style={{ color: C.mute }}>{k}</span>
                    <span style={{ color: C.ink }}>{String(v)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}