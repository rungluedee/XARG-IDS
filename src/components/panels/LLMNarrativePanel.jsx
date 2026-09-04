import { Sparkles, RefreshCw } from "lucide-react";
import Card from "../common/Card.jsx";
import Badge from "../common/Badge.jsx";
import EmptyState from "../common/EmptyState.jsx";

export default function LLMNarrativePanel({ narrative, loading, onRegenerate }) {
  // 1. Normalize ข้อมูลให้อ่านค่าได้เสมอ ไม่ว่า Backend/State จะส่ง Key มาแบบไหน
  const summaryText =
    typeof narrative === "string"
      ? narrative
      : narrative?.summary || narrative?.explanation || narrative?.text || "";

  const actionText =
    typeof narrative === "object" && narrative !== null
      ? narrative.recommendedAction ||
        narrative.recommended_action ||
        narrative.recommendation ||
        ""
      : "";

  const modelName = narrative?.model || "gemini-1.5-flash";
  const durationMs =
    narrative?.durationMs ?? narrative?.duration_ms ?? narrative?.latency ?? 0;

  return (
    <Card
      eyebrow="Stage 06 · language layer"
      title="LLM Explanation"
      tone="intel"
      right={
        narrative && (
          <button
            onClick={onRegenerate}
            disabled={loading}
            className="flex items-center gap-1.5 font-mono text-[11px] text-slate-400 hover:text-cyan-400 transition-colors disabled:opacity-40"
          >
            <RefreshCw className={`w-3 h-3 ${loading ? "animate-spin" : ""}`} />
            regenerate
          </button>
        )
      }
    >
      {!narrative && !loading && (
        <div className="text-slate-400">
          <EmptyState label="turns SHAP output into an analyst-readable explanation" />
        </div>
      )}

      {loading && (
        <div className="flex items-center gap-2 py-6 justify-center text-cyan-400">
          <Sparkles className="w-4 h-4 animate-blink" />
          <p className="font-mono text-xs text-slate-300">sending feature attribution to the LLM…</p>
        </div>
      )}

      {narrative && !loading && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <Badge tone="intel">{modelName}</Badge>
            <span className="font-mono text-[10px] text-slate-400">{durationMs} ms</span>
          </div>

          <div>
            <p className="font-mono text-[10px] text-slate-400 uppercase tracking-wide mb-1.5">Summary</p>
            <p className="text-[13.5px] leading-relaxed text-slate-200 whitespace-pre-line">
              {summaryText || "กำลังประมวลผลคำอธิบาย..."}
            </p>
          </div>

          {/* แสดงกล่อง Recommended Action เมื่อมีข้อความคำแนะนำเท่านั้น */}
          {actionText && (
            <div className="rounded border border-cyan-500/30 bg-cyan-950/20 px-3.5 py-3">
              <p className="font-mono text-[10px] text-cyan-400 uppercase tracking-wide mb-1.5">
                Recommended action
              </p>
              <p className="text-[13px] leading-relaxed text-slate-200 whitespace-pre-line">
                {actionText}
              </p>
            </div>
          )}

          <p className="font-mono text-[10px] text-slate-400 leading-relaxed">
            Only feature names, values, and the model verdict are sent to the LLM — never raw packet
            payloads. See backend/app/services/llm_service.py.
          </p>
        </div>
      )}
    </Card>
  );
}