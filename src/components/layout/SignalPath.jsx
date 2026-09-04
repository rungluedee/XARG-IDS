import { CircleDashed, CircleCheck, TriangleAlert, CornerDownRight, RotateCcw } from "lucide-react";

const STATUS_STYLE = {
  idle: { dot: "bg-line", ring: "", text: "text-muted" },
  running: { dot: "bg-signal", ring: "shadow-glow", text: "text-signal" },
  pass: { dot: "bg-signal", ring: "", text: "text-ink" },
  alert: { dot: "bg-severity-critical", ring: "shadow-glow-alert", text: "text-severity-critical" },
  intel: { dot: "bg-intel", ring: "shadow-glow-intel", text: "text-intel" },
  skipped: { dot: "bg-line", ring: "", text: "text-muted/50" },
};

function StatusIcon({ status }) {
  if (status === "running") return <CircleDashed className="w-3.5 h-3.5 animate-spin" style={{ animationDuration: "1.6s" }} />;
  if (status === "alert") return <TriangleAlert className="w-3.5 h-3.5" />;
  if (status === "pass" || status === "intel") return <CircleCheck className="w-3.5 h-3.5" />;
  return <CircleDashed className="w-3.5 h-3.5 opacity-40" />;
}

function Node({ label, sub, status = "idle", active }) {
  const s = STATUS_STYLE[status];
  return (
    <div className={`relative flex items-center gap-3 pl-1 ${active ? "" : "opacity-90"}`}>
      <div className={`relative z-10 w-6 h-6 rounded-full border border-line bg-panel flex items-center justify-center ${s.ring}`}>
        <span className={`w-2 h-2 rounded-full ${s.dot} ${status === "running" ? "animate-blink" : ""}`} />
      </div>
      <div className="flex-1 flex items-center justify-between gap-2 py-2">
        <div>
          <p className={`font-mono text-[12.5px] leading-tight ${s.text}`}>{label}</p>
          {sub && <p className="font-mono text-[10.5px] text-muted mt-0.5">{sub}</p>}
        </div>
        <StatusIcon status={status} />
      </div>
    </div>
  );
}

function Branch({ label, sub, status }) {
  const s = STATUS_STYLE[status];
  return (
    <div className="ml-9 mb-2 flex items-start gap-1.5">
      <CornerDownRight className="w-3.5 h-3.5 text-muted mt-1.5 shrink-0" />
      <div className={`flex-1 rounded border border-line bg-raised px-2.5 py-1.5 ${status === "alert" ? "border-severity-critical/40" : ""}`}>
        <p className={`font-mono text-[11.5px] ${s.text}`}>{label}</p>
        {sub && <p className="font-mono text-[10px] text-muted mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

/**
 * Live, literal rendering of the detection pipeline. `stages` keys map 1:1 to backend
 * WebSocket stage names: upload, suricata, preprocess, model1, model2, xai, llm, rulegen.
 * Each value is { status: 'idle'|'running'|'pass'|'alert'|'intel'|'skipped', sub?: string }.
 */
export default function SignalPath({ stages }) {
  const st = (key) => stages[key] || { status: "idle" };

  return (
    <nav className="relative pl-0 pr-3 py-1">
      {/* spine */}
      <div className="absolute left-[13px] top-3 bottom-3 w-px bg-line" aria-hidden="true" />

      <Node label="Upload capture" sub={st("upload").sub || ".pcap"} status={st("upload").status} />
      <Node label="Suricata / Snort" sub="signature match?" status={st("suricata").status} />
      {st("suricata").status === "alert" && (
        <Branch label="Rule match found" sub={st("suricata").sub || "output → sid + rule name"} status="alert" />
      )}

      <Node label="Preprocessing" sub="multi time-window → csv" status={st("preprocess").status} />
      <Node label="Model 1" sub="attack vs. benign" status={st("model1").status} />
      {st("model1").status === "pass" && stages.model1?.verdict === "benign" && (
        <Branch label="Normal traffic" sub="no further inference" status="pass" />
      )}

      <Node label="Model 2" sub="attack type classifier" status={st("model2").status} />
      <Node label="XAI · SHAP / LIME" sub="feature attribution" status={st("xai").status} />
      <Node label="LLM narrative" sub="plain-language explanation" status={st("llm").status} />
      <Node label="Rule generator" sub="top-k features → Suricata rule" status={st("rulegen").status} />

      {(st("rulegen").status === "pass" || st("rulegen").status === "intel") && (
        <div className="ml-9 mb-2 flex items-center gap-1.5 text-muted">
          <RotateCcw className="w-3 h-3 shrink-0" />
          <p className="font-mono text-[10px]">feeds back into Suricata ruleset on approval</p>
        </div>
      )}

      <Node label="Dashboard" sub="unified view" status={st("dashboard").status} />
    </nav>
  );
}
