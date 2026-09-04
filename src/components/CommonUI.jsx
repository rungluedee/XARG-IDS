import { ArrowRight } from "lucide-react";
import { C, mono, ui } from "../constants/theme";

export function VerdictChip({ verdict }) {
  const isNormal = verdict === "Normal";

  return (
    <span
      className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium"
      style={{
        background: isNormal ? C.mintSoft : C.crimsonSoft,
        color: isNormal ? C.mint : C.crimson,
        ...mono,
      }}
    >
      <span
        className="w-1.5 h-1.5 rounded-full"
        style={{
          background: isNormal ? C.mint : C.crimson,
        }}
      />
      {verdict}
    </span>
  );
}

export function SourceChip({ source }) {
  const map = {
    rule: { label: "Rule-based", color: C.amber, bg: C.amberSoft },
    model1: { label: "XGBoost", color: C.mute, bg: C.raised2 },
    model2: { label: "Isolation Forest", color: C.flare, bg: C.flareSoft },
  };

  const s = map[source] || map.model1;

  return (
    <span
      className="px-2 py-0.5 rounded text-[11px] font-medium tracking-wide"
      style={{
        background: s.bg,
        color: s.color,
        ...mono,
      }}
    >
      {s.label}
    </span>
  );
}

export function StatCard({ label, value, sub, accent }) {
  return (
    <div
      className="rounded-xl p-4 flex flex-col gap-1"
      style={{
        background: C.surface,
        border: `1px solid ${C.hairline}`,
      }}
    >
      <span
        className="text-xs uppercase tracking-wider"
        style={{ color: C.mute2, ...ui }}
      >
        {label}
      </span>

      <span
        className="text-3xl font-semibold"
        style={{
          color: accent || C.ink,
          ...mono,
        }}
      >
        {value}
      </span>

      {sub && (
        <span
          className="text-xs"
          style={{
            color: C.mute,
            ...ui,
          }}
        >
          {sub}
        </span>
      )}
    </div>
  );
}

export function PipelineStage({ icon: Icon, title, sub, count, tone, last }) {
  return (
    <div className="flex items-center gap-3 flex-1">
      <div
        className="flex-1 rounded-xl p-4 flex items-center gap-3"
        style={{
          background: C.surface,
          border: `1px solid ${C.hairline}`,
        }}
      >
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0"
          style={{ background: tone.bg }}
        >
          <Icon size={16} style={{ color: tone.color }} />
        </div>

        <div className="min-w-0">
          <div
            className="text-sm font-medium truncate"
            style={{ color: C.ink, ...ui }}
          >
            {title}
          </div>

          <div className="text-xs truncate" style={{ color: C.mute, ...ui }}>
            {sub}
          </div>
        </div>

        <div
          className="ml-auto text-xl font-semibold shrink-0"
          style={{
            color: tone.color,
            ...mono,
          }}
        >
          {count}
        </div>
      </div>

      {!last && (
        <ArrowRight size={16} style={{ color: C.mute2 }} className="shrink-0" />
      )}
    </div>
  );
}