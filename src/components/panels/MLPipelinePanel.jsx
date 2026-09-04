import Card from "../common/Card.jsx";
import Badge from "../common/Badge.jsx";
import EmptyState from "../common/EmptyState.jsx";
import AttackTypeChart from "../charts/AttackTypeChart.jsx";

export default function MLPipelinePanel({ preprocessing, model1, model2 }) {
  if (!preprocessing) {
    return (
      <Card eyebrow="Stage 02–04" title="ML Pipeline">
        <EmptyState label="no flows forwarded yet" />
      </Card>
    );
  }

  return (
    <Card eyebrow="Stage 02–04 · anomaly engine" title="ML Pipeline">
      <div className="grid grid-cols-3 gap-4 mb-5 pb-5 border-b border-line">
        {preprocessing.windows.map((w) => (
          <div key={w.label}>
            <p className="font-mono text-lg text-ink">{w.count}</p>
            <p className="font-mono text-[10px] text-muted uppercase tracking-wide mt-0.5">
              flows / {w.label} window
            </p>
          </div>
        ))}
      </div>

      {model1 && (
        <div className="mb-5">
          <div className="flex items-center justify-between mb-2">
            <p className="font-mono text-[11px] text-muted uppercase tracking-wide">Model 1 · binary</p>
            <Badge tone={model1.verdict === "attack" ? "high" : "benign"}>
              {model1.verdict} · {(model1.confidence * 100).toFixed(0)}%
            </Badge>
          </div>
          <div className="flex gap-4 font-mono text-[11.5px] text-muted">
            <span>
              benign: <span className="text-ink">{model1.benignFlows}</span>
            </span>
            <span>
              flagged: <span className="text-severity-high">{model1.attackFlows}</span>
            </span>
          </div>
        </div>
      )}

      {model2 && (
        <div>
          <div className="flex items-center justify-between mb-2">
            <p className="font-mono text-[11px] text-muted uppercase tracking-wide">Model 2 · attack type</p>
            <Badge tone="critical" pulse>
              {model2.attackType}
            </Badge>
          </div>
          <AttackTypeChart data={model2.classProbabilities} />
        </div>
      )}
    </Card>
  );
}
