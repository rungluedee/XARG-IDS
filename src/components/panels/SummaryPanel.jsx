import Card from "../common/Card.jsx";
import Badge from "../common/Badge.jsx";
import AttackDistributionChart from "../charts/AttackDistributionChart.jsx";

export default function SummaryPanel({ verdict, attackType, confidence, history }) {
  return (
    <Card eyebrow="Unified view" title="Session Summary">
      <div className="flex items-center gap-3 mb-5">
        {verdict === "attack" ? (
          <Badge tone="critical" pulse>
            attack detected
          </Badge>
        ) : verdict === "benign" ? (
          <Badge tone="benign">clean session</Badge>
        ) : (
          <Badge tone="neutral">analyzing…</Badge>
        )}
        {attackType && (
          <span className="font-mono text-[11.5px] text-muted">
            {attackType} · {(confidence * 100).toFixed(0)}% confidence
          </span>
        )}
      </div>

      <p className="font-mono text-[10px] text-muted uppercase tracking-wide mb-2">
        Attack types this session (5-min buckets)
      </p>
      <AttackDistributionChart data={history} />
    </Card>
  );
}
