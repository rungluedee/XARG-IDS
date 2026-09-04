import Card from "../common/Card.jsx";
import Badge from "../common/Badge.jsx";
import EmptyState from "../common/EmptyState.jsx";

export default function SuricataPanel({ result }) {
  if (!result) {
    return (
      <Card eyebrow="Stage 01" title="Suricata / Snort">
        <EmptyState label="waiting for capture" />
      </Card>
    );
  }

  return (
    <Card
      eyebrow="Stage 01 · signature engine"
      title="Suricata / Snort"
      right={
        result.matched ? (
          <Badge tone="critical" pulse>
            rule matched
          </Badge>
        ) : (
          <Badge tone="benign">no signature match</Badge>
        )
      }
    >
      <div className="grid grid-cols-3 gap-4 mb-4">
        <Stat label="flows scanned" value={result.scannedFlows} />
        <Stat label="rules evaluated" value={result.rulesEvaluated.toLocaleString()} />
        <Stat label="duration" value={`${result.durationMs} ms`} />
      </div>

      {result.matched ? (
        <div className="space-y-2">
          {result.matches.map((m) => (
            <div key={m.sid} className="rounded border border-severity-critical/30 bg-severity-critical/5 px-3 py-2.5">
              <div className="flex items-center justify-between">
                <p className="font-mono text-xs text-severity-critical">{m.rule}</p>
                <span className="font-mono text-[10px] text-muted">sid:{m.sid}</span>
              </div>
              <p className="font-mono text-[11px] text-muted mt-1">
                {m.srcIp} → {m.dstIp} · {m.proto} · severity: {m.severity}
              </p>
            </div>
          ))}
        </div>
      ) : (
        <p className="font-mono text-[11.5px] text-muted">
          No flow matched the active ruleset. Remaining flows are forwarded to preprocessing for
          anomaly-based inference.
        </p>
      )}
    </Card>
  );
}

function Stat({ label, value }) {
  return (
    <div>
      <p className="font-mono text-lg text-ink">{value}</p>
      <p className="font-mono text-[10px] text-muted uppercase tracking-wide mt-0.5">{label}</p>
    </div>
  );
}
