import { ShieldCheck, ShieldX, Clock } from "lucide-react";
import Card from "../common/Card.jsx";
import Badge from "../common/Badge.jsx";
import EmptyState from "../common/EmptyState.jsx";

const FP_STATUS = {
  pending: { tone: "medium", icon: Clock, label: "FP test pending" },
  passed: { tone: "benign", icon: ShieldCheck, label: "FP test passed" },
  failed: { tone: "critical", icon: ShieldX, label: "FP test failed" },
};

export default function RuleGeneratorPanel({ rule, onApprove, onReject }) {
  if (!rule) {
    return (
      <Card eyebrow="Stage 07" title="Rule Generator" tone="intel">
        <EmptyState label="proposes a Suricata rule from the top-k SHAP features" />
      </Card>
    );
  }

  const fp = FP_STATUS[rule.falsePositiveTestStatus];
  const FpIcon = fp.icon;

  return (
    <Card eyebrow="Stage 07 · self-learning loop" title="Rule Generator" tone="intel">
      <div className="flex items-center gap-2 mb-3">
        <Badge tone={fp.tone}>
          <FpIcon className="w-3 h-3" /> {fp.label}
        </Badge>
        <Badge tone={rule.approvalStatus === "approved" ? "benign" : "neutral"}>
          {rule.approvalStatus.replace("_", " ")}
        </Badge>
      </div>

      <pre className="font-mono text-[11px] leading-relaxed text-ink/90 bg-void border border-line rounded p-3 overflow-x-auto whitespace-pre-wrap">
        {rule.raw}
      </pre>

      <p className="font-mono text-[10.5px] text-muted mt-3 mb-4">
        Derived from top features:{" "}
        <span className="text-intel">{rule.basedOnFeatures.join(", ")}</span>
      </p>

      <div className="flex gap-2">
        <button
          onClick={onApprove}
          disabled={rule.approvalStatus !== "awaiting_review" || rule.falsePositiveTestStatus === "failed"}
          className="flex-1 font-mono text-[11px] tracking-wide uppercase py-2 rounded border border-signal/40 text-signal hover:bg-signal/10 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
        >
          Approve → deploy to ruleset
        </button>
        <button
          onClick={onReject}
          disabled={rule.approvalStatus !== "awaiting_review"}
          className="flex-1 font-mono text-[11px] tracking-wide uppercase py-2 rounded border border-line text-muted hover:text-severity-critical hover:border-severity-critical/40 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
        >
          Reject
        </button>
      </div>
      <p className="font-mono text-[10px] text-muted/70 mt-2.5">
        Auto-generated rules never deploy without human review — see the FP baseline test in
        backend/app/services/rule_generator_service.py.
      </p>
    </Card>
  );
}
