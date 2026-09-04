import Card from "../common/Card.jsx";
import Badge from "../common/Badge.jsx";
import EmptyState from "../common/EmptyState.jsx";
import FeatureImportanceChart from "../charts/FeatureImportanceChart.jsx";

export default function XAIPanel({ xai }) {
  if (!xai) {
    return (
      <Card eyebrow="Stage 05" title="XAI · Feature Attribution" tone="intel">
        <EmptyState label="explains Model 2's decision once it runs" />
      </Card>
    );
  }

  return (
    <Card
      eyebrow="Stage 05 · explainability"
      title="XAI · Feature Attribution"
      tone="intel"
      right={<Badge tone="intel">{xai.method}</Badge>}
    >
      <p className="font-mono text-[11px] text-muted mb-4">
        Features ranked by contribution to the Model 2 classification, most influential first.
      </p>
      <FeatureImportanceChart features={xai.features} />
    </Card>
  );
}
