import React from "react";
import { Network, Brain } from "lucide-react";
import { C, mono, ui } from "../constants/theme";
import {
  model1Classes,
  model1Matrix,
  model2Classes,
  model2Matrix,
  model2PerClass,
} from "../constants/mockData";
import { StatCard } from "./CommonUI";

export function ConfusionMatrix({ classes, matrix }) {
  const maxCell = Math.max(...matrix.flat());

  return (
    <div
      className="rounded-xl p-5"
      style={{
        background: C.surface,
        border: `1px solid ${C.hairline}`,
      }}
    >
      <div className="text-sm font-medium mb-4" style={{ color: C.ink, ...ui }}>
        Confusion Matrix
      </div>

      <div className="overflow-x-auto">
        <table className="border-collapse" style={mono}>
          <thead>
            <tr>
              <th className="p-2 text-xs" style={{ color: C.mute2 }} />
              {classes.map((c) => (
                <th
                  key={c}
                  className="p-2 text-xs font-normal whitespace-nowrap"
                  style={{ color: C.mute2 }}
                >
                  {c}
                </th>
              ))}
            </tr>
          </thead>

          <tbody>
            {matrix.map((row, i) => (
              <tr key={i}>
                <td
                  className="p-2 text-xs text-right pr-3 whitespace-nowrap"
                  style={{ color: C.mute2 }}
                >
                  {classes[i]}
                </td>

                {row.map((v, j) => {
                  const intensity = v / maxCell;
                  const isDiag = i === j;

                  const bg = isDiag
                    ? `rgba(53,214,140,${0.12 + intensity * 0.55})`
                    : v === 0
                    ? "transparent"
                    : `rgba(240,67,91,${0.1 + intensity * 0.6})`;

                  return (
                    <td
                      key={j}
                      className="p-2 text-center text-xs rounded"
                      style={{
                        background: bg,
                        color: isDiag ? C.mint : v ? C.crimson : C.mute2,
                        minWidth: 50,
                      }}
                    >
                      {v}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="text-xs mt-3" style={{ color: C.mute2, ...ui }}>
        แถว = Actual · คอลัมน์ = Predicted
      </div>
    </div>
  );
}

export function MetricsCards({
  accuracy,
  precision,
  recall,
  f1,
  macroF1,
  weightedF1,
}) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
      <StatCard label="Accuracy" value={accuracy} accent={C.mint} />
      <StatCard label="Precision" value={precision} accent={C.flare} />
      <StatCard label="Recall" value={recall} accent={C.flare} />
      <StatCard label="F1-score" value={f1} accent={C.flare} />
      {macroF1 && <StatCard label="Macro F1" value={macroF1} accent={C.blue} />}
      {weightedF1 && (
        <StatCard label="Weighted F1" value={weightedF1} accent={C.blue} />
      )}
    </div>
  );
}

export function PerformanceTab() {
  return (
    <div className="flex flex-col gap-8">
      {/* Model 1 */}
      <section>
        <div className="flex items-center gap-2 mb-4">
          <Network size={16} style={{ color: C.mute }} />
          <div className="text-sm font-semibold" style={{ color: C.ink, ...ui }}>
            Model 1 — Binary Classification
          </div>
          <span
            className="text-xs px-2 py-1 rounded"
            style={{ color: C.mute, background: C.raised2, ...mono }}
          >
            XGBoost
          </span>
        </div>

        <MetricsCards
          accuracy="98.40%"
          precision="97.90%"
          recall="96.80%"
          f1="97.30%"
        />

        <div className="mt-6">
          <ConfusionMatrix classes={model1Classes} matrix={model1Matrix} />
        </div>
      </section>

      {/* Model 2 */}
      <section>
        <div className="flex items-center gap-2 mb-4">
          <Brain size={16} style={{ color: C.flare }} />
          <div className="text-sm font-semibold" style={{ color: C.ink, ...ui }}>
            Model 2 — Multi-class Classification
          </div>
          <span
            className="text-xs px-2 py-1 rounded"
            style={{ color: C.flare, background: C.flareSoft, ...mono }}
          >
            XGBoost
          </span>
        </div>

        <MetricsCards
          accuracy="95.20%"
          precision="94.10%"
          recall="93.80%"
          f1="93.90%"
          macroF1="91.70%"
          weightedF1="94.80%"
        />

        <div className="grid grid-cols-1 xl:grid-cols-5 gap-6 mt-6">
          <div className="xl:col-span-3">
            <ConfusionMatrix classes={model2Classes} matrix={model2Matrix} />
          </div>

          <div
            className="xl:col-span-2 rounded-xl p-5"
            style={{
              background: C.surface,
              border: `1px solid ${C.hairline}`,
            }}
          >
            <div className="text-sm font-medium mb-4" style={{ color: C.ink, ...ui }}>
              Distribution ต่อ Class
            </div>

            <div className="flex flex-col gap-3">
              {model2PerClass.map((row) => (
                <div key={row.cls}>
                  <div className="flex justify-between text-xs mb-1" style={mono}>
                    <span style={{ color: C.ink }}>{row.cls}</span>
                    <span style={{ color: C.mute }}>
                      support {row.support} · F1 {(row.f1 * 100).toFixed(1)}%
                    </span>
                  </div>

                  <div className="h-2 rounded-full" style={{ background: C.raised2 }}>
                    <div
                      className="h-full rounded-full"
                      style={{
                        width: `${row.f1 * 100}%`,
                        background: C.flare,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Model Information */}
      <section>
        <div
          className="rounded-xl p-5"
          style={{
            background: C.surface,
            border: `1px solid ${C.hairline}`,
          }}
        >
          <div className="text-sm font-medium mb-4" style={{ color: C.ink, ...ui }}>
            Model Information
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              ["Feature Extractor", "CICFlowMeter"],
              ["Dataset", "CICIDS2017"],
              ["Model 1", "XGBoost Binary"],
              ["Model 2", "XGBoost Multi-class"],
              ["Explainability", "SHAP"],
              ["Explanation", "LLM"],
              ["Input", ".pcap / .pcapng"],
              ["Mode", "Offline Analysis"],
            ].map(([label, value]) => (
              <div
                key={label}
                className="rounded-lg p-3"
                style={{ background: C.raised }}
              >
                <div className="text-[11px]" style={{ color: C.mute2, ...ui }}>
                  {label}
                </div>
                <div className="text-sm mt-1" style={{ color: C.ink, ...mono }}>
                  {value}
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
}