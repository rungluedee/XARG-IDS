import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

export default function FeatureImportanceChart({ features }) {
  return (
    <div style={{ height: features.length * 34 + 16 }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={features} layout="vertical" margin={{ left: 0, right: 40, top: 4, bottom: 4 }}>
          <XAxis type="number" hide />
          <YAxis
            type="category"
            dataKey="name"
            width={140}
            tick={{ fill: "#7C8699", fontSize: 11, fontFamily: "IBM Plex Mono" }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip
            cursor={{ fill: "rgba(255,255,255,0.03)" }}
            contentStyle={{
              background: "#1A1F2B",
              border: "1px solid #242B3A",
              borderRadius: 6,
              fontFamily: "IBM Plex Mono",
              fontSize: 12,
            }}
            formatter={(v, name, props) => [`${(v * 100).toFixed(1)}%`, `value: ${props.payload.value}`]}
          />
          <Bar dataKey="importance" fill="#9B8CFF" radius={[0, 3, 3, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
