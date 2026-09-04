import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from "recharts";

const SERIES = [
  { key: "DDoS", color: "#FF5C7A" },
  { key: "PortScan", color: "#FF9F5A" },
  { key: "BruteForce", color: "#F5D76E" },
  { key: "Botnet", color: "#9B8CFF" },
];

export default function AttackDistributionChart({ data }) {
  return (
    <div className="h-48">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={data} margin={{ left: -20, right: 8, top: 8, bottom: 0 }}>
          <CartesianGrid stroke="#1A1F2B" vertical={false} />
          <XAxis
            dataKey="time"
            tick={{ fill: "#7C8699", fontSize: 10, fontFamily: "IBM Plex Mono" }}
            axisLine={{ stroke: "#242B3A" }}
            tickLine={false}
          />
          <YAxis tick={{ fill: "#7C8699", fontSize: 10, fontFamily: "IBM Plex Mono" }} axisLine={false} tickLine={false} />
          <Tooltip
            contentStyle={{
              background: "#1A1F2B",
              border: "1px solid #242B3A",
              borderRadius: 6,
              fontFamily: "IBM Plex Mono",
              fontSize: 11,
            }}
          />
          {SERIES.map((s) => (
            <Area
              key={s.key}
              type="monotone"
              dataKey={s.key}
              stackId="1"
              stroke={s.color}
              fill={s.color}
              fillOpacity={0.18}
              strokeWidth={1.5}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
