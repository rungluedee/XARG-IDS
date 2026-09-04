import { ChevronRight, Filter, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { ATTACK_TYPES } from "../constants/mockData";
import { C, mono, ui } from "../constants/theme";
import { SourceChip, VerdictChip } from "./CommonUI";

export function FlowsTab({ flowsList, onSelect }) {
  const [search, setSearch] = useState("");
  const [verdictFilter, setVerdictFilter] = useState("All");
  const [sourceFilter, setSourceFilter] = useState("All");
  const [attackFilter, setAttackFilter] = useState("All");

  const filteredFlows = useMemo(() => {
    const q = search.trim().toLowerCase();

    return flowsList.filter((f) => {
      const matchesSearch =
        !q ||
        f.id.toLowerCase().includes(q) ||
        f.src.toLowerCase().includes(q) ||
        f.dst.toLowerCase().includes(q) ||
        String(f.sport).includes(q) ||
        String(f.dport).includes(q) ||
        f.proto.toLowerCase().includes(q) ||
        (f.attackType || "").toLowerCase().includes(q);

      const matchesVerdict =
        verdictFilter === "All" || f.verdict === verdictFilter;

      const matchesSource =
        sourceFilter === "All" || f.source === sourceFilter;

      const matchesAttack =
        attackFilter === "All" || f.attackType === attackFilter;

      return (
        matchesSearch && matchesVerdict && matchesSource && matchesAttack
      );
    });
  }, [search, verdictFilter, sourceFilter, attackFilter, flowsList]);

  return (
    <div
      className="rounded-xl overflow-hidden"
      style={{
        background: C.surface,
        border: `1px solid ${C.hairline}`,
      }}
    >
      <div
        className="p-4 flex flex-col gap-3"
        style={{
          borderBottom: `1px solid ${C.hairline}`,
        }}
      >
        <div className="flex flex-wrap items-center gap-3">
          <div
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg flex-1 min-w-[220px] max-w-md"
            style={{ background: C.raised }}
          >
            <Search size={14} style={{ color: C.mute2 }} />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="ค้นหา IP, port, ประเภท..."
              className="bg-transparent outline-none text-sm flex-1"
              style={{
                color: C.ink,
                ...ui,
              }}
            />
          </div>

          <div
            className="flex items-center gap-2 text-xs"
            style={{
              color: C.mute,
              ...ui,
            }}
          >
            <Filter size={13} />
            Filters
          </div>

          <select
            value={verdictFilter}
            onChange={(e) => setVerdictFilter(e.target.value)}
            className="rounded-lg px-3 py-2 text-xs outline-none"
            style={{
              background: C.raised,
              color: C.ink,
              border: `1px solid ${C.hairline}`,
            }}
          >
            <option value="All">Verdict: All</option>
            <option value="Normal">Normal</option>
            <option value="Attack">Attack</option>
          </select>

          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="rounded-lg px-3 py-2 text-xs outline-none"
            style={{
              background: C.raised,
              color: C.ink,
              border: `1px solid ${C.hairline}`,
            }}
          >
            <option value="All">Detected By: All</option>
            <option value="rule">Rule-based</option>
            <option value="model1">XGBoost</option>
            <option value="model2">Isolation Forest</option>
          </select>

          <select
            value={attackFilter}
            onChange={(e) => setAttackFilter(e.target.value)}
            className="rounded-lg px-3 py-2 text-xs outline-none"
            style={{
              background: C.raised,
              color: C.ink,
              border: `1px solid ${C.hairline}`,
            }}
          >
            <option value="All">Attack Type: All</option>
            {ATTACK_TYPES.map((type) => (
              <option key={type} value={type}>
                {type}
              </option>
            ))}
          </select>
        </div>

        <div
          className="text-xs"
          style={{
            color: C.mute,
            ...ui,
          }}
        >
          แสดง {filteredFlows.length} จาก {flowsList.length} flows ·
          คลิกแถวเพื่อดูรายละเอียด
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm" style={mono}>
          <thead>
            <tr style={{ color: C.mute2 }}>
              {[
                "Flow",
                "Source IP",
                "Destination IP",
                "Src Port",
                "Dst Port",
                "Protocol",
                "Timestamp",
                "Verdict",
                "Detected By",
                "Attack Type",
              ].map((c) => (
                <th
                  key={c}
                  className="text-left font-medium px-4 py-2 text-xs uppercase tracking-wide whitespace-nowrap"
                >
                  {c}
                </th>
              ))}
              <th />
            </tr>
          </thead>

          <tbody>
            {filteredFlows.length === 0 ? (
              <tr>
                <td
                  colSpan={11}
                  className="text-center py-12 text-sm"
                  style={{ color: C.mute2, ...ui }}
                >
                  ไม่พบข้อมูล Traffic (ข้อมูลเป็น 0)
                </td>
              </tr>
            ) : (
              filteredFlows.map((f, idx) => (
            <tr
                  key={`${f.id || 'flow'}-${idx}`}
                  onClick={() => onSelect(f)}
                  className="cursor-pointer transition-colors"
                  style={{
                    borderTop: `1px solid ${C.hairline}`,
                  }}
                  onMouseEnter={(e) =>
                    (e.currentTarget.style.background = C.raised)
                  }
                  onMouseLeave={(e) =>
                    (e.currentTarget.style.background = "transparent")
                  }
                >
                  <td className="px-4 py-3 whitespace-nowrap" style={{ color: C.mute }}>{f.id}</td>
                  <td className="px-4 py-3 whitespace-nowrap" style={{ color: C.ink }}>{f.src}</td>
                  <td className="px-4 py-3 whitespace-nowrap" style={{ color: C.ink }}>{f.dst}</td>
                  <td className="px-4 py-3 whitespace-nowrap" style={{ color: C.mute }}>{f.sport}</td>
                  <td className="px-4 py-3 whitespace-nowrap" style={{ color: C.mute }}>{f.dport}</td>
                  <td className="px-4 py-3 whitespace-nowrap" style={{ color: C.mute }}>{f.proto}</td>
                  <td className="px-4 py-3 whitespace-nowrap" style={{ color: C.mute2 }}>{f.ts}</td>
                  <td className="px-4 py-3 whitespace-nowrap"><VerdictChip verdict={f.verdict} /></td>
                  <td className="px-4 py-3 whitespace-nowrap"><SourceChip source={f.source} /></td>
                  <td
                    className="px-4 py-3 whitespace-nowrap"
                    style={{
                      color: f.verdict === "Normal" ? C.mute2 : C.ink,
                    }}
                  >
                    {f.attackType || "—"}
                  </td>
                  <td className="px-4 py-3">
                    <ChevronRight size={14} style={{ color: C.mute2 }} />
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}