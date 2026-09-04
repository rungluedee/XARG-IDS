export default function EmptyState({ label }) {
  return (
    <div className="flex flex-col items-center justify-center text-center py-10 text-slate-400">
      <div className="w-8 h-8 rounded-full border border-dashed border-slate-700 mb-3 flex items-center justify-center">
        <div className="w-1.5 h-1.5 rounded-full bg-slate-500" />
      </div>
      <p className="font-mono text-xs text-slate-300">{label}</p>
    </div>
  );
}