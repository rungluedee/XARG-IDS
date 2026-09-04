export default function Card({ title, eyebrow, right, tone = "default", children, className = "" }) {
  const toneRing =
    tone === "intel"
      ? "border-cyan-500/30"
      : tone === "alert"
      ? "border-red-500/30"
      : "border-slate-800";

  return (
    <section className={`bg-slate-900/90 border ${toneRing} rounded-lg ${className}`}>
      {(title || right) && (
        <header className="flex items-center justify-between px-5 py-3.5 border-b border-slate-800">
          <div>
            {eyebrow && (
              <p className="font-mono text-[11px] tracking-widest text-slate-400 uppercase mb-0.5">
                {eyebrow}
              </p>
            )}
            {title && <h2 className="font-mono text-sm font-medium text-slate-100">{title}</h2>}
          </div>
          {right}
        </header>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}