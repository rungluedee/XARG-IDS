const TONES = {
  benign: "text-signal border-signal/40 bg-signal/10",
  critical: "text-severity-critical border-severity-critical/40 bg-severity-critical/10",
  high: "text-severity-high border-severity-high/40 bg-severity-high/10",
  medium: "text-severity-medium border-severity-medium/40 bg-severity-medium/10",
  intel: "text-intel border-intel/40 bg-intel/10",
  neutral: "text-muted border-line bg-raised",
};

export default function Badge({ tone = "neutral", children, pulse = false }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono text-[11px] tracking-wide uppercase px-2 py-1 rounded border ${TONES[tone]}`}
    >
      {pulse && <span className="w-1.5 h-1.5 rounded-full bg-current animate-blink" />}
      {children}
    </span>
  );
}
