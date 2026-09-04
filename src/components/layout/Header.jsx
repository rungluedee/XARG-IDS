import { Radio } from "lucide-react";

export default function Header({ jobLabel }) {
  return (
    <header className="flex items-center justify-between px-6 h-16 border-b border-line bg-void/80 backdrop-blur sticky top-0 z-10">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded border border-signal/40 flex items-center justify-center">
          <Radio className="w-4 h-4 text-signal" strokeWidth={2} />
        </div>
        <div>
          <h1 className="font-mono text-sm text-ink leading-none">NIDS // Hybrid Threat Console</h1>
          <p className="font-mono text-[11px] text-muted mt-1">
            Signature + ML + Explainability pipeline
          </p>
        </div>
      </div>
      <div className="font-mono text-[11px] text-muted">
        {jobLabel ? (
          <span>
            job <span className="text-ink">{jobLabel}</span>
          </span>
        ) : (
          <span>awaiting capture</span>
        )}
      </div>
    </header>
  );
}
