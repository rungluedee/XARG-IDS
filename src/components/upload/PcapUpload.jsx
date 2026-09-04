import { useCallback, useRef, useState } from "react";
import { UploadCloud, FileStack } from "lucide-react";

export default function PcapUpload({ onUpload, busy }) {
  const [dragOver, setDragOver] = useState(false);
  const inputRef = useRef(null);

  const handleFiles = useCallback(
    (files) => {
      const file = files?.[0];
      if (!file) return;
      if (!/\.(pcap|pcapng)$/i.test(file.name)) {
        alert("Please choose a .pcap or .pcapng file.");
        return;
      }
      onUpload(file);
    },
    [onUpload]
  );

  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDragOver(true);
      }}
      onDragLeave={() => setDragOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragOver(false);
        handleFiles(e.dataTransfer.files);
      }}
      onClick={() => inputRef.current?.click()}
      className={`cursor-pointer rounded-lg border border-dashed px-6 py-10 text-center transition-colors
        ${dragOver ? "border-signal bg-signal/5" : "border-line hover:border-muted"}`}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".pcap,.pcapng"
        className="hidden"
        onChange={(e) => handleFiles(e.target.files)}
      />
      {busy ? (
        <>
          <FileStack className="w-6 h-6 mx-auto text-signal animate-blink mb-3" />
          <p className="font-mono text-xs text-signal">uploading & queuing capture…</p>
        </>
      ) : (
        <>
          <UploadCloud className="w-6 h-6 mx-auto text-muted mb-3" />
          <p className="font-mono text-xs text-ink">Drop a .pcap file, or click to browse</p>
          <p className="font-mono text-[10.5px] text-muted mt-1.5">
            Runs Suricata/Snort, then the ML + XAI pipeline on the remaining flows
          </p>
        </>
      )}
    </div>
  );
}
