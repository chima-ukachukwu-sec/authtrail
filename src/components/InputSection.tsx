"use client";

import { useState, type DragEvent, type RefObject } from "react";

interface Props {
  text: string;
  fileName: string | null;
  error: string | null;
  onTextChange: (value: string) => void;
  onFile: (file: File) => void;
  onAnalyze: () => void;
  onClear: () => void;
  onLoadSample: () => void;
  fileInputRef: RefObject<HTMLInputElement | null>;
}

export default function InputSection({
  text,
  fileName,
  error,
  onTextChange,
  onFile,
  onAnalyze,
  onClear,
  onLoadSample,
  fileInputRef,
}: Props) {
  const [dragging, setDragging] = useState(false);

  const handleDrop = (e: DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) onFile(file);
  };

  return (
    <section aria-label="Log input" className="mt-8">
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        className={`border ${dragging ? "border-accent" : "border-line"} bg-surface`}
      >
        <label htmlFor="log-input" className="sr-only">
          Paste authentication log text
        </label>
        <textarea
          id="log-input"
          value={text}
          onChange={(e) => onTextChange(e.target.value)}
          placeholder={
            "Paste authentication log text here, or drop a .log / .txt file…\n\nJan  5 09:04:11 host sshd[2077]: Failed password for root from 198.51.100.23 port 41120 ssh2"
          }
          spellCheck={false}
          rows={9}
          className="block w-full resize-y bg-transparent p-4 font-mono text-[13px] leading-relaxed text-ink placeholder:text-faint focus:outline-none"
        />
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-t border-line px-4 py-3">
          <input
            ref={fileInputRef}
            type="file"
            accept=".log,.txt,text/plain"
            className="sr-only"
            aria-label="Choose a log file"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) onFile(file);
            }}
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="text-sm text-muted underline decoration-line underline-offset-4 hover:text-ink"
          >
            Choose file
          </button>
          <button
            type="button"
            onClick={onLoadSample}
            className="text-sm text-muted underline decoration-line underline-offset-4 hover:text-ink"
          >
            Load sample
          </button>
          {fileName !== null && (
            <span className="font-mono text-[13px] text-faint">{fileName}</span>
          )}
          <span className="grow" />
          <button
            type="button"
            onClick={onClear}
            disabled={text.length === 0}
            className="px-3 py-1.5 text-sm text-muted hover:text-ink disabled:cursor-not-allowed disabled:opacity-40"
          >
            Clear
          </button>
          <button
            type="button"
            onClick={onAnalyze}
            disabled={text.trim().length === 0}
            className="bg-accent px-4 py-1.5 text-sm font-medium text-bg hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Analyze
          </button>
        </div>
      </div>

      {error !== null && (
        <p role="alert" className="mt-3 text-sm text-high">
          {error}
        </p>
      )}
      <p className="mt-3 text-[13px] text-faint">
        Files up to 25 MB. The file is read into this page and analyzed
        locally; it is not uploaded anywhere.
      </p>
    </section>
  );
}
