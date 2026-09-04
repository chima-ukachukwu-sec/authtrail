"use client";

import { useCallback, useRef, useState } from "react";
import { analyzeLogText } from "@/lib/analyze";
import {
  looksBinary,
  validateText,
  MAX_FILE_BYTES,
  MAX_PASTE_CHARS,
  formatBytes,
} from "@/lib/ingest";
import { SAMPLE_LOG } from "@/lib/sample";
import type { AnalysisResult } from "@/lib/types";
import InputSection from "./InputSection";
import SummaryStrip from "./SummaryStrip";
import FindingsList from "./FindingsList";
import StatsTables from "./StatsTables";
import EventTable from "./EventTable";

export interface InputError {
  message: string;
}

export default function AuthTrailApp() {
  const [text, setText] = useState("");
  const [fileName, setFileName] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [analysisId, setAnalysisId] = useState(0);
  const [announcement, setAnnouncement] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const acceptFile = useCallback((file: File) => {
    setError(null);
    const isText =
      file.type.startsWith("text/") ||
      /\.(log|txt)$/i.test(file.name) ||
      file.type === "";
    if (!isText) {
      setError(`"${file.name}" is not a .log or .txt file.`);
      return;
    }
    if (file.size > MAX_FILE_BYTES) {
      setError(
        `"${file.name}" is ${formatBytes(file.size)} — the limit is ${formatBytes(MAX_FILE_BYTES)}.`,
      );
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      const content = String(reader.result ?? "");
      if (looksBinary(content)) {
        setError(`"${file.name}" does not look like a text log file.`);
        return;
      }
      setText(content);
      setFileName(file.name);
      setResult(null);
    };
    reader.onerror = () => setError(`Could not read "${file.name}".`);
    reader.readAsText(file);
  }, []);

  const analyze = useCallback(() => {
    setError(null);
    // Origin-aware size contract: pasted text 5 MB, uploaded file 25 MB.
    // fileName tracks origin: set by acceptFile, cleared on any manual edit.
    const maxChars = fileName !== null ? MAX_FILE_BYTES : MAX_PASTE_CHARS;
    const validation = validateText(text, maxChars);
    if (!validation.ok) {
      setError(validation.message ?? "The input cannot be analyzed.");
      setResult(null);
      return;
    }
    try {
      const analysis = analyzeLogText(text);
      setResult(analysis);
      setAnalysisId((id) => id + 1);
      setAnnouncement(
        `Analysis complete. ${analysis.summary.attempts} authentication attempts, ${analysis.findings.length} findings.`,
      );
    } catch {
      setResult(null);
      setError(
        "Analysis failed unexpectedly. The input could not be processed.",
      );
    }
  }, [text, fileName]);

  const clear = useCallback(() => {
    setText("");
    setFileName(null);
    setError(null);
    setResult(null);
    setAnnouncement("Input cleared.");
    if (fileInputRef.current) fileInputRef.current.value = "";
  }, []);

  const loadSample = useCallback(() => {
    setError(null);
    setText(SAMPLE_LOG);
    setFileName(null);
    setResult(null);
  }, []);

  return (
    <div className="mx-auto max-w-6xl px-5 pb-20 sm:px-8">
      <div aria-live="polite" className="sr-only">
        {announcement}
      </div>

      <header className="flex flex-wrap items-baseline justify-between gap-x-8 gap-y-2 border-b border-line py-6">
        <div>
          <h1 className="font-mono text-xl font-semibold tracking-tight">
            AuthTrail
          </h1>
          <p className="mt-1 text-sm text-muted">
            Local SSH authentication log analysis
          </p>
        </div>
        <p className="text-sm text-muted">
          Analysis runs entirely in your browser —{" "}
          <span className="text-ink">log data never leaves this device</span>.
        </p>
      </header>

      <main>
        <InputSection
          text={text}
          fileName={fileName}
          error={error}
          onTextChange={(value) => {
            setText(value);
            setFileName(null);
            setResult(null);
            setError(null);
          }}
          onFile={acceptFile}
          onAnalyze={analyze}
          onClear={clear}
          onLoadSample={loadSample}
          fileInputRef={fileInputRef}
        />

        {result === null ? (
          <section className="mt-14 max-w-2xl">
            <h2 className="text-sm font-medium tracking-wide text-faint uppercase">
              What this does
            </h2>
            <p className="mt-3 text-muted">
              Paste an OpenSSH log (<span className="font-mono text-ink">auth.log</span>,{" "}
              <span className="font-mono text-ink">secure</span>, or journalctl output)
              above. AuthTrail normalizes each line into authentication
              attempts, then applies five deterministic rules: failure bursts,
              username enumeration, targeted accounts, privileged-account
              activity, and logins that follow a burst of failures.
            </p>
            <p className="mt-3 text-muted">
              Findings describe observed behavior with their evidence. A failed
              password alone never makes an address &ldquo;malicious&rdquo;.
            </p>
          </section>
        ) : (
          // Keyed by analysisId: a new analysis remounts the results subtree,
          // resetting result-specific UI state (filters, query, expanded rows,
          // pagination, evidence disclosures) from the previous result.
          <div key={analysisId} className="mt-10 space-y-12">
            <SummaryStrip result={result} />
            <FindingsList findings={result.findings} events={result.events} />
            <StatsTables
              topIps={result.topIps}
              topUsernames={result.topUsernames}
            />
            <EventTable events={result.events} />
          </div>
        )}
      </main>

      <footer className="mt-16 border-t border-line pt-6 text-sm text-faint">
        <p>
          Deterministic rules with fixed thresholds. No network lookups, no
          telemetry, no storage — reloading this page discards everything.
        </p>
      </footer>
    </div>
  );
}
