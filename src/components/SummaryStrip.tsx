import type { AnalysisResult } from "@/lib/types";
import { formatDuration } from "@/lib/format";

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <dt className="text-[12px] font-medium tracking-wide text-faint uppercase">
        {label}
      </dt>
      <dd className="mt-1 font-mono text-2xl font-medium text-ink tabular-nums">
        {value}
      </dd>
    </div>
  );
}

export default function SummaryStrip({ result }: { result: AnalysisResult }) {
  const { summary, chronology } = result;

  return (
    <section aria-label="Summary">
      <dl className="grid grid-cols-2 gap-x-6 gap-y-6 sm:grid-cols-3 lg:grid-cols-6">
        <Stat label="Attempts" value={summary.attempts} />
        <Stat label="Failed" value={summary.failedAttempts} />
        <Stat label="Successful" value={summary.successfulAttempts} />
        <Stat label="Invalid-user" value={summary.invalidUserAttempts} />
        <Stat label="Source IPs" value={summary.uniqueSourceIps} />
        <Stat
          label="Span (approx.)"
          value={
            chronology.spanMs !== null ? formatDuration(chronology.spanMs) : "—"
          }
        />
      </dl>

      {!chronology.confident && (
        <p role="status" className="mt-6 border-l-2 border-medium pl-3 text-sm text-medium">
          Timestamps in this log are inconsistent, so relative chronology could
          not be established. Time-based detections were suppressed:{" "}
          {summary.suppressedRules.join("; ")}. Count-based findings still
          apply.
        </p>
      )}

      <p className="mt-6 text-[13px] text-faint">
        {summary.totalLines} non-blank lines analyzed
        {summary.duplicatesExcluded > 0 &&
          ` · ${summary.duplicatesExcluded} identical repeated line${summary.duplicatesExcluded === 1 ? "" : "s"} excluded from counts`}
        {summary.unparsedLines > 0 &&
          ` · ${summary.unparsedLines} line${summary.unparsedLines === 1 ? "" : "s"} not recognized`}
        {summary.unattributedObservations > 0 &&
          ` · ${summary.unattributedObservations} observation${summary.unattributedObservations === 1 ? "" : "s"} could not be confidently attributed`}
      </p>
    </section>
  );
}
