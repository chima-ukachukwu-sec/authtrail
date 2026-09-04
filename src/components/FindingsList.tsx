import type { AuthEvent, Finding, Severity } from "@/lib/types";

const SEVERITY_STYLE: Record<Severity, { bar: string; label: string; text: string }> = {
  high: { bar: "bg-high", label: "high", text: "text-high" },
  medium: { bar: "bg-medium", label: "medium", text: "text-medium" },
  low: { bar: "bg-low", label: "low", text: "text-low" },
  informational: { bar: "bg-info", label: "info", text: "text-faint" },
};

function FindingItem({
  finding,
  eventsById,
}: {
  finding: Finding;
  eventsById: Map<string, AuthEvent>;
}) {
  const style = SEVERITY_STYLE[finding.severity];
  const evidence = finding.eventIds
    .map((id) => eventsById.get(id))
    .filter((e): e is AuthEvent => e !== undefined);

  return (
    <li className="flex gap-4 border-t border-line py-5 first:border-t-0 first:pt-0">
      <span aria-hidden="true" className={`mt-1 w-0.5 shrink-0 self-stretch ${style.bar}`} />
      <div className="min-w-0">
        <div className="flex flex-wrap items-baseline gap-x-3">
          <span className={`font-mono text-[11px] tracking-widest uppercase ${style.text}`}>
            {style.label} · {finding.ruleId}
          </span>
          <h3 className="text-[15px] font-medium text-ink">{finding.title}</h3>
        </div>
        <p className="mt-1.5 max-w-3xl text-sm text-muted">
          {finding.description}
        </p>
        <dl className="mt-2.5 flex flex-wrap gap-x-6 gap-y-1">
          {finding.facts.map((f) => (
            <div key={f.label} className="flex items-baseline gap-2 text-[13px]">
              <dt className="text-faint">{f.label}</dt>
              <dd className="font-mono text-ink">{f.value}</dd>
            </div>
          ))}
        </dl>
        {evidence.length > 0 && (
          <details className="mt-3">
            <summary className="cursor-pointer text-[13px] text-faint hover:text-muted">
              Evidence — {evidence.length} referenced line
              {evidence.length === 1 ? "" : "s"}
            </summary>
            <ol className="mt-2 space-y-1 border-l border-line pl-3">
              {evidence.map((e) => (
                <li key={e.id} className="font-mono text-[12px] break-all text-muted">
                  <span className="text-faint">L{e.lineNumber}</span> {e.raw}
                </li>
              ))}
            </ol>
          </details>
        )}
      </div>
    </li>
  );
}

export default function FindingsList({
  findings,
  events,
}: {
  findings: Finding[];
  events: AuthEvent[];
}) {
  // The id index is built once per analysis, not once per finding.
  const eventsById = new Map(events.map((e) => [e.id, e]));
  return (
    <section aria-label="Findings">
      <h2 className="text-sm font-medium tracking-wide text-faint uppercase">
        Findings
      </h2>
      {findings.length === 0 ? (
        <p className="mt-4 text-sm text-muted">
          No findings — all detection rules were below their thresholds for
          this log.
        </p>
      ) : (
        <ul className="mt-4">
          {findings.map((f, i) => (
            <FindingItem
              key={`${f.ruleId}-${i}`}
              finding={f}
              eventsById={eventsById}
            />
          ))}
        </ul>
      )}
    </section>
  );
}
