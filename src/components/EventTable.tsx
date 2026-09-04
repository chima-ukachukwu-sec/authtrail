"use client";

import { useMemo, useState } from "react";
import type { AuthEvent } from "@/lib/types";
import { eventTypeLabel } from "@/lib/format";

type TypeFilter = "all" | "failed" | "success" | "probe" | "observation" | "unparsed";

const PAGE_SIZE = 200;
const PAGE_INCREMENT = 500;

const TYPE_STYLE: Record<string, string> = {
  failed: "text-high",
  success: "text-accent",
  probe: "text-medium",
  observation: "text-faint",
  unparsed: "text-faint",
};

export default function EventTable({ events }: { events: AuthEvent[] }) {
  const [typeFilter, setTypeFilter] = useState<TypeFilter>("all");
  const [hideDuplicates, setHideDuplicates] = useState(true);
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [limit, setLimit] = useState(PAGE_SIZE);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return events.filter((e) => {
      if (hideDuplicates && e.duplicateOf !== null) return false;
      const label = eventTypeLabel(e);
      if (typeFilter !== "all" && label !== typeFilter) return false;
      if (q !== "") {
        const haystack = `${e.raw} ${e.username ?? ""} ${e.sourceIp ?? ""}`.toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
  }, [events, typeFilter, hideDuplicates, query]);

  const visible = filtered.slice(0, limit);

  const toggle = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <section aria-label="Event log">
      <h2 className="text-sm font-medium tracking-wide text-faint uppercase">
        Events
      </h2>

      <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-3">
        <label className="flex items-center gap-2 text-[13px] text-muted">
          Type
          <select
            value={typeFilter}
            onChange={(e) => {
              setTypeFilter(e.target.value as TypeFilter);
              setLimit(PAGE_SIZE);
            }}
            className="border border-line bg-surface px-2 py-1 text-[13px] text-ink"
          >
            <option value="all">All</option>
            <option value="failed">Failed</option>
            <option value="success">Successful</option>
            <option value="probe">Invalid-user probes</option>
            <option value="observation">Observations</option>
            <option value="unparsed">Unparsed</option>
          </select>
        </label>
        <label className="flex items-center gap-2 text-[13px] text-muted">
          Filter
          <input
            type="search"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setLimit(PAGE_SIZE);
            }}
            placeholder="user, IP, or text"
            className="w-48 border border-line bg-surface px-2 py-1 font-mono text-[13px] text-ink placeholder:text-faint"
          />
        </label>
        <label className="flex items-center gap-2 text-[13px] text-muted">
          <input
            type="checkbox"
            checked={hideDuplicates}
            onChange={(e) => setHideDuplicates(e.target.checked)}
            className="size-3.5 accent-[#6ea8fe]"
          />
          Hide repeated lines
        </label>
        <span className="text-[13px] text-faint">
          {filtered.length} of {events.length} lines
        </span>
      </div>

      <div className="mt-4 overflow-x-auto"><table className="w-full min-w-[640px] border-collapse">
        <thead>
          <tr className="border-b border-line">
            <th scope="col" className="px-3 py-2 text-left text-[12px] font-medium tracking-wide text-faint uppercase">Line</th>
            <th scope="col" className="px-3 py-2 text-left text-[12px] font-medium tracking-wide text-faint uppercase">Time (as logged)</th>
            <th scope="col" className="px-3 py-2 text-left text-[12px] font-medium tracking-wide text-faint uppercase">Type</th>
            <th scope="col" className="px-3 py-2 text-left text-[12px] font-medium tracking-wide text-faint uppercase">User</th>
            <th scope="col" className="px-3 py-2 text-left text-[12px] font-medium tracking-wide text-faint uppercase">Source</th>
            <th scope="col" className="px-3 py-2 text-left text-[12px] font-medium tracking-wide text-faint uppercase">Method</th>
            <th scope="col" className="px-3 py-2 text-right text-[12px] font-medium tracking-wide text-faint uppercase">
              <span className="sr-only">Raw line</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {visible.map((e) => {
            const label = eventTypeLabel(e);
            const isOpen = expanded.has(e.id);
            return [
              <tr
                key={e.id}
                className={`border-b border-line/60 ${e.duplicateOf !== null ? "opacity-50" : ""}`}
              >
                <td className="px-3 py-1.5 font-mono text-[12px] text-faint">
                  {e.lineNumber}
                </td>
                <td className="px-3 py-1.5 font-mono text-[12px] whitespace-nowrap text-muted">
                  {e.timestampRaw ?? "—"}
                </td>
                <td className={`px-3 py-1.5 text-[12px] font-medium ${TYPE_STYLE[label]}`}>
                  {label}
                  {e.isInvalidUser && e.category === "attempt" && (
                    <span className="ml-1.5 text-faint">invalid user</span>
                  )}
                  {e.duplicateOf !== null && (
                    <span className="ml-1.5 text-faint">repeat</span>
                  )}
                </td>
                <td className="max-w-40 truncate px-3 py-1.5 font-mono text-[13px] break-all text-ink">
                  {e.username ?? "—"}
                  {e.isPrivilegedTarget && (
                    <span className="ml-1.5 text-[11px] text-medium">root</span>
                  )}
                </td>
                <td className="max-w-44 truncate px-3 py-1.5 font-mono text-[13px] break-all text-ink">
                  {e.sourceIp ?? "—"}
                </td>
                <td className="px-3 py-1.5 text-[12px] text-muted">
                  {e.method ?? "—"}
                </td>
                <td className="px-3 py-1.5 text-right">
                  <button
                    type="button"
                    onClick={() => toggle(e.id)}
                    aria-expanded={isOpen}
                    aria-label={`Show raw line ${e.lineNumber}`}
                    className="text-[12px] text-faint underline decoration-line underline-offset-4 hover:text-muted"
                  >
                    {isOpen ? "hide" : "raw"}
                  </button>
                </td>
              </tr>,
              ...(isOpen
                ? [
                    <tr key={`${e.id}-raw`} className="border-b border-line/60">
                      <td colSpan={7} className="bg-surface px-3 py-2">
                        <p className="font-mono text-[12px] break-all whitespace-pre-wrap text-muted">
                          {e.raw}
                        </p>
                      </td>
                    </tr>,
                  ]
                : []),
            ];
          })}
        </tbody>
      </table></div>

      {filtered.length > limit && (
        <button
          type="button"
          onClick={() => setLimit((n) => n + PAGE_INCREMENT)}
          className="mt-4 text-sm text-muted underline decoration-line underline-offset-4 hover:text-ink"
        >
          Show more ({filtered.length - limit} remaining)
        </button>
      )}
    </section>
  );
}
