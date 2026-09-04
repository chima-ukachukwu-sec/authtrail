import { markDuplicates, splitLines } from './ingest';
import { parseLines } from './parse';
import { buildChronology } from './timestamp';
import { correlateEvents } from './correlate';
import { runRules } from './detect';
import { summarize } from './stats';
import type { AnalysisResult } from './types';

/**
 * Single entry point for analysis. Pure and synchronous: text in, result out.
 * Everything runs in the caller's environment (the browser); nothing here
 * performs I/O or network activity.
 */
export function analyzeLogText(text: string): AnalysisResult {
  const lines = markDuplicates(splitLines(text));
  const events = parseLines(lines);
  const chronology = buildChronology(events);
  const { unattributedObservations } = correlateEvents(events);

  const attempts = events.filter(
    (e) => e.category === 'attempt' && e.duplicateOf === null,
  );
  const { findings, suppressed } = runRules(attempts, chronology);
  const { summary, topIps, topUsernames } = summarize(
    events,
    chronology,
    unattributedObservations,
    suppressed,
  );

  return { summary, chronology, findings, events, topIps, topUsernames };
}
