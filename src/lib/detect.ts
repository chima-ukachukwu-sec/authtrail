import type {
  AuthEvent,
  Chronology,
  Finding,
  FindingFact,
  Severity,
} from './types';

export const THRESHOLDS = {
  /** R1: failure burst from one source IP. */
  R1_WINDOW_MS: 10 * 60 * 1000,
  R1_MIN_FAILURES: 5,
  R1_HIGH_FAILURES: 20,
  /** R2: username enumeration from one IP. */
  R2_MIN_USERNAMES: 3,
  R2_WINDOW_MS: 10 * 60 * 1000,
  /** R3: frequently targeted usernames. */
  R3_MIN_ATTEMPTS: 3,
  R3_MAX_LISTED: 5,
  /** R5: success after a same-IP, same-user failure burst. */
  R5_WINDOW_MS: 10 * 60 * 1000,
  R5_MIN_FAILURES: 3,
  /** Cap on event ids embedded in a single finding. */
  MAX_EVIDENCE_EVENTS: 25,
} as const;

export const PRIVILEGED_USERNAMES = ['root'];

const SEVERITY_RANK: Record<Severity, number> = {
  high: 3,
  medium: 2,
  low: 1,
  informational: 0,
};

function byTime(events: AuthEvent[]): AuthEvent[] {
  return events
    .filter((e): e is AuthEvent & { relativeMs: number } => e.relativeMs !== null)
    .sort((a, b) => a.relativeMs - b.relativeMs);
}

/** Largest number of events within any sliding window of `windowMs`. */
function maxCountInWindow(sorted: AuthEvent[], windowMs: number): number {
  let best = 0;
  let start = 0;
  for (let end = 0; end < sorted.length; end++) {
    while (sorted[end].relativeMs! - sorted[start].relativeMs! > windowMs) {
      start++;
    }
    best = Math.max(best, end - start + 1);
  }
  return best;
}

/** Events falling inside the densest window (for evidence lists). */
function densestWindow(sorted: AuthEvent[], windowMs: number): AuthEvent[] {
  // Track the best window as range indices and slice once at the end —
  // slicing on every improvement is quadratic when thousands of events
  // share one window.
  let bestStart = 0;
  let bestLength = 0;
  let start = 0;
  for (let end = 0; end < sorted.length; end++) {
    while (sorted[end].relativeMs! - sorted[start].relativeMs! > windowMs) {
      start++;
    }
    if (end - start + 1 > bestLength) {
      bestLength = end - start + 1;
      bestStart = start;
    }
  }
  return sorted.slice(bestStart, bestStart + bestLength);
}

/** Events of the window with the most distinct usernames (for evidence). */
function densestDistinctUsernamesWindow(
  sorted: AuthEvent[],
  windowMs: number,
): AuthEvent[] {
  let bestStart = 0;
  let bestEnd = 0;
  let bestDistinct = 0;
  let start = 0;
  const counts = new Map<string, number>();
  for (let end = 0; end < sorted.length; end++) {
    const user = sorted[end].username!;
    counts.set(user, (counts.get(user) ?? 0) + 1);
    while (sorted[end].relativeMs! - sorted[start].relativeMs! > windowMs) {
      const u = sorted[start].username!;
      counts.set(u, counts.get(u)! - 1);
      if (counts.get(u) === 0) counts.delete(u);
      start++;
    }
    if (counts.size > bestDistinct) {
      bestDistinct = counts.size;
      bestStart = start;
      bestEnd = end + 1;
    }
  }
  return sorted.slice(bestStart, bestEnd);
}

function evidenceIds(events: AuthEvent[]): string[] {
  return events.slice(0, THRESHOLDS.MAX_EVIDENCE_EVENTS).map((e) => e.id);
}

/**
 * Picks event ids under MAX_EVIDENCE_EVENTS so the events that prove the
 * finding always survive truncation: required (causal) events are retained
 * first, remaining capacity is filled with supporting events, and the final
 * list is in time order.
 */
function selectEvidence(
  required: AuthEvent[],
  supporting: AuthEvent[],
): string[] {
  const cap = THRESHOLDS.MAX_EVIDENCE_EVENTS;
  const chosen = new Map<string, AuthEvent>();
  for (const e of required) {
    if (chosen.size >= cap) break;
    chosen.set(e.id, e);
  }
  for (const e of byTime(supporting)) {
    if (chosen.size >= cap) break;
    chosen.set(e.id, e);
  }
  return byTime([...chosen.values()]).map((e) => e.id);
}

function fact(label: string, value: string | number): FindingFact {
  return { label, value: String(value) };
}

/** Half-open index range [lo, hi) into a time-sorted event list. */
interface WindowRange {
  lo: number;
  hi: number;
}

/**
 * For each success (time-sorted), the range of events from a time-sorted
 * list that precede it within `windowMs`. Two monotonic pointers make this
 * O(F + S) per pair. Only indices are returned — the caller materializes
 * just the few events it needs as evidence, so a window holding thousands
 * of events is never copied once per success.
 */
function windowRangesBeforeEach(
  sortedEvents: AuthEvent[],
  sortedSuccesses: AuthEvent[],
  windowMs: number,
): WindowRange[] {
  const result: WindowRange[] = [];
  let lo = 0; // first index still inside the current window
  let hi = 0; // first index not strictly before the current success
  for (const s of sortedSuccesses) {
    const t = s.relativeMs!;
    while (hi < sortedEvents.length && sortedEvents[hi].relativeMs! < t) hi++;
    while (lo < hi && t - sortedEvents[lo].relativeMs! > windowMs) lo++;
    result.push({ lo, hi });
  }
  return result;
}

/**
 * Incremental sliding window over a time-sorted list, tracking the distinct
 * usernames currently inside the window and each username's first in-window
 * event. advance() is amortized O(1) per success, so distinct-username
 * checks stay near-linear even when thousands of events share one window.
 */
class SlidingUsernameWindow {
  private lo = 0;
  private hi = 0;
  private readonly queues = new Map<
    string,
    { events: AuthEvent[]; head: number }
  >();

  constructor(
    private readonly sorted: AuthEvent[],
    private readonly windowMs: number,
  ) {}

  advance(t: number): void {
    const s = this.sorted;
    while (this.hi < s.length && s[this.hi].relativeMs! < t) {
      const username = s[this.hi].username!;
      let queue = this.queues.get(username);
      if (!queue) {
        queue = { events: [], head: 0 };
        this.queues.set(username, queue);
      }
      queue.events.push(s[this.hi]);
      this.hi++;
    }
    while (this.lo < this.hi && t - s[this.lo].relativeMs! > this.windowMs) {
      const queue = this.queues.get(s[this.lo].username!)!;
      queue.head++;
      if (queue.head === queue.events.length) {
        this.queues.delete(s[this.lo].username!);
      }
      this.lo++;
    }
  }

  get distinct(): number {
    return this.queues.size;
  }

  /** First in-window event of up to `limit` distinct usernames. */
  firstByUser(limit: number): AuthEvent[] {
    const firsts: AuthEvent[] = [];
    for (const queue of this.queues.values()) {
      if (firsts.length >= limit) break;
      firsts.push(queue.events[queue.head]);
    }
    return firsts;
  }
}

export interface RuleOutput {
  findings: Finding[];
  /** Rule tiers suppressed because relative chronology is not confident. */
  suppressed: string[];
}

/**
 * Deterministic detection over the deduplicated, correlated attempt set.
 * Findings describe observed behavior; none assert that an IP "is malicious".
 */
export function runRules(
  attempts: AuthEvent[],
  chronology: Chronology,
): RuleOutput {
  const findings: Finding[] = [];
  const suppressed: string[] = [];
  const timeable = chronology.confident;

  const failed = attempts.filter((a) => a.attemptType === 'failed_attempt');
  const successes = attempts.filter(
    (a) => a.attemptType === 'successful_attempt',
  );
  const byIp = (list: AuthEvent[]) => {
    const map = new Map<string, AuthEvent[]>();
    for (const e of list) {
      if (e.sourceIp === null) continue;
      const l = map.get(e.sourceIp) ?? [];
      l.push(e);
      map.set(e.sourceIp, l);
    }
    return map;
  };

  // R1 — failure burst from one source IP (time-dependent).
  if (timeable) {
    for (const [ip, list] of byIp(failed)) {
      const sorted = byTime(list);
      const max = maxCountInWindow(sorted, THRESHOLDS.R1_WINDOW_MS);
      if (max < THRESHOLDS.R1_MIN_FAILURES) continue;
      const window = densestWindow(sorted, THRESHOLDS.R1_WINDOW_MS);
      const users = new Set(window.map((e) => e.username).filter(Boolean));
      findings.push({
        ruleId: 'R1',
        severity: max >= THRESHOLDS.R1_HIGH_FAILURES ? 'high' : 'medium',
        title: `Failure burst from ${ip}`,
        description: `${max} failed authentication attempts from ${ip} occurred within a 10-minute window. This is consistent with password-guessing behavior; it does not by itself establish malicious intent.`,
        facts: [
          fact('Source IP', ip),
          fact('Failures within 10 min', max),
          fact('Total failures from this IP', list.length),
          fact('Usernames targeted in window', users.size),
        ],
        eventIds: evidenceIds(window),
      });
    }
  } else {
    suppressed.push('R1 (failure bursts)');
  }

  // R2 — username enumeration from one IP. The count-based tier needs no
  // clock; the medium tier requires a 10-minute window.
  for (const [ip, list] of byIp(
    attempts.filter((a) => a.isInvalidUser && a.username !== null),
  )) {
    const users = new Set(list.map((a) => a.username!));
    if (users.size < THRESHOLDS.R2_MIN_USERNAMES) continue;
    const sorted = byTime(list);
    const rapidWindow = timeable
      ? densestDistinctUsernamesWindow(sorted, THRESHOLDS.R2_WINDOW_MS)
      : [];
    const rapid =
      new Set(rapidWindow.map((e) => e.username)).size >=
      THRESHOLDS.R2_MIN_USERNAMES;
    const listed = [...users].slice(0, 6).join(', ');
    // The distinct usernames are what prove the finding, so one event per
    // username is always retained; the cap's remaining capacity is filled
    // with the rest of the window in time order. Medium tier: reference the
    // actual rapid window, not arbitrary earlier events. Low tier describes
    // the whole period.
    const evidencePool = rapid ? rapidWindow : sorted;
    const firstByUser = new Map<string, AuthEvent>();
    for (const e of evidencePool) {
      if (!firstByUser.has(e.username!)) firstByUser.set(e.username!, e);
    }
    findings.push({
      ruleId: 'R2',
      severity: rapid ? 'medium' : 'low',
      title: `Username enumeration from ${ip}`,
      description: rapid
        ? `${users.size} distinct nonexistent usernames were attempted from ${ip}, at least ${THRESHOLDS.R2_MIN_USERNAMES} of them within 10 minutes — a pattern consistent with username probing.`
        : `${users.size} distinct nonexistent usernames were attempted from ${ip} over the observed period. Trying nonexistent accounts is not typical of legitimate use, but the pacing observed here is slow.`,
      facts: [
        fact('Source IP', ip),
        fact('Distinct invalid usernames', users.size),
        fact('Usernames', listed + (users.size > 6 ? ', …' : '')),
      ],
      eventIds: selectEvidence([...firstByUser.values()], evidencePool),
    });
  }
  if (!timeable) suppressed.push('R2 elevated tier (rapid enumeration)');

  // R3 — frequently targeted usernames (informational).
  const byUser = new Map<string, AuthEvent[]>();
  for (const a of attempts) {
    if (a.username === null) continue;
    const l = byUser.get(a.username) ?? [];
    l.push(a);
    byUser.set(a.username, l);
  }
  const targeted = [...byUser.entries()]
    .filter(([, l]) => l.length >= THRESHOLDS.R3_MIN_ATTEMPTS)
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, THRESHOLDS.R3_MAX_LISTED);
  if (targeted.length > 0) {
    findings.push({
      ruleId: 'R3',
      severity: 'informational',
      title: 'Frequently targeted usernames',
      description: `These usernames received the most authentication attempts in this log: ${targeted
        .map(([u, l]) => `${u} (${l.length})`)
        .join(', ')}.`,
      facts: targeted.map(([u, l]) =>
        fact(
          u,
          `${l.length} attempts from ${new Set(l.map((e) => e.sourceIp).filter(Boolean)).size} IPs`,
        ),
      ),
      eventIds: evidenceIds(targeted.flatMap(([, l]) => l)),
    });
  }

  // R4 — privileged-account activity, tiered. A root success alone is
  // medium; it escalates to high only when temporally correlated with a
  // same-IP failure burst (R5 condition) or same-IP enumeration immediately
  // preceding it.
  const privilegedFailures = failed.filter((a) => a.isPrivilegedTarget);
  if (privilegedFailures.length > 0) {
    const ips = new Set(
      privilegedFailures.map((a) => a.sourceIp).filter(Boolean),
    );
    findings.push({
      ruleId: 'R4',
      severity: 'informational',
      title: 'Failed attempts against privileged accounts',
      description: `${privilegedFailures.length} failed attempts targeted privileged accounts (root). On internet-facing SSH this is common background noise; it becomes significant only in combination with other evidence.`,
      facts: [
        fact('Failed attempts', privilegedFailures.length),
        fact('Distinct source IPs', ips.size),
      ],
      eventIds: evidenceIds(privilegedFailures),
    });
  }

  const rootSuccesses = successes.filter((a) => a.username === 'root');
  if (rootSuccesses.length > 0) {
    let escalated = false;
    const escalationRequired: AuthEvent[] = [];
    const escalationSupporting: AuthEvent[] = [];
    if (timeable) {
      // Indexes built once, so each root success consults small per-IP lists
      // instead of rescanning the full attempt/failure arrays.
      const rootFailedByIp = new Map<string, AuthEvent[]>();
      for (const f of failed) {
        if (f.sourceIp === null || f.username !== 'root') continue;
        const l = rootFailedByIp.get(f.sourceIp) ?? [];
        l.push(f);
        rootFailedByIp.set(f.sourceIp, l);
      }
      for (const [ip, list] of rootFailedByIp) {
        rootFailedByIp.set(ip, byTime(list));
      }
      const invalidByIp = new Map<string, AuthEvent[]>();
      for (const a of attempts) {
        if (!a.isInvalidUser || a.username === null || a.sourceIp === null)
          continue;
        const l = invalidByIp.get(a.sourceIp) ?? [];
        l.push(a);
        invalidByIp.set(a.sourceIp, l);
      }
      for (const [ip, list] of invalidByIp) invalidByIp.set(ip, byTime(list));

      const rootSuccessesByIp = new Map<string, AuthEvent[]>();
      for (const s of rootSuccesses) {
        if (s.sourceIp === null || s.relativeMs === null) continue;
        const l = rootSuccessesByIp.get(s.sourceIp) ?? [];
        l.push(s);
        rootSuccessesByIp.set(s.sourceIp, l);
      }
      for (const [ip, list] of rootSuccessesByIp) {
        const successes = byTime(list);
        const rootFailed = rootFailedByIp.get(ip) ?? [];
        const burstRanges = windowRangesBeforeEach(
          rootFailed,
          successes,
          THRESHOLDS.R5_WINDOW_MS,
        );
        const enumerationWindow = new SlidingUsernameWindow(
          invalidByIp.get(ip) ?? [],
          THRESHOLDS.R2_WINDOW_MS,
        );
        for (let i = 0; i < successes.length; i++) {
          const success = successes[i];
          enumerationWindow.advance(success.relativeMs!);
          const burstEscalates =
            burstRanges[i].hi - burstRanges[i].lo >= THRESHOLDS.R5_MIN_FAILURES;
          const enumerationEscalates =
            enumerationWindow.distinct >= THRESHOLDS.R2_MIN_USERNAMES;
          if (!burstEscalates && !enumerationEscalates) continue;
          escalated = true;
          // Evidence = one complete causal chain per escalating success: the
          // success plus enough precursors to show the cause. Only those few
          // proving events are materialized (never the whole window), and a
          // chain is added only while it fits under the evidence cap; further
          // escalating successes remain as supporting representatives.
          const chain: AuthEvent[] = [success];
          if (burstEscalates) {
            chain.push(
              ...rootFailed.slice(
                burstRanges[i].lo,
                burstRanges[i].lo + THRESHOLDS.R5_MIN_FAILURES,
              ),
            );
          }
          if (enumerationEscalates) {
            chain.push(
              ...enumerationWindow.firstByUser(THRESHOLDS.R2_MIN_USERNAMES),
            );
          }
          if (
            escalationRequired.length + chain.length <=
            THRESHOLDS.MAX_EVIDENCE_EVENTS
          ) {
            escalationRequired.push(...chain);
          } else {
            escalationSupporting.push(success);
          }
        }
      }
    } else {
      suppressed.push('R4 high tier (correlated root success)');
    }
    const ips = [...new Set(rootSuccesses.map((a) => a.sourceIp).filter(Boolean))];
    findings.push({
      ruleId: 'R4',
      severity: escalated ? 'high' : 'medium',
      title: escalated
        ? 'Root login correlated with preceding suspicious activity'
        : 'Successful root authentication',
      description: escalated
        ? `${rootSuccesses.length} successful root login(s) observed, and at least one directly followed a burst of failures or username enumeration from the same IP within 10 minutes. Verify urgently whether this was expected administrative activity.`
        : `${rootSuccesses.length} successful root login(s) observed. AuthTrail cannot tell whether direct root login is permitted in this environment — verify this was expected administrative activity.`,
      facts: [
        fact('Successful root logins', rootSuccesses.length),
        fact('Source IPs', ips.join(', ') || 'unknown'),
      ],
      eventIds: escalated
        ? selectEvidence(escalationRequired, escalationSupporting)
        : evidenceIds(rootSuccesses),
    });
  }

  // R5 — successful login after a same-IP, same-user failure burst.
  if (timeable) {
    // Index failures once by (ip, username); per-pair checks then scan only
    // the pair's own failure list, never the full array.
    const failedByPair = new Map<string, AuthEvent[]>();
    for (const f of failed) {
      if (f.sourceIp === null || f.username === null) continue;
      const key = `${f.sourceIp} ${f.username}`;
      const l = failedByPair.get(key) ?? [];
      l.push(f);
      failedByPair.set(key, l);
    }
    const pairSuccesses = new Map<string, AuthEvent[]>();
    for (const s of successes) {
      if (s.sourceIp === null || s.username === null || s.relativeMs === null)
        continue;
      const key = `${s.sourceIp} ${s.username}`;
      const l = pairSuccesses.get(key) ?? [];
      l.push(s);
      pairSuccesses.set(key, l);
    }
    for (const [key, list] of pairSuccesses) {
      const [ip, user] = key.split(' ');
      const pairFailed = byTime(failedByPair.get(key) ?? []);
      const pairSuccessesSorted = byTime(list);
      const ranges = windowRangesBeforeEach(
        pairFailed,
        pairSuccessesSorted,
        THRESHOLDS.R5_WINDOW_MS,
      );
      const hits: AuthEvent[] = [];
      const hitRanges: WindowRange[] = [];
      for (let i = 0; i < pairSuccessesSorted.length; i++) {
        if (ranges[i].hi - ranges[i].lo >= THRESHOLDS.R5_MIN_FAILURES) {
          hits.push(pairSuccessesSorted[i]);
          hitRanges.push(ranges[i]);
        }
      }
      if (hits.length === 0) continue;
      // Evidence: complete causal chains — one triggering success plus the
      // precursor failures that prove it, per hit. Only those few events are
      // materialized (never the whole window), and chains are added only
      // while a full chain still fits under the evidence cap, so a finding
      // with many hits still shows a complete causal example instead of
      // filling up on successes alone. Remaining hits act as supporting
      // representatives.
      const required: AuthEvent[] = [];
      let chainedHits = 0;
      for (let i = 0; i < hits.length; i++) {
        const precursors = pairFailed.slice(
          hitRanges[i].lo,
          hitRanges[i].lo + THRESHOLDS.R5_MIN_FAILURES,
        );
        if (
          required.length + precursors.length + 1 >
          THRESHOLDS.MAX_EVIDENCE_EVENTS
        ) {
          break;
        }
        required.push(hits[i], ...precursors);
        chainedHits++;
      }
      findings.push({
        ruleId: 'R5',
        severity: 'high',
        title: `Login success after failure burst (${user} from ${ip})`,
        description: `${hits.length} successful login(s) for ${user} from ${ip} each followed at least ${THRESHOLDS.R5_MIN_FAILURES} failed attempts from the same IP and username within 10 minutes. This is a possible compromise indicator — verify out-of-band before drawing conclusions.`,
        facts: [
          fact('Username', user),
          fact('Source IP', ip),
          fact('Successes matching pattern', hits.length),
          fact('Failed attempts for this pair', pairFailed.length),
        ],
        eventIds: selectEvidence(required, hits.slice(chainedHits)),
      });
    }
  } else {
    suppressed.push('R5 (success after failure burst)');
  }

  findings.sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      a.ruleId.localeCompare(b.ruleId),
  );
  return { findings, suppressed: [...new Set(suppressed)] };
}
