import type { AuthEvent } from './types';

const AUTH_OBSERVATION_LABELS = new Set([
  'invalid_user',
  'connection_closed',
  'disconnected',
  'pam_failure',
]);

/**
 * Correlation is only defensible within one session. A pid is reused by the
 * OS, so pid-only matching across hosts, identities, or long time gaps would
 * merge unrelated sessions: observation lines must share the attempt's host,
 * agree on whatever identity fields they carry, and fall within this gap.
 */
const MAX_SESSION_GAP_MS = 10 * 60 * 1000;

function identityConsistent(a: AuthEvent, b: AuthEvent): boolean {
  return (
    (a.username === null || b.username === null || a.username === b.username) &&
    (a.sourceIp === null || b.sourceIp === null || a.sourceIp === b.sourceIp)
  );
}

function withinSessionGap(a: AuthEvent, b: AuthEvent): boolean {
  if (a.relativeMs === null || b.relativeMs === null) return true;
  return Math.abs(a.relativeMs - b.relativeMs) <= MAX_SESSION_GAP_MS;
}

export interface CorrelationResult {
  /** Auth-relevant observations that could not be confidently attributed. */
  unattributedObservations: number;
}

/**
 * Correlates sshd observation lines with the authentication attempts they
 * belong to, so one underlying attempt is never counted twice.
 *
 * Invariants:
 * - Only self-contained credential-result lines (Failed/Accepted) mint
 *   attempts directly. Observation lines never create attempts unless a
 *   confident group merge applies.
 * - Uncertain observations create ZERO attempts: they stay visible as
 *   observations, are disclosed as unattributed, and contribute nothing to
 *   detection thresholds or statistics. When uncertain, AuthTrail
 *   under-reports rather than over-reports.
 *
 * Duplicate lines are excluded here (dedupe happened at ingest), so repeated
 * raw lines cannot fabricate adjacency or distort grouping.
 */
export function correlateEvents(events: AuthEvent[]): CorrelationResult {
  const unique = events.filter(
    (e) => e.duplicateOf === null && e.category !== 'unparsed',
  );
  const byLine = new Map<number, AuthEvent>();
  for (const e of unique) byLine.set(e.lineNumber, e);

  const isAuthObservation = (e: AuthEvent) =>
    e.category === 'observation' && AUTH_OBSERVATION_LABELS.has(e.parseLabel);

  const pidKey = (e: AuthEvent) => `${e.host ?? ''}\0${e.pid}`;

  const attemptsByPid = new Map<string, AuthEvent[]>();
  for (const e of unique) {
    if (e.category === 'attempt' && e.pid !== null) {
      const list = attemptsByPid.get(pidKey(e)) ?? [];
      list.push(e);
      attemptsByPid.set(pidKey(e), list);
    }
  }

  const attributed = new Set<number>();
  const attach = (attempt: AuthEvent, observation: AuthEvent) => {
    attempt.evidenceLineNumbers.push(observation.lineNumber);
    attributed.add(observation.lineNumber);
  };

  // Pass 1: attach observations to an attempt of the same session (host +
  // pid). Only identity-consistent, temporally sane candidates qualify; a
  // conflicting observation is never attached merely because the pid matches
  // (pids are reused) — it stays an observation instead of contaminating an
  // unrelated attempt.
  for (const o of unique) {
    if (!isAuthObservation(o) || o.pid === null) continue;
    const candidates = attemptsByPid.get(pidKey(o));
    if (!candidates || candidates.length === 0) continue;
    const eligible = candidates.filter(
      (a) => identityConsistent(a, o) && withinSessionGap(a, o),
    );
    if (eligible.length === 0) continue;
    // Prefer the temporally nearest attempt; fall back to line distance.
    const nearest = eligible.reduce((best, a) => {
      const dist = (x: AuthEvent) =>
        x.relativeMs !== null && o.relativeMs !== null
          ? Math.abs(x.relativeMs - o.relativeMs)
          : Math.abs(x.lineNumber - o.lineNumber);
      return dist(a) < dist(best) ? a : best;
    });
    attach(nearest, o);
  }

  // Pass 2: remaining pid-tagged observations. Sessions are distinguished by
  // identity consistency and time gaps, so pid reuse cannot merge unrelated
  // sessions. A session with an invalid-user signal but no credential result
  // is exactly one probing attempt (the client disconnected before
  // submitting a credential).
  const groups = new Map<string, AuthEvent[]>();
  for (const o of unique) {
    if (!isAuthObservation(o) || o.pid === null || attributed.has(o.lineNumber))
      continue;
    const list = groups.get(pidKey(o)) ?? [];
    list.push(o);
    groups.set(pidKey(o), list);
  }
  for (const group of groups.values()) {
    // Partition the pid group into identity-consistent sessions.
    const sessions: AuthEvent[][] = [];
    for (const o of group) {
      const session = sessions.find(
        (s) =>
          s.every((m) => identityConsistent(m, o)) &&
          withinSessionGap(s[s.length - 1], o),
      );
      if (session) session.push(o);
      else sessions.push([o]);
    }
    for (const session of sessions) {
      const anchor =
        session.find((o) => o.parseLabel === 'invalid_user') ??
        session.find((o) => o.isInvalidUser);
      if (!anchor) continue; // no invalid-user signal → unattributed
      anchor.category = 'attempt';
      anchor.attemptType = 'invalid_user_probe';
      for (const o of session) {
        if (o !== anchor) attach(anchor, o);
        else attributed.add(o.lineNumber);
      }
    }
  }

  // Pass 3: pid-less fallback. Strict same-second, same-identity adjacency
  // only; anything less certain stays an unattributed observation.
  for (const o of unique) {
    if (!isAuthObservation(o) || attributed.has(o.lineNumber)) continue;
    if (o.pid !== null) continue;
    if (o.username === null || o.sourceIp === null) continue;

    const neighbors = [byLine.get(o.lineNumber - 1), byLine.get(o.lineNumber + 1)].filter(
      (e): e is AuthEvent => e !== undefined,
    );
    const sameIdentity = (e: AuthEvent) =>
      e.timestampRaw === o.timestampRaw &&
      e.username === o.username &&
      e.sourceIp === o.sourceIp;

    const attempt = neighbors.find(
      (e) => e.category === 'attempt' && sameIdentity(e),
    );
    if (attempt) {
      attach(attempt, o);
      continue;
    }

    const partner = neighbors.find(
      (e) =>
        e.category === 'observation' &&
        e.isInvalidUser &&
        !attributed.has(e.lineNumber) &&
        sameIdentity(e),
    );
    if (partner && o.isInvalidUser) {
      const anchor = o.parseLabel === 'invalid_user' ? o : partner;
      const other = anchor === o ? partner : o;
      anchor.category = 'attempt';
      anchor.attemptType = 'invalid_user_probe';
      attributed.add(anchor.lineNumber);
      attach(anchor, other);
    }
  }

  let unattributedObservations = 0;
  for (const o of unique) {
    if (isAuthObservation(o) && !attributed.has(o.lineNumber)) {
      unattributedObservations++;
    }
  }
  return { unattributedObservations };
}
