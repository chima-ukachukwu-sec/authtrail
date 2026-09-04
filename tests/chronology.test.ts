import { describe, it, expect } from 'vitest';
import { analyzeLines, failed, fixture } from './helpers';

describe('relative chronology', () => {
  it('accumulates elapsed time across same-day syslog lines', () => {
    const r = analyzeLines([
      failed('Jan  5 10:00:00', 'a', '10.0.0.1'),
      failed('Jan  5 10:01:00', 'a', '10.0.0.1'),
      failed('Jan  5 10:03:30', 'a', '10.0.0.1'),
    ]);
    expect(r.chronology.confident).toBe(true);
    expect(r.chronology.spanMs).toBe(3.5 * 60 * 1000);
    const times = r.events
      .filter((e) => e.relativeMs !== null)
      .map((e) => e.relativeMs);
    expect(times).toEqual([0, 60_000, 210_000]);
  });

  it('handles Dec 31 -> Jan 1 as elapsed time, not a fabricated year', () => {
    const r = analyzeLines(fixture('rollover.log').trimEnd().split('\n'));
    expect(r.chronology.confident).toBe(true);
    // 23:55 -> 00:01 next day is 6 minutes of elapsed time.
    expect(r.chronology.spanMs).toBe(6 * 60 * 1000);
    // No line carried a year, so no absolute time may be claimed.
    expect(r.events.every((e) => e.absoluteTime === null)).toBe(true);
    expect(r.chronology.explicitAnchors).toBe(0);
    // The 6 failures within 6 minutes cross the year boundary and still fire R1.
    expect(r.findings.some((f) => f.ruleId === 'R1')).toBe(true);
  });

  it('marks scrambled chronology not confident and suppresses time-dependent rules', () => {
    const r = analyzeLines(fixture('ambiguous.log').trimEnd().split('\n'));
    expect(r.chronology.confident).toBe(false);
    expect(r.findings.some((f) => f.ruleId === 'R1')).toBe(false);
    expect(r.findings.some((f) => f.ruleId === 'R5')).toBe(false);
    expect(r.summary.suppressedRules.join()).toContain('R1');
    expect(r.summary.suppressedRules.join()).toContain('R5');
  });

  it('tolerates small out-of-order jitter without losing confidence', () => {
    const r = analyzeLines([
      failed('Jan  5 10:00:00', 'a', '10.0.0.1'),
      failed('Jan  5 09:58:00', 'a', '10.0.0.1'), // 2 min backward: clamp
      failed('Jan  5 10:02:00', 'a', '10.0.0.1'),
    ]);
    expect(r.chronology.confident).toBe(true);
  });

  it('uses exact deltas from ISO timestamps and records absolute time', () => {
    const r = analyzeLines([
      '2024-01-05T10:00:00+00:00 host sshd[101]: Failed password for root from 10.0.0.1 port 22 ssh2',
      '2024-01-05T10:02:30+00:00 host sshd[102]: Failed password for root from 10.0.0.1 port 22 ssh2',
    ]);
    expect(r.chronology.explicitAnchors).toBe(2);
    expect(r.chronology.spanMs).toBe(150_000);
    expect(r.events[0].absoluteTime?.toISOString()).toBe(
      '2024-01-05T10:00:00.000Z',
    );
    expect(r.events[1].relativeMs).toBe(150_000);
  });

  it('accepts space-separated ISO-like timestamps', () => {
    const r = analyzeLines([
      '2024-01-05 10:00:00 host sshd[101]: Failed password for root from 10.0.0.1 port 22 ssh2',
      '2024-01-05 10:01:00 host sshd[102]: Failed password for root from 10.0.0.1 port 22 ssh2',
    ]);
    expect(r.chronology.spanMs).toBe(60_000);
    expect(r.chronology.confident).toBe(true);
  });

  it('marks mixed syslog/ISO sequences not confident instead of inventing continuity', () => {
    const r = analyzeLines([
      'Sep  3 10:00:00 host sshd[6001]: Failed password for root from 10.0.0.9 port 1 ssh2',
      '2026-09-03T10:03:00Z host sshd[6002]: Failed password for root from 10.0.0.9 port 2 ssh2',
      'Sep  3 10:06:00 host sshd[6003]: Failed password for root from 10.0.0.9 port 3 ssh2',
      '2026-09-03T10:09:00Z host sshd[6004]: Accepted password for root from 10.0.0.9 port 4 ssh2',
    ]);
    // Raw timestamps are preserved for display, but elapsed continuity
    // across the format boundary is unknowable.
    expect(r.events[0].timestampRaw).toBe('Sep  3 10:00:00');
    expect(r.events[1].timestampRaw).toBe('2026-09-03T10:03:00Z');
    expect(r.chronology.confident).toBe(false);
  });

  it('suppresses time-windowed rules across a fabricated mixed-format window', () => {
    // Real timeline: failures at 10:00-10:01, success at 10:31 — 30 minutes
    // later, outside the 10-minute R5 window. A cursor-holding bug used to
    // compress this into 2 minutes and fire R5.
    const r = analyzeLines([
      'Sep  3 10:00:00 host sshd[7001]: Failed password for alice from 10.0.0.5 port 11 ssh2',
      'Sep  3 10:00:30 host sshd[7002]: Failed password for alice from 10.0.0.5 port 12 ssh2',
      'Sep  3 10:01:00 host sshd[7003]: Failed password for alice from 10.0.0.5 port 13 ssh2',
      '2026-09-03T10:30:00Z host sshd[7004]: Failed password for alice from 10.0.0.5 port 14 ssh2',
      '2026-09-03T10:31:00Z host sshd[7005]: Accepted password for alice from 10.0.0.5 port 15 ssh2',
    ]);
    expect(r.chronology.confident).toBe(false);
    expect(r.findings.some((f) => f.ruleId === 'R5')).toBe(false);
    expect(r.findings.some((f) => f.ruleId === 'R1')).toBe(false);
    expect(r.summary.suppressedRules.join()).toContain('R5');
  });

  it('keeps count-based rules working when chronology is not confident', () => {
    const r = analyzeLines([
      'Sep  3 10:00:00 host sshd[7101]: Failed password for invalid user aaa from 10.0.0.6 port 1 ssh2',
      '2026-09-03T10:05:00Z host sshd[7102]: Failed password for invalid user bbb from 10.0.0.6 port 2 ssh2',
      'Sep  3 10:10:00 host sshd[7103]: Failed password for invalid user ccc from 10.0.0.6 port 3 ssh2',
    ]);
    expect(r.chronology.confident).toBe(false);
    const r2 = r.findings.find((f) => f.ruleId === 'R2');
    // Count-based tier still fires; the rapid (windowed) tier must not.
    expect(r2?.severity).toBe('low');
    expect(r.summary.suppressedRules.join()).toContain('R2');
  });
});
