import { describe, it, expect } from 'vitest';
import { analyzeLines, accepted, failed } from './helpers';

function burst(
  startMinute: number,
  count: number,
  user: string,
  ip: string,
  stepSeconds = 30,
): string[] {
  const lines: string[] = [];
  for (let i = 0; i < count; i++) {
    const totalSeconds = startMinute * 60 + i * stepSeconds;
    const hh = String(Math.floor(totalSeconds / 3600)).padStart(2, '0');
    const mm = String(Math.floor((totalSeconds % 3600) / 60)).padStart(2, '0');
    const ss = String(totalSeconds % 60).padStart(2, '0');
    lines.push(failed(`Jan  5 ${hh}:${mm}:${ss}`, user, ip));
  }
  return lines;
}

describe('R1 — failure burst from one IP (>=5 within 10 min)', () => {
  it('fires medium at exactly 5 failures inside the window', () => {
    const r = analyzeLines(burst(0, 5, 'alice', '10.0.0.1'));
    const f = r.findings.find((f) => f.ruleId === 'R1');
    expect(f?.severity).toBe('medium');
  });

  it('does not fire at 4 failures (boundary below threshold)', () => {
    const r = analyzeLines(burst(0, 4, 'alice', '10.0.0.1'));
    expect(r.findings.some((f) => f.ruleId === 'R1')).toBe(false);
  });

  it('escalates to high at 20 failures inside the window', () => {
    const r = analyzeLines(burst(0, 20, 'alice', '10.0.0.1', 20));
    const f = r.findings.find((f) => f.ruleId === 'R1');
    expect(f?.severity).toBe('high');
  });

  it('does not fire for 5 failures spread across hours', () => {
    const r = analyzeLines([
      failed('Jan  5 08:00:00', 'alice', '10.0.0.1'),
      failed('Jan  5 09:00:00', 'alice', '10.0.0.1'),
      failed('Jan  5 10:00:00', 'alice', '10.0.0.1'),
      failed('Jan  5 11:00:00', 'alice', '10.0.0.1'),
      failed('Jan  5 12:00:00', 'alice', '10.0.0.1'),
    ]);
    expect(r.findings.some((f) => f.ruleId === 'R1')).toBe(false);
  });

  it('cannot be triggered by duplicating one line', () => {
    const line = failed('Jan  5 10:00:00', 'alice', '10.0.0.1', { pid: 7001 });
    const r = analyzeLines(Array(10).fill(line));
    expect(r.findings.some((f) => f.ruleId === 'R1')).toBe(false);
    expect(r.summary.duplicatesExcluded).toBe(9);
  });
});

describe('R2 — username enumeration (>=3 distinct invalid usernames)', () => {
  it('does not fire with only 2 distinct invalid usernames', () => {
    const r = analyzeLines([
      failed('Jan  5 10:00:00', 'aaa', '10.0.0.2', { invalid: true }),
      failed('Jan  5 10:01:00', 'bbb', '10.0.0.2', { invalid: true }),
    ]);
    expect(r.findings.some((f) => f.ruleId === 'R2')).toBe(false);
  });

  it('never fires for authenticating-user disconnects (regression: A1)', () => {
    const r = analyzeLines([
      'Jan  5 10:00:00 host sshd[5001]: Disconnected from authenticating user alice 10.0.0.2 port 1234',
      'Jan  5 10:01:00 host sshd[5002]: Disconnected from authenticating user bob 10.0.0.2 port 1235',
      'Jan  5 10:02:00 host sshd[5003]: Disconnected from authenticating user carol 10.0.0.2 port 1236',
    ]);
    expect(r.summary.attempts).toBe(0);
    expect(r.findings.some((f) => f.ruleId === 'R2')).toBe(false);
  });

  it('fires for invalid-user disconnects from one IP (control)', () => {
    const r = analyzeLines([
      'Jan  5 10:00:00 host sshd[5001]: Disconnected from invalid user alice 10.0.0.2 port 1234',
      'Jan  5 10:01:00 host sshd[5002]: Disconnected from invalid user bob 10.0.0.2 port 1235',
      'Jan  5 10:02:00 host sshd[5003]: Disconnected from invalid user carol 10.0.0.2 port 1236',
    ]);
    const f = r.findings.find((f) => f.ruleId === 'R2');
    expect(f).toBeDefined();
  });

  it('is low severity when attempts are spread out, medium when rapid', () => {
    const slow = analyzeLines([
      failed('Jan  5 08:00:00', 'aaa', '10.0.0.2', { invalid: true }),
      failed('Jan  5 10:00:00', 'bbb', '10.0.0.2', { invalid: true }),
      failed('Jan  5 12:00:00', 'ccc', '10.0.0.2', { invalid: true }),
    ]);
    const slowFinding = slow.findings.find((f) => f.ruleId === 'R2');
    expect(slowFinding?.severity).toBe('low');

    const rapid = analyzeLines([
      failed('Jan  5 10:00:00', 'aaa', '10.0.0.2', { invalid: true }),
      failed('Jan  5 10:01:00', 'bbb', '10.0.0.2', { invalid: true }),
      failed('Jan  5 10:02:00', 'ccc', '10.0.0.2', { invalid: true }),
    ]);
    const rapidFinding = rapid.findings.find((f) => f.ruleId === 'R2');
    expect(rapidFinding?.severity).toBe('medium');
  });
});

describe('R3 — frequently targeted usernames', () => {
  it('fires informationally at 3+ attempts against a username', () => {
    const r = analyzeLines(burst(0, 3, 'deploy', '10.0.0.3', 360));
    const f = r.findings.find((f) => f.ruleId === 'R3');
    expect(f?.severity).toBe('informational');
    expect(f?.description).toContain('deploy');
  });
});

describe('R4 — privileged-account activity tiers', () => {
  it('reports root failures informationally', () => {
    const r = analyzeLines(burst(0, 2, 'root', '10.0.0.4', 360));
    const f = r.findings.find(
      (f) => f.ruleId === 'R4' && f.title.includes('Failed'),
    );
    expect(f?.severity).toBe('informational');
  });

  it('reports a lone root success as medium, worded for verification', () => {
    const r = analyzeLines([accepted('Jan  5 10:00:00', 'root', '10.0.0.5')]);
    const f = r.findings.find((f) => f.ruleId === 'R4');
    expect(f?.severity).toBe('medium');
    expect(f?.description).toContain('verify');
  });

  it('escalates to high when the root success follows a same-IP failure burst', () => {
    const r = analyzeLines([
      ...burst(0, 3, 'root', '10.0.0.6', 60),
      accepted('Jan  5 00:04:00', 'root', '10.0.0.6'),
    ]);
    const f = r.findings.find(
      (f) => f.ruleId === 'R4' && f.severity === 'high',
    );
    expect(f).toBeDefined();
  });

  it('stays medium when same-IP enumeration happened 30+ minutes earlier', () => {
    const r = analyzeLines([
      failed('Jan  5 08:00:00', 'aaa', '10.0.0.7', { invalid: true }),
      failed('Jan  5 08:01:00', 'bbb', '10.0.0.7', { invalid: true }),
      failed('Jan  5 08:02:00', 'ccc', '10.0.0.7', { invalid: true }),
      accepted('Jan  5 08:40:00', 'root', '10.0.0.7'),
    ]);
    const root = r.findings.find(
      (f) => f.ruleId === 'R4' && f.title.includes('Successful'),
    );
    expect(root?.severity).toBe('medium');
  });

  it('escalates to high when enumeration precedes the root success within 10 min', () => {
    const r = analyzeLines([
      failed('Jan  5 08:52:00', 'aaa', '10.0.0.8', { invalid: true }),
      failed('Jan  5 08:54:00', 'bbb', '10.0.0.8', { invalid: true }),
      failed('Jan  5 08:56:00', 'ccc', '10.0.0.8', { invalid: true }),
      accepted('Jan  5 09:00:00', 'root', '10.0.0.8'),
    ]);
    const root = r.findings.find(
      (f) => f.ruleId === 'R4' && f.title.includes('correlated'),
    );
    expect(root?.severity).toBe('high');
  });
});

describe('R5 — success after failure burst (same IP + user, >=3 within 10 min)', () => {
  it('fires high for success after 3 same-pair failures', () => {
    const r = analyzeLines([
      ...burst(0, 3, 'alice', '10.0.0.9', 60),
      accepted('Jan  5 00:04:00', 'alice', '10.0.0.9'),
    ]);
    const f = r.findings.find((f) => f.ruleId === 'R5');
    expect(f?.severity).toBe('high');
  });

  it('does not fire with only 2 preceding failures', () => {
    const r = analyzeLines([
      ...burst(0, 2, 'alice', '10.0.0.10', 60),
      accepted('Jan  5 00:04:00', 'alice', '10.0.0.10'),
    ]);
    expect(r.findings.some((f) => f.ruleId === 'R5')).toBe(false);
  });

  it('does not fire when failures fall just outside the 10-minute window', () => {
    const r = analyzeLines([
      failed('Jan  5 10:00:00', 'alice', '10.0.0.11'), // 601s before success
      failed('Jan  5 10:05:00', 'alice', '10.0.0.11'),
      failed('Jan  5 10:07:00', 'alice', '10.0.0.11'),
      accepted('Jan  5 10:10:01', 'alice', '10.0.0.11'),
    ]);
    expect(r.findings.some((f) => f.ruleId === 'R5')).toBe(false);
  });

  it('does not fire when the failures came from a different IP', () => {
    const r = analyzeLines([
      ...burst(0, 3, 'alice', '10.0.0.12', 60),
      accepted('Jan  5 00:04:00', 'alice', '10.0.0.99'),
    ]);
    expect(r.findings.some((f) => f.ruleId === 'R5')).toBe(false);
  });
});

describe('anti-overclaim guard', () => {
  it('a benign log produces no medium-or-higher findings', () => {
    const r = analyzeLines([
      accepted('Jan  5 09:00:00', 'alice', '192.0.2.10'),
      accepted('Jan  5 09:30:00', 'bob', '192.0.2.11'),
      failed('Jan  5 11:00:00', 'alice', '192.0.2.10'),
      accepted('Jan  5 11:00:30', 'alice', '192.0.2.10'),
      failed('Jan  5 15:00:00', 'carol', '192.0.2.12'),
    ]);
    const elevated = r.findings.filter(
      (f) => f.severity === 'medium' || f.severity === 'high',
    );
    expect(elevated).toEqual([]);
  });
});

describe('finding evidence completeness', () => {
  it('R5 references the precursor failures plus the success', () => {
    const r = analyzeLines([
      ...burst(0, 3, 'alice', '10.0.0.9', 60),
      accepted('Jan  5 00:04:00', 'alice', '10.0.0.9'),
    ]);
    const f = r.findings.find((f) => f.ruleId === 'R5')!;
    const types = f.eventIds.map(
      (id) => r.events.find((e) => e.id === id)!.attemptType,
    );
    expect(f.eventIds).toHaveLength(4);
    expect(types.filter((t) => t === 'failed_attempt')).toHaveLength(3);
    expect(types.filter((t) => t === 'successful_attempt')).toHaveLength(1);
  });

  it('R5 evidence keeps a complete causal chain when >25 successes qualify', () => {
    // 30 failures then 30 qualifying successes for one pair: the evidence cap
    // must not fill up with successes alone — it must still show at least one
    // triggering success and the precursor failures that prove the burst.
    const lines: string[] = [];
    for (let i = 0; i < 30; i++) {
      lines.push(
        failed('Jan  5 10:00:00', 'alice', '10.0.0.20', { pid: 3000 + i }),
      );
    }
    for (let i = 0; i < 30; i++) {
      lines.push(
        accepted('Jan  5 10:00:30', 'alice', '10.0.0.20', { pid: 4000 + i }),
      );
    }
    const r = analyzeLines(lines);
    const f = r.findings.find((f) => f.ruleId === 'R5')!;
    expect(
      f.facts.find((x) => x.label === 'Successes matching pattern')?.value,
    ).toBe('30');
    expect(f.eventIds.length).toBeLessThanOrEqual(25);
    const types = f.eventIds.map(
      (id) => r.events.find((e) => e.id === id)!.attemptType,
    );
    expect(
      types.filter((t) => t === 'successful_attempt').length,
    ).toBeGreaterThanOrEqual(1);
    expect(
      types.filter((t) => t === 'failed_attempt').length,
    ).toBeGreaterThanOrEqual(3);
  });

  it('R4-high references the events responsible for the escalation', () => {
    const r = analyzeLines([
      ...burst(0, 3, 'root', '10.0.0.6', 60),
      accepted('Jan  5 00:04:00', 'root', '10.0.0.6'),
    ]);
    const f = r.findings.find(
      (f) => f.ruleId === 'R4' && f.severity === 'high',
    )!;
    const types = f.eventIds.map(
      (id) => r.events.find((e) => e.id === id)!.attemptType,
    );
    expect(types.filter((t) => t === 'failed_attempt')).toHaveLength(3);
    expect(types.filter((t) => t === 'successful_attempt')).toHaveLength(1);
  });

  it('R2-medium references the actual rapid window, not arbitrary earlier events', () => {
    const lines: string[] = [];
    // 30 distinct invalid users, one every 30 minutes (slow background).
    for (let i = 0; i < 30; i++) {
      const total = i * 30 * 60;
      const hh = String(Math.floor(total / 3600)).padStart(2, '0');
      const mm = String(Math.floor((total % 3600) / 60)).padStart(2, '0');
      lines.push(
        failed(`Jan  5 ${hh}:${mm}:00`, `slow${i}`, '10.0.0.6', {
          invalid: true,
        }),
      );
    }
    // The actual rapid window: 3 distinct users within 2 minutes, at the end.
    lines.push(failed('Jan  5 23:00:00', 'fast1', '10.0.0.6', { invalid: true }));
    lines.push(failed('Jan  5 23:01:00', 'fast2', '10.0.0.6', { invalid: true }));
    lines.push(failed('Jan  5 23:02:00', 'fast3', '10.0.0.6', { invalid: true }));
    const r = analyzeLines(lines);
    const f = r.findings.find((f) => f.ruleId === 'R2')!;
    expect(f.severity).toBe('medium');
    const users = f.eventIds.map(
      (id) => r.events.find((e) => e.id === id)!.username,
    );
    expect(users).toEqual(
      expect.arrayContaining(['fast1', 'fast2', 'fast3']),
    );
    expect(users).not.toContain('slow0');
  });
});
