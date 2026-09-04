import { describe, it, expect } from 'vitest';
import { analyzeLogText } from '@/lib/analyze';

/**
 * Performance budget: parse + correlate + detect + stats for a ~25 MB /
 * ~200k-line log in <= 2 s on the development machine. The assertion uses a
 * generous 10 s ceiling to stay stable on slower CI; the measured value is
 * what gets reported.
 */
describe('performance budget (measurement, not a claim)', () => {
  it('measures analysis of a 200k-line synthetic log', () => {
    const lines: string[] = [];
    for (let i = 0; i < 200_000; i++) {
      const hh = String(Math.floor(i / 3600) % 24).padStart(2, '0');
      const mm = String(Math.floor(i / 60) % 60).padStart(2, '0');
      const ss = String(i % 60).padStart(2, '0');
      const kind = i % 10;
      if (kind < 6) {
        lines.push(
          `Jan  5 ${hh}:${mm}:${ss} prod sshd[${1000 + i}]: Failed password for invalid user user${i % 500} from 203.0.113.${i % 250} port ${20000 + (i % 40000)} ssh2`,
        );
      } else if (kind < 8) {
        lines.push(
          `Jan  5 ${hh}:${mm}:${ss} prod sshd[${1000 + i}]: Invalid user probe${i % 300} from 198.51.100.${i % 250} port ${20000 + (i % 40000)}`,
        );
      } else if (kind === 8) {
        lines.push(
          `Jan  5 ${hh}:${mm}:${ss} prod sshd[${1000 + i}]: Accepted publickey for admin from 192.0.2.${i % 250} port ${20000 + (i % 40000)} ssh2`,
        );
      } else {
        lines.push(
          `Jan  5 ${hh}:${mm}:${ss} prod CRON[${1000 + i}]: pam_unix(cron:session): session opened for user root by (uid=0)`,
        );
      }
    }
    const text = lines.join('\n');
    const approxBytes = text.length;

    const start = performance.now();
    const result = analyzeLogText(text);
    const elapsedMs = performance.now() - start;

    console.log(
      `[bench] ${lines.length} lines, ~${(approxBytes / 1024 / 1024).toFixed(1)} MB analyzed in ${elapsedMs.toFixed(0)} ms (attempts=${result.summary.attempts})`,
    );
    expect(result.summary.attempts).toBeGreaterThan(0);
    expect(elapsedMs).toBeLessThan(10_000);
  }, 30_000);

  it('stays near-linear on a high-cardinality adversarial workload', () => {
    // Many unique (source IP, username) pairs, each 3 failures + 1 success:
    // the worst case for per-pair detection loops. Regression test for the
    // quadratic full-array scans that made 128k lines take ~64 s.
    const pairs = 32_000;
    const lines: string[] = [];
    let t = 0;
    const tsAt = (sec: number) => {
      const day = 1 + Math.floor(sec / 86400);
      const rem = sec % 86400;
      const p = (n: number) => String(n).padStart(2, '0');
      return `2026-01-${p(day)}T${p(Math.floor(rem / 3600))}:${p(Math.floor(rem / 60) % 60)}:${p(rem % 60)}Z`;
    };
    for (let i = 0; i < pairs; i++) {
      const ip = `203.0.${Math.floor(i / 250) % 250}.${i % 250}`;
      for (let f = 0; f < 3; f++) {
        lines.push(
          `${tsAt(t)} prod sshd[${2000 + i}]: Failed password for user${i} from ${ip} port ${10000 + i} ssh2`,
        );
        t += 10;
      }
      lines.push(
        `${tsAt(t)} prod sshd[${2000 + i}]: Accepted password for user${i} from ${ip} port ${10000 + i} ssh2`,
      );
      t += 5;
    }
    const text = lines.join('\n');

    const start = performance.now();
    const result = analyzeLogText(text);
    const elapsedMs = performance.now() - start;

    console.log(
      `[bench] high-cardinality: ${lines.length} lines, ${pairs} unique pairs, ~${(text.length / 1024 / 1024).toFixed(1)} MB analyzed in ${elapsedMs.toFixed(0)} ms`,
    );
    expect(result.chronology.confident).toBe(true);
    expect(elapsedMs).toBeLessThan(5_000);
  }, 30_000);

  it('stays near-linear on a dense single (IP, username) pair', () => {
    // All events for one pair, 3 failures + 1 success repeating: the worst
    // case for the per-pair sliding-window checks in R5/R4, which used to
    // rescan the pair's full failure list once per success.
    const lines: string[] = [];
    let t = 0;
    const p = (n: number) => String(n).padStart(2, '0');
    const tsAt = (sec: number) => {
      const day = 1 + Math.floor(sec / 86400);
      const rem = sec % 86400;
      return `2026-01-${p(day)}T${p(Math.floor(rem / 3600))}:${p(Math.floor(rem / 60) % 60)}:${p(rem % 60)}Z`;
    };
    for (let i = 0; i < 128_000; i++) {
      const verb = i % 4 === 3 ? 'Accepted' : 'Failed';
      lines.push(
        `${tsAt(t)} prod sshd[${2000 + i}]: ${verb} password for root from 203.0.113.7 port 22 ssh2`,
      );
      t += 1;
    }
    const text = lines.join('\n');

    const start = performance.now();
    const result = analyzeLogText(text);
    const elapsedMs = performance.now() - start;

    console.log(
      `[bench] dense-pair: ${lines.length} lines, ~${(text.length / 1024 / 1024).toFixed(1)} MB analyzed in ${elapsedMs.toFixed(0)} ms (findings=${result.findings.length})`,
    );
    expect(result.chronology.confident).toBe(true);
    expect(elapsedMs).toBeLessThan(5_000);
  }, 30_000);

  it('stays near-linear on a same-window dense burst for one pair', () => {
    // Adversarial regression: a large failure burst and a large success burst
    // for one (IP, username) pair all share a single 10-minute window.
    // Materializing the complete failure window once per success is
    // quadratic; unique pid/port values keep deduplication from collapsing
    // the bursts.
    const failures = 12_000;
    const successes = 12_000;
    const lines: string[] = [];
    for (let i = 0; i < failures; i++) {
      lines.push(
        `2026-01-01T10:00:00Z prod sshd[${10_000 + i}]: Failed password for deploy from 203.0.113.9 port ${20_000 + i} ssh2`,
      );
    }
    for (let i = 0; i < successes; i++) {
      lines.push(
        `2026-01-01T10:00:01Z prod sshd[${40_000 + i}]: Accepted password for deploy from 203.0.113.9 port ${45_000 + i} ssh2`,
      );
    }
    const text = lines.join('\n');

    const start = performance.now();
    const result = analyzeLogText(text);
    const elapsedMs = performance.now() - start;

    const r5 = result.findings.find((f) => f.ruleId === 'R5');
    console.log(
      `[bench] dense-burst: ${lines.length} lines (${failures} failures + ${successes} successes in one window), ~${(text.length / 1024 / 1024).toFixed(1)} MB analyzed in ${elapsedMs.toFixed(0)} ms (R5 hits=${r5?.facts.find((x) => x.label === 'Successes matching pattern')?.value})`,
    );
    expect(result.chronology.confident).toBe(true);
    expect(r5).toBeDefined();
    expect(elapsedMs).toBeLessThan(5_000);
  }, 60_000);

  it('analyzes a workload near the 25 MB supported file ceiling', () => {
    // Same realistic distribution as the baseline, scaled to ~24 MB.
    const lines: string[] = [];
    for (let i = 0; i < 245_000; i++) {
      const hh = String(Math.floor(i / 3600) % 24).padStart(2, '0');
      const mm = String(Math.floor(i / 60) % 60).padStart(2, '0');
      const ss = String(i % 60).padStart(2, '0');
      const day = 5 + Math.floor(i / 86400);
      const kind = i % 10;
      if (kind < 6) {
        lines.push(
          `Jan  ${day} ${hh}:${mm}:${ss} prod sshd[${1000 + i}]: Failed password for invalid user user${i % 500} from 203.0.113.${i % 250} port ${20000 + (i % 40000)} ssh2`,
        );
      } else if (kind < 8) {
        lines.push(
          `Jan  ${day} ${hh}:${mm}:${ss} prod sshd[${1000 + i}]: Invalid user probe${i % 300} from 198.51.100.${i % 250} port ${20000 + (i % 40000)}`,
        );
      } else if (kind === 8) {
        lines.push(
          `Jan  ${day} ${hh}:${mm}:${ss} prod sshd[${1000 + i}]: Accepted publickey for admin from 192.0.2.${i % 250} port ${20000 + (i % 40000)} ssh2`,
        );
      } else {
        lines.push(
          `Jan  ${day} ${hh}:${mm}:${ss} prod CRON[${1000 + i}]: pam_unix(cron:session): session opened for user root by (uid=0)`,
        );
      }
    }
    const text = lines.join('\n');
    const approxMb = text.length / 1024 / 1024;

    const start = performance.now();
    const result = analyzeLogText(text);
    const elapsedMs = performance.now() - start;

    console.log(
      `[bench] ceiling: ${lines.length} lines, ~${approxMb.toFixed(1)} MB analyzed in ${elapsedMs.toFixed(0)} ms (attempts=${result.summary.attempts})`,
    );
    expect(approxMb).toBeGreaterThan(20);
    expect(approxMb).toBeLessThan(25);
    expect(elapsedMs).toBeLessThan(10_000);
  }, 60_000);
});
