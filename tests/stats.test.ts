import { describe, it, expect } from 'vitest';
import { analyzeLines, accepted, failed } from './helpers';

describe('summary statistics', () => {
  it('counts only confirmed attempts and reports top tables', () => {
    const r = analyzeLines([
      failed('Jan  5 10:00:00', 'alice', '10.0.0.1'),
      failed('Jan  5 10:01:00', 'alice', '10.0.0.1'),
      failed('Jan  5 10:02:00', 'bob', '10.0.0.1', { invalid: true }),
      accepted('Jan  5 10:03:00', 'alice', '10.0.0.1'),
      accepted('Jan  5 10:04:00', 'carol', '10.0.0.2'),
    ]);
    expect(r.summary.attempts).toBe(5);
    expect(r.summary.failedAttempts).toBe(3);
    expect(r.summary.successfulAttempts).toBe(2);
    expect(r.summary.invalidUserAttempts).toBe(1);
    expect(r.summary.uniqueSourceIps).toBe(2);
    expect(r.summary.uniqueUsernames).toBe(3);

    const topIp = r.topIps[0];
    expect(topIp.ip).toBe('10.0.0.1');
    expect(topIp.attempts).toBe(4);
    expect(topIp.failed).toBe(3);
    expect(topIp.successful).toBe(1);
    expect(topIp.distinctUsernames).toBe(2);

    const topUser = r.topUsernames[0];
    expect(topUser.username).toBe('alice');
    expect(topUser.attempts).toBe(3);
  });

  it('excludes duplicates from every statistic but discloses them', () => {
    const line = failed('Jan  5 10:00:00', 'alice', '10.0.0.1', { pid: 9001 });
    const r = analyzeLines([line, line]);
    expect(r.summary.totalLines).toBe(2);
    expect(r.summary.uniqueLines).toBe(1);
    expect(r.summary.duplicatesExcluded).toBe(1);
    expect(r.summary.attempts).toBe(1);
    expect(r.topIps[0].attempts).toBe(1);
  });

  it('marks privileged usernames in the username table', () => {
    const r = analyzeLines([failed('Jan  5 10:00:00', 'root', '10.0.0.1')]);
    expect(r.topUsernames[0].privileged).toBe(true);
  });

  it('treats IPv4, IPv4-mapped IPv6, and case variants as one source', () => {
    const r = analyzeLines([
      failed('Jan  5 10:00:00', 'root', '192.0.2.1'),
      failed('Jan  5 10:01:00', 'root', '::ffff:192.0.2.1'),
      failed('Jan  5 10:02:00', 'root', '::FFFF:192.0.2.1'),
    ]);
    expect(r.summary.uniqueSourceIps).toBe(1);
    expect(r.topIps).toHaveLength(1);
    expect(r.topIps[0].ip).toBe('192.0.2.1');
    expect(r.topIps[0].attempts).toBe(3);
  });
});
