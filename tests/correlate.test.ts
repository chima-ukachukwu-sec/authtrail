import { describe, it, expect } from 'vitest';
import { analyzeLines, failed, syslog, fixture } from './helpers';

describe('correlation: attempts vs supporting observations', () => {
  it('counts "Invalid user" + "Failed password" for the same pid as ONE attempt', () => {
    const r = analyzeLines([
      syslog( 'Jan  5 10:00:00', 5001, 'Invalid user bob from 10.0.0.1 port 40000'),
      syslog( 'Jan  5 10:00:01', 5001, 'Failed password for invalid user bob from 10.0.0.1 port 40000 ssh2'),
    ]);
    expect(r.summary.attempts).toBe(1);
    expect(r.summary.failedAttempts).toBe(1);
    expect(r.summary.invalidUserAttempts).toBe(1);
    const attempt = r.events.find((e) => e.category === 'attempt')!;
    expect(attempt.evidenceLineNumbers).toContain(1);
  });

  it('promotes an invalid-user + preauth-close group to ONE probe attempt', () => {
    const r = analyzeLines([
      syslog('Jan  5 10:00:00', 5002, 'Invalid user admin from 10.0.0.2 port 40001'),
      syslog('Jan  5 10:00:00', 5002, 'Connection closed by invalid user admin 10.0.0.2 port 40001 [preauth]'),
    ]);
    expect(r.summary.attempts).toBe(1);
    expect(r.summary.invalidUserProbes).toBe(1);
    expect(r.summary.unattributedObservations).toBe(0);
  });

  it('creates ZERO attempts from uncertain observations', () => {
    // Preauth close with no username and no invalid-user signal: nothing can
    // be confidently inferred, so no attempt is minted.
    const r = analyzeLines([
      syslog('Jan  5 10:00:00', 5003, 'Connection closed by 10.0.0.3 port 40002 [preauth]'),
    ]);
    expect(r.summary.attempts).toBe(0);
    expect(r.summary.unattributedObservations).toBe(1);
    // The observation remains visible with its raw line.
    expect(r.events[0].category).toBe('observation');
    expect(r.events[0].raw).toContain('Connection closed');
  });

  it('correlates pid-less adjacent lines only on strict identity match', () => {
    const r = analyzeLines([
      'Jan  5 10:00:00 host sshd: Invalid user bob from 10.0.0.4 port 40003',
      'Jan  5 10:00:00 host sshd: Connection closed by invalid user bob 10.0.0.4 port 40003 [preauth]',
    ]);
    expect(r.summary.invalidUserProbes).toBe(1);
  });

  it('leaves pid-less orphan observations unattributed', () => {
    const r = analyzeLines([
      'Jan  5 10:00:00 host sshd: Connection closed by 10.0.0.5 port 40004 [preauth]',
    ]);
    expect(r.summary.attempts).toBe(0);
    expect(r.summary.unattributedObservations).toBe(1);
  });

  it('duplicated lines cannot create attempts or inflate counts', () => {
    const line = failed('Jan  5 10:00:00', 'alice', '10.0.0.6', { pid: 5010 });
    const r = analyzeLines([line, line, line, line, line]);
    expect(r.summary.totalLines).toBe(5);
    expect(r.summary.duplicatesExcluded).toBe(4);
    expect(r.summary.attempts).toBe(1);
    expect(r.summary.failedAttempts).toBe(1);
  });

  it('attaches pam failures to the matching attempt by pid', () => {
    const r = analyzeLines([
      failed('Jan  5 10:00:00', 'root', '10.0.0.7', { pid: 5020 }),
      syslog('Jan  5 10:00:00', 5020, 'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.0.7  user=root'),
    ]);
    expect(r.summary.attempts).toBe(1);
    expect(r.summary.unattributedObservations).toBe(0);
  });
});

describe('correlation: authenticating users are never enumeration evidence', () => {
  it('authenticating-user disconnects create zero attempts and zero probes', () => {
    const r = analyzeLines([
      syslog('Jan  5 10:00:00', 5001, 'Disconnected from authenticating user alice 10.0.0.1 port 1234'),
      syslog('Jan  5 10:01:00', 5002, 'Disconnected from authenticating user bob 10.0.0.1 port 1235'),
      syslog('Jan  5 10:02:00', 5003, 'Disconnected from authenticating user carol 10.0.0.1 port 1236'),
    ]);
    expect(r.summary.attempts).toBe(0);
    expect(r.summary.invalidUserProbes).toBe(0);
    expect(r.summary.unattributedObservations).toBe(3);
    expect(r.events.every((e) => !e.isInvalidUser)).toBe(true);
  });

  it('invalid-user disconnects still promote to probes (control)', () => {
    const r = analyzeLines([
      syslog('Jan  5 10:00:00', 5001, 'Disconnected from invalid user alice 10.0.0.1 port 1234'),
      syslog('Jan  5 10:01:00', 5002, 'Disconnected from invalid user bob 10.0.0.1 port 1235'),
      syslog('Jan  5 10:02:00', 5003, 'Disconnected from invalid user carol 10.0.0.1 port 1236'),
    ]);
    expect(r.summary.invalidUserProbes).toBe(3);
  });
});

describe('correlation: pid reuse stays session-local', () => {
  it('never attaches a conflicting observation merely because the pid matches', () => {
    const r = analyzeLines([
      syslog('Jan  5 10:00:00', 7001, 'Accepted publickey for alice from 10.0.0.1 port 100 ssh2'),
      syslog('Jan  5 18:00:00', 7001, 'Disconnected from invalid user mallory 10.9.9.9 port 200'),
    ]);
    // alice's successful login is not contaminated with unrelated evidence.
    expect(r.events[0].evidenceLineNumbers).toEqual([]);
    // The observation stands on its own as exactly one probe.
    expect(r.events[1].category).toBe('attempt');
    expect(r.events[1].attemptType).toBe('invalid_user_probe');
    expect(r.summary.invalidUserProbes).toBe(1);
  });

  it('pid reuse across identities yields one probe per session, not a merge', () => {
    const r = analyzeLines([
      syslog('Jan  5 10:00:00', 8001, 'Invalid user aaa from 10.0.0.1 port 300'),
      syslog('Jan  5 18:00:00', 8001, 'Invalid user bbb from 10.0.0.2 port 400'),
    ]);
    expect(r.summary.invalidUserProbes).toBe(2);
    expect(r.summary.attempts).toBe(2);
  });

  it('does not merge same-identity sessions separated by a long interval', () => {
    const r = analyzeLines([
      syslog('Jan  5 10:00:00', 9001, 'Invalid user aaa from 10.0.0.1 port 300'),
      syslog('Jan  5 10:05:00', 9001, 'Connection closed by invalid user aaa 10.0.0.1 port 300 [preauth]'),
      syslog('Jan  5 23:00:00', 9001, 'Invalid user aaa from 10.0.0.1 port 301'),
    ]);
    expect(r.summary.invalidUserProbes).toBe(2);
  });

  it('still merges one close-in-time session (control)', () => {
    const r = analyzeLines([
      syslog('Jan  5 10:00:00', 9002, 'Invalid user aaa from 10.0.0.1 port 300'),
      syslog('Jan  5 10:00:05', 9002, 'Connection closed by invalid user aaa 10.0.0.1 port 300 [preauth]'),
    ]);
    expect(r.summary.invalidUserProbes).toBe(1);
    expect(r.summary.unattributedObservations).toBe(0);
  });
});

describe('end-to-end fixture: basic-auth.log', () => {
  it('produces expected counts and findings', () => {
    const text = fixture('basic-auth.log');
    const r = analyzeLines(text.trimEnd().split('\n'));

    expect(r.summary.totalLines).toBe(16);
    expect(r.summary.attempts).toBe(11);
    expect(r.summary.failedAttempts).toBe(7);
    expect(r.summary.successfulAttempts).toBe(2);
    expect(r.summary.invalidUserProbes).toBe(2);
    expect(r.summary.uniqueSourceIps).toBe(5);
    expect(r.summary.unparsedLines).toBe(0);
    expect(r.summary.unattributedObservations).toBe(0);
    expect(r.chronology.confident).toBe(true);

    const byRule = r.findings.map((f) => `${f.ruleId}:${f.severity}`);
    expect(byRule).toContain('R5:high');
    expect(byRule).toContain('R4:high');
    expect(byRule).toContain('R2:medium');
    expect(byRule).toContain('R4:informational');
    expect(byRule).toContain('R3:informational');
    // 4 failures from 198.51.100.23 stay below the R1 threshold.
    expect(byRule).not.toContain('R1:medium');
  });
});
