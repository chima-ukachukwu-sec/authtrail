import { describe, it, expect } from 'vitest';
import { parseLines } from '@/lib/parse';
import { markDuplicates, splitLines } from '@/lib/ingest';
import { validateIp } from '@/lib/parse';

function parseOne(line: string) {
  const [event] = parseLines(markDuplicates(splitLines(line)));
  return event;
}

describe('line parsing', () => {
  it('parses a failed password for an invalid user as one failed attempt', () => {
    const e = parseOne(
      'Jan  5 09:02:31 prod sshd[2051]: Failed password for invalid user test from 203.0.113.7 port 51244 ssh2',
    );
    expect(e.category).toBe('attempt');
    expect(e.attemptType).toBe('failed_attempt');
    expect(e.username).toBe('test');
    expect(e.isInvalidUser).toBe(true);
    expect(e.sourceIp).toBe('203.0.113.7');
    expect(e.ipVersion).toBe(4);
    expect(e.sourcePort).toBe(51244);
    expect(e.method).toBe('password');
    expect(e.pid).toBe(2051);
    expect(e.host).toBe('prod');
  });

  it('parses an accepted publickey login', () => {
    const e = parseOne(
      'Jan  5 09:05:00 prod sshd[2090]: Accepted publickey for alice from 192.0.2.10 port 52200 ssh2',
    );
    expect(e.category).toBe('attempt');
    expect(e.attemptType).toBe('successful_attempt');
    expect(e.method).toBe('publickey');
    expect(e.isInvalidUser).toBe(false);
  });

  it('flags attempts against root as privileged', () => {
    const e = parseOne(
      'Jan  5 09:04:11 prod sshd[2077]: Failed password for root from 198.51.100.23 port 41120 ssh2',
    );
    expect(e.isPrivilegedTarget).toBe(true);
  });

  it('parses sshd-session process names (OpenSSH 10+)', () => {
    const e = parseOne(
      'Jan  5 09:00:00 prod sshd-session[100]: Failed password for root from 10.0.0.1 port 22 ssh2',
    );
    expect(e.category).toBe('attempt');
    expect(e.attemptType).toBe('failed_attempt');
  });

  it('parses "Invalid user" and preauth close lines as observations', () => {
    const invalid = parseOne(
      'Jan  5 09:01:12 prod sshd[2040]: Invalid user admin from 203.0.113.7 port 51200',
    );
    expect(invalid.category).toBe('observation');
    expect(invalid.parseLabel).toBe('invalid_user');
    expect(invalid.isInvalidUser).toBe(true);

    const closed = parseOne(
      'Jan  5 09:01:12 prod sshd[2040]: Connection closed by invalid user admin 203.0.113.7 port 51200 [preauth]',
    );
    expect(closed.category).toBe('observation');
    expect(closed.parseLabel).toBe('connection_closed');
    expect(closed.username).toBe('admin');
    expect(closed.isInvalidUser).toBe(true);
  });

  it('parses pam_unix authentication failures as observations', () => {
    const e = parseOne(
      'Jan  5 09:10:00 prod sshd[3000]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.5  user=root',
    );
    expect(e.category).toBe('observation');
    expect(e.parseLabel).toBe('pam_failure');
    expect(e.username).toBe('root');
    expect(e.sourceIp).toBe('203.0.113.5');
  });

  it('parses IPv6 sources and canonicalizes IPv4-mapped addresses', () => {
    const v6 = parseOne(
      'Jan  5 09:06:40 prod sshd[2101]: Failed password for deploy from 2001:db8::42 port 38000 ssh2',
    );
    expect(v6.sourceIp).toBe('2001:db8::42');
    expect(v6.ipVersion).toBe(6);

    // IPv4-mapped IPv6 is the same source as the plain IPv4 form.
    const mapped = parseOne(
      'Jan  5 09:06:40 prod sshd[2102]: Failed password for deploy from ::ffff:203.0.113.7 port 38000 ssh2',
    );
    expect(mapped.sourceIp).toBe('203.0.113.7');
    expect(mapped.ipVersion).toBe(4);
  });

  it('distinguishes invalid-user from authenticating-user disconnects', () => {
    const invalid = parseOne(
      'Jan  5 09:07:00 prod sshd[2201]: Disconnected from invalid user alice 203.0.113.7 port 51244',
    );
    expect(invalid.parseLabel).toBe('disconnected');
    expect(invalid.username).toBe('alice');
    expect(invalid.isInvalidUser).toBe(true);

    const closedInvalid = parseOne(
      'Jan  5 09:07:01 prod sshd[2202]: Connection closed by invalid user alice 203.0.113.7 port 51244 [preauth]',
    );
    expect(closedInvalid.parseLabel).toBe('connection_closed');
    expect(closedInvalid.isInvalidUser).toBe(true);

    // An authenticating user is a real account: the presence of a username
    // must never mark the line as an invalid-user signal.
    const authenticating = parseOne(
      'Jan  5 09:07:02 prod sshd[2203]: Disconnected from authenticating user alice 203.0.113.7 port 51244',
    );
    expect(authenticating.parseLabel).toBe('disconnected');
    expect(authenticating.username).toBe('alice');
    expect(authenticating.isInvalidUser).toBe(false);

    const closedAuthenticating = parseOne(
      'Jan  5 09:07:03 prod sshd[2204]: Connection closed by authenticating user alice 203.0.113.7 port 51244 [preauth]',
    );
    expect(closedAuthenticating.parseLabel).toBe('connection_closed');
    expect(closedAuthenticating.isInvalidUser).toBe(false);
  });

  it('parses fractional-second syslog timestamps (journalctl short-precise)', () => {
    const e = parseOne(
      'Sep  3 10:00:00.123456 prod sshd[2301]: Failed password for root from 10.0.0.1 port 22 ssh2',
    );
    expect(e.parseLabel).toBe('failed_auth');
    expect(e.category).toBe('attempt');
    expect(e.timestampRaw).toBe('Sep  3 10:00:00.123456');
    expect(e.syslogTimeOfDayMs).toBe(10 * 3_600_000 + 123);
  });

  it('leaves sourceIp null when the source is a hostname or an invalid IP', () => {
    const hostnamed = parseOne(
      'Jan  5 09:06:40 prod sshd[2103]: Failed password for deploy from mail.example.com port 38000 ssh2',
    );
    expect(hostnamed.sourceIp).toBeNull();

    const badIp = parseOne(
      'Jan  5 09:06:40 prod sshd[2104]: Failed password for deploy from 999.1.2.3 port 38000 ssh2',
    );
    expect(badIp.sourceIp).toBeNull();
  });

  it('treats non-sshd syslog lines as observations, not attempts', () => {
    const e = parseOne(
      'Jan  5 09:05:02 prod sudo: pam_unix(sudo:session): session opened for user root by alice(uid=1000)',
    );
    expect(e.category).toBe('observation');
    expect(e.parseLabel).toBe('other_process');
    expect(e.process).toBe('sudo');
  });

  it('marks lines with no recognizable shape as unparsed and keeps the raw text', () => {
    const garbage = 'this is not a log line at all';
    const e = parseOne(garbage);
    expect(e.category).toBe('unparsed');
    expect(e.raw).toBe(garbage);
  });

  it('captures HTML/script-like usernames as plain text', () => {
    const e = parseOne(
      'Jan  5 09:08:00 prod sshd[2120]: Invalid user <script>alert(1)</script> from 203.0.113.99 port 60000',
    );
    expect(e.username).toBe('<script>alert(1)</script>');
  });
});

describe('IP validation', () => {
  it('accepts valid IPv4 and rejects out-of-range octets', () => {
    expect(validateIp('192.0.2.1')).toEqual({ ip: '192.0.2.1', version: 4 });
    expect(validateIp('256.0.0.1')).toBeNull();
    expect(validateIp('1.2.3')).toBeNull();
  });

  it('accepts compressed and full IPv6', () => {
    expect(validateIp('2001:db8::1')).toEqual({ ip: '2001:db8::1', version: 6 });
    expect(validateIp('2001:0db8:0000:0000:0000:0000:0000:0001')).toEqual({
      ip: '2001:db8::1',
      version: 6,
    });
    expect(validateIp('2001:::1')).toBeNull();
    expect(validateIp('2001:db8::g1')).toBeNull();
  });

  it('merges expanded, compressed, and case-variant IPv6 forms into one identity', () => {
    const canonical = { ip: '2001:db8::1', version: 6 as const };
    expect(validateIp('2001:db8::1')).toEqual(canonical);
    expect(validateIp('2001:0db8:0:0:0:0:0:1')).toEqual(canonical);
    expect(validateIp('2001:0DB8:0000:0000:0000:0000:0000:0001')).toEqual(
      canonical,
    );
    // The longest zero run (leftmost on ties) is the one compressed.
    expect(validateIp('2001:0:0:1:0:0:0:1')).toEqual({
      ip: '2001:0:0:1::1',
      version: 6,
    });
  });

  it('rejects invalid IPv6 forms', () => {
    expect(validateIp('1:2:3:4:5:6:7:8:9')).toBeNull();
    expect(validateIp('1:2:3:4:5:6:7')).toBeNull();
    expect(validateIp('2001:db8::1::2')).toBeNull();
    expect(validateIp('2001:db8::12345')).toBeNull();
    expect(validateIp('::ffff:999.0.0.1')).toBeNull();
  });

  it('canonicalizes IPv4-mapped IPv6 and case variants to one identity', () => {
    expect(validateIp('::ffff:192.0.2.1')).toEqual({
      ip: '192.0.2.1',
      version: 4,
    });
    expect(validateIp('::FFFF:192.0.2.1')).toEqual({
      ip: '192.0.2.1',
      version: 4,
    });
    // Hex form of the same mapped address is the same IPv4 source.
    expect(validateIp('::ffff:c000:201')).toEqual({
      ip: '192.0.2.1',
      version: 4,
    });
    expect(validateIp('0:0:0:0:0:ffff:192.0.2.1')).toEqual({
      ip: '192.0.2.1',
      version: 4,
    });
    expect(validateIp('2001:DB8::1')).toEqual({
      ip: '2001:db8::1',
      version: 6,
    });
  });
});

describe('strict timestamp validation', () => {
  const msg = 'Failed password for root from 10.0.0.1 port 22 ssh2';

  it('rejects out-of-range syslog times of day', () => {
    for (const ts of [
      'Jan  5 24:00:00',
      'Jan  5 99:00:00',
      'Jan  5 10:60:00',
      'Jan  5 10:00:60',
    ]) {
      const e = parseOne(`${ts} prod sshd[2401]: ${msg}`);
      expect(e.timestampRaw).toBeNull();
    }
    // Boundary values remain valid.
    expect(parseOne(`Jan  5 23:59:59 prod sshd[2402]: ${msg}`).timestampRaw)
      .not.toBeNull();
    expect(parseOne(`Jan  5 00:00:00 prod sshd[2403]: ${msg}`).timestampRaw)
      .not.toBeNull();
  });

  it('rejects impossible syslog dates but allows Feb 29 (year is unknown)', () => {
    expect(parseOne(`Feb 29 10:00:00 prod sshd[2404]: ${msg}`).timestampRaw)
      .not.toBeNull();
    for (const ts of [
      'Feb 30 10:00:00',
      'Feb 31 10:00:00',
      'Apr 31 10:00:00',
      'Jun 31 10:00:00',
      'Jan 32 10:00:00',
      'Jan  0 10:00:00',
    ]) {
      expect(parseOne(`${ts} prod sshd[2405]: ${msg}`).timestampRaw)
        .toBeNull();
    }
    // Real month lengths stay valid.
    expect(parseOne(`Jan 31 10:00:00 prod sshd[2406]: ${msg}`).timestampRaw)
      .not.toBeNull();
    expect(parseOne(`Apr 30 10:00:00 prod sshd[2407]: ${msg}`).timestampRaw)
      .not.toBeNull();
  });

  it('rejects impossible ISO dates instead of letting Date normalize them', () => {
    for (const ts of [
      '2026-02-30T10:00:00Z',
      '2026-02-29T10:00:00Z', // 2026 is not a leap year
      '2026-04-31T10:00:00Z',
      '2026-13-01T10:00:00Z',
      '2026-00-10T10:00:00Z',
      '2026-01-00T10:00:00Z',
    ]) {
      expect(parseOne(`${ts} prod sshd[2408]: ${msg}`).timestampRaw)
        .toBeNull();
    }
    // A real leap day stays valid.
    expect(parseOne(`2024-02-29T10:00:00Z prod sshd[2409]: ${msg}`).timestampRaw)
      .not.toBeNull();
  });

  it('rejects out-of-range ISO times of day', () => {
    for (const ts of [
      '2026-01-05T24:00:00Z',
      '2026-01-05T10:60:00Z',
      '2026-01-05T10:00:60Z',
    ]) {
      expect(parseOne(`${ts} prod sshd[2410]: ${msg}`).timestampRaw)
        .toBeNull();
    }
    expect(parseOne(`2026-01-05T23:59:59Z prod sshd[2411]: ${msg}`).timestampRaw)
      .not.toBeNull();
  });
});
