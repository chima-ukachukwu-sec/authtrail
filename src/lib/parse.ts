import type { AuthEvent, AuthMethod, ParseLabel } from './types';
import type { IngestedLine } from './ingest';
import { parseTimestampPrefix } from './timestamp';

const SYSLOG_PREFIX = /^(\S+)\s+([^\s\[]+?)(?:\[(\d+)\])?:\s*(.*)$/;
const SSHD_PROCESSES = new Set(['sshd', 'sshd-session']);

const FAILED_RE =
  /^Failed (password|publickey|keyboard-interactive\/pam|none) for (invalid user )?(\S+) from (\S+) port (\d+)/;
const ACCEPTED_RE =
  /^Accepted (password|publickey|keyboard-interactive\/pam) for (\S+) from (\S+) port (\d+)/;
const INVALID_USER_RE = /^Invalid user (\S+) from (\S+?)(?: port (\d+))?$/;
const CONNECTION_CLOSED_RE =
  /^Connection closed by (?:(invalid|authenticating) user (\S+) )?(\S+) port (\d+)/;
const DISCONNECTED_RE =
  /^Disconnected from (?:(invalid|authenticating) user (\S+) )?(\S+) port (\d+)/;
const PAM_FAILURE_RE = /^pam_unix\(sshd[^)]*\): authentication failure;/;
const PAM_RHOST_RE = /rhost=(\S+)/;
const PAM_USER_RE = /user=(\S+)/;

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const HEXTET_RE = /^[0-9a-fA-F]{1,4}$/;

function isValidIpv4(token: string): boolean {
  const m = IPV4_RE.exec(token);
  if (!m) return false;
  return m.slice(1).every((octet) => Number(octet) <= 255);
}

/**
 * Parses an IPv6 address (including a trailing embedded IPv4, e.g.
 * ::ffff:1.2.3.4) into its eight 16-bit groups, or null when invalid.
 */
function parseIpv6Groups(token: string): number[] | null {
  let t = token;
  if (t.includes('.')) {
    const lastColon = t.lastIndexOf(':');
    if (lastColon === -1) return null;
    const v4 = IPV4_RE.exec(t.slice(lastColon + 1));
    if (!v4 || v4.slice(1).some((octet) => Number(octet) > 255)) return null;
    const o = v4.slice(1).map(Number);
    t = `${t.slice(0, lastColon + 1)}${((o[0] << 8) | o[1]).toString(16)}:${((o[2] << 8) | o[3]).toString(16)}`;
  }
  let parts: string[];
  if (t.includes('::')) {
    const halves = t.split('::');
    if (halves.length !== 2) return null;
    const head = halves[0] === '' ? [] : halves[0].split(':');
    const tail = halves[1] === '' ? [] : halves[1].split(':');
    const zeros = 8 - head.length - tail.length;
    if (zeros < 1) return null;
    parts = [...head, ...new Array<string>(zeros).fill('0'), ...tail];
  } else {
    parts = t.split(':');
    if (parts.length !== 8) return null;
  }
  if (!parts.every((p) => HEXTET_RE.test(p))) return null;
  return parts.map((p) => parseInt(p, 16));
}

/**
 * RFC 5952 canonical text for an IPv6 address: lowercase, no leading zeros,
 * the longest (leftmost on ties) run of zero groups compressed to '::'.
 * Equivalent textual forms of one address share one identity. IPv4-mapped
 * addresses return the plain dotted IPv4 form instead.
 */
function canonicalizeIpv6(token: string): { ip: string; version: 4 | 6 } | null {
  const groups = parseIpv6Groups(token);
  if (groups === null) return null;
  // IPv4-mapped (::ffff:a.b.c.d, dotted or hex form) is the same source as
  // the plain IPv4 identity.
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    const ip = [
      groups[6] >> 8,
      groups[6] & 0xff,
      groups[7] >> 8,
      groups[7] & 0xff,
    ].join('.');
    return { ip, version: 4 };
  }
  let bestStart = -1;
  let bestLen = 0;
  let runStart = -1;
  for (let i = 0; i <= 8; i++) {
    if (i < 8 && groups[i] === 0) {
      if (runStart === -1) runStart = i;
    } else if (runStart !== -1) {
      if (i - runStart > bestLen) {
        bestStart = runStart;
        bestLen = i - runStart;
      }
      runStart = -1;
    }
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLen >= 2) {
    const head = hex.slice(0, bestStart).join(':');
    const tail = hex.slice(bestStart + bestLen).join(':');
    return { ip: `${head}::${tail}`, version: 6 };
  }
  return { ip: hex.join(':'), version: 6 };
}

export function validateIp(token: string): { ip: string; version: 4 | 6 } | null {
  if (isValidIpv4(token)) return { ip: token, version: 4 };
  return canonicalizeIpv6(token);
}

function toMethod(raw: string): AuthMethod {
  if (raw === 'keyboard-interactive/pam') return 'keyboard-interactive';
  if (raw === 'password' || raw === 'publickey' || raw === 'none') return raw;
  return null;
}

const PRIVILEGED_USERNAMES = new Set(['root']);

interface MessageMatch {
  label: ParseLabel;
  username?: string | null;
  isInvalidUser?: boolean;
  sourceToken?: string | null;
  sourcePort?: number | null;
  method?: AuthMethod;
}

function matchSshdMessage(message: string): MessageMatch {
  let m: RegExpExecArray | null;

  if ((m = FAILED_RE.exec(message))) {
    return {
      label: 'failed_auth',
      method: toMethod(m[1]),
      isInvalidUser: m[2] !== undefined,
      username: m[3],
      sourceToken: m[4],
      sourcePort: Number(m[5]),
    };
  }
  if ((m = ACCEPTED_RE.exec(message))) {
    return {
      label: 'accepted_auth',
      method: toMethod(m[1]),
      username: m[2],
      sourceToken: m[3],
      sourcePort: Number(m[4]),
    };
  }
  if ((m = INVALID_USER_RE.exec(message))) {
    return {
      label: 'invalid_user',
      isInvalidUser: true,
      username: m[1],
      sourceToken: m[2],
      sourcePort: m[3] !== undefined ? Number(m[3]) : null,
    };
  }
  if ((m = CONNECTION_CLOSED_RE.exec(message))) {
    return {
      label: 'connection_closed',
      isInvalidUser: m[1] === 'invalid',
      username: m[2] ?? null,
      sourceToken: m[3],
      sourcePort: Number(m[4]),
    };
  }
  if ((m = DISCONNECTED_RE.exec(message))) {
    return {
      label: 'disconnected',
      isInvalidUser: m[1] === 'invalid',
      username: m[2] ?? null,
      sourceToken: m[3],
      sourcePort: Number(m[4]),
    };
  }
  if (PAM_FAILURE_RE.test(message)) {
    const rhost = PAM_RHOST_RE.exec(message);
    const user = PAM_USER_RE.exec(message);
    return {
      label: 'pam_failure',
      username: user ? user[1] : null,
      sourceToken: rhost ? rhost[1] : null,
    };
  }
  return { label: 'other_sshd' };
}

/**
 * Parses every ingested line into an AuthEvent. Every line becomes a record;
 * lines that fit nothing are 'unparsed' with the raw text retained.
 * Credential-result lines (Failed/Accepted) are minted as attempts here —
 * they are self-contained. Everything else starts as an observation and can
 * only be promoted by the correlation pass.
 */
export function parseLines(lines: IngestedLine[]): AuthEvent[] {
  return lines.map(({ lineNumber, raw, duplicateOfLine }) => {
    const event: AuthEvent = {
      id: `e${lineNumber}`,
      lineNumber,
      raw,
      timestampRaw: null,
      absoluteTime: null,
      relativeMs: null,
      host: null,
      process: null,
      pid: null,
      category: 'unparsed',
      attemptType: null,
      parseLabel: 'unparsed',
      username: null,
      isInvalidUser: false,
      isPrivilegedTarget: false,
      sourceIp: null,
      ipVersion: null,
      sourcePort: null,
      method: null,
      duplicateOf:
        duplicateOfLine !== null ? `e${duplicateOfLine}` : null,
      evidenceLineNumbers: [],
    };

    const ts = parseTimestampPrefix(raw);
    if (ts === null) return event;
    event.timestampRaw = ts.raw;
    if (ts.kind === 'iso' && ts.absolute) {
      event.absoluteTime = ts.absolute;
    } else {
      event.syslogDoy = ts.doy;
      event.syslogTimeOfDayMs = ts.timeOfDayMs;
    }

    const prefix = SYSLOG_PREFIX.exec(ts.rest);
    if (prefix === null) return event;
    event.host = prefix[1];
    event.process = prefix[2];
    event.pid = prefix[3] !== undefined ? Number(prefix[3]) : null;
    const message = prefix[4];

    if (!SSHD_PROCESSES.has(event.process)) {
      event.category = 'observation';
      event.parseLabel = 'other_process';
      return event;
    }

    const match = matchSshdMessage(message);
    event.parseLabel = match.label;

    if (match.username !== undefined) event.username = match.username;
    event.isInvalidUser = match.isInvalidUser ?? false;
    event.isPrivilegedTarget =
      event.username !== null && PRIVILEGED_USERNAMES.has(event.username);
    event.method = match.method ?? null;
    event.sourcePort = match.sourcePort ?? null;

    if (match.sourceToken != null) {
      const ip = validateIp(match.sourceToken);
      if (ip) {
        event.sourceIp = ip.ip;
        event.ipVersion = ip.version;
      }
      // A hostname in the source field is left null; the raw line retains it.
    }

    if (match.label === 'failed_auth') {
      event.category = 'attempt';
      event.attemptType = 'failed_attempt';
    } else if (match.label === 'accepted_auth') {
      event.category = 'attempt';
      event.attemptType = 'successful_attempt';
    } else {
      event.category = 'observation';
    }

    return event;
  });
}
