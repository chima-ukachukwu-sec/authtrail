export type AuthMethod =
  | 'password'
  | 'publickey'
  | 'keyboard-interactive'
  | 'none'
  | null;

export type EventCategory = 'attempt' | 'observation' | 'unparsed';

export type AttemptType =
  | 'failed_attempt'
  | 'successful_attempt'
  | 'invalid_user_probe';

/**
 * Internal parse-stage label. Not the analysis contract: detection and
 * statistics consume only events where category === 'attempt'.
 */
export type ParseLabel =
  | 'failed_auth'
  | 'accepted_auth'
  | 'invalid_user'
  | 'connection_closed'
  | 'disconnected'
  | 'pam_failure'
  | 'other_sshd'
  | 'other_process'
  | 'unparsed';

export interface AuthEvent {
  /** Stable key, derived from the original line number. */
  id: string;
  /** 1-based line number in the original input. */
  lineNumber: number;
  /** Original line, verbatim. */
  raw: string;
  /** Timestamp exactly as written in the log, e.g. "Jan  3 04:12:55". */
  timestampRaw: string | null;
  /**
   * Absolute time, set ONLY when the log line itself carries a year
   * (ISO 8601). Never inferred for yearless syslog timestamps.
   */
  absoluteTime: Date | null;
  /**
   * Milliseconds elapsed since the first timestamped line, computed by an
   * ordered walk with Dec→Jan rollover handled as elapsed days. Internal,
   * approximate; used only for time-window detections. Null when the line
   * has no parseable timestamp.
   */
  relativeMs: number | null;
  /** Internal: day-of-year for yearless syslog timestamps (chronology walk). */
  syslogDoy?: number;
  /** Internal: milliseconds since midnight for syslog timestamps. */
  syslogTimeOfDayMs?: number;
  host: string | null;
  process: string | null;
  pid: number | null;
  category: EventCategory;
  attemptType: AttemptType | null;
  parseLabel: ParseLabel;
  username: string | null;
  isInvalidUser: boolean;
  isPrivilegedTarget: boolean;
  sourceIp: string | null;
  ipVersion: 4 | 6 | null;
  sourcePort: number | null;
  method: AuthMethod;
  /**
   * Id of the first occurrence when this line is an exact byte-identical
   * repeat of an earlier line. Duplicates are preserved for provenance but
   * excluded from all behavioral counts (anti-inflation policy).
   */
  duplicateOf: string | null;
  /** Line numbers of observation lines confidently absorbed as evidence. */
  evidenceLineNumbers: number[];
}

export type Severity = 'informational' | 'low' | 'medium' | 'high';

export interface FindingFact {
  label: string;
  value: string;
}

export interface Finding {
  ruleId: 'R1' | 'R2' | 'R3' | 'R4' | 'R5';
  severity: Severity;
  title: string;
  description: string;
  facts: FindingFact[];
  /** Ids of attempts referenced as evidence. */
  eventIds: string[];
}

export interface Chronology {
  /**
   * False when line ordering/timestamps are contradictory enough that
   * relative time cannot be trusted. Time-dependent rules (R1, R5, and the
   * elevated tiers of R2/R4) do not fire when this is false.
   */
  confident: boolean;
  /** Approximate elapsed span between first and last timestamped line. */
  spanMs: number | null;
  /** Number of lines carrying an explicit absolute (ISO) timestamp. */
  explicitAnchors: number;
}

export interface IpStat {
  ip: string;
  ipVersion: 4 | 6 | null;
  attempts: number;
  failed: number;
  successful: number;
  distinctUsernames: number;
}

export interface UsernameStat {
  username: string;
  attempts: number;
  failed: number;
  successful: number;
  distinctIps: number;
  privileged: boolean;
}

export interface Summary {
  /** Non-blank input lines analyzed (blank lines are skipped). */
  totalLines: number;
  uniqueLines: number;
  duplicatesExcluded: number;
  attempts: number;
  failedAttempts: number;
  successfulAttempts: number;
  invalidUserProbes: number;
  /** Failed attempts against nonexistent users + invalid-user probes. */
  invalidUserAttempts: number;
  uniqueSourceIps: number;
  uniqueUsernames: number;
  observations: number;
  /** Auth-relevant observations that could not be confidently attributed. */
  unattributedObservations: number;
  unparsedLines: number;
  /** Human-readable labels of rule tiers suppressed by low chronology confidence. */
  suppressedRules: string[];
}

export interface AnalysisResult {
  summary: Summary;
  chronology: Chronology;
  findings: Finding[];
  /** Every input line, in original order (attempts, observations, unparsed, duplicates). */
  events: AuthEvent[];
  topIps: IpStat[];
  topUsernames: UsernameStat[];
}
