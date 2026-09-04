import type {
  AuthEvent,
  Chronology,
  IpStat,
  Summary,
  UsernameStat,
} from './types';

const TOP_N = 10;

export interface StatsOutput {
  summary: Summary;
  topIps: IpStat[];
  topUsernames: UsernameStat[];
}

/**
 * Aggregations over the deduplicated, correlated events. Only confirmed
 * attempts feed behavioral counts; observations and duplicates are reported
 * but never counted.
 */
export function summarize(
  events: AuthEvent[],
  chronology: Chronology,
  unattributedObservations: number,
  suppressedRules: string[],
): StatsOutput {
  const unique = events.filter((e) => e.duplicateOf === null);
  const attempts = unique.filter((e) => e.category === 'attempt');
  const failed = attempts.filter((e) => e.attemptType === 'failed_attempt');
  const successful = attempts.filter(
    (e) => e.attemptType === 'successful_attempt',
  );
  const probes = attempts.filter((e) => e.attemptType === 'invalid_user_probe');
  const invalidUserAttempts =
    failed.filter((e) => e.isInvalidUser).length + probes.length;

  const ips = new Map<string, IpStat & { users: Set<string> }>();
  const usernames = new Map<string, UsernameStat & { ips: Set<string> }>();

  for (const a of attempts) {
    if (a.sourceIp !== null) {
      const s =
        ips.get(a.sourceIp) ??
        ({
          ip: a.sourceIp,
          ipVersion: a.ipVersion,
          attempts: 0,
          failed: 0,
          successful: 0,
          distinctUsernames: 0,
          users: new Set<string>(),
        } satisfies IpStat & { users: Set<string> });
      s.attempts++;
      if (a.attemptType === 'failed_attempt') s.failed++;
      if (a.attemptType === 'successful_attempt') s.successful++;
      if (a.username !== null) s.users.add(a.username);
      ips.set(a.sourceIp, s);
    }
    if (a.username !== null) {
      const s =
        usernames.get(a.username) ??
        ({
          username: a.username,
          attempts: 0,
          failed: 0,
          successful: 0,
          distinctIps: 0,
          privileged: a.isPrivilegedTarget,
          ips: new Set<string>(),
        } satisfies UsernameStat & { ips: Set<string> });
      s.attempts++;
      if (a.attemptType === 'failed_attempt') s.failed++;
      if (a.attemptType === 'successful_attempt') s.successful++;
      if (a.sourceIp !== null) s.ips.add(a.sourceIp);
      s.privileged = s.privileged || a.isPrivilegedTarget;
      usernames.set(a.username, s);
    }
  }

  const topIps: IpStat[] = [...ips.values()]
    .map(({ users, ...rest }) => ({ ...rest, distinctUsernames: users.size }))
    .sort((a, b) => b.attempts - a.attempts)
    .slice(0, TOP_N);
  const topUsernames: UsernameStat[] = [...usernames.values()]
    .map(({ ips: ipSet, ...rest }) => ({ ...rest, distinctIps: ipSet.size }))
    .sort((a, b) => b.attempts - a.attempts)
    .slice(0, TOP_N);

  const summary: Summary = {
    totalLines: events.length,
    uniqueLines: unique.length,
    duplicatesExcluded: events.length - unique.length,
    attempts: attempts.length,
    failedAttempts: failed.length,
    successfulAttempts: successful.length,
    invalidUserProbes: probes.length,
    invalidUserAttempts,
    uniqueSourceIps: ips.size,
    uniqueUsernames: usernames.size,
    observations: unique.filter((e) => e.category === 'observation').length,
    unattributedObservations,
    unparsedLines: unique.filter((e) => e.category === 'unparsed').length,
    suppressedRules,
  };

  void chronology;
  return { summary, topIps, topUsernames };
}
