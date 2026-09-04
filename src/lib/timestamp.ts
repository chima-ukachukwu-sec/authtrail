import type { AuthEvent, Chronology } from './types';

const MONTHS: Record<string, number> = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

/** Non-leap-year cumulative days at the start of each month. */
const MONTH_START_DAYS = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
/**
 * Longest month each day can belong to. February may reach 29 because the
 * year is genuinely unknown for yearless syslog timestamps; Feb 30/31 and
 * out-of-range times of day are malformed and never count as evidence.
 */
const SYSLOG_MAX_DAY = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

function isLeapYear(year: number): boolean {
  return year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
}

function daysInMonth(year: number, month: number): number {
  const days = [31, isLeapYear(year) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  return days[month - 1];
}

function isValidTimeOfDay(hour: number, minute: number, second: number): boolean {
  return hour <= 23 && minute <= 59 && second <= 59;
}

const DAY_MS = 86_400_000;
/** Backward jitter tolerated in merged logs before chronology is doubted. */
const OUT_OF_ORDER_TOLERANCE_MS = 5 * 60 * 1000;
/** A backward month/day jump larger than this is treated as a year rollover. */
const ROLLOVER_THRESHOLD_DAYS = 180;

const SYSLOG_TS =
  /^((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(.*)$/;
const ISO_TS =
  /^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(.*)$/;

export interface ParsedTimestamp {
  kind: 'syslog' | 'iso';
  /** Timestamp exactly as written. */
  raw: string;
  /** Remainder of the line after the timestamp. */
  rest: string;
  /** syslog only: day-of-year (0-364) and milliseconds since midnight. */
  doy?: number;
  timeOfDayMs?: number;
  /** iso only: absolute time carried by the line itself. */
  absolute?: Date;
}

export function parseTimestampPrefix(line: string): ParsedTimestamp | null {
  const iso = ISO_TS.exec(line);
  if (iso) {
    // Validate the calendar fields explicitly: Date normalization would
    // silently accept 2026-02-30 as March 2, inventing a real-looking time
    // from a line that carries none.
    const fields =
      /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})/.exec(iso[1]);
    if (!fields) return null;
    const year = Number(fields[1]);
    const month = Number(fields[2]);
    const day = Number(fields[3]);
    if (month < 1 || month > 12 || day < 1 || day > daysInMonth(year, month)) {
      return null;
    }
    if (
      !isValidTimeOfDay(Number(fields[4]), Number(fields[5]), Number(fields[6]))
    ) {
      return null;
    }
    // Date.parse needs 'T'; a space-separated variant is normalized.
    const normalized = iso[1].replace(' ', 'T').replace(',', '.');
    const hasZone = /(Z|[+-]\d{2}:?\d{2})$/.test(normalized);
    const absolute = new Date(normalized + (hasZone ? '' : 'Z'));
    if (Number.isNaN(absolute.getTime())) return null;
    return { kind: 'iso', raw: iso[1], rest: iso[2], absolute };
  }

  const syslog = SYSLOG_TS.exec(line);
  if (syslog) {
    const m = /^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?$/.exec(
      syslog[1],
    );
    if (!m) return null;
    const month = MONTHS[m[1]];
    if (month === undefined) return null;
    const day = Number(m[2]);
    if (day < 1 || day > SYSLOG_MAX_DAY[month]) return null;
    const hour = Number(m[3]);
    const minute = Number(m[4]);
    const second = Number(m[5]);
    if (!isValidTimeOfDay(hour, minute, second)) return null;
    // Fractional seconds (journalctl short-precise, rsyslog high-precision)
    // are truncated to whole milliseconds.
    const fracMs = m[6] !== undefined ? Number(`0.${m[6]}`) * 1000 : 0;
    const timeOfDayMs =
      hour * 3_600_000 +
      minute * 60_000 +
      second * 1000 +
      Math.floor(fracMs);
    return {
      kind: 'syslog',
      raw: syslog[1],
      rest: syslog[2],
      doy: MONTH_START_DAYS[month] + day - 1,
      timeOfDayMs,
    };
  }

  return null;
}

interface SyslogCursor {
  dayIndex: number;
  timeOfDayMs: number;
}

/**
 * Establishes relative chronology by walking timestamped, non-duplicate lines
 * in original order. Yearless syslog lines are mapped onto a synthetic axis
 * whose only claim is elapsed time: a genuine month-level backward rollover
 * (Dec 31 → Jan 1) adds one year of days, small out-of-order jitter is
 * clamped, and contradictory jumps mark the chronology not confident.
 *
 * Absolute (ISO) timestamps are used exactly where present. Mixed-format
 * boundaries contribute zero elapsed time rather than a guess, and because no
 * defensible continuity exists across a syslog↔ISO transition (syslog lines
 * carry no year), the first such transition marks the chronology not
 * confident: raw/display timestamps are preserved, but time-dependent rules
 * are suppressed rather than fired on invented relative times.
 */
export function buildChronology(events: AuthEvent[]): Chronology {
  let confident = true;
  let explicitAnchors = 0;
  let cursorMs = 0;
  let rollovers = 0;
  let originSet = false;
  let prevKind: 'syslog' | 'iso' | null = null;
  let prevSyslog: SyslogCursor | null = null;
  let prevIsoMs: number | null = null;

  for (const event of events) {
    if (event.duplicateOf !== null) continue;
    if (event.timestampRaw === null) continue;

    const kind: 'syslog' | 'iso' =
      event.absoluteTime !== null ? 'iso' : 'syslog';
    if (prevKind !== null && prevKind !== kind) {
      // Elapsed time across a timestamp-format boundary is unknowable; never
      // claim continuity that cannot be established.
      confident = false;
    }
    prevKind = kind;

    if (event.absoluteTime !== null) {
      explicitAnchors++;
      const absMs = event.absoluteTime.getTime();
      if (!originSet) {
        originSet = true;
      } else if (prevIsoMs !== null) {
        let delta = absMs - prevIsoMs;
        if (delta < -OUT_OF_ORDER_TOLERANCE_MS) {
          confident = false;
          delta = 0;
        } else if (delta < 0) {
          delta = 0;
        }
        cursorMs += delta;
      }
      // Mixed boundary (previous sample was syslog): elapsed time across the
      // boundary is unknowable, so the cursor holds rather than guesses.
      prevIsoMs = absMs;
      event.relativeMs = cursorMs;
      continue;
    }

    if (event.syslogDoy === undefined || event.syslogTimeOfDayMs === undefined) {
      continue;
    }

    let dayIndex = event.syslogDoy + rollovers * 365;
    if (!originSet) {
      originSet = true;
      prevSyslog = { dayIndex, timeOfDayMs: event.syslogTimeOfDayMs };
      event.relativeMs = cursorMs;
      continue;
    }
    if (prevSyslog !== null) {
      if (prevSyslog.dayIndex - dayIndex > ROLLOVER_THRESHOLD_DAYS) {
        rollovers++;
        dayIndex += 365;
      }
      let delta =
        (dayIndex - prevSyslog.dayIndex) * DAY_MS +
        (event.syslogTimeOfDayMs - prevSyslog.timeOfDayMs);
      if (delta < -OUT_OF_ORDER_TOLERANCE_MS) {
        confident = false;
        delta = 0;
      } else if (delta < 0) {
        delta = 0;
      }
      cursorMs += delta;
      prevSyslog = { dayIndex, timeOfDayMs: event.syslogTimeOfDayMs };
    }
    // If prevSyslog is null (only ISO lines seen so far), hold the cursor.
    event.relativeMs = cursorMs;
  }

  return {
    confident,
    spanMs: originSet ? cursorMs : null,
    explicitAnchors,
  };
}
