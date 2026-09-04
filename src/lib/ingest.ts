export const MAX_FILE_BYTES = 25 * 1024 * 1024;
export const MAX_PASTE_CHARS = 5 * 1024 * 1024;
const SNIFF_BYTES = 8 * 1024;

export interface IngestedLine {
  /** 1-based line number in the original input, before blank lines were dropped. */
  lineNumber: number;
  raw: string;
  duplicateOfLine: number | null;
}

export type InputRejection =
  | 'empty'
  | 'too_large'
  | 'binary'
  | 'unsupported_type';

export interface InputValidation {
  ok: boolean;
  reason?: InputRejection;
  message?: string;
}

export function validateText(text: string, maxChars: number): InputValidation {
  if (text.trim().length === 0) {
    return { ok: false, reason: 'empty', message: 'The input is empty.' };
  }
  if (text.length > maxChars) {
    return {
      ok: false,
      reason: 'too_large',
      message: `The input exceeds the ${formatBytes(maxChars)} limit.`,
    };
  }
  if (looksBinary(text)) {
    return {
      ok: false,
      reason: 'binary',
      message: 'The content does not look like a text log file.',
    };
  }
  return { ok: true };
}

export function looksBinary(text: string): boolean {
  const sample = text.slice(0, SNIFF_BYTES);
  if (sample.includes('\0')) return true;
  let replacements = 0;
  for (let i = 0; i < sample.length; i++) {
    if (sample.charCodeAt(i) === 0xfffd) replacements++;
  }
  return sample.length > 0 && replacements / sample.length > 0.01;
}

/**
 * Splits on LF, CRLF, or lone CR. Whitespace-only lines are dropped from
 * analysis, but survivors keep their ORIGINAL 1-based source line numbers so
 * event references and evidence labels map back to the user's file.
 */
export function splitLines(text: string): SplitLine[] {
  return text
    .split(/\r\n|\r|\n/)
    .map((raw, index) => ({ lineNumber: index + 1, raw }))
    .filter((line) => line.raw.trim().length > 0);
}

export interface SplitLine {
  lineNumber: number;
  raw: string;
}

/**
 * Marks exact byte-identical repeated lines. Identical repeats cannot be
 * distinguished from copy/paste or logrotate duplication artifacts, so as an
 * anti-inflation policy only the first occurrence participates in behavioral
 * counts. All occurrences are preserved and disclosed.
 */
export function markDuplicates(lines: SplitLine[]): IngestedLine[] {
  const firstSeen = new Map<string, number>();
  return lines.map(({ lineNumber, raw }) => {
    const first = firstSeen.get(raw);
    if (first === undefined) {
      firstSeen.set(raw, lineNumber);
      return { lineNumber, raw, duplicateOfLine: null };
    }
    return { lineNumber, raw, duplicateOfLine: first };
  });
}

export function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) return `${Math.round(bytes / (1024 * 1024))} MB`;
  if (bytes >= 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${bytes} bytes`;
}
