import { describe, it, expect } from 'vitest';
import {
  looksBinary,
  markDuplicates,
  splitLines,
  validateText,
  MAX_PASTE_CHARS,
} from '@/lib/ingest';
import { analyzeLogText } from '@/lib/analyze';

describe('splitLines', () => {
  it('handles LF, CRLF, and lone CR line endings', () => {
    const expected = [
      { lineNumber: 1, raw: 'a' },
      { lineNumber: 2, raw: 'b' },
      { lineNumber: 3, raw: 'c' },
    ];
    expect(splitLines('a\nb\nc')).toEqual(expected);
    expect(splitLines('a\r\nb\r\nc')).toEqual(expected);
    expect(splitLines('a\rb\rc')).toEqual(expected);
  });

  it('drops whitespace-only lines but preserves original line numbers', () => {
    expect(splitLines('a\n\n   \nb\n')).toEqual([
      { lineNumber: 1, raw: 'a' },
      { lineNumber: 4, raw: 'b' },
    ]);
  });
});

describe('markDuplicates', () => {
  it('marks exact repeats with their first occurrence', () => {
    const lines = markDuplicates([
      { lineNumber: 1, raw: 'x' },
      { lineNumber: 3, raw: 'y' },
      { lineNumber: 5, raw: 'x' },
      { lineNumber: 7, raw: 'x' },
    ]);
    expect(lines[0].duplicateOfLine).toBeNull();
    expect(lines[1].duplicateOfLine).toBeNull();
    expect(lines[2].duplicateOfLine).toBe(1);
    expect(lines[3].duplicateOfLine).toBe(1);
  });

  it('treats lines differing by a single character as distinct', () => {
    const lines = markDuplicates([
      { lineNumber: 1, raw: 'abc' },
      { lineNumber: 2, raw: 'abd' },
    ]);
    expect(lines[1].duplicateOfLine).toBeNull();
  });
});

describe('original line-number provenance', () => {
  it('events reference original source line numbers across blank lines', () => {
    const r = analyzeLogText(
      [
        'Jan  5 10:00:00 host sshd[1001]: Failed password for root from 10.0.0.1 port 41 ssh2',
        '   ',
        '',
        'Jan  5 10:01:00 host sshd[1002]: Accepted password for root from 10.0.0.1 port 42 ssh2',
      ].join('\n'),
    );
    expect(r.events.map((e) => e.lineNumber)).toEqual([1, 4]);
    expect(r.events.map((e) => e.id)).toEqual(['e1', 'e4']);
  });
});

describe('validateText', () => {
  it('rejects empty input', () => {
    expect(validateText('   \n ', MAX_PASTE_CHARS).reason).toBe('empty');
  });

  it('rejects oversized input', () => {
    expect(validateText('x'.repeat(101), 100).reason).toBe('too_large');
  });

  it('rejects binary-looking content', () => {
    expect(validateText('abc\0pq', MAX_PASTE_CHARS).reason).toBe('binary');
  });

  it('accepts ordinary log text', () => {
    expect(validateText('Jan  5 09:00:00 h sshd[1]: msg', MAX_PASTE_CHARS).ok).toBe(
      true,
    );
  });
});

describe('looksBinary', () => {
  it('flags NUL bytes and dense replacement characters', () => {
    expect(looksBinary('a\uFFFD'.repeat(100))).toBe(true);
    expect(looksBinary('plain ascii log text')).toBe(false);
  });
});
