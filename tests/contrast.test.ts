import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

function luminance(hex: string): number {
  const channels = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const linear = channels.map((v) =>
    v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4),
  );
  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
}

function contrastRatio(fg: string, bg: string): number {
  const [l1, l2] = [luminance(fg), luminance(bg)].sort((a, b) => b - a);
  return (l1 + 0.05) / (l2 + 0.05);
}

describe('color tokens meet WCAG AA for normal text (>= 4.5:1)', () => {
  const css = readFileSync(join(__dirname, '../src/app/globals.css'), 'utf8');
  const token = (name: string): string => {
    const m = new RegExp(`--color-${name}:\\s*(#[0-9a-fA-F]{6})`).exec(css);
    if (!m) throw new Error(`token --color-${name} not found in globals.css`);
    return m[1].toLowerCase();
  };

  // Tokens used for small normal text must hold 4.5:1 on every surface they
  // appear on (bg and surface).
  it.each(['ink', 'muted', 'faint', 'accent', 'high', 'medium', 'low'])(
    '%s is readable on bg and surface',
    (name) => {
      for (const surface of ['bg', 'surface'] as const) {
        const ratio = contrastRatio(token(name), token(surface));
        expect(
          ratio,
          `${name} (${token(name)}) on ${surface} (${token(surface)})`,
        ).toBeGreaterThanOrEqual(4.5);
      }
    },
  );
});
