// @vitest-environment jsdom
import { describe, it, expect, afterEach, vi } from 'vitest';
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react';
import AuthTrailApp from '@/components/AuthTrailApp';
import * as analyzeModule from '@/lib/analyze';

afterEach(cleanup);
afterEach(() => vi.restoreAllMocks());

function pasteAndAnalyze(text: string) {
  render(<AuthTrailApp />);
  fireEvent.change(screen.getByLabelText(/paste authentication log/i), {
    target: { value: text },
  });
  fireEvent.click(screen.getByRole('button', { name: 'Analyze' }));
}

describe('AuthTrail UI', () => {
  it('analyzes pasted log text and renders summary and findings', () => {
    const lines: string[] = [];
    for (let i = 0; i < 6; i++) {
      lines.push(
        `Jan  5 10:0${i}:00 host sshd[${6000 + i}]: Failed password for invalid user user${i} from 203.0.113.7 port 4000${i} ssh2`,
      );
    }
    lines.push(
      'Jan  5 10:07:00 host sshd[6010]: Accepted password for root from 198.51.100.9 port 50000 ssh2',
    );
    pasteAndAnalyze(lines.join('\n'));

    expect(screen.getAllByText('Attempts').length).toBeGreaterThan(0);
    expect(screen.getByText(/Failure burst from 203\.0\.113\.7/)).toBeTruthy();
    expect(screen.getByText(/Successful root authentication/)).toBeTruthy();
    expect(
      screen.getByText(/never leaves this device/i),
    ).toBeTruthy();
  });

  it('renders HTML/script-like log content as inert text', () => {
    pasteAndAnalyze(
      'Jan  5 10:00:00 host sshd[7001]: Invalid user <img src=x onerror=alert(1)> from 203.0.113.99 port 60000',
    );
    // The payload must appear as text, not as an element.
    expect(screen.getByText(/<img src=x onerror=alert\(1\)>/)).toBeTruthy();
    expect(document.querySelector('img[src="x"]')).toBeNull();
  });

  it('rejects empty input with an accessible alert', () => {
    render(<AuthTrailApp />);
    fireEvent.change(screen.getByLabelText(/paste authentication log/i), {
      target: { value: '   ' },
    });
    // Analyze is disabled for blank input.
    expect(
      (screen.getByRole('button', { name: 'Analyze' }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
  });

  it('keyboard-toggles a raw log line open and closed', () => {
    pasteAndAnalyze(
      'Jan  5 10:00:00 host sshd[8001]: Failed password for root from 10.9.9.9 port 22 ssh2',
    );
    const toggle = screen.getByRole('button', { name: /raw line 1/i });
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    fireEvent.click(toggle);
    expect(toggle.getAttribute('aria-expanded')).toBe('true');
    const matches = screen.getAllByText(/Failed password for root from 10\.9\.9\.9/);
    // Once in the textarea value, once in the expanded raw-line row.
    expect(matches.some((el) => el.tagName === 'P')).toBe(true);
  });

  it('analyzes a file-origin input larger than the 5 MB paste limit', async () => {
    render(<AuthTrailApp />);
    const big = `Jan  5 10:00:00 host sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2\n${'x'.repeat(6 * 1024 * 1024)}`;
    const file = new File([big], 'big.log', { type: 'text/plain' });
    fireEvent.change(screen.getByLabelText(/choose a log file/i), {
      target: { files: [file] },
    });
    // FileReader loads asynchronously.
    await waitFor(() =>
      expect(screen.getByText('big.log')).toBeTruthy(),
    );
    fireEvent.click(screen.getByRole('button', { name: 'Analyze' }));
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getAllByText('Attempts').length).toBeGreaterThan(0);
  });

  it('rejects pasted text larger than 5 MB', () => {
    render(<AuthTrailApp />);
    fireEvent.change(screen.getByLabelText(/paste authentication log/i), {
      target: { value: 'x'.repeat(5 * 1024 * 1024 + 10) },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Analyze' }));
    expect(screen.getByRole('alert').textContent).toContain(
      'exceeds the 5 MB limit',
    );
  });

  it('resets result-specific UI state on a new analysis', () => {
    pasteAndAnalyze(
      'Jan  5 10:00:00 host sshd[8001]: Failed password for alice from 10.9.9.9 port 22 ssh2',
    );
    // Set a type filter, a text query, and expand a raw row.
    fireEvent.change(screen.getByRole('combobox'), {
      target: { value: 'failed' },
    });
    fireEvent.change(screen.getByPlaceholderText('user, IP, or text'), {
      target: { value: 'alice' },
    });
    fireEvent.click(screen.getByRole('button', { name: /raw line 1/i }));
    expect(
      screen.getByRole('button', { name: /raw line 1/i }).getAttribute('aria-expanded'),
    ).toBe('true');

    // Analyze a different log.
    fireEvent.change(screen.getByLabelText(/paste authentication log/i), {
      target: {
        value:
          'Jan  6 11:00:00 host sshd[8002]: Accepted password for bob from 192.0.2.9 port 22 ssh2',
      },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Analyze' }));

    expect(
      (screen.getByRole('combobox') as HTMLSelectElement).value,
    ).toBe('all');
    expect(
      (screen.getByPlaceholderText('user, IP, or text') as HTMLInputElement)
        .value,
    ).toBe('');
    expect(
      screen.getByRole('button', { name: /raw line 1/i }).getAttribute('aria-expanded'),
    ).toBe('false');
  });

  it('surfaces a user-visible error when analysis fails unexpectedly', () => {
    vi.spyOn(analyzeModule, 'analyzeLogText').mockImplementation(() => {
      throw new Error('synthetic failure');
    });
    pasteAndAnalyze(
      'Jan  5 10:00:00 host sshd[8001]: Failed password for root from 10.9.9.9 port 22 ssh2',
    );
    expect(screen.getByRole('alert').textContent).toContain(
      'Analysis failed unexpectedly',
    );
    // No stale result is shown.
    expect(screen.queryByText('Attempts')).toBeNull();
  });
});
