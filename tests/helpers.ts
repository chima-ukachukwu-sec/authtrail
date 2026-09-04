import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { analyzeLogText } from '@/lib/analyze';

export function fixture(name: string): string {
  return readFileSync(join(__dirname, 'fixtures', name), 'utf8');
}

let pid = 1000;
export function nextPid(): number {
  return ++pid;
}

export function syslog(
  ts: string,
  pidNum: number,
  message: string,
  host = 'host',
): string {
  return `${ts} ${host} sshd[${pidNum}]: ${message}`;
}

export function failed(
  ts: string,
  user: string,
  ip: string,
  opts: { invalid?: boolean; pid?: number; method?: string } = {},
): string {
  return syslog(
    ts,
    opts.pid ?? nextPid(),
    `Failed ${opts.method ?? 'password'} for ${opts.invalid ? 'invalid user ' : ''}${user} from ${ip} port 5${opts.pid ?? pid} ssh2`,
  );
}

export function accepted(
  ts: string,
  user: string,
  ip: string,
  opts: { pid?: number; method?: string } = {},
): string {
  return syslog(
    ts,
    opts.pid ?? nextPid(),
    `Accepted ${opts.method ?? 'password'} for ${user} from ${ip} port 5${opts.pid ?? pid} ssh2`,
  );
}

export function analyzeLines(lines: string[]) {
  return analyzeLogText(lines.join('\n'));
}
