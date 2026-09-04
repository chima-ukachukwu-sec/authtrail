# AuthTrail

Local-first Linux authentication log analyzer. Paste an OpenSSH log or drop a
`.log` / `.txt` file; AuthTrail normalizes SSH authentication activity and
reports deterministic security findings with their evidence — entirely in
your browser.

## Privacy model

- All parsing, correlation, detection, and statistics run client-side in the
  browser. Log contents are never transmitted.
- No telemetry, analytics, external APIs, IP reputation lookups, accounts, or
  database.
- Nothing is persisted: reloading the page discards the log and the analysis.
- The production build is a static export (`next build` → `out/`); there is
  no server component that could touch log data.
- Log content is rendered only as React text (auto-escaped);
  `dangerouslySetInnerHTML` is not used anywhere.

## What it detects

Rules are deterministic with fixed thresholds (`src/lib/detect.ts`) and
describe observed behavior — AuthTrail never claims an IP "is malicious".

| Rule | Condition | Severity |
| --- | --- | --- |
| R1 | ≥ 5 failed attempts from one IP within a 10-minute sliding window | medium (high ≥ 20) |
| R2 | ≥ 3 distinct nonexistent usernames from one IP | low; medium if within a 10-minute window |
| R3 | Usernames with ≥ 3 attempts | informational |
| R4 | Failed attempts against root | informational |
| R4 | Successful root login | medium ("verify expected"); high only when temporally correlated with a same-IP failure burst or same-IP enumeration within the preceding 10 minutes |
| R5 | Successful login after ≥ 3 failures from the same IP + username within 10 minutes | high |

Time-dependent rules (R1, R5, elevated tiers of R2/R4) require confident
relative chronology; contradictory timestamps suppress them with a visible
notice rather than producing unreliable findings.

## Correctness policies

- **Attempts vs. observations**: only self-contained credential-result lines
  (`Failed`/`Accepted`) mint authentication attempts. Supporting sshd lines
  (`Invalid user`, `Connection closed`, PAM failures) are observations: they
  attach to attempts as evidence when confidently correlated (same pid, or
  strict same-second/same-identity adjacency), form a single probing attempt
  when confidently grouped, and otherwise remain visible but excluded from
  all counts. Uncertain observations create zero attempts — when in doubt,
  AuthTrail under-reports rather than over-reports.
- **Duplicates**: identical repeated lines cannot be distinguished from
  copy/paste or logrotate artifacts. As an anti-inflation policy, only the
  first occurrence participates in behavioral counts; repeats are preserved,
  marked, and disclosed.
- **Timestamps**: traditional syslog timestamps carry no year. The UI shows
  timestamps exactly as written and never fabricates a calendar year. For
  windowed detections, AuthTrail builds an approximate relative chronology
  from line order (Dec 31 → Jan 1 is elapsed time, not an inferred year) and
  explicitly flags when that chronology is not trustworthy.
- Every non-blank input line becomes a record; unrecognized lines are shown
  as unparsed, never silently dropped. Blank lines are skipped, and every
  record keeps its original source line number.

## Input constraints

- Files: `.log` / `.txt`, up to 25 MB, UTF-8 text (binary-looking content is
  rejected).
- Paste: up to 5 MB.
- IPv4 and IPv6 sources; IPv4-mapped IPv6 addresses (`::ffff:203.0.113.7`)
  are canonicalized to the plain IPv4 identity. Hostname sources are
  preserved in the raw line but not treated as IPs.
- Timestamps: traditional syslog (`Jan  5 09:04:11`, including fractional
  seconds as in `journalctl -o short-precise`) and ISO 8601 (journalctl
  `short-iso`). A log that mixes both formats is still analyzed, but
  time-windowed rules are suppressed: elapsed continuity across the two
  formats cannot be established reliably, so the chronology is flagged as
  not confident.
- Recognized sshd lines: `Failed`/`Accepted` (`password`, `publickey`,
  `keyboard-interactive/pam`, `none`); `Invalid user`; `Disconnected from`
  and `Connection closed by` in their plain, `invalid user`, and
  `authenticating user` forms; `pam_unix(sshd:…): authentication failure`.
  Other sshd messages (PAM errors, connection resets, banners, protocol
  notices, …) are kept as context observations and are never counted as
  authentication attempts.
- Supported processes: `sshd`, `sshd-session` (OpenSSH 10+). Other syslog
  lines (sudo, CRON, …) are kept as context observations.

## Development

```sh
npm install
npm run dev     # development server
npm test        # vitest suite (parsing, correlation, chronology, rules, UI)
npm run bench   # performance measurement on a 200k-line synthetic log
npm run lint    # eslint
npm run build   # static export to out/
```

## Architecture

```
src/lib/            pure TypeScript, no React — independently testable
  ingest.ts         validation, line splitting, duplicate marking
  timestamp.ts      timestamp parsing + relative chronology walk
  parse.ts          line parser → normalized AuthEvent records
  correlate.ts      observation → attempt correlation
  detect.ts         rules R1–R5 with thresholds
  stats.ts          summary + top tables
  analyze.ts        analyzeLogText(text) façade
  types.ts          shared contracts
src/components/     React presentation (client components)
tests/              vitest suite + fixtures
```

Data flow: ingest → parse → chronology → correlate → detect/stats → render.
Detection and statistics consume only deduplicated, confirmed attempts.
